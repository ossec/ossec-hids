/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "maild.h"
#include "mail_list.h"
#include "sms_queue.h"
#ifdef USE_SMTP_CURL
#include <curl/curl.h>
#include "os_net/os_net.h"
#endif

#ifndef ARGV0
#define ARGV0 "ossec-maild"
#endif

/* Global variables */
unsigned int mail_timeout;
unsigned int   _g_subject_level;
char _g_subject[SUBJECT_SIZE + 2];

typedef struct mail_worker_arg {
    MailConfig *mail;
    struct tm tm_copy;
    char subject[SUBJECT_SIZE + 2];
    unsigned int subject_level;
    int gran_count;
    int *gran_set_snap;
    MailNode *batch;
} mail_worker_arg;

typedef struct sms_worker_arg {
    MailConfig *mail;
    struct tm tm_copy;
    MailMsg *sms_msg;
    int gran_count;
    int *gran_set_snap;
} sms_worker_arg;

static pthread_mutex_t mail_workers_mu;
pthread_mutex_t mail_send_mu;
static int mail_active_workers = 0;
static int mail_max_workers = MAX_MAIL_WORKERS;
static volatile sig_atomic_t maild_shutting_down = 0;
static int mail_spawn_fail_streak = 0;

#define MAILD_SHUTDOWN_WORKER_TIMEOUT 60

/* Prototypes */
static void OS_Run(MailConfig *mail) __attribute__((nonnull)) __attribute__((noreturn));
static void help_maild(int status) __attribute__((noreturn));
static void *mail_send_worker(void *arg);
static void *sms_send_worker(void *arg);
static void maild_HandleSIG(int sig);
static void mail_spawn_backoff(void);
static void maild_shutdown_drain(MailConfig *mail, struct tm *p, file_queue *fileq);

/* Returns 0 on success, -1 on allocation failure. */
static int mail_snapshot_gran(MailConfig *mail, int **gran_set_snap, int *gran_count)
{
    int n = 0;

    *gran_set_snap = NULL;
    *gran_count = 0;

    if (!mail->gran_to || !mail->gran_set) {
        return (0);
    }

    while (mail->gran_to[n] != NULL) {
        n++;
    }

    if (n == 0) {
        return (0);
    }

    *gran_count = n;
    *gran_set_snap = (int *)calloc((size_t)n, sizeof(int));
    if (!*gran_set_snap) {
        merror(MEM_ERROR, ARGV0, errno, strerror(errno));
        *gran_count = 0;
        return (-1);
    }
    memcpy(*gran_set_snap, mail->gran_set, (size_t)n * sizeof(int));
    return (0);
}

static void mail_spawn_backoff(void)
{
    int delay = 1;

    mail_spawn_fail_streak++;
    if (mail_spawn_fail_streak > 1) {
        delay = 1 << (mail_spawn_fail_streak - 1);
        if (delay > 30) {
            delay = 30;
        }
    }

    sleep((unsigned int)delay);
}

/* During SIGTERM, send one pending SMS or batch if a worker slot is free. */
static void maild_shutdown_drain(MailConfig *mail, struct tm *p, file_queue *fileq)
{
    int spawn = 0;

    os_mutex_lock(&mail_workers_mu);
    if (mail_active_workers < mail_max_workers) {
        mail_active_workers++;
        spawn = 1;
    }
    os_mutex_unlock(&mail_workers_mu);

    if (!spawn) {
        return;
    }

    if (OS_SmsQueuePending()) {
        sms_worker_arg *sms_work;
        MailMsg *sms_msg = OS_SmsDequeue();

        if (!sms_msg) {
            os_mutex_lock(&mail_workers_mu);
            mail_active_workers--;
            os_mutex_unlock(&mail_workers_mu);
            return;
        }

        os_calloc(1, sizeof(sms_worker_arg), sms_work);
        sms_work->mail = mail;
        memcpy(&sms_work->tm_copy, p, sizeof(struct tm));
        sms_work->sms_msg = sms_msg;
        sms_work->gran_count = 0;
        sms_work->gran_set_snap = NULL;

        os_mutex_lock(&mail_send_mu);
        if (mail_snapshot_gran(mail, &sms_work->gran_set_snap,
                               &sms_work->gran_count) < 0) {
            os_mutex_unlock(&mail_send_mu);
            os_mutex_lock(&mail_workers_mu);
            mail_active_workers--;
            os_mutex_unlock(&mail_workers_mu);
            OS_SmsRequeueFront(sms_msg);
            free(sms_work);
            return;
        }
        os_mutex_unlock(&mail_send_mu);

        if (CreateThread(sms_send_worker, sms_work) != 0) {
            os_mutex_lock(&mail_workers_mu);
            mail_active_workers--;
            os_mutex_unlock(&mail_workers_mu);
            OS_SmsRequeueFront(sms_work->sms_msg);
            free(sms_work->gran_set_snap);
            free(sms_work);
            return;
        }

        return;
    }

    if (OS_CheckLastMail() == NULL) {
        os_mutex_lock(&mail_workers_mu);
        mail_active_workers--;
        os_mutex_unlock(&mail_workers_mu);
        return;
    }

    {
        mail_worker_arg *work;
        MailNode *batch;

        fflush(fileq->fp);

        os_calloc(1, sizeof(mail_worker_arg), work);
        work->mail = mail;
        memcpy(&work->tm_copy, p, sizeof(struct tm));
        work->gran_count = 0;
        work->gran_set_snap = NULL;
        work->batch = NULL;

        os_mutex_lock(&mail_send_mu);
        OS_MailListLock();
        work->subject_level = _g_subject_level;
        memcpy(work->subject, _g_subject, SUBJECT_SIZE + 2);
        if (mail_snapshot_gran(mail, &work->gran_set_snap, &work->gran_count) < 0) {
            OS_MailListUnlock();
            os_mutex_unlock(&mail_send_mu);
            os_mutex_lock(&mail_workers_mu);
            mail_active_workers--;
            os_mutex_unlock(&mail_workers_mu);
            free(work);
            return;
        }

        batch = OS_DrainMailListUnlocked();
        work->batch = batch;
        OS_MailListUnlock();
        os_mutex_unlock(&mail_send_mu);

        if (batch == NULL) {
            os_mutex_lock(&mail_workers_mu);
            mail_active_workers--;
            os_mutex_unlock(&mail_workers_mu);
            free(work->gran_set_snap);
            free(work);
            return;
        }

        if (CreateThread(mail_send_worker, work) != 0) {
            os_mutex_lock(&mail_send_mu);
            OS_MailListLock();
            OS_RequeueMailBatch(batch);
            OS_MailListUnlock();
            os_mutex_unlock(&mail_send_mu);
            os_mutex_lock(&mail_workers_mu);
            mail_active_workers--;
            os_mutex_unlock(&mail_workers_mu);
            free(work->gran_set_snap);
            free(work);
            return;
        }
    }
}

#ifndef WIN32
static void maild_HandleSIG(int sig)
{
    if (!maild_shutting_down) {
        maild_shutting_down = 1;
        merror("%s: Shutdown requested (signal %d); waiting for mail workers to finish.",
               ARGV0, sig);
        return;
    }

    merror(SIGNAL_RECV, ARGV0, sig, strsignal(sig));
    DeletePID(ARGV0);
    exit(1);
}
#endif

#ifdef USE_SMTP_CURL
static MailConfig *s_mail_cleanup = NULL;
static void maild_clear_smtp_secrets(void)
{
    if (s_mail_cleanup) {
        if (s_mail_cleanup->smtp_user) {
            memset_secure(s_mail_cleanup->smtp_user, 0, strlen(s_mail_cleanup->smtp_user));
        }
        if (s_mail_cleanup->smtp_pass) {
            memset_secure(s_mail_cleanup->smtp_pass, 0, strlen(s_mail_cleanup->smtp_pass));
        }
        if (s_mail_cleanup->smtpserver_resolved) {
            free(s_mail_cleanup->smtpserver_resolved);
            s_mail_cleanup->smtpserver_resolved = NULL;
        }
    }
    curl_global_cleanup();
}
#endif


/* Print help statement */
static void help_maild(int status)
{
    print_header();
    print_out("  %s: -[Vhdtf] [-u user] [-g group] [-c config] [-D dir]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground");
    print_out("    -u <user>   User to run as (default: %s)", MAILUSER);
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -c <config> Configuration file to use (default: %s)", DEFAULTCPATH);
    print_out("    -D <dir>    Directory to chroot into (default: %s)", DEFAULTDIR);
    print_out(" ");
    exit(status);
}

int main(int argc, char **argv)
{
    int c, test_config = 0, run_foreground = 0;
    uid_t uid;
    gid_t gid;
    const char *dir  = DEFAULTDIR;
    const char *user = MAILUSER;
    const char *group = GROUPGLOBAL;
    const char *cfg = DEFAULTCPATH;

    /* Mail Structure */
    MailConfig mail;

    /* Set the name */
    OS_SetName(ARGV0);

    while ((c = getopt(argc, argv, "Vdhtfu:g:D:c:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_maild(0);
                break;
            case 'd':
                nowDebug();
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'u':
                if (!optarg) {
                    ErrorExit("%s: -u needs an argument", ARGV0);
                }
                user = optarg;
                break;
            case 'g':
                if (!optarg) {
                    ErrorExit("%s: -g needs an argument", ARGV0);
                }
                group = optarg;
                break;
            case 'D':
                if (!optarg) {
                    ErrorExit("%s: -D needs an argument", ARGV0);
                }
                dir = optarg;
                break;
            case 'c':
                if (!optarg) {
                    ErrorExit("%s: -c needs an argument", ARGV0);
                }
                cfg = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            default:
                help_maild(1);
                break;
        }
    }

    /* Start daemon */
    debug1(STARTED_MSG, ARGV0);

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        ErrorExit(USER_ERROR, ARGV0, user, group);
    }

    /* Read configuration */
    if (MailConf(test_config, cfg, &mail) < 0) {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    }

#ifdef USE_SMTP_CURL
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        ErrorExit("%s: curl_global_init failed.", ARGV0);
    }
    s_mail_cleanup = &mail;
    atexit(maild_clear_smtp_secrets);
#endif

    /* Read internal options */
    mail.strict_checking = getDefine_Int("maild",
                                         "strict_checking",
                                         0, 1);

    /* Get groupping */
    mail.groupping = getDefine_Int("maild",
                                   "groupping",
                                   0, 1);

    /* Get subject type */
    mail.subject_full = getDefine_Int("maild",
                                      "full_subject",
                                      0, 1);

#ifdef LIBGEOIP_ENABLED
    /* Get GeoIP */
    mail.geoip = getDefine_Int("maild",
                               "geoip",
                               0, 1);
#endif

    /* Exit here if test config is set */
    if (test_config) {
        exit(0);
    }

    if (!run_foreground) {
        nowDaemon();
        goDaemon();
    }

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        ErrorExit(SETGID_ERROR, ARGV0, group, errno, strerror(errno));
    }

#ifdef USE_SMTP_CURL
    /* Pre-resolve SMTP hostname before chroot; DNS is unavailable inside the jail.
     * global-config.c also resolves at parse time, but verify here as a safeguard. */
    if (mail.smtpserver && mail.smtpserver[0] != '/' && !mail.smtpserver_resolved) {
        mail.smtpserver_resolved = OS_GetHost(mail.smtpserver, 5);
        if (!mail.smtpserver_resolved) {
            merror("%s: Could not resolve smtp_server '%s'. DNS will not work after chroot.", ARGV0, mail.smtpserver);
            ErrorExit(CONFIG_ERROR, ARGV0, cfg);
        }
    }
#endif

    if (mail.smtpserver && mail.smtpserver[0] != '/') {
        /* chroot */
        if (Privsep_Chroot(dir) < 0) {
            ErrorExit(CHROOT_ERROR, ARGV0, dir, errno, strerror(errno));
        }
        nowChroot();
        debug1(CHROOT_MSG, ARGV0, dir);
    }

    /* Change user */
    if (Privsep_SetUser(uid) < 0) {
        ErrorExit(SETUID_ERROR, ARGV0, user, errno, strerror(errno));
    }

    debug1(PRIVSEP_MSG, ARGV0, user);

    /* Signal manipulation */
#ifndef WIN32
    StartSIG2(ARGV0, maild_HandleSIG);
#else
    StartSIG(ARGV0);
#endif

    /* Create PID files */
    if (CreatePID(ARGV0, getpid()) < 0) {
        ErrorExit(PID_ERROR, ARGV0);
    }

    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());

    /* The real daemon now */
    OS_Run(&mail);
}

/* Read the queue and send the appropriate alerts
 * Not supposed to return
 */
static void *mail_send_worker(void *arg)
{
    mail_worker_arg *work = (mail_worker_arg *)arg;
    MailConfig *mail = work->mail;
    struct tm tm_copy = work->tm_copy;
    char subject[SUBJECT_SIZE + 2];
    unsigned int subject_level = work->subject_level;
    int gran_count = work->gran_count;
    int *gran_set_snap = work->gran_set_snap;
    MailNode *batch = work->batch;
    const int *gran_override = NULL;

    os_block_worker_signals();

    memcpy(subject, work->subject, SUBJECT_SIZE + 2);
    free(work);

    if (!batch) {
        free(gran_set_snap);
        os_mutex_lock(&mail_workers_mu);
        mail_active_workers--;
        os_mutex_unlock(&mail_workers_mu);
        return NULL;
    }

    if (gran_count > 0 && gran_set_snap) {
        gran_override = gran_set_snap;
    }

    if (OS_Sendmail(mail, &tm_copy, batch, gran_override, subject,
                    subject_level) < 0) {
        merror(SNDMAIL_ERROR, ARGV0, mail->smtpserver);
    }

    free(gran_set_snap);

    os_mutex_lock(&mail_workers_mu);
    mail_active_workers--;
    os_mutex_unlock(&mail_workers_mu);

    return NULL;
}

static void *sms_send_worker(void *arg)
{
    sms_worker_arg *work = (sms_worker_arg *)arg;
    MailConfig *mail = work->mail;
    struct tm tm_copy = work->tm_copy;
    MailMsg *sms_msg = work->sms_msg;
    int gran_count = work->gran_count;
    int *gran_set_snap = work->gran_set_snap;
    const int *gran_override = NULL;

    os_block_worker_signals();
    free(work);

    if (gran_count > 0 && gran_set_snap) {
        gran_override = gran_set_snap;
    }

    if (OS_Sendsms(mail, &tm_copy, sms_msg, gran_override) < 0) {
        merror(SNDMAIL_ERROR, ARGV0, mail->smtpserver);
    }

    FreeMailMsg(sms_msg);
    free(gran_set_snap);

    os_mutex_lock(&mail_workers_mu);
    mail_active_workers--;
    os_mutex_unlock(&mail_workers_mu);

    return NULL;
}

static void OS_Run(MailConfig *mail)
{
    MailMsg *msg;
    MailMsg *s_msg = NULL;

    time_t tm;
    struct tm *p;

    int i = 0;
    int mailtosend = 0;
    /* Counts batch/SMS worker spawns per hour (email_maxperhour), not SMTP completions. */
    int mails_sent_this_hour = 0;
    int thishour = 0;
    int sms_defer_logged_hour = -1;
    struct tm tm_buf;
    time_t shutdown_start = 0;

    file_queue *fileq;

    os_mutex_init(&mail_workers_mu, NULL);
    os_mutex_init(&mail_send_mu, NULL);
    mail_max_workers = getDefine_Int("maild", "max_workers", 1, 32);

    /* Get current time before starting */
    tm = time(NULL);
    localtime_r(&tm, &tm_buf);
    p = &tm_buf;
    thishour = p->tm_hour;

    /* Initialize file queue */
    i = 0;
    i |= CRALERT_MAIL_SET;
    os_calloc(1, sizeof(file_queue), fileq);
    Init_FileQueue(fileq, p, i);

    /* Create the list */
    OS_CreateMailList(MAIL_LIST_SIZE);
    OS_SmsQueueInit();

    /* Set default timeout */
    mail_timeout = DEFAULT_TIMEOUT;

    /* Clear global variables */
    _g_subject_level = 0;
    memset(_g_subject, '\0', SUBJECT_SIZE + 2);

    while (1) {
        tm = time(NULL);
        localtime_r(&tm, &tm_buf);
        p = &tm_buf;

        if (maild_shutting_down) {
            int active;

            if (shutdown_start == 0) {
                shutdown_start = tm;
            }

            maild_shutdown_drain(mail, p, fileq);

            os_mutex_lock(&mail_workers_mu);
            active = mail_active_workers;
            os_mutex_unlock(&mail_workers_mu);

            if (active == 0) {
                if (!OS_SmsQueuePending() && OS_CheckLastMail() == NULL) {
                    verbose("%s: Shutdown complete (no active mail workers).", ARGV0);
                } else {
                    verbose("%s: Shutdown complete (pending mail/SMS abandoned).", ARGV0);
                }
                DeletePID(ARGV0);
                exit(0);
            }

            if ((tm - shutdown_start) >= MAILD_SHUTDOWN_WORKER_TIMEOUT) {
                merror("%s: Shutdown timeout (%d s) with %d mail worker(s) still active.",
                       ARGV0, MAILD_SHUTDOWN_WORKER_TIMEOUT, active);
                DeletePID(ARGV0);
                exit(1);
            }

            sleep(1);
            continue;
        }

        /* SMS messages are sent without grouping delay (4.6 parity). */
        if (OS_SmsQueuePending()) {
            sms_worker_arg *sms_work;
            MailMsg *sms_msg;
            int spawn_sms = 0;
            int sms_deferred = 0;

            if (mails_sent_this_hour >= mail->maxperhour) {
                if (sms_defer_logged_hour != thishour) {
                    verbose("%s: INFO: SMS deferred until next hour (email_maxperhour=%d).",
                            ARGV0, mail->maxperhour);
                    sms_defer_logged_hour = thishour;
                }
                sms_deferred = 1;
            } else {
                os_mutex_lock(&mail_workers_mu);
                if (mail_active_workers < mail_max_workers) {
                    mail_active_workers++;
                    spawn_sms = 1;
                } else {
                    debug2("%s: SMS deferred (max_workers=%d busy).",
                           ARGV0, mail_max_workers);
                    sms_deferred = 1;
                }
                os_mutex_unlock(&mail_workers_mu);
            }

            if (spawn_sms) {
                sms_msg = OS_SmsDequeue();
                if (!sms_msg) {
                    os_mutex_lock(&mail_workers_mu);
                    mail_active_workers--;
                    os_mutex_unlock(&mail_workers_mu);
                } else {
                    os_calloc(1, sizeof(sms_worker_arg), sms_work);
                    sms_work->mail = mail;
                    memcpy(&sms_work->tm_copy, p, sizeof(struct tm));
                    sms_work->sms_msg = sms_msg;
                    sms_work->gran_count = 0;
                    sms_work->gran_set_snap = NULL;

                    os_mutex_lock(&mail_send_mu);
                    if (mail_snapshot_gran(mail, &sms_work->gran_set_snap,
                                           &sms_work->gran_count) < 0) {
                        os_mutex_unlock(&mail_send_mu);
                        os_mutex_lock(&mail_workers_mu);
                        mail_active_workers--;
                        os_mutex_unlock(&mail_workers_mu);
                        OS_SmsRequeueFront(sms_msg);
                        free(sms_work);
                    } else {
                        os_mutex_unlock(&mail_send_mu);

                        if (CreateThread(sms_send_worker, sms_work) != 0) {
                            os_mutex_lock(&mail_workers_mu);
                            mail_active_workers--;
                            os_mutex_unlock(&mail_workers_mu);
                            OS_SmsRequeueFront(sms_work->sms_msg);
                            free(sms_work->gran_set_snap);
                            free(sms_work);
                            merror(THREAD_ERROR, ARGV0);
                            mail_spawn_backoff();
                        } else {
                            mail_spawn_fail_streak = 0;
                            mails_sent_this_hour++;
                        }
                    }
                }
            } else if (sms_deferred) {
                sleep(1);
            }
        }

        /* If mail_timeout == NEXTMAIL_TIMEOUT, we will try to get
         * more messages, before sending anything
         */
        if ((mail_timeout == NEXTMAIL_TIMEOUT) && (p->tm_hour == thishour)) {
            /* Get more messages */
        }

        /* Hour changed: send all suppressed mails */
        else if ((((mailtosend != 0) &&
                   (mails_sent_this_hour < mail->maxperhour)) ||
                  (p->tm_hour != thishour))) {
            mail_worker_arg *work;
            MailNode *batch;
            int spawn_batch = 0;

            if (OS_CheckLastMail() != NULL &&
                (mails_sent_this_hour < mail->maxperhour ||
                 p->tm_hour != thishour)) {
                os_mutex_lock(&mail_workers_mu);
                if (mail_active_workers < mail_max_workers) {
                    mail_active_workers++;
                    spawn_batch = 1;
                }
                os_mutex_unlock(&mail_workers_mu);
            }

            if (!spawn_batch) {
                if (OS_CheckLastMail() != NULL &&
                    (mails_sent_this_hour < mail->maxperhour ||
                     p->tm_hour != thishour)) {
                    sleep(1);
                }
                goto snd_check_hour;
            }

            fflush(fileq->fp);

            os_calloc(1, sizeof(mail_worker_arg), work);
            work->mail = mail;
            memcpy(&work->tm_copy, p, sizeof(struct tm));
            work->gran_count = 0;
            work->gran_set_snap = NULL;
            work->batch = NULL;

            os_mutex_lock(&mail_send_mu);
            OS_MailListLock();
            work->subject_level = _g_subject_level;
            memcpy(work->subject, _g_subject, SUBJECT_SIZE + 2);
            if (mail_snapshot_gran(mail, &work->gran_set_snap,
                                   &work->gran_count) < 0) {
                OS_MailListUnlock();
                os_mutex_unlock(&mail_send_mu);
                os_mutex_lock(&mail_workers_mu);
                mail_active_workers--;
                os_mutex_unlock(&mail_workers_mu);
                free(work);
                goto snd_check_hour;
            }

            batch = OS_DrainMailListUnlocked();
            work->batch = batch;

            OS_MailListUnlock();
            os_mutex_unlock(&mail_send_mu);

            if (batch == NULL) {
                os_mutex_lock(&mail_workers_mu);
                mail_active_workers--;
                os_mutex_unlock(&mail_workers_mu);
                free(work->gran_set_snap);
                free(work);
                goto snd_check_hour;
            }

            if (CreateThread(mail_send_worker, work) != 0) {
                os_mutex_lock(&mail_send_mu);
                OS_MailListLock();
                OS_RequeueMailBatch(batch);
                OS_MailListUnlock();
                os_mutex_unlock(&mail_send_mu);
                os_mutex_lock(&mail_workers_mu);
                mail_active_workers--;
                os_mutex_unlock(&mail_workers_mu);
                free(work->gran_set_snap);
                free(work);
                merror(THREAD_ERROR, ARGV0);
                mail_spawn_backoff();
                continue;
            }

            mail_spawn_fail_streak = 0;
            mails_sent_this_hour++;

            /* Commit batch: clear grouped subject and live granular routing state. */
            os_mutex_lock(&mail_send_mu);
            _g_subject[0] = '\0';
            _g_subject_level = 0;
            if (mail->gran_to && mail->gran_set) {
                i = 0;
                while (mail->gran_to[i] != NULL) {
                    mail->gran_set[i] = 0;
                    i++;
                }
            }
            os_mutex_unlock(&mail_send_mu);

snd_check_hour:
            /* If we sent everything */
            if (p->tm_hour != thishour) {
                thishour = p->tm_hour;

                mailtosend = 0;
                mails_sent_this_hour = 0;
                sms_defer_logged_hour = -1;
            }
        }

        /* Saved message for the do_not_group option */
        if (s_msg) {
            /* Set the remaining do no group to full format */
            os_mutex_lock(&mail_send_mu);
            if (mail->gran_to) {
                i = 0;
                while (mail->gran_to[i] != NULL) {
                    if (mail->gran_set[i] == DONOTGROUP) {
                        mail->gran_set[i] = FULL_FORMAT;
                    }
                    i++;
                }
            }
            os_mutex_unlock(&mail_send_mu);

            OS_AddMailtoList(s_msg);

            s_msg = NULL;
            mailtosend++;
            continue;
        }

        /* Receive message from queue */
        if ((msg = OS_RecvMailQ(fileq, p, mail)) != NULL) {
            /* If the e-mail priority is do_not_group,
             * flush all previous entries and then send it.
             * Use s_msg to hold the pointer to the message while we flush it.
             */
            if (mail->priority == DONOTGROUP) {
                s_msg = msg;
            } else {
                OS_AddMailtoList(msg);
            }

            /* Change timeout to see if any new message is coming shortly */
            if (mail->groupping) {
                /* If priority is set, send email now */
                if (mail->priority) {
                    mail_timeout = DEFAULT_TIMEOUT;

                    /* If do_not_group is set, we do not increase the list count */
                    if (mail->priority != DONOTGROUP) {
                        mailtosend++;
                    }
                } else {
                    /* 5 seconds only */
                    mail_timeout = NEXTMAIL_TIMEOUT;
                }
            } else {
                /* Send message by itself */
                mailtosend++;
            }
        } else {
            if (mail_timeout == NEXTMAIL_TIMEOUT) {
                mailtosend++;

                /* Default timeout */
                mail_timeout = DEFAULT_TIMEOUT;
            }
        }

    }
}

