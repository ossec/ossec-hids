/* Copyright (C) 2010 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* SCHED_BATCH is Linux specific and is only picked up with _GNU_SOURCE */
#ifdef __linux__
#define _GNU_SOURCE
#include <sched.h>
#endif
#ifdef WIN32
#include <winsock2.h>
#include <aclapi.h>
#include <sddl.h>
#endif

#include "shared.h"
#include "syscheck.h"
#include "fim_sum_op.h"
#include "win_acl_op.h"
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/sha1/sha1_op.h"
#include "os_crypto/sha256/sha256_op.h"
#include "os_crypto/md5_sha1/md5_sha1_op.h"
#include "rootcheck/rootcheck.h"

/* Prototypes */
static void send_sk_db(void);
static void syscheck_log_send_failures(void);
static time_t syscheck_idle_wait(time_t curr_time, time_t prev_time_sk,
                                 time_t prev_time_rk);

/* Count of baseline/update messages that could not reach the agent queue. */
static unsigned int syscheck_send_failures = 0;

/* Max idle between daemon-loop iterations: honor <frequency> / rootcheck
 * cadence while still capping at SYSCHECK_WAIT so long frequencies do not
 * block forever in select/sleep.
 */
static time_t syscheck_idle_wait(time_t curr_time, time_t prev_time_sk,
                                 time_t prev_time_rk)
{
    time_t remaining;
    time_t next_sk;
    time_t sk_remain;

    next_sk = prev_time_sk + (time_t)syscheck.time;
    sk_remain = next_sk - curr_time;
    remaining = sk_remain;

    if (syscheck.rootcheck && rootcheck.time > 0) {
        time_t next_rk = prev_time_rk + (time_t)rootcheck.time;
        time_t rk_remain = next_rk - curr_time;
        if (rk_remain < remaining) {
            remaining = rk_remain;
        }
    }

    if (remaining < 1) {
        remaining = 1;
    }
    if (remaining > SYSCHECK_WAIT) {
        remaining = SYSCHECK_WAIT;
    }
    return remaining;
}


/* Send a message related to syscheck change/addition.
 * Returns 0 on success, -1 if the message could not be delivered.
 */
int send_syscheck_msg(const char *msg)
{
    if (SendMSG(syscheck.queue, msg, SYSCHECK, SYSCHECK_MQ) < 0) {
        merror(QUEUE_SEND, ARGV0);

        if ((syscheck.queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
            ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
        }

        /* Try to send it again */
        if (SendMSG(syscheck.queue, msg, SYSCHECK, SYSCHECK_MQ) < 0) {
            syscheck_send_failures++;
            return (-1);
        }
    }
    return (0);
}

static void syscheck_log_send_failures(void)
{
    if (syscheck_send_failures > 0) {
        merror("%s: WARN: %u syscheck database entries were not delivered to "
              "the manager and will be retried on the next scan.",
              ARGV0, syscheck_send_failures);
        syscheck_send_failures = 0;
    }
}

/* Send a message related to rootcheck change/addition */
int send_rootcheck_msg(const char *msg)
{
    if (SendMSG(syscheck.queue, msg, ROOTCHECK, ROOTCHECK_MQ) < 0) {
        merror(QUEUE_SEND, ARGV0);

        if ((syscheck.queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
            ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
        }

        /* Try to send it again */
        SendMSG(syscheck.queue, msg, ROOTCHECK, ROOTCHECK_MQ);
    }
    return (0);
}

/* Send syscheck db to the server */
static void send_sk_db()
{
    /* Send scan start message */
    if (syscheck.dir[0]) {
        merror("%s: INFO: Starting syscheck scan (forwarding database).", ARGV0);
        send_rootcheck_msg("Starting syscheck scan.");
    } else {
        return;
    }

    syscheck_send_failures = 0;
    create_db();

    /* Send scan ending message */
    sleep(syscheck.tsleep + 10);

    if (syscheck.dir[0]) {
        merror("%s: INFO: Ending syscheck scan (forwarding database).", ARGV0);
        send_rootcheck_msg("Ending syscheck scan.");
    }
}

/* Periodically run the integrity checker */
void start_daemon()
{
    int day_scanned = 0;
    int curr_day = 0;
    time_t curr_time = 0;
    time_t prev_time_rk = 0;
    time_t prev_time_sk = 0;
    char curr_hour[12];
    struct tm *p;

#ifdef INOTIFY_ENABLED
    /* To be used by select */
    struct timeval selecttime;
    fd_set rfds;
#endif

    /* SCHED_BATCH forces the kernel to assume this is a cpu intensive
     * process and gives it a lower priority. This keeps ossec-syscheckd
     * from reducing the interactivity of an ssh session when checksumming
     * large files. This is available in kernel flavors >= 2.6.16.
     */
#ifdef SCHED_BATCH
    struct sched_param pri;
    int status;

    pri.sched_priority = 0;
    status = sched_setscheduler(0, SCHED_BATCH, &pri);

    debug1("%s: Setting SCHED_BATCH returned: %d", ARGV0, status);
#endif

#ifdef DEBUG
    verbose("%s: Starting daemon ..", ARGV0);
#endif

    /* Some time to settle */
    memset(curr_hour, '\0', 12);
    sleep(syscheck.tsleep * 10);

    /* If the scan time/day is set, reset the
     * syscheck.time/rootcheck.time
     */
    if (syscheck.scan_time || syscheck.scan_day) {
        /* At least once a week */
        syscheck.time = 604800;
        rootcheck.time = 604800;
    }

    /* Will create the db to store syscheck data */
    if (syscheck.scan_on_start) {
        sleep(syscheck.tsleep * 15);
        send_sk_db();

#ifdef WIN32
        /* Check for registry changes on Windows */
        os_winreg_check();
#endif
        /* Send database completed message */
        syscheck_log_send_failures();
        send_syscheck_msg(HC_SK_DB_COMPLETED);
        debug2("%s: DEBUG: Sending database completed message.", ARGV0);

    } else {
        prev_time_rk = time(0);
    }

    /* Before entering in daemon mode itself */
    prev_time_sk = time(0);
    sleep(syscheck.tsleep * 10);

    /* If the scan_time or scan_day is set, we need to handle the
     * current day/time on the loop.
     */
    if (syscheck.scan_time || syscheck.scan_day) {
        curr_time = time(0);
        p = localtime(&curr_time);

        /* Assign hour/min/sec values */
        snprintf(curr_hour, 9, "%02d:%02d:%02d",
                 p->tm_hour,
                 p->tm_min,
                 p->tm_sec);

        curr_day = p->tm_mday;

        if (syscheck.scan_time && syscheck.scan_day) {
            if ((OS_IsAfterTime(curr_hour, syscheck.scan_time)) &&
                    (OS_IsonDay(p->tm_wday, syscheck.scan_day))) {
                day_scanned = 1;
            }
        } else if (syscheck.scan_time) {
            if (OS_IsAfterTime(curr_hour, syscheck.scan_time)) {
                day_scanned = 1;
            }
        } else if (syscheck.scan_day) {
            if (OS_IsonDay(p->tm_wday, syscheck.scan_day)) {
                day_scanned = 1;
            }
        }
    }

    /* Loop: run due scans, then idle up to min(SYSCHECK_WAIT, remaining freq). */
    while (1) {
        int run_now = 0;
        int select_rc;
        time_t idle_wait;
        curr_time = time(0);

        /* Check if syscheck should be restarted */
        run_now = os_check_restart_syscheck();

        /* Check if a day_time or scan_time is set */
        if (syscheck.scan_time || syscheck.scan_day) {
            p = localtime(&curr_time);

            /* Day changed */
            if (curr_day != p->tm_mday) {
                day_scanned = 0;
                curr_day = p->tm_mday;
            }

            /* Check for the time of the scan */
            if (!day_scanned && syscheck.scan_time && syscheck.scan_day) {
                /* Assign hour/min/sec values */
                snprintf(curr_hour, 9, "%02d:%02d:%02d",
                         p->tm_hour, p->tm_min, p->tm_sec);

                if ((OS_IsAfterTime(curr_hour, syscheck.scan_time)) &&
                        (OS_IsonDay(p->tm_wday, syscheck.scan_day))) {
                    day_scanned = 1;
                    run_now = 1;
                }
            } else if (!day_scanned && syscheck.scan_time) {
                /* Assign hour/min/sec values */
                snprintf(curr_hour, 9, "%02d:%02d:%02d",
                         p->tm_hour, p->tm_min, p->tm_sec);

                if (OS_IsAfterTime(curr_hour, syscheck.scan_time)) {
                    run_now = 1;
                    day_scanned = 1;
                }
            } else if (!day_scanned && syscheck.scan_day) {
                /* Check for the day of the scan */
                if (OS_IsonDay(p->tm_wday, syscheck.scan_day)) {
                    run_now = 1;
                    day_scanned = 1;
                }
            }
        }

        /* If time elapsed is higher than the rootcheck_time, run it */
        if (syscheck.rootcheck) {
            if (((curr_time - prev_time_rk) > rootcheck.time) || run_now) {
                run_rk_check();
                prev_time_rk = time(0);
            }
        }

        /* If time elapsed is higher than the syscheck time, run syscheck time */
        if (((curr_time - prev_time_sk) > syscheck.time) || run_now) {
            if (syscheck.scan_on_start == 0) {
                /* Need to create the db if scan on start is not set */
                sleep(syscheck.tsleep * 10);
                send_sk_db();
                sleep(syscheck.tsleep * 10);

                syscheck.scan_on_start = 1;
            } else {
                syscheck_send_failures = 0;
                /* Send scan start message */
                if (syscheck.dir[0]) {
                    merror("%s: INFO: Starting syscheck scan.", ARGV0);
                    send_rootcheck_msg("Starting syscheck scan.");
                }
#ifdef WIN32
                /* Check for registry changes on Windows */
                os_winreg_check();
#endif
                /* Check for changes */
                run_dbcheck();
            }

            /* Send scan ending message */
            sleep(syscheck.tsleep + 20);
            if (syscheck.dir[0]) {
                merror("%s: INFO: Ending syscheck scan.", ARGV0);
                send_rootcheck_msg("Ending syscheck scan.");
            }

            syscheck_log_send_failures();
            /* Send database completed message */
            send_syscheck_msg(HC_SK_DB_COMPLETED);
            debug2("%s: DEBUG: Sending database completed message.", ARGV0);

            prev_time_sk = time(0);
        }

        curr_time = time(0);
        idle_wait = syscheck_idle_wait(curr_time, prev_time_sk, prev_time_rk);

#ifdef INOTIFY_ENABLED
        if (syscheck.realtime && (syscheck.realtime->fd >= 0)) {
            selecttime.tv_sec = (long)idle_wait;
            selecttime.tv_usec = 0;

            /* zero-out the fd_set */
            FD_ZERO (&rfds);
            FD_SET(syscheck.realtime->fd, &rfds);

            select_rc = select(syscheck.realtime->fd + 1, &rfds,
                               NULL, NULL, &selecttime);
            if (select_rc < 0) {
                merror("%s: ERROR: Select failed (for realtime fim).", ARGV0);
                sleep((unsigned int)idle_wait);
            } else if (select_rc == 0) {
                /* Timeout — re-evaluate frequency */
            } else if (FD_ISSET (syscheck.realtime->fd, &rfds)) {
                realtime_process();
            }
        } else {
            sleep((unsigned int)idle_wait);
        }
#elif defined(WIN32)
        if (syscheck.realtime && (syscheck.realtime->fd >= 0)) {
            if (WaitForSingleObjectEx(syscheck.realtime->evt,
                                      (DWORD)(idle_wait * 1000), TRUE) == WAIT_FAILED) {
                merror("%s: ERROR: WaitForSingleObjectEx failed (for realtime fim).", ARGV0);
                sleep((unsigned int)idle_wait);
            } else {
                sleep(1);
            }
        } else {
            sleep((unsigned int)idle_wait);
        }
#else
        sleep((unsigned int)idle_wait);
#endif
    }
}

/* Resolve syscheck opts for a path (longest matching configured directory).
 * Sets *matched to 1 when a directory matched, 0 otherwise (so callers can
 * distinguish "matched with opts==0" from "no match").
 */
static int syscheck_opts_for_path(const char *path, int *matched)
{
    int i;
    int best = -1;
    size_t best_len = 0;

    if (matched) {
        *matched = 0;
    }
    if (!path || !syscheck.dir) {
        return (0);
    }

    for (i = 0; syscheck.dir[i]; i++) {
        size_t len = strlen(syscheck.dir[i]);
        char next;

        if (len == 0) {
            continue;
        }
        /* Normalize trailing separators so "/var/log/" matches "/var/log/foo".
         * Keep a lone "/" (or "\") so the root directory still matches. */
        while (len > 1 && (syscheck.dir[i][len - 1] == '/' ||
                           syscheck.dir[i][len - 1] == '\\')) {
            len--;
        }
        if (len < best_len) {
            continue;
        }
#ifdef WIN32
        if (strncasecmp(path, syscheck.dir[i], len) != 0) {
            continue;
        }
#else
        if (strncmp(path, syscheck.dir[i], len) != 0) {
            continue;
        }
#endif
        next = path[len];
        if (next != '\0' && next != '/' && next != '\\') {
            continue;
        }
        best_len = len;
        best = i;
    }

    if (best < 0) {
        return (0);
    }
    if (matched) {
        *matched = 1;
    }
    return (syscheck.opts[best]);
}

/* Read file information and return a pointer to the checksum.
 * Returns 0 on success, -1 if the file is missing (delete alert already
 * sent), -2 if metadata/checksum read failed (e.g. EACCES, EMFILE) so
 * the caller should skip without treating it as an integrity change.
 */
int c_read_file(const char *file_name, const char *oldsum, char *newsum)
{
    int size = 0, perm = 0, owner = 0, group = 0, md5sum = 0, sha1sum = 0, sha256sum = 0;
    int attrs = 0;
    int acl = 0;
    int return_error = 0;
    int checksum_failed = 0;
    int sum_off;
    int path_opts;
    int path_matched = 0;
    struct stat statbuf;
    os_md5 mf_sum;
    os_sha1 sf_sum;
    os_sha256 sha256_sum;
#ifdef WIN32
    DWORD win_attrs = 0;
    char acl_digest[33];
    fim_acl_t facl;
    int have_facl = 0;
#endif

    /* Clean sums */
    strncpy(mf_sum, "xxx", 4);
    strncpy(sf_sum, "xxx", 4);
    strncpy(sha256_sum, "xxx", 4);
#ifdef WIN32
    acl_digest[0] = '\0';
    memset(&facl, 0, sizeof(facl));
#endif

    path_opts = syscheck_opts_for_path(file_name, &path_matched);

    /* Stat the file */
#ifdef WIN32
    return_error = (stat(file_name, &statbuf) < 0);
#else
    return_error = (lstat(file_name, &statbuf) < 0);
#endif
    if (return_error)
    {
        /* Only treat missing paths as deletions; other metadata errors
         * (EACCES, etc.) must not look like "file deleted". */
        if (errno == ENOENT || errno == ENOTDIR) {
            char alert_msg[PATH_MAX+4];

            alert_msg[PATH_MAX + 3] = '\0';
            snprintf(alert_msg, PATH_MAX + 4, "-1 %s", file_name);
            send_syscheck_msg(alert_msg);
            return (-1);
        }

        merror("%s: WARN: Unable to stat file '%s': %s",
               ARGV0, file_name, strerror(errno));
        return (-2);
    }

    /* Get the old sum values */
    sum_off = fim_sum_data_offset(oldsum);

    /* size */
    if (oldsum[0] == '+') {
        size = 1;
    }

    /* perm */
    if (oldsum[1] == '+') {
        perm = 1;
    }

    /* owner */
    if (oldsum[2] == '+') {
        owner = 1;
    }

    /* group */
    if (oldsum[3] == '+') {
        group = 1;
    }

    /* md5 sum */
    if (oldsum[4] == '+') {
        md5sum = 1;
    }

    /* sha1 sum: '+' or 's' means enabled; '-' or 'n' means disabled.
     * ('s'/'n' also encode report_changes / seechanges.) */
    if (oldsum[5] == '+' || oldsum[5] == 's') {
        sha1sum = 1;
    } else {
        sha1sum = 0;
    }

    /* sha256 sum - check backward compatibility */
    if (oldsum[6] == '+') {
        sha256sum = 1;
    } else if (oldsum[6] == '-') {
        sha256sum = 0;
    }
    /* If it's a digit (size), then it's the old format, no sha256 */

#ifdef WIN32
    /* Prefer current directory opts over sticky cache flags so enabling or
     * disabling check_attrs / check_acl takes effect without a DB wipe. */
    if (path_opts & CHECK_ATTRS) {
        attrs = 1;
        win_attrs = GetFileAttributes(file_name);
        if (win_attrs == INVALID_FILE_ATTRIBUTES) {
            merror("%s: WARN: Unable to get attributes for '%s' (%lu)",
                   ARGV0, file_name, (unsigned long)GetLastError());
            return (-2);
        }
    } else if (!path_matched && sum_off >= 8 && oldsum[7] == '+') {
        /* Path not matched to a configured directory; honor cache flags. */
        attrs = 1;
        win_attrs = GetFileAttributes(file_name);
        if (win_attrs == INVALID_FILE_ATTRIBUTES) {
            merror("%s: WARN: Unable to get attributes for '%s' (%lu)",
                   ARGV0, file_name, (unsigned long)GetLastError());
            return (-2);
        }
    }

    if (path_opts & CHECK_ACL) {
        acl = 1;
        if (fim_win_acl_read(file_name, &facl) != 0 ||
                fim_win_acl_digest(&facl, acl_digest) != 0) {
            fim_acl_free(&facl);
            merror("%s: WARN: Unable to read ACL for '%s'", ARGV0, file_name);
            return (-2);
        }
        have_facl = 1;
    } else if (!path_matched && sum_off >= 9 && oldsum[8] == '+') {
        acl = 1;
        if (fim_win_acl_read(file_name, &facl) != 0 ||
                fim_win_acl_digest(&facl, acl_digest) != 0) {
            fim_acl_free(&facl);
            merror("%s: WARN: Unable to read ACL for '%s'", ARGV0, file_name);
            return (-2);
        }
        have_facl = 1;
    }
#else
    (void)attrs;
    (void)acl;
    (void)sum_off;
    (void)path_opts;
    (void)path_matched;
#endif

    /* Generate new checksum */
    if (S_ISREG(statbuf.st_mode))
    {
        if (sha1sum || md5sum || sha256sum) {
            /* Generate checksums of the file */
            if (sha1sum || md5sum) {
                if (OS_MD5_SHA1_File(file_name, syscheck.prefilter_cmd, mf_sum, sf_sum, OS_BINARY) < 0) {
                    merror("%s: WARN: Unable to read file '%s' for checksum: %s",
                           ARGV0, file_name, strerror(errno));
                    checksum_failed = 1;
                    strncpy(sf_sum, "xxx", 4);
                    strncpy(mf_sum, "xxx", 4);
                }
            }
            if (sha256sum) {
                if (OS_SHA256_File(file_name, sha256_sum, OS_BINARY) < 0) {
                    merror("%s: WARN: Unable to read file '%s' for sha256: %s",
                           ARGV0, file_name, strerror(errno));
                    checksum_failed = 1;
                    strncpy(sha256_sum, "xxx", 4);
                }
            }
        }
    }
#ifndef WIN32
    /* If it is a link, check if the actual file is valid */
    else if (S_ISLNK(statbuf.st_mode)) {
        struct stat statbuf_lnk;
        if (stat(file_name, &statbuf_lnk) == 0) {
            if (S_ISREG(statbuf_lnk.st_mode)) {
                if (sha1sum || md5sum || sha256sum) {
                    /* Generate checksums of the file */
                    if (sha1sum || md5sum) {
                        if (OS_MD5_SHA1_File(file_name, syscheck.prefilter_cmd, mf_sum, sf_sum, OS_BINARY) < 0) {
                            merror("%s: WARN: Unable to read file '%s' for checksum: %s",
                                   ARGV0, file_name, strerror(errno));
                            checksum_failed = 1;
                            strncpy(sf_sum, "xxx", 4);
                            strncpy(mf_sum, "xxx", 4);
                        }
                    }
                    if (sha256sum) {
                        if (OS_SHA256_File(file_name, sha256_sum, OS_BINARY) < 0) {
                            merror("%s: WARN: Unable to read file '%s' for sha256: %s",
                                   ARGV0, file_name, strerror(errno));
                            checksum_failed = 1;
                            strncpy(sha256_sum, "xxx", 4);
                        }
                    }
                }
            }
        }
    }
#endif

    if (checksum_failed) {
#ifdef WIN32
        if (have_facl) {
            fim_acl_free(&facl);
        }
#endif
        return (-2);
    }

    newsum[0] = '\0';
    /* Caller is expected to provide a buffer of at least
     * OS_MAXSTR + 1 bytes for `newsum`.
     */

#ifndef WIN32
    snprintf(newsum, OS_MAXSTR, "%ld:%d:%d:%d:%s:%s:%s",
             size == 0 ? 0 : (long)statbuf.st_size,
             perm == 0 ? 0 : (int)statbuf.st_mode,
             owner == 0 ? 0 : (int)statbuf.st_uid,
             group == 0 ? 0 : (int)statbuf.st_gid,
             md5sum   == 0 ? "xxx" : mf_sum,
             sha1sum  == 0 ? "xxx" : sf_sum,
             sha256sum == 0 ? "xxx" : sha256_sum);
#else
    HANDLE hFile = CreateFile(file_name, GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD dwErrorCode = GetLastError();
        char alert_msg[PATH_MAX+4];
        if (have_facl) {
            fim_acl_free(&facl);
        }
        alert_msg[PATH_MAX + 3] = '\0';
        snprintf(alert_msg, PATH_MAX + 4, "CreateFile=%ld %s", dwErrorCode, file_name);
        send_syscheck_msg(alert_msg);
        return -1;
    }

    PSID pSidOwner = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    DWORD dwRtnCode = GetSecurityInfo(hFile, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &pSidOwner, NULL, NULL, NULL, &pSD);
    if (dwRtnCode != ERROR_SUCCESS) {
        DWORD dwErrorCode = GetLastError();
        CloseHandle(hFile);
        if (have_facl) {
            fim_acl_free(&facl);
        }
        {
            char alert_msg[PATH_MAX+4];
            alert_msg[PATH_MAX + 3] = '\0';
            snprintf(alert_msg, PATH_MAX + 4, "GetSecurityInfo=%ld %s", dwErrorCode, file_name);
            send_syscheck_msg(alert_msg);
        }
        return -1;
    }

    LPSTR szSID = NULL;
    ConvertSidToStringSid(pSidOwner, &szSID);
    char* st_uid = NULL;
    if( szSID ) {
      st_uid = (char *) calloc( strlen(szSID) + 1, 1 );
      memcpy( st_uid, szSID, strlen(szSID) );
    }
    LocalFree(szSID);
    if (pSD) {
        LocalFree(pSD);
    }
    CloseHandle(hFile);

    if (acl) {
        /* attrs slot always present when ACL is enabled (0 if unchecked). */
        snprintf(newsum, OS_MAXSTR, "%ld:%d:%s:%d:%s:%s:%s:%lu:%s",
                 size == 0 ? 0 : (long)statbuf.st_size,
                 perm == 0 ? 0 : (int)statbuf.st_mode,
                 owner == 0 ? "0" : (st_uid ? st_uid : "0"),
                 group == 0 ? 0 : (int)statbuf.st_gid,
                 md5sum   == 0 ? "xxx" : mf_sum,
                 sha1sum  == 0 ? "xxx" : sf_sum,
                 sha256sum == 0 ? "xxx" : sha256_sum,
                 attrs ? (unsigned long)win_attrs : 0UL,
                 acl_digest);
        /* Append SID-stable snapshot for local cache / ACE diffs. */
        if (have_facl) {
            size_t used = strlen(newsum);
            if (used + 2 < (size_t)OS_MAXSTR) {
                newsum[used] = '\n';
                newsum[used + 1] = '\0';
                if (fim_win_acl_snapshot(&facl, newsum + used + 1,
                                         (size_t)OS_MAXSTR - used - 1) != 0) {
                    newsum[used] = '\0';
                }
            }
            fim_acl_free(&facl);
            have_facl = 0;
        }
    } else if (attrs) {
        snprintf(newsum, OS_MAXSTR, "%ld:%d:%s:%d:%s:%s:%s:%lu",
                 size == 0 ? 0 : (long)statbuf.st_size,
                 perm == 0 ? 0 : (int)statbuf.st_mode,
                 owner == 0 ? "0" : (st_uid ? st_uid : "0"),
                 group == 0 ? 0 : (int)statbuf.st_gid,
                 md5sum   == 0 ? "xxx" : mf_sum,
                 sha1sum  == 0 ? "xxx" : sf_sum,
                 sha256sum == 0 ? "xxx" : sha256_sum,
                 (unsigned long)win_attrs);
    } else {
        snprintf(newsum, OS_MAXSTR, "%ld:%d:%s:%d:%s:%s:%s",
                 size == 0 ? 0 : (long)statbuf.st_size,
                 perm == 0 ? 0 : (int)statbuf.st_mode,
                 owner == 0 ? "0" : (st_uid ? st_uid : "0"),
                 group == 0 ? 0 : (int)statbuf.st_gid,
                 md5sum   == 0 ? "xxx" : mf_sum,
                 sha1sum  == 0 ? "xxx" : sf_sum,
                 sha256sum == 0 ? "xxx" : sha256_sum);
    }

    if (have_facl) {
        fim_acl_free(&facl);
    }
    free(st_uid);
#endif

    return (0);
}
