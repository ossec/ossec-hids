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

#ifdef LIBSODIUM_ENABLED
#include <sodium.h>
#endif

#include "shared.h"
#include "syscheck.h"
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/sha1/sha1_op.h"
#include "os_crypto/md5_sha1/md5_sha1_op.h"
#include "rootcheck/rootcheck.h"

/* Prototypes */
static void send_sk_db(void);


/* Send a message related to syscheck change/addition */
int send_syscheck_msg(const char *msg)
{
    if (SendMSG(syscheck.queue, msg, SYSCHECK, SYSCHECK_MQ) < 0) {
        merror(QUEUE_SEND, ARGV0);

        if ((syscheck.queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
            ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
        }

        /* Try to send it again */
        SendMSG(syscheck.queue, msg, SYSCHECK, SYSCHECK_MQ);
    }
    return (0);
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

    /* Check every SYSCHECK_WAIT */
    while (1) {
        int run_now = 0;
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

            /* Send database completed message */
            send_syscheck_msg(HC_SK_DB_COMPLETED);
            debug2("%s: DEBUG: Sending database completed message.", ARGV0);

            prev_time_sk = time(0);
        }

#ifdef INOTIFY_ENABLED
        if (syscheck.realtime && (syscheck.realtime->fd >= 0)) {
            selecttime.tv_sec = SYSCHECK_WAIT;
            selecttime.tv_usec = 0;

            /* zero-out the fd_set */
            FD_ZERO (&rfds);
            FD_SET(syscheck.realtime->fd, &rfds);

            run_now = select(syscheck.realtime->fd + 1, &rfds,
                             NULL, NULL, &selecttime);
            if (run_now < 0) {
                merror("%s: ERROR: Select failed (for realtime fim).", ARGV0);
                sleep(SYSCHECK_WAIT);
            } else if (run_now == 0) {
                /* Timeout */
            } else if (FD_ISSET (syscheck.realtime->fd, &rfds)) {
                realtime_process();
            }
        } else {
            sleep(SYSCHECK_WAIT);
        }
#elif defined(WIN32)
        if (syscheck.realtime && (syscheck.realtime->fd >= 0)) {
            if (WaitForSingleObjectEx(syscheck.realtime->evt, SYSCHECK_WAIT * 1000, TRUE) == WAIT_FAILED) {
                merror("%s: ERROR: WaitForSingleObjectEx failed (for realtime fim).", ARGV0);
                sleep(SYSCHECK_WAIT);
            } else {
                sleep(1);
            }
        } else {
            sleep(SYSCHECK_WAIT);
        }
#else
        sleep(SYSCHECK_WAIT);
#endif
    }
}

/* Read file information and return a pointer to the checksum */
int c_read_file(const char *file_name, const char *oldsum, char *newsum, int sysopts)
{
    int size = 0, perm = 0, owner = 0, group = 0, md5sum = 0, sha1sum = 0;
    int return_error = 0;
    struct stat statbuf;
    os_md5 mf_sum;
    os_sha1 sf_sum;

#ifdef LIBSODIUM_ENABLED

    struct hash_output *file_sums;
    file_sums = malloc(sizeof(struct hash_output));
    if(file_sums == NULL) {
        merror("run_check file_sums malloc failed: %s", strerror(errno));
    }

    /* Clean sums */
    strncpy(file_sums->md5output, "MD5=", 5);
    strncpy(file_sums->sha256output, "SHA256=", 8);
    strncpy(file_sums->sha1output, "SHA1=", 5);
    strncpy(file_sums->genericoutput, "GENERIC=", 9);
    /* set the checks */
    if(sysopts & CHECK_MD5SUM) {
        file_sums->check_md5 = 1;
    }
    if(sysopts & CHECK_SHA1SUM) {
        file_sums->check_sha1 = 1;
    }
    if(sysopts & CHECK_SHA256SUM) {
        file_sums->check_sha256 = 1;
    }

    if(sysopts & CHECK_GENERIC) {
        file_sums->check_generic = 1;
    }

    if(file_sums->check_md5 != 1 && file_sums->check_sha1 != 1 && file_sums->check_sha256 != 1 && file_sums->check_generic != 1) {
        merror("XXX DOES NOT COMPUTER!"); // TODO replace with real message or something respectable
    }

#endif // LIBSODIUM_ENABLED

    /* Clean sums */
    strncpy(mf_sum, "xxx", 4);
    strncpy(sf_sum, "xxx", 4);

    /* Stat the file */
#ifdef WIN32
    return_error = (stat(file_name, &statbuf) < 0);
#else
    return_error = (lstat(file_name, &statbuf) < 0);
#endif
    if (return_error)
    {
        char alert_msg[PATH_MAX+4];

        alert_msg[PATH_MAX + 3] = '\0';
        snprintf(alert_msg, PATH_MAX + 4, "-1 %s", file_name);
        send_syscheck_msg(alert_msg);
#ifdef LIBSODIUM_ENABLED
        free(file_sums);
#endif
        return (-1);
    }

    /* Get the old sum values */
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

    /* sha1 sum */
    if (oldsum[5] == '+') {
        sha1sum = 1;
    } else if (oldsum[5] == 's') {
        sha1sum = 1;
    } else if (oldsum[5] == 'n') {
        sha1sum = 0;
    }

    /* Generate new checksum */
    if (S_ISREG(statbuf.st_mode))
    {
        if (sha1sum || md5sum) {
            /* Generate checksums of the file */
#ifdef LIBSODIUM_ENABLED
            if (OS_Hash_File(file_name, syscheck.prefilter_cmd, file_sums, OS_BINARY) < 0) {
                merror("syscheckd: ERROR: OS_Hash_File() failed. (0x01)");
            }
#else
            if (OS_MD5_SHA1_File(file_name, syscheck.prefilter_cmd, mf_sum, sf_sum, OS_BINARY) < 0) {
                strncpy(sf_sum, "xxx", 4);
                strncpy(mf_sum, "xxx", 4);
            }
#endif
        }
    }
#ifndef WIN32
    /* If it is a link, check if the actual file is valid */
    else if (S_ISLNK(statbuf.st_mode)) {
        struct stat statbuf_lnk;
        if (stat(file_name, &statbuf_lnk) == 0) {
            if (S_ISREG(statbuf_lnk.st_mode)) {
                if (sha1sum || md5sum) {
                    /* Generate checksums of the file */
#ifdef LIBSODIUM_ENABLED
                    if (OS_Hash_File(file_name, syscheck.prefilter_cmd, file_sums, OS_BINARY) < 0) {
                        merror("syscheckd: ERROR: OS_Hash_File() failed. (0x02)");
                    }
#else
                    if (OS_MD5_SHA1_File(file_name, syscheck.prefilter_cmd, mf_sum, sf_sum, OS_BINARY) < 0) {
                        strncpy(sf_sum, "xxx", 4);
                        strncpy(mf_sum, "xxx", 4);
                    }
#endif
                }
            }
        }
    }
#endif

    newsum[0] = '\0';
    newsum[255] = '\0';

#ifdef LIBSODIUM_ENABLED
    char new_hashes[512], new_hashes_tmp[512];
    int hashc = 0;
    if(file_sums->check_sha256 > 0) {
        snprintf(new_hashes, 511, "%s", file_sums->sha256output);
        hashc++;
    }
    if(file_sums->check_generic > 0) {
        if(hashc > 0) {
            snprintf(new_hashes_tmp, 511, "%s:%s", new_hashes, file_sums->genericoutput);
            strncpy(new_hashes, new_hashes_tmp, 511);
            hashc++;
        } else if(hashc == 0) {
            snprintf(new_hashes, 511, "%s", file_sums->genericoutput);
            hashc++;
        }
    }
    if(file_sums->check_sha1 > 0 && hashc < 2) {
        if(hashc > 0) {
            snprintf(new_hashes_tmp, 511, "%s:%s", new_hashes, file_sums->sha1output);
            strncpy(new_hashes, new_hashes_tmp, 511);
            hashc++;
        } else if(hashc == 0) {                                                                                                                 snprintf(new_hashes, 511, "%s", file_sums->sha1output);
            hashc++;
        }
    }
    if(file_sums->check_md5 > 0 && hashc < 2) {
        if(hashc > 0) {
            snprintf(new_hashes_tmp, 511, "%s:%s", new_hashes, file_sums->md5output);
            strncpy(new_hashes, new_hashes_tmp, 511);
            hashc++;
        } else if(hashc == 0) {
            snprintf(new_hashes, 511, "%s", file_sums->md5output);                                                                              hashc++;
        }
    }
    if(hashc < 2) {
        if(hashc == 0) {
            strncpy(new_hashes, "xxx:xxx", 8);
        } else if (hashc == 1) {                                                                                                                snprintf(new_hashes_tmp, 511, "%s:xxx", new_hashes);
            strncpy(new_hashes, new_hashes_tmp, 511);
        }
    }

    snprintf(newsum, 255, "%ld:%d:%d:%d:%s",
             size == 0 ? 0 : (long)statbuf.st_size,
             perm == 0 ? 0 : (int)statbuf.st_mode,
             owner == 0 ? 0 : (int)statbuf.st_uid,
             group == 0 ? 0 : (int)statbuf.st_gid,
             new_hashes);
#else //LIBSODIUM_ENABLED
#ifndef WIN32
    snprintf(newsum, 255, "%ld:%d:%d:%d:%s:%s",
             size == 0 ? 0 : (long)statbuf.st_size,
             perm == 0 ? 0 : (int)statbuf.st_mode,
             owner == 0 ? 0 : (int)statbuf.st_uid,
             group == 0 ? 0 : (int)statbuf.st_gid,
             md5sum   == 0 ? "xxx" : mf_sum,
             sha1sum  == 0 ? "xxx" : sf_sum);
#else //WIN32
    HANDLE hFile = CreateFile(file_name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD dwErrorCode = GetLastError();
        char alert_msg[PATH_MAX+4];
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
        char alert_msg[PATH_MAX+4];
        alert_msg[PATH_MAX + 3] = '\0';
        snprintf(alert_msg, PATH_MAX + 4, "GetSecurityInfo=%ld %s", dwErrorCode, file_name);
        send_syscheck_msg(alert_msg);
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
    CloseHandle(hFile);

    snprintf(newsum, 255, "%ld:%d:%s:%d:%s:%s",
             size == 0 ? 0 : (long)statbuf.st_size,
             perm == 0 ? 0 : (int)statbuf.st_mode,
             owner == 0 ? "0" : st_uid,
             group == 0 ? 0 : (int)statbuf.st_gid,
             md5sum   == 0 ? "xxx" : mf_sum,
             sha1sum  == 0 ? "xxx" : sf_sum);

    free(st_uid);
#endif //WIN32
#endif //LIBSODIUM_ENABLED

/*
#ifdef LIBSODIUM_ENABLED
    free(file_sums);
#endif
*/
    return (0);
}
