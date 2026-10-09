/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#ifndef WIN32
#include <time.h>
#endif

#ifdef WIN32
#define sleep(x) Sleep(x * 1000)
#endif

#include "shared.h"

#ifdef INOTIFY_ENABLED
#include <sys/inotify.h>
#endif

#include "syscheck.h"
#include "error_messages/error_messages.h"
#include "win_acl_op.h"

/* Prototypes */
int realtime_checksumfile(const char *file_name) __attribute__((nonnull));


/* Checksum of the realtime file being monitored */
int realtime_checksumfile(const char *file_name)
{
    char *buf;

    buf = (char *) OSHash_Get(syscheck.fp, file_name);
    if (buf != NULL) {
        char c_sum[OS_MAXSTR + 1];

        c_sum[0] = '\0';
        c_sum[OS_MAXSTR] = '\0';

        /* -1: missing (alert deferred when the realtime queue asked).
         * -2: read failed; caller retries. */
        {
            int read_rc = c_read_file(file_name, buf, c_sum);

            if (read_rc < 0) {
                return (read_rc);
            }
        }

        {
            int sum_off = fim_sum_data_offset(buf);

            if (!fim_sum_equal(c_sum, buf + sum_off)) {
                char alert_msg[OS_MAXSTR + 1];
                int real_change = fim_sum_has_real_change(buf + sum_off, c_sum);

                if (real_change) {
                    alert_msg[OS_MAXSTR] = '\0';

                    #ifdef WIN32
                    {
                        char *sum_only = NULL;
                        char *acl_txt = NULL;
                        size_t slen = fim_sum_data_len(c_sum);

                        os_calloc(OS_MAXSTR + 1, sizeof(char), sum_only);
                        os_calloc(OS_MAXSTR + 1, sizeof(char), acl_txt);
                        if (slen > (size_t)OS_MAXSTR) {
                            slen = (size_t)OS_MAXSTR;
                        }
                        memcpy(sum_only, c_sum, slen);
                        sum_only[slen] = '\0';

                        /* fim_win_acl_change_text() already no-ops unless the
                         * new sum carries an ACL digest/snapshot that changed,
                         * so do not gate on sum_off (legacy 7/8-flag cache). */
                        if (fim_win_acl_change_text(buf + sum_off, c_sum,
                                                    acl_txt, (size_t)OS_MAXSTR + 1) > 0) {
                            snprintf(alert_msg, OS_MAXSTR, "%s %s\n%s",
                                     sum_only, file_name, acl_txt);
                        } else {
                            snprintf(alert_msg, OS_MAXSTR, "%s %s", sum_only, file_name);
                        }
                        free(sum_only);
                        free(acl_txt);
                    }
                    #else
                    char *fullalert = NULL;

                    if (buf[5] == 's' || buf[5] == 'n') {
                        fullalert = seechanges_addfile(file_name);
                        if (fullalert) {
                            snprintf(alert_msg, OS_MAXSTR, "%s %s\n%s", c_sum, file_name, fullalert);
                            free(fullalert);
                            fullalert = NULL;
                        } else {
                            snprintf(alert_msg, 912, "%s %s", c_sum, file_name);
                        }
                    } else {
                        snprintf(alert_msg, 912, "%s %s", c_sum, file_name);
                    }
                    #endif
                    if (send_syscheck_msg(alert_msg) != 0) {
                        merror("%s: WARN: Failed to send syscheck update for '%s'. "
                              "Change will be retried on the next event/scan.", ARGV0, file_name);
                        /* Do not keep this on the realtime retry list. A down
                         * queue would pin every changed path and the daemon
                         * would never idle. The cache is unchanged, so the
                         * next scan or notification sends it. */
                        return (0);
                    }
                }

                /* Heal/refresh local cache after a successful send, or for
                 * placeholder-only transitions that need no manager alert. */
                {
                    char *updated;
                    char *old_data = buf;
                    int nflags;
                    int fields = 1;
                    size_t clen = fim_sum_data_len(c_sum);
                    size_t i;

                    for (i = 0; i < clen; i++) {
                        if (c_sum[i] == ':') {
                            fields++;
                        }
                    }
                    if (fields >= 9) {
                        nflags = 9;
                    } else if (fields >= 8) {
                        nflags = 8;
                    } else {
                        nflags = 7;
                    }

                    os_calloc((size_t)nflags + strlen(c_sum) + 1, sizeof(char), updated);
                    /* Copy only the old flag prefix — never pull size digits
                     * from legacy 6-flag entries into the flag slots. */
                    {
                        size_t flag_copy = (sum_off < 7) ? (size_t)sum_off : 7;

                        memcpy(updated, buf, flag_copy);
                        if (sum_off < 7) {
                            /* Legacy cache had no sha256 enable flag. */
                            updated[6] = '-';
                        }
                    }
                    if (nflags >= 8) {
                        updated[7] = (fields >= 8) ? '+' : '-';
                        /* When only ACL forced the attrs slot, keep the slot
                         * disabled unless the old entry marked attrs enabled. */
                        if (fields == 9 && (sum_off < 8 || buf[7] != '+')) {
                            updated[7] = '-';
                        }
                    }
                    if (nflags >= 9) {
                        updated[8] = '+';
                    }
                    memcpy(updated + nflags, c_sum, strlen(c_sum) + 1);
                    if (OSHash_Update(syscheck.fp, file_name, updated) == 1) {
                        free(old_data);
                    } else {
                        free(updated);
                    }
                }

                return (real_change ? 1 : 0);
            }
        }
        return (0);
    } else {
        /* New file */
        char *c;
        int i;
        int read_rc = 0;
        buf = strdup(file_name);

        /* Find container directory */

        while (c = strrchr(buf, '/'), c && c != buf) {
            *c = '\0';

            for (i = 0; syscheck.dir[i]; i++) {
                if (strcmp(syscheck.dir[i], buf) == 0) {
                    debug1("%s: DEBUG: Scanning new file '%s' with options for directory '%s'.", ARGV0, file_name, buf);
                    /* New realtime paths are files; read_dir() would opendir()
                     * and WARN on ENOENT races for ephemeral names (#1792).
                     */
                    read_rc = read_file(file_name, syscheck.opts[i],
                                        syscheck.filerestrict[i]);
                    break;
                }
            }

            if (syscheck.dir[i]) {
                break;
            }
        }

        free(buf);
        /* A sharing failure on a file that is not in the database yet
         * returns -1 from read_file. Closing the handle may not notify
         * again, so the queue must retry it. */
        if (read_rc < 0) {
            return (-2);
        }
    }

    return (0);
}

/* First look is delayed so an editor can finish a save (vim replace,
 * Windows truncate while the file is still locked). A missing path is
 * confirmed once before a delete alert. A failed read stays queued:
 * closing the handle does not generate another notification (#1386).
 */
#define RT_FIRST_DELAY_MS       200
#define RT_DELETE_CONFIRM_MS    1000
#define RT_RETRY_CAP_MS         5000

typedef struct _rt_pend {
    char *path;
    unsigned long long due;
    int attempts;
    int missing_seen;
    struct _rt_pend *next;
} rt_pend;

static rt_pend *rt_pend_head = NULL;
static OSHash *rt_pend_hash = NULL;

static unsigned long long rt_now_ms(void)
{
#ifdef WIN32
    return (unsigned long long)GetTickCount();
#else
    struct timespec ts;

    /* Wall clock jumps (NTP) would stall or fire every pending retry. */
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return ((unsigned long long)ts.tv_sec * 1000ULL) +
               (unsigned long long)(ts.tv_nsec / 1000000L);
    }

    {
        struct timeval tv;

        gettimeofday(&tv, NULL);
        return ((unsigned long long)tv.tv_sec * 1000ULL) +
               (unsigned long long)(tv.tv_usec / 1000);
    }
#endif
}

/* Absolute due time. On Windows the clock is 32-bit and wraps. */
static unsigned long long rt_due_after(unsigned int delay_ms)
{
#ifdef WIN32
    return (unsigned long long)((unsigned long)rt_now_ms() + delay_ms);
#else
    return rt_now_ms() + (unsigned long long)delay_ms;
#endif
}

/* Milliseconds from now until due. Zero when due or already past. */
static unsigned long long rt_until(unsigned long long due)
{
    unsigned long long now = rt_now_ms();

#ifdef WIN32
    unsigned long left = (unsigned long)due - (unsigned long)now;

    if (left >= 0x80000000UL) {
        return 0;
    }
    return (unsigned long long)left;
#else
    if (due <= now) {
        return 0;
    }
    return due - now;
#endif
}

static unsigned int rt_backoff_ms(int attempts)
{
    static const unsigned int steps[] = {200, 500, 1000, 2000, RT_RETRY_CAP_MS};

    if (attempts < 1) {
        return steps[0];
    }
    if (attempts <= (int)(sizeof(steps) / sizeof(steps[0]))) {
        return steps[attempts - 1];
    }
    /* The entry stays queued: closing the file is not a new event, so
     * dropping it would lose the change until the next scheduled scan.
     * After the short retries, wake infrequently. */
    return 30000;
}

static int rt_path_missing(const char *path)
{
    struct stat st;

#ifdef WIN32
    if (stat(path, &st) < 0 && (errno == ENOENT || errno == ENOTDIR))
#else
    if (lstat(path, &st) < 0 && (errno == ENOENT || errno == ENOTDIR))
#endif
    {
        return (1);
    }
    return (0);
}

static void rt_pend_drop(rt_pend *prev, rt_pend *entry)
{
    if (prev != NULL) {
        prev->next = entry->next;
    } else {
        rt_pend_head = entry->next;
    }
    if (rt_pend_hash != NULL) {
        OSHash_Delete(rt_pend_hash, entry->path);
    }
    free(entry->path);
    free(entry);
}

void realtime_enqueue(const char *file_name)
{
    rt_pend *entry;
    unsigned long long soon;

    if (file_name == NULL || file_name[0] == '\0') {
        return;
    }

    if (rt_pend_hash == NULL) {
        rt_pend_hash = OSHash_Create();
        if (rt_pend_hash == NULL) {
            realtime_checksumfile(file_name);
            return;
        }
    }

    soon = rt_due_after(RT_FIRST_DELAY_MS);
    entry = (rt_pend *)OSHash_Get(rt_pend_hash, file_name);
    if (entry != NULL) {
        /* Another notification arrived. Look again shortly, but do not
         * push the due time out or a busy file would never be read. */
        entry->missing_seen = 0;
        if (rt_until(entry->due) > RT_FIRST_DELAY_MS) {
            entry->due = soon;
        }
        return;
    }

    os_calloc(1, sizeof(rt_pend), entry);
    os_strdup(file_name, entry->path);
    entry->due = soon;
    if (OSHash_Add(rt_pend_hash, entry->path, entry) != 2) {
        free(entry->path);
        free(entry);
        realtime_checksumfile(file_name);
        return;
    }
    entry->next = rt_pend_head;
    rt_pend_head = entry;
}

int realtime_pending_ms(void)
{
    rt_pend *entry;
    unsigned long long best = 0;
    int have = 0;

    for (entry = rt_pend_head; entry != NULL; entry = entry->next) {
        unsigned long long left = rt_until(entry->due);

        if (!have || left < best) {
            best = left;
            have = 1;
        }
    }
    if (!have) {
        return (-1);
    }
    if (best > 600000ULL) {
        return (600000);
    }
    return ((int)best);
}

void realtime_pending_process(void)
{
    rt_pend *entry;
    rt_pend *prev;
    rt_pend *next;

    prev = NULL;
    for (entry = rt_pend_head; entry != NULL; entry = next) {
        int read_rc;

        next = entry->next;
        if (rt_until(entry->due) > 0) {
            prev = entry;
            continue;
        }

        /* Do not alert a delete on the first look. Editors replace a
         * file by unlinking it, and the new name appears a moment later. */
        if (rt_path_missing(entry->path) && !entry->missing_seen) {
            entry->missing_seen = 1;
            entry->due = rt_due_after(RT_DELETE_CONFIRM_MS);
            prev = entry;
            continue;
        }

        c_read_set_quiet(entry->attempts > 0);
        /* Do not alert from inside the checksum. The file can disappear
         * after rt_path_missing() and before the stat in c_read_file.
         * A new file must not be stored with an "xxx" checksum either. */
        c_read_defer_missing_alert(1);
        c_read_set_hold_baseline(1);
        read_rc = realtime_checksumfile(entry->path);
        c_read_set_hold_baseline(0);
        c_read_defer_missing_alert(0);
        c_read_set_quiet(0);

        if (read_rc == -1) {
            if (!entry->missing_seen) {
                entry->missing_seen = 1;
                entry->due = rt_due_after(RT_DELETE_CONFIRM_MS);
                prev = entry;
                continue;
            }

            {
                char alert_msg[PATH_MAX + 4];

                alert_msg[PATH_MAX + 3] = '\0';
                snprintf(alert_msg, PATH_MAX + 4, "-1 %s", entry->path);
                send_syscheck_msg(alert_msg);
            }
            rt_pend_drop(prev, entry);
            continue;
        }

        if (read_rc == -2) {
            entry->missing_seen = 0;
            entry->attempts++;
            entry->due = rt_due_after(rt_backoff_ms(entry->attempts));
            if (entry->attempts == 1) {
                debug1("%s: DEBUG: Realtime check of '%s' will be retried.",
                       ARGV0, entry->path);
            }
            prev = entry;
            continue;
        }

        rt_pend_drop(prev, entry);
    }
}

#ifdef INOTIFY_ENABLED
#include <sys/inotify.h>

#define REALTIME_MONITOR_FLAGS  IN_MODIFY|IN_ATTRIB|IN_MOVED_FROM|IN_MOVED_TO|IN_CREATE|IN_DELETE|IN_DELETE_SELF
#define REALTIME_EVENT_SIZE     (sizeof (struct inotify_event))
#define REALTIME_EVENT_BUFFER   (2048 * (REALTIME_EVENT_SIZE + 16))

/* Start real time monitoring using inotify */
int realtime_start()
{
    verbose("%s: INFO: Initializing real time file monitoring (not started).", ARGV0);

    syscheck.realtime = (rtfim *) calloc(1, sizeof(rtfim));
    if (syscheck.realtime == NULL) {
        ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno));
    }
    syscheck.realtime->dirtb = OSHash_Create();
    syscheck.realtime->fd = -1;

#ifdef INOTIFY_ENABLED
    syscheck.realtime->fd = inotify_init();
    if (syscheck.realtime->fd < 0) {
        merror("%s: ERROR: Unable to initialize inotify.", ARGV0);
        return (-1);
    }
#endif

    return (1);
}

/* Add a directory to real time checking */
int realtime_adddir(const char *dir, __attribute__((unused)) int opts)
{
    if (!syscheck.realtime) {
        realtime_start();
    }

    /* Check if it is ready to use */
    if (syscheck.realtime->fd < 0) {
        return (-1);
    } else {
        int wd = 0;

        if(syscheck.skip_nfs) {
            short is_nfs = IsNFS(dir);
            if( is_nfs == 1 ) {
                merror("%s: ERROR: %s NFS Directories do not support iNotify.", ARGV0, dir);
            	return(-1);
            }
            else {
                debug2("%s: DEBUG: syscheck.skip_nfs=%d, %s::is_nfs=%d", ARGV0, syscheck.skip_nfs, dir, is_nfs);
            }
        }

        wd = inotify_add_watch(syscheck.realtime->fd,
                               dir,
                               REALTIME_MONITOR_FLAGS);
        if (wd < 0) {
            merror("%s: ERROR: Unable to add directory to real time "
                   "monitoring: '%s'. %d %s", ARGV0, dir, wd, strerror(errno));
        } else {
            char wdchar[32 + 1];
            wdchar[32] = '\0';
            snprintf(wdchar, 32, "%d", wd);

            /* Entry not present */
            if (!OSHash_Get(syscheck.realtime->dirtb, wdchar)) {
                char *ndir;

                ndir = strdup(dir);
                if (ndir == NULL) {
                    ErrorExit("%s: ERROR: Out of memory. Exiting.", ARGV0);
                }

                OSHash_Add(syscheck.realtime->dirtb, wdchar, ndir);
                debug1("%s: DEBUG: Directory added for real time monitoring: "
                       "'%s'.", ARGV0, ndir);
            }
        }
    }

    return (1);
}

/* Process events in the real time queue */
int realtime_process()
{
    ssize_t len;
    size_t i = 0;
    char buf[REALTIME_EVENT_BUFFER + 1];
    struct inotify_event *event;

    buf[REALTIME_EVENT_BUFFER] = '\0';

    len = read(syscheck.realtime->fd, buf, REALTIME_EVENT_BUFFER);
    if (len < 0) {
        merror("%s: ERROR: Unable to read from real time buffer.", ARGV0);
    } else if (len > 0) {
        buf[len] = '\0';
        while (i < (size_t) len) {
            event = (struct inotify_event *) (void *) &buf[i];

            if (event->len) {
                char wdchar[32 + 1];
                char final_name[MAX_LINE + 1];

                wdchar[32] = '\0';
                final_name[MAX_LINE] = '\0';

                snprintf(wdchar, 32, "%d", event->wd);

                snprintf(final_name, MAX_LINE, "%s/%s",
                         (char *)OSHash_Get(syscheck.realtime->dirtb, wdchar),
                         event->name);
                /* Delay the read so a vim replace is not seen as a delete.
                 * The daemon loop drains the queue; do not sleep here. */
                realtime_enqueue(final_name);
            }

            i += REALTIME_EVENT_SIZE + event->len;
        }
    }

    return (0);
}

#elif defined(WIN32)
typedef struct _win32rtfim {
    HANDLE h;
    OVERLAPPED overlap;

    char *dir;
    int opts;
    TCHAR buffer[1228800];
} win32rtfim;

int realtime_win32read(win32rtfim *rtlocald);

void CALLBACK RTCallBack(DWORD dwerror, DWORD dwBytes, LPOVERLAPPED overlap)
{
    int lcount;
    size_t offset = 0;
    char wdchar[32 + 1];
    char final_path[MAX_LINE + 1];
    win32rtfim *rtlocald;
    PFILE_NOTIFY_INFORMATION pinfo;
    TCHAR finalfile[MAX_PATH];

    /* Resolve the watch that completed this overlapped I/O. Keys are the
     * Offset values assigned in realtime_adddir(), not a fixed "0". */
    wdchar[32] = '\0';
    snprintf(wdchar, 32, "%d", (int)overlap->Offset);
    rtlocald = OSHash_Get(syscheck.realtime->dirtb, wdchar);
    if (rtlocald == NULL) {
        merror("%s: ERROR: real time call back called, but hash is empty.",
               ARGV0);
        return;
    }

    if (dwerror != ERROR_SUCCESS) {
        merror("%s: ERROR: real time call back called, but error is set.",
               ARGV0);
        return;
    }

    if (dwBytes != 0) {
        do {
            pinfo = (PFILE_NOTIFY_INFORMATION) &rtlocald->buffer[offset];
            offset += pinfo->NextEntryOffset;

            lcount = WideCharToMultiByte(CP_ACP, 0, pinfo->FileName,
                                         pinfo->FileNameLength / sizeof(WCHAR),
                                         finalfile, MAX_PATH - 1, NULL, NULL);
            finalfile[lcount] = TEXT('\0');

            /* Build a path that matches scheduled FIM (forward-slash form).
             * Credit: Brad Lhotsky (@reyjrar) for identifying the realtime vs
             * full-scan slash mismatch in PR #235.
             */
            final_path[MAX_LINE] = '\0';
            snprintf(final_path, MAX_LINE, "%s/%s", rtlocald->dir, finalfile);
            os_normalize_path(final_path);

            /* Queue the change. A locked truncate must be retried after
             * this callback returns; closing the file is not a new event. */
            realtime_enqueue(final_path);
        } while (pinfo->NextEntryOffset != 0);
    } else {
        /* Empty completion usually means the change buffer overflowed and
         * events were dropped. Re-arm the watch so realtime FIM continues. */
        merror("%s: ERROR: real time call back called, but 0 bytes "
               "(likely buffer overflow).", ARGV0);
    }

    realtime_win32read(rtlocald);

    return;
}

int realtime_start()
{
    verbose("%s: INFO: Initializing real time file monitoring (not started).", ARGV0);

    os_calloc(1, sizeof(rtfim), syscheck.realtime);
    syscheck.realtime->dirtb = (void *)OSHash_Create();
    syscheck.realtime->fd = -1;
    syscheck.realtime->evt = CreateEvent(NULL, TRUE, FALSE, NULL);

    return (0);
}

int realtime_win32read(win32rtfim *rtlocald)
{
    int rc;
    DWORD notify_filter;

    notify_filter = FILE_NOTIFY_CHANGE_FILE_NAME |
                    FILE_NOTIFY_CHANGE_DIR_NAME |
                    FILE_NOTIFY_CHANGE_SIZE |
                    FILE_NOTIFY_CHANGE_LAST_WRITE |
                    FILE_NOTIFY_CHANGE_SECURITY;
    /* Attribute notifications only when check_attrs is enabled for this dir. */
    if (rtlocald->opts & CHECK_ATTRS) {
        notify_filter |= FILE_NOTIFY_CHANGE_ATTRIBUTES;
    }

    rc = ReadDirectoryChangesW(rtlocald->h,
                               rtlocald->buffer,
                               sizeof(rtlocald->buffer) / sizeof(TCHAR),
                               TRUE,
                               notify_filter,
                               0,
                               &rtlocald->overlap,
                               RTCallBack);
    if (rc == 0) {
        merror("%s: ERROR: Unable to set directory for monitoring: %s",
               ARGV0, rtlocald->dir);
        sleep(2);
    }

    return (0);
}

int realtime_adddir(const char *dir, int opts)
{
    char wdchar[32 + 1];
    win32rtfim *rtlocald;

    if (!syscheck.realtime) {
        realtime_start();
    }

    /* Maximum limit for realtime on Windows */
    if (syscheck.realtime->fd > 256) {
        merror("%s: ERROR: Unable to add directory to real time "
               "monitoring: '%s' - Maximum size permitted.", ARGV0, dir);
        return (0);
    }

    os_calloc(1, sizeof(win32rtfim), rtlocald);

    rtlocald->h = CreateFile(dir,
                             FILE_LIST_DIRECTORY,
                             FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                             NULL,
                             OPEN_EXISTING,
                             FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                             NULL);


    if (rtlocald->h == INVALID_HANDLE_VALUE ||
            rtlocald->h == NULL) {
        free(rtlocald);
        rtlocald = NULL;
        merror("%s: ERROR: Unable to add directory to real time "
               "monitoring: '%s'.", ARGV0, dir);
        return (0);
    }

    rtlocald->overlap.Offset = ++syscheck.realtime->fd;
    rtlocald->opts = opts;

    /* Set key for hash */
    wdchar[32] = '\0';
    snprintf(wdchar, 32, "%d", (int)rtlocald->overlap.Offset);

    if (OSHash_Get(syscheck.realtime->dirtb, wdchar)) {
        merror("%s: ERROR: Entry already in the real time hash: %s",
               ARGV0, wdchar);
        CloseHandle(rtlocald->h);
        free(rtlocald);
        rtlocald = NULL;
        return (0);
    }

    /* Add final elements to the hash */
    os_strdup(dir, rtlocald->dir);
    OSHash_Add(syscheck.realtime->dirtb, strdup(wdchar), rtlocald);

    /* Add directory to be monitored */
    realtime_win32read(rtlocald);

    return (1);
}

#else /* !WIN32 */

int realtime_start()
{
    verbose("%s: ERROR: Unable to initialize real time file monitoring.", ARGV0);

    return (0);
}

int realtime_adddir(__attribute__((unused)) const char *dir,
                    __attribute__((unused)) int opts)
{
    return (0);
}

int realtime_process()
{
    return (0);
}

#endif /* WIN32 */

