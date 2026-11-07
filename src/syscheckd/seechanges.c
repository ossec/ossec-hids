/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "shared.h"
#include "os_crypto/sha256/sha256_op.h"
#include "syscheck.h"

/* Prototypes */
static char *gen_diff_alert(const char *filename, time_t alert_diff_time) __attribute__((nonnull));
static int seechanges_dupfile(const char *old, const char *current) __attribute__((nonnull));
static int seechanges_safedir(const char *dir) __attribute__((nonnull));
static int seechanges_createpath(const char *filename) __attribute__((nonnull));
static void seechanges_unlink_counted(const char *path) __attribute__((nonnull));
static int seechanges_quota_allow(const char *filename, size_t add, size_t drop) __attribute__((nonnull));
static void seechanges_note_added(size_t n);
static void seechanges_abs_path(const char *in, char *out, size_t outsz) __attribute__((nonnull));

#ifdef USE_MAGIC
#include <magic.h>

/* Global variables */
extern magic_t magic_cookie;


int is_text(magic_t cookie, const void *buf, size_t len)
{
    const char *magic = magic_buffer(cookie, buf, len);

    if (!magic) {
        const char *err = magic_error(cookie);
        merror("%s: ERROR: magic_buffer: %s", ARGV0, err ? err : "unknown");
        return (1); // TODO default to true?
    } else {
        if (strncmp(magic, "text/", 5) == 0) {
            return (1);
        }
    }

    return (0);
}
#endif

/* Return TRUE if the file name match one of the ``nodiff`` entries.
   Return FALSE otherwise */
int is_nodiff(const char *filename){
    if (syscheck.nodiff){
        int i;
        for (i = 0; syscheck.nodiff[i] != NULL; i++){
            if (strncasecmp(syscheck.nodiff[i], filename,
                            strlen(syscheck.nodiff[i])) == 0) {
                return (TRUE);
            }
        }
    }
    if (syscheck.nodiff_regex) {
        int i;
        for (i = 0; syscheck.nodiff_regex[i] != NULL; i++) {
            if (OSMatch_Execute(filename, strlen(filename),
                                syscheck.nodiff_regex[i])) {
                 return (TRUE);
            }
        }
    }
    return (FALSE);
}

/* Generate diffs alerts */
static char *gen_diff_alert(const char *filename, time_t alert_diff_time)
{
    size_t n = 0;
    FILE *fp;
    char *tmp_str;
    char buf[OS_MAXSTR + 1];
    char diff_alert[OS_MAXSTR + 1];
    int truncated = 0;

    buf[OS_MAXSTR] = '\0';
    diff_alert[OS_MAXSTR] = '\0';

    snprintf(buf, OS_MAXSTR, "%s/local/%s/diff.%d",
             DIFF_DIR_PATH, filename,  (int)alert_diff_time);

    fp = fopen(buf, "r");
    if (!fp) {
        merror("%s: ERROR: Unable to generate diff alert.", ARGV0);
        return (NULL);
    }

    n = fread(buf, 1, 4096 - 1, fp);
    if (n <= 0) {
        merror("%s: ERROR: Unable to generate diff alert (fread).", ARGV0);
        fclose(fp);
        return (NULL);
    } else if (n >= 4000) {
        truncated = 1;
        /* Clear the last newline */
        buf[n] = '\0';
        tmp_str = strrchr(buf, '\n');
        if (tmp_str) {
            *tmp_str = '\0';
        } else {
            /* Weird diff with only one large line */
            buf[256] = '\0';
        }
    } else {
        buf[n] = '\0';
    }

    if (!feof(fp)) {
        truncated = 1;
    }

    n = 0;

    /* Get up to 20 line changes */
    tmp_str = buf;

    while (tmp_str && (*tmp_str != '\0')) {
        tmp_str = strchr(tmp_str, '\n');
        if (!tmp_str) {
            break;
        } else if (n >= 19) {
            *tmp_str = '\0';
            truncated = 1;
            break;
        }
        n++;
        tmp_str++;
    }

    /* Create alert */
    snprintf(diff_alert, 4096 - 1, "%s%s",
             buf, truncated ?
             "\n... diff was truncated ..." :
             "");

    fclose(fp);
    return (strdup(diff_alert));
}

/* Remove a last-entry that is a symlink or already larger than the diff
 * cap. unlink() on a symlink removes the link, not its target. */
static void seechanges_reclaim_snapshot(const char *path)
{
#ifndef WIN32
    struct stat snap;

    if (lstat(path, &snap) < 0) {
        return;
    }
    if (S_ISLNK(snap.st_mode)) {
        (void)unlink(path);
        return;
    }
    if (S_ISREG(snap.st_mode) && syscheck.diff_max_size > 0 &&
            snap.st_size > 0 &&
            (size_t)snap.st_size > syscheck.diff_max_size) {
        seechanges_unlink_counted(path);
    }
#else
    (void)path;
#endif
}

#ifndef WIN32
/* Create or replace the snapshot without following a symlink at the
 * final path. A planted last-entry link must not be truncated. */
static FILE *seechanges_open_dest(const char *path)
{
    int fd;
    FILE *fp;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0640);
    if (fd < 0 && errno == ELOOP) {
        if (unlink(path) == 0) {
            fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0640);
        }
    }
    if (fd < 0) {
        return (NULL);
    }
    fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
    }
    return (fp);
}
#endif

static int seechanges_dupfile(const char *old, const char *current)
{
    size_t n;
    FILE *fpr;
    FILE *fpw;
    unsigned char buf[2048 + 1];

    buf[2048] = '\0';

#ifndef WIN32
    /* Component walk with O_NOFOLLOW so a leaf or parent symlink cannot
     * redirect the snapshot at a root-only file (ANT-2026-2138NB95). */
    fpr = fopen_regular_nofollow(old);
#else
    fpr = fopen(old, "r");
#endif
    if (!fpr) {
        return (0);
    }

#ifndef WIN32
    if (syscheck.diff_max_size > 0) {
        struct stat srcst;

        if (fstat(fileno(fpr), &srcst) == 0 && srcst.st_size > 0 &&
                (size_t)srcst.st_size > syscheck.diff_max_size) {
            fclose(fpr);
            return (0);
        }
    }
#endif

#ifndef WIN32
    fpw = seechanges_open_dest(current);
#else
    fpw = fopen(current, "w");
#endif
    if (!fpw) {
        fclose(fpr);
        return (0);
    }

    n = fread(buf, 1, 2048, fpr);
#ifdef USE_MAGIC
    if (is_text(magic_cookie, buf, n) == 0) {
        goto cleanup;
    }
#endif

    {
        size_t copied = 0;

        do {
            if (n > 0) {
                copied += n;
                if (syscheck.diff_max_size > 0 && copied > syscheck.diff_max_size) {
                    fclose(fpr);
                    fclose(fpw);
                    unlink(current);
                    return (0);
                }
                if (fwrite(buf, 1, n, fpw) != n) {
                    fclose(fpr);
                    fclose(fpw);
                    unlink(current);
                    return (0);
                }
            }
        } while ((n = fread(buf, 1, 2048, fpr)) > 0);
    }

#ifdef USE_MAGIC
cleanup:
#endif
    if (fclose(fpr) == EOF) {
        fclose(fpw);
        unlink(current);
        return (0);
    }
    if (fclose(fpw) == EOF) {
        unlink(current);
        return (0);
    }
    return (1);
}

/* The diff store is written as root and by path name. A directory of it that
 * is a link, or where another user can replace our entries, would let that
 * user choose the files we write to.
 */
static int seechanges_safedir(const char *dir)
{
    struct stat st;

    if (lstat(dir, &st) < 0 || !S_ISDIR(st.st_mode)) {
        return (0);
    }

    if (st.st_uid != 0 && st.st_uid != geteuid()) {
        return (0);
    }

    /* DIFF_DIR_PATH is shared with the ossec group: sticky bit required */
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) && !(st.st_mode & S_ISVTX)) {
        return (0);
    }

    return (1);
}

/* Create the missing directories of the path and check the existing ones */
static int seechanges_createpath(const char *filename)
{
    char *buffer = NULL;
    char *tmpstr = NULL;
    char *newdir = NULL;

    os_strdup(filename, buffer);
    newdir = buffer;
    tmpstr = strchr(buffer + 1, '/');
    if (!tmpstr) {
        merror("%s: ERROR: Invalid path name: '%s'", ARGV0, filename);
        free(buffer);
        return (0);
    }
    *tmpstr = '\0';
    tmpstr++;

    while (1) {
        if (IsDir(newdir) != 0) {
#ifndef WIN32
            if (mkdir(newdir, 0750) == -1)
#else
            if (mkdir(newdir) == -1)
#endif
            {
                merror(MKDIR_ERROR, ARGV0, newdir, errno, strerror(errno));
                free(buffer);
                return (0);
            }
        } else {
            size_t diff_len = strlen(DIFF_DIR_PATH);

            /* Only directories at or under DIFF_DIR_PATH (exact prefix). */
            if (strncmp(newdir, DIFF_DIR_PATH, diff_len) == 0 &&
                (newdir[diff_len] == '\0' || newdir[diff_len] == '/') &&
                !seechanges_safedir(newdir)) {
                merror("%s: ERROR: '%s' must be a directory that only root can "
                       "change. Not using it for diffs.", ARGV0, newdir);
                free(buffer);
                return (0);
            }
        }

        if (*tmpstr == '\0') {
            break;
        }

        tmpstr[-1] = '/';
        tmpstr = strchr(tmpstr, '/');
        if (!tmpstr) {
            break;
        }
        *tmpstr = '\0';
        tmpstr++;
    }

    free(buffer);
    return (1);
}

/* One last-entry per file, plus a byte cap on the whole diff store
 * (ANT-2026-4T9F7XIQ). History files from older versions are removed
 * the first time a snapshot is written. */
static size_t seechanges_store_used;
static int seechanges_store_scanned;

static void seechanges_note_removed(size_t n)
{
    if (!seechanges_store_scanned || n == 0) {
        return;
    }
    if (n > seechanges_store_used) {
        seechanges_store_used = 0;
    } else {
        seechanges_store_used -= n;
    }
}

static void seechanges_note_added(size_t n)
{
    if (!seechanges_store_scanned || n == 0) {
        return;
    }
    seechanges_store_used += n;
}

static void seechanges_unlink_counted(const char *path)
{
    struct stat st;
    size_t n = 0;

    if (lstat(path, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0) {
        n = (size_t)st.st_size;
    }
    if (unlink(path) == 0) {
        seechanges_note_removed(n);
    }
}

/* A directory we will read or delete. Same rule as seechanges_safedir,
 * applied to an fd so a symlink cannot be swapped in after the check. */
static int seechanges_dir_trusted(const struct stat *st)
{
    if (!S_ISDIR(st->st_mode)) {
        return (0);
    }
    if (st->st_uid != 0 && st->st_uid != geteuid()) {
        return (0);
    }
    if ((st->st_mode & (S_IWGRP | S_IWOTH)) && !(st->st_mode & S_ISVTX)) {
        return (0);
    }
    return (1);
}

/* Open DIFF_DIR_PATH/local without following a symlink at local/. */
static int seechanges_open_local(void)
{
    int base;
    int local;
    struct stat st;

    base = open(DIFF_DIR_PATH, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (base < 0) {
        return (-1);
    }
    if (fstat(base, &st) < 0 || !seechanges_dir_trusted(&st)) {
        close(base);
        return (-1);
    }
    local = openat(base, "local", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(base);
    if (local < 0) {
        return (-1);
    }
    if (fstat(local, &st) < 0 || !seechanges_dir_trusted(&st)) {
        close(local);
        return (-1);
    }
    return (local);
}

static int seechanges_open_child(int parentfd, const char *name)
{
    int fd;
    struct stat st;

    fd = openat(parentfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return (-1);
    }
    if (fstat(fd, &st) < 0 || !seechanges_dir_trusted(&st)) {
        close(fd);
        return (-1);
    }
    return (fd);
}

/* Remove name from parentfd. Symlinks are unlinked, not followed.
 * Returns the size of regular files actually unlinked. */
static size_t seechanges_rmtree_at(int parentfd, const char *name, int depth)
{
    int fd;
    int walkfd;
    DIR *dp;
    struct dirent *ent;
    struct stat st;
    size_t bytes = 0;

    if (depth > 256 || name[0] == '\0' || strchr(name, '/') != NULL) {
        return (0);
    }
    if (fstatat(parentfd, name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
        return (0);
    }
    if (!S_ISDIR(st.st_mode)) {
        size_t n = 0;

        if (S_ISREG(st.st_mode) && st.st_size > 0) {
            n = (size_t)st.st_size;
        }
        if (unlinkat(parentfd, name, 0) == 0) {
            return (n);
        }
        return (0);
    }

    fd = seechanges_open_child(parentfd, name);
    if (fd < 0) {
        return (0);
    }
    walkfd = dup(fd);
    if (walkfd < 0) {
        close(fd);
        return (0);
    }
    dp = fdopendir(walkfd);
    if (!dp) {
        close(walkfd);
        close(fd);
        return (0);
    }
    while ((ent = readdir(dp)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
            continue;
        }
        bytes += seechanges_rmtree_at(fd, ent->d_name, depth + 1);
    }
    closedir(dp);
    close(fd);
    (void)unlinkat(parentfd, name, AT_REMOVEDIR);
    return (bytes);
}

/* dir is the snapshot directory. The leaf is already gone; climb from
 * its parent and stop at queue/diff/local. */
static void seechanges_rmdir_parents(char *dir)
{
    char root[OS_MAXSTR + 1];
    size_t root_len;
    char *slash;

    snprintf(root, OS_MAXSTR, "%s/local", DIFF_DIR_PATH);
    root_len = strlen(root);
    slash = strrchr(dir, '/');
    if (!slash) {
        return;
    }
    *slash = '\0';
    for (;;) {
        if (strlen(dir) <= root_len) {
            break;
        }
        if (rmdir(dir) < 0) {
            break;
        }
        slash = strrchr(dir, '/');
        if (!slash) {
            break;
        }
        *slash = '\0';
    }
}

static void seechanges_scan_at(int dirfd, char *live, size_t live_sz,
                               size_t live_len, int depth)
{
    int walkfd;
    DIR *dp;
    struct dirent *ent;

    if (depth > 256) {
        return;
    }
    walkfd = dup(dirfd);
    if (walkfd < 0) {
        return;
    }
    dp = fdopendir(walkfd);
    if (!dp) {
        close(walkfd);
        return;
    }
    while ((ent = readdir(dp)) != NULL) {
        struct stat st;
        size_t namelen;

        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
            continue;
        }
        if (strchr(ent->d_name, '/') != NULL) {
            continue;
        }
        if (fstatat(dirfd, ent->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0 ||
                S_ISLNK(st.st_mode)) {
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            int child;
            size_t next_len;
            int missing;

            child = seechanges_open_child(dirfd, ent->d_name);
            if (child < 0) {
                continue;
            }
            namelen = strlen(ent->d_name);
            if (live_len + 1 + namelen >= live_sz) {
                close(child);
                continue;
            }
            live[live_len] = '/';
            memcpy(live + live_len + 1, ent->d_name, namelen + 1);
            next_len = live_len + 1 + namelen;
            missing = (lstat(live, &st) < 0 &&
                       (errno == ENOENT || errno == ENOTDIR || errno == ELOOP));
            if (missing) {
                close(child);
                (void)seechanges_rmtree_at(dirfd, ent->d_name, depth + 1);
            } else {
                seechanges_scan_at(child, live, live_sz, next_len, depth + 1);
                close(child);
            }
            live[live_len] = '\0';
            continue;
        }
        if (strncmp(ent->d_name, "state.", 6) == 0 ||
                strncmp(ent->d_name, "diff.", 5) == 0) {
            (void)unlinkat(dirfd, ent->d_name, 0);
            continue;
        }
        if (strcmp(ent->d_name, DIFF_LAST_FILE) == 0 &&
                S_ISREG(st.st_mode) && st.st_size > 0) {
            /* A snapshot taken before the per-file cap must not sit in the
             * quota forever. The next change of that path starts clean. */
            if (syscheck.diff_max_size > 0 &&
                    (size_t)st.st_size > syscheck.diff_max_size) {
                (void)unlinkat(dirfd, ent->d_name, 0);
                continue;
            }
            seechanges_store_used += (size_t)st.st_size;
        }
    }
    closedir(dp);
}

static void seechanges_ensure_store(void)
{
    int fd;
    char live[OS_MAXSTR + 1];

    if (seechanges_store_scanned) {
        return;
    }
    seechanges_store_used = 0;
    live[0] = '\0';
    fd = seechanges_open_local();
    if (fd >= 0) {
        seechanges_scan_at(fd, live, sizeof(live), 0, 0);
        close(fd);
    }
    seechanges_store_scanned = 1;
}

static size_t seechanges_snapshot_size(const char *path)
{
    struct stat st;

    if (lstat(path, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0) {
        return ((size_t)st.st_size);
    }
    return (0);
}

static int seechanges_quota_allow(const char *filename, size_t add, size_t drop)
{
    size_t base;
    size_t next;

    seechanges_ensure_store();
    if (syscheck.diff_quota_size == 0) {
        return (1);
    }
    if (drop > seechanges_store_used) {
        drop = seechanges_store_used;
    }
    base = seechanges_store_used - drop;
    next = base + add;
    if (next < base || next > syscheck.diff_quota_size) {
        merror("%s: WARN: '%s' would exceed syscheck.diff_quota_size. "
               "Not copying it.", ARGV0, filename);
        return (0);
    }
    return (1);
}

static void seechanges_drop_replaced(const char *state_path, const char *diff_path,
                                     size_t old_sz, size_t new_sz)
{
    struct stat st;

    /* Leave old_sz in the counter when the state file is still on disk. */
    if (lstat(state_path, &st) == 0 && unlink(state_path) == 0) {
        seechanges_note_removed(old_sz);
    }
    if (lstat(diff_path, &st) == 0) {
        size_t n = 0;

        if (S_ISREG(st.st_mode) && st.st_size > 0) {
            n = (size_t)st.st_size;
        }
        if (unlink(diff_path) != 0 && n > 0) {
            seechanges_note_added(n);
        }
    }
    seechanges_note_added(new_sz);
}

/* A symlink target is resolved against the directory that holds the link.
 * Store paths are relative when DEFAULTDIR is, so hand diff(1) an absolute
 * target or the redirect lands under tmp/. */
static void seechanges_abs_path(const char *in, char *out, size_t outsz)
{
    char cwd[PATH_MAX];

    if (in[0] == '/') {
        snprintf(out, outsz, "%s", in);
        return;
    }
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        snprintf(out, outsz, "%s", in);
        return;
    }
    if (in[0] == '.' && in[1] == '/') {
        in += 2;
    }
    snprintf(out, outsz, "%s/%s", cwd, in);
}

void seechanges_delfile(const char *filename)
{
    char relbuf[OS_MAXSTR + 1];
    char dir[OS_MAXSTR + 1];
    const char *rel;
    char *cursor;
    char *slash;
    char *leaf;
    int fd;
    int next;
    size_t removed;

    rel = (filename[0] == '/') ? filename + 1 : filename;
    if (rel[0] == '\0') {
        return;
    }
    if (snprintf(relbuf, sizeof(relbuf), "%s", rel) >= (int)sizeof(relbuf)) {
        return;
    }
    fd = seechanges_open_local();
    if (fd < 0) {
        return;
    }

    leaf = strrchr(relbuf, '/');
    if (leaf != NULL) {
        *leaf = '\0';
        leaf++;
        cursor = relbuf;
        while ((slash = strchr(cursor, '/')) != NULL) {
            *slash = '\0';
            next = seechanges_open_child(fd, cursor);
            close(fd);
            if (next < 0) {
                return;
            }
            fd = next;
            cursor = slash + 1;
        }
        next = seechanges_open_child(fd, cursor);
        close(fd);
        if (next < 0) {
            return;
        }
        fd = next;
    } else {
        leaf = relbuf;
    }

    removed = seechanges_rmtree_at(fd, leaf, 0);
    close(fd);
    seechanges_note_removed(removed);
    snprintf(dir, OS_MAXSTR, "%s/local/%s", DIFF_DIR_PATH, rel);
    seechanges_rmdir_parents(dir);
}

/* Check if the file has changed */
char *seechanges_addfile(const char *filename)
{
    time_t old_date_of_change;
    time_t new_date_of_change;
    char old_location[OS_MAXSTR + 1];
    char tmp_location[OS_MAXSTR + 1];
    char diff_location[OS_MAXSTR + 1];
    char old_tmp[OS_MAXSTR + 1];
    char new_tmp[OS_MAXSTR + 1];
    char diff_tmp[OS_MAXSTR + 1];
    char diff_cmd[OS_MAXSTR + 1];
    os_sha256 sha256_old;
    os_sha256 sha256_new;
    int status = -1;
    int replaced = 0;
    size_t old_sz = 0;
    size_t new_sz = 0;
    struct stat statbuf;
    char *alert = NULL;

    /* Refuse a leaf symlink (lstat). Parent-component symlinks are still
     * followed by lstat/stat; those are refused when hashing and copying
     * via fopen_regular_nofollow() (ANT-2026-2138NB95). FIFO / device
     * refusal remains in the open helper (ANT-2026-KZAJSOET).
     */
    if (lstat(filename, &statbuf) < 0 || !S_ISREG(statbuf.st_mode)) {
        debug1("%s: DEBUG: Not a regular file, no diff for '%s'.", ARGV0, filename);
        return (NULL);
    }

    old_location[OS_MAXSTR] = '\0';
    tmp_location[OS_MAXSTR] = '\0';
    diff_location[OS_MAXSTR] = '\0';
    old_tmp[OS_MAXSTR] = '\0';
    new_tmp[OS_MAXSTR] = '\0';
    diff_tmp[OS_MAXSTR] = '\0';
    diff_cmd[OS_MAXSTR] = '\0';
    sha256_new[0] = '\0';
    sha256_old[0] = '\0';

    snprintf(
        old_location,
        OS_MAXSTR,
        "%s/local/%s/%s",
        DIFF_DIR_PATH,
        filename + 1,
        DIFF_LAST_FILE
    );

    /* Everything below writes to the store by path name: make sure it is ours first */
    if (!seechanges_createpath(old_location)) {
        return (NULL);
    }
    seechanges_ensure_store();

    /* Diff copies use a smaller cap than checksums, so one sparse file
     * cannot write a gigabyte of zeros into queue/diff (ANT-2026-J8XF7LCX).
     * st_size 0 still reaches the copy loop, which counts bytes.
     * Drop an already-expanded snapshot so a pre-cap copy does not stay
     * on disk while the live file remains over the limit. */
    if (syscheck.diff_max_size > 0 && statbuf.st_size > 0 &&
            (size_t)statbuf.st_size > syscheck.diff_max_size) {
        seechanges_reclaim_snapshot(old_location);
        debug1("%s: DEBUG: '%s' is over the diff size limit.", ARGV0, filename);
        return (NULL);
    }

    /* Hash the stored snapshot with the same byte cap. A last-entry
     * written before the cap (or a sparse one) must not be read to EOF. */
#ifndef WIN32
    if (OS_SHA256_File_nofollow_max(old_location, sha256_old, OS_BINARY,
                                    syscheck.diff_max_size) != 0) {
#else
    if (OS_SHA256_File_max(old_location, sha256_old, OS_BINARY,
                           syscheck.diff_max_size) != 0) {
#endif
        if (errno == EFBIG) {
            /* Drop the oversized snapshot so the next scan does not
             * re-read it up to the cap. A st_size of 0 would not match
             * the reclaim size check, so unlink here as well. */
            seechanges_unlink_counted(old_location);
        } else {
            /* Symlink last-entry (ELOOP): remove the link before the
             * copy, which must not truncate the link target. */
            seechanges_reclaim_snapshot(old_location);
        }
        if (!seechanges_quota_allow(filename, (size_t)statbuf.st_size, 0)) {
            return (NULL);
        }
        if (seechanges_dupfile(filename, old_location) != 1) {
            merror("%s: ERROR: Unable to create snapshot for %s", ARGV0, filename);
            return (NULL);
        }
        /* Book the bytes actually written. The file can grow during the copy. */
        new_sz = seechanges_snapshot_size(old_location);
        if (!seechanges_quota_allow(filename, new_sz, 0)) {
            (void)unlink(old_location);
            return (NULL);
        }
        seechanges_note_added(new_sz);
        return (NULL);
    }

    /* Hash the live path the same way we snapshot it (nofollow). */
#ifndef WIN32
    if (OS_SHA256_File_nofollow_max(filename, sha256_new, OS_BINARY,
                                    syscheck.diff_max_size) != 0) {
#else
    if (OS_SHA256_File_max(filename, sha256_new, OS_BINARY,
                           syscheck.diff_max_size) != 0) {
#endif
        if (errno == EFBIG) {
            merror("%s: ERROR: '%s' is over the diff size limit.",
                   ARGV0, filename);
        }
        return (NULL);
    }

    /* If they match, keep the old file and remove the new */
    if (strcmp(sha256_new, sha256_old) == 0) {
        return (NULL);
    }

    /* Save the old file at timestamp and rename new to last */
    old_date_of_change = File_DateofChange(old_location);
    {
        struct stat oldst;

        if (lstat(old_location, &oldst) == 0 && S_ISREG(oldst.st_mode) &&
                oldst.st_size > 0) {
            old_sz = (size_t)oldst.st_size;
        }
    }
    if (!seechanges_quota_allow(filename, (size_t)statbuf.st_size, old_sz)) {
        return (NULL);
    }

    snprintf(
        tmp_location,
        OS_MAXSTR,
        "%s/local/%s/state.%d",
        DIFF_DIR_PATH,
        filename + 1,
        (int)old_date_of_change
    );

    if (rename(old_location, tmp_location) < 0) {
        merror("%s: ERROR rename of %s failed: %s", ARGV0, old_location, strerror(errno));
        return (NULL);
    }

    if (seechanges_dupfile(filename, old_location) != 1) {
        merror("%s: ERROR: Unable to create snapshot for %s", ARGV0, filename);
        /* Restore last-entry so a nofollow refusal does not strand the store.
         * If the rename back fails, drop the stranded state file so the
         * quota counter does not keep counting it. */
        if (rename(tmp_location, old_location) < 0) {
            merror("%s: ERROR: Unable to restore %s after failed snapshot: %s",
                   ARGV0, old_location, strerror(errno));
            seechanges_unlink_counted(tmp_location);
        }
        return (NULL);
    }
    new_sz = seechanges_snapshot_size(old_location);
    if (!seechanges_quota_allow(filename, new_sz, old_sz)) {
        (void)unlink(old_location);
        if (rename(tmp_location, old_location) < 0) {
            merror("%s: ERROR: Unable to restore %s after quota refusal: %s",
                   ARGV0, old_location, strerror(errno));
            seechanges_unlink_counted(tmp_location);
        }
        return (NULL);
    }
    replaced = 1;

    new_date_of_change = File_DateofChange(old_location);

    /* Create file names. They end up on the diff command line, which every
     * local user can read in the process list, so they must not be derived
     * from the file content (the sha256 sums). The process id is enough to
     * keep them unique: only this daemon creates entries in the tmp dir.
     */
    snprintf(
        old_tmp,
        OS_MAXSTR,
        "%s/%s/syscheck-changes-%d-old",
        DEFAULTDIR,
        TMP_DIR,
        (int)getpid()
    );

    snprintf(
        new_tmp,
        OS_MAXSTR,
        "%s/%s/syscheck-changes-%d-new",
        DEFAULTDIR,
        TMP_DIR,
        (int)getpid()
    );

    snprintf(
        diff_tmp,
        OS_MAXSTR,
        "%s/%s/syscheck-changes-%d-diff",
        DEFAULTDIR,
        TMP_DIR,
        (int)getpid()
    );

    /* Remove leftovers of a killed process that had the same pid */
    unlink(old_tmp);
    unlink(new_tmp);
    unlink(diff_tmp);

    /* Create diff location */
    snprintf(
        diff_location,
        OS_MAXSTR,
        "%s/local/%s/diff.%d",
        DIFF_DIR_PATH,
        filename + 1,
        (int)new_date_of_change
    );

    /* Create symlinks. Targets must be absolute: a relative target is
     * resolved against tmp/, not the process cwd. */
    {
        char abs_old[OS_MAXSTR + 1];
        char abs_new[OS_MAXSTR + 1];
        char abs_diff[OS_MAXSTR + 1];

        seechanges_abs_path(old_location, abs_old, sizeof(abs_old));
        seechanges_abs_path(tmp_location, abs_new, sizeof(abs_new));
        seechanges_abs_path(diff_location, abs_diff, sizeof(abs_diff));

        if (symlink(abs_old, old_tmp) == -1) {
            merror(LINK_ERROR, ARGV0, abs_old, old_tmp, errno, strerror(errno));
            goto cleanup;
        }

        if (symlink(abs_new, new_tmp) == -1) {
            merror(LINK_ERROR, ARGV0, abs_new, new_tmp, errno, strerror(errno));
            goto cleanup;
        }

        if (symlink(abs_diff, diff_tmp) == -1) {
            merror(LINK_ERROR, ARGV0, abs_diff, diff_tmp, errno, strerror(errno));
            goto cleanup;
        }
    }

    if (is_nodiff(filename)) {
        /* Dont leak sensible data with a diff hanging around */
        FILE *fdiff;
        char *nodiff_message = "<Diff truncated because nodiff option>";
        fdiff = fopen(diff_location, "w");
        if (!fdiff) {
            merror("%s: ERROR: Unable to open file for writing `%s`", ARGV0, diff_location);
            goto cleanup;
        }
        fwrite(nodiff_message, strlen(nodiff_message) + 1, 1, fdiff);
        fclose(fdiff);
        /* Success */
        status = 0;
    } else {
        /* OK, run diff */
        snprintf(
            diff_cmd,
            2048,
            "diff \"%s\" \"%s\" > \"%s\" 2> /dev/null",
            new_tmp,
            old_tmp,
            diff_tmp
        );

        {
            int diff_status = system(diff_cmd);

            if (diff_status == -1 ||
                !WIFEXITED(diff_status) ||
                WEXITSTATUS(diff_status) > 1) {
                merror("%s: ERROR: Unable to run `%s`", ARGV0, diff_cmd);
                goto cleanup;
            }
        }

        /* Success */
        status = 0;
    }

cleanup:
    if ((unlink(old_tmp)) < 0) {
        merror("%s: ERROR: Unable to unlink %s (old_tmp): %s", ARGV0, old_tmp, strerror(errno));
    }
    if ((unlink(new_tmp)) < 0) {
        merror("%s: ERROR: Unable to unlink %s (new_tmp): %s", ARGV0, new_tmp, strerror(errno));
    }
    if ((unlink(diff_tmp)) < 0) {
        merror("%s: ERROR: Unable to unlink %s (diff_tmp): %s", ARGV0, diff_tmp, strerror(errno));
    }

    if (status == 0) {
        alert = gen_diff_alert(filename, new_date_of_change);
    }
    /* Keep only last-entry. state.* and diff.* are read for the alert
     * and then removed, including when diff(1) itself failed. */
    if (replaced) {
        seechanges_drop_replaced(tmp_location, diff_location, old_sz, new_sz);
    }
    return (alert);
}
