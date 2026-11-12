/* Copyright (C) 2026 Atomicorp LLC
 * All rights reserved.
 *
 * After a complete directory walk, report cached paths that are gone.
 * Periodic scans only visit names that still exist (readdir /
 * FindFirstFile), so deletions are invisible without this pass.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "shared.h"
#include "syscheck.h"

#ifdef WIN32
#define fim_path_ncmp    strncasecmp
#define fim_path_sep(c)  ((c) == '/' || (c) == '\\')
#else
#define fim_path_ncmp    strncmp
#define fim_path_sep(c)  ((c) == '/')
#endif

/* path is under dir (or is dir). Mirrors realtime overflow matching. */
static int fim_path_under_dir(const char *path, const char *dir)
{
    size_t len;

    if (path == NULL || dir == NULL || dir[0] == '\0') {
        return (0);
    }

    len = strlen(dir);
    while (len > 1 && fim_path_sep(dir[len - 1])) {
        len--;
    }
    if (fim_path_ncmp(path, dir, len) != 0) {
        return (0);
    }
    return (path[len] == '\0' || fim_path_sep(path[len]) ||
            fim_path_sep(dir[len - 1]));
}

static int fim_path_missing(const char *path)
{
    struct stat st;

#ifdef WIN32
    if (stat(path, &st) < 0 && (errno == ENOENT || errno == ENOTDIR))
#else
    if (lstat(path, &st) < 0 &&
            (errno == ENOENT || errno == ENOTDIR || errno == ELOOP))
#endif
    {
        return (1);
    }
    return (0);
}

/* Alert and drop cached paths under dir that no longer exist on disk.
 * Call only after a complete enumeration of dir; an incomplete walk must
 * not look like a mass delete. */
void syscheck_reconcile_missing(const char *dir)
{
    unsigned int i;
    OSHashNode *curr;
    char **gone = NULL;
    size_t ngone = 0;
    size_t cap = 0;

    if (syscheck.fp == NULL || dir == NULL) {
        return;
    }

    for (i = 0; i <= syscheck.fp->rows; i++) {
        for (curr = syscheck.fp->table[i]; curr != NULL; curr = curr->next) {
            char *copy;

            if (curr->key == NULL || !fim_path_under_dir(curr->key, dir) ||
                    !fim_path_missing(curr->key)) {
                continue;
            }

            if (ngone >= cap) {
                size_t ncap = (cap == 0) ? 16 : (cap * 2);
                char **ng = (char **)realloc(gone, ncap * sizeof(char *));

                if (ng == NULL) {
                    merror("%s: WARN: Unable to allocate delete reconcile "
                           "list for '%s'.", ARGV0, dir);
                    goto cleanup;
                }
                gone = ng;
                cap = ncap;
            }

            copy = strdup(curr->key);
            if (copy == NULL) {
                merror("%s: WARN: Unable to duplicate path for delete "
                       "reconcile under '%s'.", ARGV0, dir);
                goto cleanup;
            }
            gone[ngone++] = copy;
        }
    }

    for (i = 0; i < ngone; i++) {
        char alert_msg[PATH_MAX + 4];
        void *oldsum;

        alert_msg[PATH_MAX + 3] = '\0';
        snprintf(alert_msg, PATH_MAX + 4, "-1 %s", gone[i]);
        /* Keep the cache entry if delivery fails so a later scan can
         * still report the deletion. */
        if (send_syscheck_msg(alert_msg) != 0) {
            merror("%s: WARN: Failed to send syscheck delete for '%s'. "
                   "Deletion will be retried.", ARGV0, gone[i]);
            continue;
        }
#ifndef WIN32
        seechanges_delfile(gone[i]);
#endif
        oldsum = OSHash_Delete(syscheck.fp, gone[i]);
        free(oldsum);
    }

cleanup:
    for (i = 0; i < ngone; i++) {
        free(gone[i]);
    }
    free(gone);
}
