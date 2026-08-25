/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "json-queue.h"

#define JQUEUE_READ_FAILED  0x100

void jqueue_init(file_queue *queue)
{
    memset(queue, 0, sizeof(file_queue));
}

int jqueue_open_path(file_queue *queue, const char *path, int tail)
{
    if (!queue || !path || path[0] == '\0') {
        return -1;
    }

    strncpy(queue->file_name, path, MAX_FQUEUE);
    queue->file_name[MAX_FQUEUE] = '\0';

    if (queue->fp) {
        fclose(queue->fp);
        queue->fp = NULL;
    }

    queue->fp = fopen(queue->file_name, "r");
    if (!queue->fp) {
        /* alerts.json is created with the first JSON alert; ENOENT is expected. */
        if (errno == ENOENT) {
            debug1("%s: DEBUG: JSON alerts file '%s' not present yet.",
                   __local_name, queue->file_name);
        } else {
            merror(FOPEN_ERROR, __local_name, queue->file_name, errno, strerror(errno));
        }
        return -1;
    }

    if (tail && fseek(queue->fp, 0, SEEK_END) == -1) {
        merror(FSEEK_ERROR, __local_name, queue->file_name, errno, strerror(errno));
        fclose(queue->fp);
        queue->fp = NULL;
        return -1;
    }

    if (fstat(fileno(queue->fp), &queue->f_status) < 0) {
        merror(FSTAT_ERROR, __local_name, queue->file_name, errno, strerror(errno));
        fclose(queue->fp);
        queue->fp = NULL;
        return -1;
    }

    queue->flags = 0;
    return 0;
}

int jqueue_open(file_queue *queue, int tail)
{
    char path[MAX_FQUEUE + 1];

    if (isChroot()) {
        strncpy(path, ALERTSJSON_DAILY, MAX_FQUEUE);
    } else {
        snprintf(path, sizeof(path), "%s%s", DEFAULTDIR, ALERTSJSON_DAILY);
    }
    path[MAX_FQUEUE] = '\0';

    return jqueue_open_path(queue, path, tail);
}

cJSON *jqueue_next(file_queue *queue)
{
    struct stat buf;
    cJSON *alert;
    long pos;

    if (!queue) {
        return NULL;
    }

    if (!queue->fp) {
        /* Reopen from the start. Startup already tailed via jqueue_open(..., 1);
         * a later ENOENT means the file was just created (first JSON alert)
         * and tailing it would skip that alert. */
        if (queue->file_name[0] != '\0') {
            if (jqueue_open_path(queue, queue->file_name, 0) < 0) {
                return NULL;
            }
        } else if (jqueue_open(queue, 0) < 0) {
            return NULL;
        }
    }

    clearerr(queue->fp);
    alert = jqueue_parse_json(queue);

    if (alert && !(queue->flags & JQUEUE_READ_FAILED)) {
        return alert;
    }

    if (alert) {
        cJSON_Delete(alert);
        alert = NULL;
    }

    queue->flags = 0;

    if (!queue->fp) {
        return NULL;
    }

    pos = ftell(queue->fp);

    if (stat(queue->file_name, &buf) < 0) {
        fclose(queue->fp);
        queue->fp = NULL;
        return NULL;
    }

    /* Daily rotate replaces the path with a new inode. Check that
     * before a size-based rewind so we do not seek the unlinked old file. */
    if (buf.st_ino != queue->f_status.st_ino) {
        debug2("%s: DEBUG: alerts.json inode changed; reloading.", __local_name);
        if (jqueue_open_path(queue, queue->file_name, 0) < 0) {
            return NULL;
        }
        clearerr(queue->fp);
        return jqueue_parse_json(queue);
    }

    /* Same inode, shorter file (external truncate). */
    if (buf.st_size < queue->f_status.st_size ||
        (pos > 0 && buf.st_size < pos)) {
        debug2("%s: DEBUG: alerts.json truncated; rewinding.", __local_name);
        if (fseek(queue->fp, 0, SEEK_SET) != 0) {
            fclose(queue->fp);
            queue->fp = NULL;
            return NULL;
        }
        queue->f_status = buf;
        clearerr(queue->fp);
        return jqueue_parse_json(queue);
    }

    queue->f_status = buf;
    return NULL;
}

void jqueue_close(file_queue *queue)
{
    if (!queue) {
        return;
    }
    if (queue->fp) {
        fclose(queue->fp);
        queue->fp = NULL;
    }
}

cJSON *jqueue_parse_json(file_queue *queue)
{
    cJSON *object = NULL;
    char buffer[OS_MAXSTR + 1];
    long initial_pos;
    long offset;
    const char *json_err = NULL;
    char *nl;

    if (!queue || !queue->fp) {
        return NULL;
    }

    initial_pos = ftell(queue->fp);
    if (initial_pos < 0) {
        queue->flags = JQUEUE_READ_FAILED;
        return NULL;
    }

    if (!fgets(buffer, (int)sizeof(buffer), queue->fp)) {
        queue->flags = JQUEUE_READ_FAILED;
        return NULL;
    }

    offset = ftell(queue->fp);
    if (offset < 0) {
        queue->flags = JQUEUE_READ_FAILED;
        return NULL;
    }

    nl = strchr(buffer, '\n');
    if (!nl) {
        /* Incomplete line (still being written) or overlong record. */
        if (offset - initial_pos >= (long)OS_MAXSTR) {
            merror("%s: WARN: Overlong JSON alert read from '%s'.",
                   __local_name, queue->file_name);
            while (fgets(buffer, (int)sizeof(buffer), queue->fp)) {
                if (strchr(buffer, '\n')) {
                    break;
                }
            }
            return NULL;
        }
        if (fseek(queue->fp, initial_pos, SEEK_SET) != 0) {
            queue->flags = JQUEUE_READ_FAILED;
        }
        return NULL;
    }

    *nl = '\0';
    object = cJSON_ParseWithOpts(buffer, &json_err, 1);
    if (object && (!json_err || *json_err == '\0')) {
        return object;
    }

    cJSON_Delete(object);
    merror("%s: WARN: Invalid JSON alert read from '%s'.",
           __local_name, queue->file_name);
    return NULL;
}
