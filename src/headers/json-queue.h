/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef JSON_QUEUE_H
#define JSON_QUEUE_H

#include "cJSON.h"
#include "file-queue.h"

void jqueue_init(file_queue *queue);

/* Open alerts.json (chroot-aware). Returns 0 on success or -1 on error. */
int jqueue_open(file_queue *queue, int tail);

/* Open an explicit JSON alerts file. Used by tests and by jqueue_open. */
int jqueue_open_path(file_queue *queue, const char *path, int tail);

/* Next JSON object, or NULL if none is available yet. */
cJSON *jqueue_next(file_queue *queue);

void jqueue_close(file_queue *queue);

cJSON *jqueue_parse_json(file_queue *queue);

#endif
