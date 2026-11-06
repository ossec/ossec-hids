/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "remoted.h"

#include <string.h>

/* Forward every complete TCP syslog line in storage_buffer. Strip a trailing
 * CR and a leading <PRI> on each line, leave any incomplete rest at the front,
 * and update *sb_used. send_fn returns <0 to abort. ANT-2026-2BEPXI8W.
 */
int syslog_tcp_drain_complete_lines(char *storage_buffer, size_t *sb_used,
                                    int (*send_fn)(const char *msg, void *ctx),
                                    void *ctx)
{
    char *line;
    char *line_end;
    char *buffer_pt;

    if (!storage_buffer || !sb_used || !send_fn) {
        return (-1);
    }

    line = storage_buffer;
    while ((line_end = strchr(line, '\n')) != NULL) {
        *line_end = '\0';

        buffer_pt = strchr(line, '\r');
        if (buffer_pt) {
            *buffer_pt = '\0';
        }

        if (line[0] == '<') {
            buffer_pt = strchr(line + 1, '>');
            if (buffer_pt) {
                buffer_pt++;
            } else {
                buffer_pt = line;
            }
        } else {
            buffer_pt = line;
        }

        if (send_fn(buffer_pt, ctx) < 0) {
            return (-1);
        }

        line = line_end + 1;
    }

    *sb_used = strlen(line);
    memmove(storage_buffer, line, *sb_used + 1);
    return (0);
}
