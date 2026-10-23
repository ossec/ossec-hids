/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Field helpers for logcollector ossecalert forwarding (ANT-2026-8TB11KJO).
 */

#ifndef OSSECALERT_FIELD_H
#define OSSECALERT_FIELD_H

#include <stddef.h>

/* Longest srcip/user value that fits in a 256-byte field buffer with
 * the tag prefix and the closing ';'. */
#define OA_FIELD_MAX 240

/* Replace ';' with ',' in place so the ossecalert wire format cannot
 * sprout a new field from log-derived values. */
void OS_OaCleanField(char *field);

/* Format " <tag>: <value>;" into dst. value may be truncated to OA_FIELD_MAX.
 * Returns 0 on success, -1 on bad args. */
int OS_OaFormatTaggedField(char *dst, size_t dst_sz,
                           const char *tag, const char *value);

#endif /* OSSECALERT_FIELD_H */
