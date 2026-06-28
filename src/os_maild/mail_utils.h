/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef MAIL_UTILS_H
#define MAIL_UTILS_H

#include <stddef.h>

/* True if address contains CR or LF (SMTP command injection risk). */
int mail_address_has_crlf(const char *addr);

/* Copy src into dst (size bytes), stripping CR/LF for safe SMTP headers. */
void mail_sanitize_header_value(const char *src, char *dst, size_t dst_size);

/* Append line to buf if space remains; returns 0 on success, -1 if full or error. */
int mail_append_header_line(char *buf, size_t cap, const char *line);

/* True when additional email_to CC recipients exist (not for SMS-only sends). */
int mail_has_cc_recipients(char **to, int sms_only);

/* Copy envelope field into dst; returns 0 on success, -1 if CRLF or empty. */
int mail_safe_envelope_value(const char *src, char *dst, size_t dst_size);

#endif /* MAIL_UTILS_H */
