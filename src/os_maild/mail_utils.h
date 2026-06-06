/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef MAIL_UTILS_H
#define MAIL_UTILS_H

#include <stddef.h>

/* True if address contains CR or LF (SMTP command injection risk). */
int mail_address_has_crlf(const char *addr);

/* Copy src into dst (size bytes), stripping CR/LF for safe SMTP headers. */
void mail_sanitize_header_value(const char *src, char *dst, size_t dst_size);

#endif /* MAIL_UTILS_H */
