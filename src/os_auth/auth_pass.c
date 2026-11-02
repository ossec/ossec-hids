/* Copyright (C) 2026 Trend Micro Inc. / OSSEC Project.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <ctype.h>

#include "shared.h"
#include "auth_pass.h"

char *OS_AuthSanitizePassLine(char *buf)
{
    size_t len;
    const char *p;
    int has_nonblank = 0;

    if (!buf) {
        return (NULL);
    }

    /* Strip CR/LF only — keep any other password bytes, including spaces. */
    len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        buf[--len] = '\0';
    }

    if (len == 0) {
        return (NULL);
    }

    for (p = buf; *p != '\0'; p++) {
        if (!isspace((unsigned char)*p)) {
            has_nonblank = 1;
            break;
        }
    }
    if (!has_nonblank) {
        return (NULL);
    }

    return (buf);
}

char *OS_AuthParsePassLine(char *buf)
{
    char *clean;

    clean = OS_AuthSanitizePassLine(buf);
    if (!clean) {
        return (NULL);
    }
    return (strdup(clean));
}

int OS_AuthUsingFilePassword(const char *authpass, const char *raw_line)
{
    /* Ignore raw_line: a non-empty fgets buffer is not a password. */
    (void)raw_line;
    return (authpass != NULL);
}
