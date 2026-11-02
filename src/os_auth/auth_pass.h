/* Copyright (C) 2026 Trend Micro Inc. / OSSEC Project.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef AUTH_PASS_H
#define AUTH_PASS_H

/* Sanitize a first line from authd.pass (mutates buf): strip CR/LF only.
 * Returns buf if it still holds a non-whitespace-only password, or NULL
 * for empty / whitespace-only lines. Leading/trailing spaces in a real
 * password are preserved for upgrade compatibility. */
char *OS_AuthSanitizePassLine(char *buf);

/* Parse first line into a heap password. Returns malloc'd string or NULL.
 * Mutates buf. */
char *OS_AuthParsePassLine(char *buf);

/* Whether the manager may claim "using password from file". Keyed on
 * authpass only (ANT-2026-ZO60J6E9). raw_line is unused; kept so call
 * sites can pass the fgets buffer without churn. */
int OS_AuthUsingFilePassword(const char *authpass, const char *raw_line);

#endif
