/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "os_regex.h"

/* Compare an already compiled pattern with a not NULL string.
 * Returns 1 on success or 0 on error.
 * The error code is set on reg->error.
 */
int OSMatch_Execute(const char *str, size_t str_len, OSMatch *reg)
{
    return reg->exec_function(str, str_len, reg);
}

int OSMatch_Execute_true(const char *subject, size_t len, OSMatch *match)
{
    (void)subject;
    (void)len;
    (void)match;
    return (1);
}

int OSMatch_Execute_pcre2_match(const char *str, size_t str_len, OSMatch * reg)
{
    int rc = 0;

#ifdef USE_PCRE2_JIT
    rc = pcre2_jit_match(reg->regex, (PCRE2_SPTR)str, str_len, 0, 0, reg->match_data, NULL);
#else
    rc = pcre2_match(reg->regex, (PCRE2_SPTR)str, str_len, 0, 0, reg->match_data, NULL);
#endif

    return (rc >= 0);
}

int OSMatch_Execute_strcmp(const char *subject, size_t len, OSMatch *match)
{
    //^literal$
    (void)len;
    return !strcmp(match->pattern, subject);
}

int OSMatch_Execute_strncmp(const char *subject, size_t len, OSMatch *match)
{
    //^literal
    (void)len;
    return !strncmp(match->pattern, subject, match->pattern_len);
}

int OSMatch_Execute_strrcmp(const char *subject, size_t len, OSMatch *match)
{
    // literal$
    if (len >= match->pattern_len) {
        return !strcmp(match->pattern, &subject[len - match->pattern_len]);
    }
    return (0);
}

int OSMatch_Execute_strcasecmp(const char *subject, size_t len, OSMatch *match)
{
    return (len == match->pattern_len && !strcasecmp(match->pattern, subject));
}

int OSMatch_Execute_strncasecmp(const char *subject, size_t len, OSMatch *match)
{
    (void)len;
    return !strncasecmp(match->pattern, subject, match->pattern_len);
}

int OSMatch_Execute_strrcasecmp(const char *subject, size_t len, OSMatch *match) {
    if (len >= match->pattern_len) {
        return !strcasecmp(match->pattern, &subject[len - match->pattern_len]);
    }
    return (0);
}

