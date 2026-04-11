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

int OSMatch_Execute_pcre2_match(const char *subject, size_t len, OSMatch *match);
int OSMatch_Execute_true(const char *subject, size_t len, OSMatch *match);
int OSMatch_Execute_strncmp(const char *subject, size_t len, OSMatch *match);
int OSMatch_Execute_strrcmp(const char *subject, size_t len, OSMatch *match);
int OSMatch_Execute_strcmp(const char *subject, size_t len, OSMatch *match);
int OSMatch_Execute_strncasecmp(const char *subject, size_t len, OSMatch *match);
int OSMatch_Execute_strrcasecmp(const char *subject, size_t len, OSMatch *match);
int OSMatch_Execute_strcasecmp(const char *subject, size_t len, OSMatch *match);
int OSMatch_CouldBeOptimized(const char *pattern2check);

/* Compile a pattern to be used later
 * Allowed flags are:
 *      - OS_CASE_SENSITIVE
 * Returns 1 on success or 0 on error
 * The error code is set on reg->error
 */
int OSMatch_Compile(const char *pattern, OSMatch *reg, int flags)
{
    char *pattern_pcre2 = NULL;
    int flags_compile = 0;
    int error = 0;
    PCRE2_SIZE erroroffset = 0;
    size_t pattern_len = 0UL;
    char first_char, last_char;

    /* Check for references not initialized */
    if (reg == NULL) {
        return (0);
    }

    /* Initialize OSMatch structure */
    reg->error = 0;
    reg->regex = NULL;
    reg->match_data = NULL;
    reg->pattern_len = 0UL;
    reg->pattern = NULL;
    reg->exec_function = NULL;

    /* The pattern can't be null */
    if (pattern == NULL) {
        reg->error = OS_REGEX_PATTERN_NULL;
        goto compile_error;
    }

    /* Maximum size of the pattern */
    pattern_len = strlen(pattern);
    if (pattern_len > OS_PATTERN_MAXSIZE) {
        reg->error = OS_REGEX_MAXSIZE;
        goto compile_error;
    }

    if (pattern_len == 0) {
        reg->exec_function = OSMatch_Execute_true;
        return (1);
    } else if (OSMatch_CouldBeOptimized(pattern)) {
        first_char = pattern[0];
        last_char = pattern[pattern_len - 1];

        if (first_char == '^') {
            if (last_char == '$') {
                reg->pattern = strdup(&pattern[1]);
                reg->pattern_len = pattern_len - 2;
                reg->pattern[reg->pattern_len] = '\0';
                if (flags & OS_CASE_SENSITIVE) {
                    reg->exec_function = OSMatch_Execute_strcmp;
                } else {
                    reg->exec_function = OSMatch_Execute_strcasecmp;
                }
                return (1);
            } else {
                reg->pattern = strdup(&pattern[1]);
                reg->pattern_len = pattern_len - 1;
                if (flags & OS_CASE_SENSITIVE) {
                    reg->exec_function = OSMatch_Execute_strncmp;
                } else {
                    reg->exec_function = OSMatch_Execute_strncasecmp;
                }
                return (1);
            }
        } else {
            if (last_char == '$') {
                reg->pattern = strdup(pattern);
                reg->pattern_len = pattern_len - 1;
                reg->pattern[reg->pattern_len] = '\0';
                if (flags & OS_CASE_SENSITIVE) {
                    reg->exec_function = OSMatch_Execute_strrcmp;
                } else {
                    reg->exec_function = OSMatch_Execute_strrcasecmp;
                }
                return (1);
            }
        }
    }

    reg->exec_function = OSMatch_Execute_pcre2_match;

    /* Ossec pattern conversion */
    if (OSRegex_Convert(pattern, &pattern_pcre2, OS_CONVERT_MATCH) == 0) {
        reg->error = OS_REGEX_BADREGEX;
        goto compile_error;
    }

    flags_compile |= PCRE2_UTF;
    flags_compile |= PCRE2_NO_UTF_CHECK;
    flags_compile |= (flags & OS_CASE_SENSITIVE) ? 0 : PCRE2_CASELESS;
    reg->regex = pcre2_compile((PCRE2_SPTR)pattern_pcre2, PCRE2_ZERO_TERMINATED, flags_compile,
                               &error, &erroroffset, NULL);
    if (reg->regex == NULL) {
        reg->error = OS_REGEX_BADREGEX;
        goto compile_error;
    }

    reg->match_data = pcre2_match_data_create_from_pattern(reg->regex, NULL);
    if (reg->match_data == NULL) {
        reg->error = OS_REGEX_OUTOFMEMORY;
        goto compile_error;
    }

#ifdef USE_PCRE2_JIT
    /* Just In Time compilation for faster execution */
    if (pcre2_jit_compile(reg->regex, PCRE2_JIT_COMPLETE) != 0) {
        reg->error = OS_REGEX_NO_JIT;
        goto compile_error;
    }
#endif

    free(pattern_pcre2);

    return (1);

compile_error:
    /* Error handling */

    if (pattern_pcre2) {
        free(pattern_pcre2);
    }

    OSMatch_FreePattern(reg);

    return (0);
}

int OSMatch_CouldBeOptimized(const char *pattern2check)
{
    return OS_Pcre2("^\\^?[^$|^]+\\$?$", pattern2check);
}

