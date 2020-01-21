/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "os_regex.h"

const char *OSPcre2_Execute_pcre2_match(const char *str, OSPcre2 *reg);
const char *OSPcre2_Execute_strncmp(const char *subject, OSPcre2 *reg);
const char *OSPcre2_Execute_strrcmp(const char *subject, OSPcre2 *reg);
const char *OSPcre2_Execute_strcasecmp(const char *subject, OSPcre2 *reg);
const char *OSPcre2_Execute_strncasecmp(const char *subject, OSPcre2 *reg);
const char *OSPcre2_Execute_strrcasecmp(const char *subject, OSPcre2 *reg);
const char *OSPcre2_Execute_strcmp(const char *subject, OSPcre2 *reg);
int OSPcre2_CouldBeOptimized(const char *pattern);

int OSPcre2_Compile(const char *pattern, OSPcre2 *reg, int flags)
{
    int error = 0;
    PCRE2_SIZE erroroffset;
    size_t pattern_len = 0UL;
    char first_char, last_char;
    uint32_t count, i;

    /* Check for references not initialized */
    if (reg == NULL) {
        return (0);
    }

    /* Initialize OSRegex structure */
    reg->error = 0;
    reg->sub_strings = NULL;
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
#if 0
    if (pattern_len > OS_PATTERN_MAXSIZE) {
        reg->error = OS_REGEX_MAXSIZE;
        goto compile_error;
    }
#endif

    /* The pattern can't be empty */
    if (pattern_len == 0) {
        reg->error = OS_REGEX_PATTERN_EMPTY;
        goto compile_error;
    }

    if (OSPcre2_CouldBeOptimized(pattern)) {
        first_char = pattern[0];
        last_char = pattern[pattern_len - 1];

        if (first_char == '^') {
            if (last_char == '$') {
                reg->pattern = strdup(&pattern[1]);
                reg->pattern_len = pattern_len - 2;
                reg->pattern[reg->pattern_len] = '\0';
                if (flags & PCRE2_CASELESS) {
                    reg->exec_function = OSPcre2_Execute_strcasecmp;
                } else {
                    reg->exec_function = OSPcre2_Execute_strcmp;
                }
                return (1);
            } else {
                reg->pattern = strdup(&pattern[1]);
                reg->pattern_len = pattern_len - 1;
                if (flags & PCRE2_CASELESS) {
                    reg->exec_function = OSPcre2_Execute_strncasecmp;
                } else {
                    reg->exec_function = OSPcre2_Execute_strncmp;
                }
                return (1);
            }
        } else {
            if (last_char == '$') {
                reg->pattern = strdup(pattern);
                reg->pattern_len = pattern_len - 1;
                reg->pattern[reg->pattern_len] = '\0';
                if (flags & PCRE2_CASELESS) {
                    reg->exec_function = OSPcre2_Execute_strrcasecmp;
                } else {
                    reg->exec_function = OSPcre2_Execute_strrcmp;
                }
                return (1);
            }
        }
    }

    reg->exec_function = OSPcre2_Execute_pcre2_match;

    reg->regex = pcre2_compile((PCRE2_SPTR)pattern, pattern_len, flags, &error, &erroroffset, NULL);
    if (reg->regex == NULL) {
        reg->error = OS_REGEX_BADREGEX;
        goto compile_error;
    }

    reg->match_data = pcre2_match_data_create_from_pattern(reg->regex, NULL);
    if (reg->match_data == NULL) {
        reg->error = OS_REGEX_OUTOFMEMORY;
        goto compile_error;
    }

    pcre2_pattern_info(reg->regex, PCRE2_INFO_CAPTURECOUNT, (void *)&count);
    count++; // to store NULL pointer at the end
    reg->sub_strings = calloc(count, sizeof(char *));
    if (reg->sub_strings == NULL) {
        reg->error = OS_REGEX_OUTOFMEMORY;
        goto compile_error;
    }
    for (i = 0; i < count; i++) {
        reg->sub_strings[i] = NULL;
    }

#ifdef USE_PCRE2_JIT
    /* Just In Time compilation for faster execution */
    if (pcre2_jit_compile(reg->regex, PCRE2_JIT_COMPLETE) != 0) {
        reg->error = OS_REGEX_NO_JIT;
        goto compile_error;
    }
#endif

    return (1);

compile_error:
    /* Error handling */

    OSPcre2_FreePattern(reg);

    return (0);
}

int OSPcre2_CouldBeOptimized(const char *pattern)
{
    pcre2_code *preg = NULL;
    pcre2_match_data *md = NULL;
    PCRE2_SPTR re = (PCRE2_SPTR) "^\\^?[a-zA-Z0-9 !\"#%&',/:;<=>@_`~-]*\\$?$";
    int error = 0;
    PCRE2_SIZE erroroffset = 0;
    int should_be_optimized = 0;

    preg = pcre2_compile(re, PCRE2_ZERO_TERMINATED, PCRE2_UTF | PCRE2_NO_UTF_CHECK, &error,
                         &erroroffset, NULL);
    md = pcre2_match_data_create_from_pattern(preg, NULL);

    if (pcre2_match(preg, (PCRE2_SPTR)pattern, strlen(pattern), 0, 0, md, NULL) >= 0) {
        should_be_optimized = 1;
    }

    pcre2_match_data_free(md);
    pcre2_code_free(preg);

    return should_be_optimized;
}
