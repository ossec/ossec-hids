/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdlib.h>
#include "os_regex.h"

#ifndef WIN32
static __thread regex_matching *os_regex_tls_match = NULL;
#else
static regex_matching *os_regex_tls_match = NULL;
#endif

void regex_matching_clear(regex_matching *match)
{
    int i;

    if (!match) {
        return;
    }

    for (i = 0; i < REGEX_MATCH_MAX_GROUPS && match->sub_strings[i]; i++) {
        free(match->sub_strings[i]);
        match->sub_strings[i] = NULL;
    }
}

void regex_matching_free_match_data(regex_matching *match)
{
    if (!match || !match->match_data) {
        return;
    }

    pcre2_match_data_free(match->match_data);
    match->match_data = NULL;
}

pcre2_match_data *regex_matching_get_match_data(regex_matching *match, const pcre2_code *code)
{
    uint32_t capture_count;
    uint32_t needed;

    if (!match || !code) {
        return NULL;
    }

    /*
     * Size ovector from the pattern. Reuse the thread-owned buffer when it is
     * already large enough; recreate when a larger pattern is used.
     * REGEX_MATCH_MAX_GROUPS remains the limit for copying captures.
     */
    capture_count = 0;
    if (pcre2_pattern_info(code, PCRE2_INFO_CAPTURECOUNT, &capture_count) != 0) {
        return NULL;
    }
    needed = capture_count + 1;

    if (!match->match_data || pcre2_get_ovector_count(match->match_data) < needed) {
        if (match->match_data) {
            pcre2_match_data_free(match->match_data);
            match->match_data = NULL;
        }
        match->match_data = pcre2_match_data_create_from_pattern(code, NULL);
    }

    return match->match_data;
}

void os_regex_set_thread_match(regex_matching *match)
{
    os_regex_tls_match = match;
}

regex_matching *os_regex_get_thread_match(void)
{
    return os_regex_tls_match;
}

char **os_regex_get_substring_buffer(OSRegex *reg)
{
    regex_matching *match = os_regex_get_thread_match();

    if (match) {
        regex_matching_clear(match);
        return match->sub_strings;
    }

    return reg->sub_strings;
}

char **ospcre2_get_substring_buffer(OSPcre2 *reg)
{
    regex_matching *match = os_regex_get_thread_match();

    if (match) {
        regex_matching_clear(match);
        return match->sub_strings;
    }

    return reg->sub_strings;
}
