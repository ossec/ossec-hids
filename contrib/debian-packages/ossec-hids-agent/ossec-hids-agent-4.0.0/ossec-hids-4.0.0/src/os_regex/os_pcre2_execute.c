/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "defs.h"
#include "os_regex.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *OSPcre2_Execute(const char *str, OSPcre2 *reg)
{
    /* Check for references not initialized */
    if (str == NULL) {
        reg->error = OS_REGEX_STR_NULL;
        return (NULL);
    }

    return reg->exec_function(str, reg);
}

const char *OSPcre2_Execute_pcre2_match(const char *str, OSPcre2 *reg)
{
    int rc = 0, nbs = 0, i = 0;
    PCRE2_SIZE *ov = NULL;

    /* Execute the reg */
#ifdef USE_PCRE2_JIT
    rc = pcre2_jit_match(reg->regex, (PCRE2_SPTR)str, strlen(str), 0, 0, reg->match_data, NULL);
#else
    rc = pcre2_match(reg->regex, (PCRE2_SPTR)str, strlen(str), 0, 0, reg->match_data, NULL);
#endif

    /* Check execution result */
    if (rc <= 0) {
        return NULL;
    }

    /* get the offsets informations for the match */
    ov = pcre2_get_ovector_pointer(reg->match_data);

    /* get the substrings if required */
    for (i = 1; i < rc; i++) {
        PCRE2_SIZE sub_string_start = ov[2 * i];
        PCRE2_SIZE sub_string_end = ov[2 * i + 1];
        PCRE2_SIZE sub_string_len = sub_string_end - sub_string_start;
        if (sub_string_start != -1) {
            reg->sub_strings[nbs] = (char *)calloc(sub_string_len + 1, sizeof(char));
            strncpy(reg->sub_strings[nbs], &str[sub_string_start], sub_string_len);
            nbs++;
        }
    }
    reg->sub_strings[nbs] = NULL;

    return &str[ov[1]];
}

const char *OSPcre2_Execute_strcmp(const char *subject, OSPcre2 *reg)
{
    if (!strcmp(reg->pattern, subject)) {
        return &subject[reg->pattern_len];
    }
    return NULL;
}

const char *OSPcre2_Execute_strncmp(const char *subject, OSPcre2 *reg)
{
    if (!strncmp(reg->pattern, subject, reg->pattern_len)) {
        return &subject[reg->pattern_len];
    }
    return NULL;
}

const char *OSPcre2_Execute_strrcmp(const char *subject, OSPcre2 *reg)
{
    size_t len = strlen(subject);
    if (len >= reg->pattern_len && !strcmp(reg->pattern, &subject[len - reg->pattern_len])) {
        return &subject[len];
    }
    return NULL;
}

const char *OSPcre2_Execute_strcasecmp(const char *subject, OSPcre2 *reg)
{
    if (!strcasecmp(reg->pattern, subject)) {
        return &subject[reg->pattern_len];
    }
    return NULL;
}

const char *OSPcre2_Execute_strncasecmp(const char *subject, OSPcre2 *reg)
{
    if (!strncasecmp(reg->pattern, subject, reg->pattern_len)) {
        return &subject[reg->pattern_len];
    }
    return NULL;
}

const char *OSPcre2_Execute_strrcasecmp(const char *subject, OSPcre2 *reg)
{
    size_t len = strlen(subject);
    if (len >= reg->pattern_len &&
        !strcasecmp(reg->pattern, &subject[len - reg->pattern_len])) {
        return &subject[len];
    }
    return NULL;
}
