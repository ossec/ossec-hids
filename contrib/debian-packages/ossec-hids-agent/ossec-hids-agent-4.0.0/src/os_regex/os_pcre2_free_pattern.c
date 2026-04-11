/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "os_regex.h"

/* Release all the memory created by the compilation/execution phases */
void OSPcre2_FreePattern(OSPcre2 *reg)
{
    /* Free the match data */
    if (reg->match_data) {
        pcre2_match_data_free(reg->match_data);
        reg->match_data = NULL;
    }

    /* Free the regex */
    if (reg->regex) {
        pcre2_code_free(reg->regex);
        reg->regex = NULL;
    }

    /* Free the patter, */
    if (reg->pattern) {
        free(reg->pattern);
        reg->pattern = NULL;
    }

    /* Free the sub strings */
    if (reg->sub_strings) {
        OSPcre2_FreeSubStrings(reg);
        free(reg->sub_strings);
        reg->sub_strings = NULL;
    }

    return;
}

