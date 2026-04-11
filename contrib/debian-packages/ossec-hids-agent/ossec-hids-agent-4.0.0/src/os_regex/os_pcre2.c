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

int OS_Pcre2(const char *pattern, const char *str)
{
    int r_code = 0;
    OSPcre2 reg;

    if (OSPcre2_Compile(pattern, &reg, PCRE2_UTF | PCRE2_NO_UTF_CHECK | PCRE2_CASELESS)) {
        if(OSPcre2_Execute(str, &reg)) {
            r_code = 1;
        }

        OSPcre2_FreePattern(&reg);
    }

    return (r_code);
}

