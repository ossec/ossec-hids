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

/* Release all the memory created to store the sub strings */
void OSPcre2_FreeSubStrings(OSPcre2 *reg) {
    int i = 0;

    /* Free the sub strings */
    if (reg->sub_strings) {
        while (reg->sub_strings[i]) {
            free(reg->sub_strings[i]);
            reg->sub_strings[i] = NULL;
            i++;
        }
    }
    return;
}

