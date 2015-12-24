/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "string.h"


/* Trim CR and/or LF from the last positions of a string */
void os_trimcrlf(char *str)
{
    size_t len;

    len = strlen(str);
    len--;

    while (str[len] == '\n' || str[len] == '\r') {
        str[len] = '\0';
        len--;
    }
}

/* Remove offending char (e.g., double quotes) from source */
char *os_strip_char(const char *source, char remove)
{
    char *clean;
    const char *iterator = source;
    size_t length = 0;
    int i;

    /* Figure out how much memory to allocate */
    for ( ; *iterator; iterator++ ) {
        if ( *iterator != remove ) {
            length++;
        }
    }

    /* Allocate the memory */
    if ( (clean = (char *) malloc( length + 1 )) == NULL ) {
        // Return NULL
        return NULL;
    }
    memset(clean, '\0', length + 1);

    /* Remove the characters */
    iterator = source;
    for ( i = 0; *iterator; iterator++ ) {
        if ( *iterator != remove ) {
            clean[i] = *iterator;
            i++;
        }
    }

    return clean;
}

/* Do a substring */
int os_substr(char *dest, const char *src, size_t position, ssize_t length)
{
    dest[0] = '\0';

    if ( length <= 0  ) {
        /* Unsupported negative length string */
        return -3;
    }
    if ( src == NULL ) {
        return -2;
    }
    if ( position >= strlen(src) ) {
        return -1;
    }

    strncat(dest, (src + position), (size_t) length);

    return 0;
}

/* Escape a set of characters */
char *os_shell_escape(const char *src)
{
    /* Maximum Length of the String is 2 times the current length */
    char shell_escapes[] = { '\\', '"', '\'', ' ', '\t', ';', '`', '>', '<', '|', '#',
                             '*', '[', ']', '{', '}', '&', '$', '!', ':', '(', ')'
                           };

    char *escaped_string;
    size_t length = 0;
    int i = 0;

    if (src == NULL) {
        return NULL;
    }

    /* Determine how long the string will be */
    const char *iterator = src;
    for (; *iterator; iterator++) {
        if ( strchr(shell_escapes, *iterator) ) {
            length++;
        }
        length++;
    }
    /* Allocate memory */
    if ( (escaped_string = (char *) calloc(1, length + 1 )) == NULL ) {
        // Return NULL
        return NULL;
    }

    /* Escape the escapable characters */
    iterator = src;
    for ( i = 0; *iterator; iterator++ ) {
        if ( strchr(shell_escapes, *iterator) ) {
            escaped_string[i] = '\\';
            i++;
        }
        escaped_string[i] = *iterator;
        i++;
    }

    return escaped_string;
}

