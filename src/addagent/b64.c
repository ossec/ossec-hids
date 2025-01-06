/*
 * Copyright (C), 2000-2004 by the monit project group.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/* base64 encoding/decoding
 * Author: Jan-Henrik Haukeland <hauk@tildeslash.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>  // For using bool instead of int for boolean functions

/* Prototypes */
static bool is_base64(char c);
static char encode_char(unsigned char u);
static unsigned char decode_char(char c);

/* Global functions */
char *decode_base64(const char *src);
char *encode_base64(int size, const char *src);

/* Encode a character into Base64 */
static char encode_char(unsigned char u) {
    if (u < 26) return 'A' + u;
    if (u < 52) return 'a' + (u - 26);
    if (u < 62) return '0' + (u - 52);
    return (u == 62) ? '+' : '/';
}

/* Decode a Base64 character */
static unsigned char decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    return (c == '+') ? 62 : 63;
}

/* Check if a character is a valid Base64 character */
static bool is_base64(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || (c == '+') || 
           (c == '/') || (c == '=');
}

/* Encode data to Base64 */
char *encode_base64(int size, const char *src) {
    if (!src) return NULL;

    if (size == 0) size = strlen(src);

    int out_size = (size + 2) / 3 * 4 + 1;  // +1 for null terminator
    char *out = (char *)calloc(out_size, sizeof(char));
    if (!out) return NULL;

    char *p = out;

    for (int i = 0; i < size; i += 3) {
        unsigned char b1 = src[i];
        unsigned char b2 = (i + 1 < size) ? src[i + 1] : 0;
        unsigned char b3 = (i + 2 < size) ? src[i + 2] : 0;

        *p++ = encode_char(b1 >> 2);
        *p++ = encode_char(((b1 & 0x3) << 4) | (b2 >> 4));
        *p++ = (i + 1 < size) ? encode_char(((b2 & 0xf) << 2) | (b3 >> 6)) : '=';
        *p++ = (i + 2 < size) ? encode_char(b3 & 0x3f) : '=';
    }

    return out;
}

/* Decode Base64 encoded string */
char *decode_base64(const char *src) {
    if (!src || !*src) return NULL;

    int len = strlen(src);
    int out_len = len * 3 / 4;
    char *dest = (char *)calloc(out_len + 1, sizeof(char));  // +1 for null terminator
    if (!dest) return NULL;

    unsigned char *buf = (unsigned char *)malloc(len);
    if (!buf) {
        free(dest);
        return NULL;
    }

    // Ignore non-Base64 characters
    int l = 0;
    for (int k = 0; k < len; k++) {
        if (is_base64(src[k])) {
            buf[l++] = src[k];
        }
    }

    unsigned char *p = (unsigned char *)dest;

    for (int k = 0; k < l; k += 4) {
        unsigned char b1 = decode_char(buf[k]);
        unsigned char b2 = decode_char((k + 1 < l) ? buf[k + 1] : 'A');
        unsigned char b3 = decode_char((k + 2 < l) ? buf[k + 2] : 'A');
        unsigned char b4 = decode_char((k + 3 < l) ? buf[k + 3] : 'A');

        *p++ = (b1 << 2) | (b2 >> 4);
        if (buf[k + 2] != '=') *p++ = ((b2 & 0xf) << 4) | (b3 >> 2);
        if (buf[k + 3] != '=') *p++ = ((b3 & 0x3) << 6) | b4;
    }

    free(buf);
    return dest;
}
