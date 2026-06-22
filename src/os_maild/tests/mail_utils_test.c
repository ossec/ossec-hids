/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Unit tests for mail_utils helpers (SMS header safety). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../mail_utils.h"

#ifndef ARGV0
#define ARGV0 "mail_utils_test"
#endif

static void test_cc_guard_sms_only_null_to(void)
{
    assert(mail_has_cc_recipients(NULL, 1) == 0);
    assert(mail_has_cc_recipients(NULL, 0) == 0);
}

static void test_cc_guard_with_recipients(void)
{
    char *one[] = { "a@example.com", NULL };
    char *two[] = { "a@example.com", "b@example.com", NULL };

    assert(mail_has_cc_recipients(one, 0) == 0);
    assert(mail_has_cc_recipients(two, 0) == 1);
    assert(mail_has_cc_recipients(two, 1) == 0);
}

static void test_append_header_line_bounds(void)
{
    char buf[512];
    char line[64];
    int i;

    buf[0] = '\0';
    for (i = 0; i < 40; i++) {
        snprintf(line, sizeof(line), "To: <sms%02d@example.com>\r\n", i);
        if (mail_append_header_line(buf, sizeof(buf), line) != 0) {
            break;
        }
    }

    assert(strlen(buf) < sizeof(buf));
    assert(mail_append_header_line(buf, sizeof(buf), line) == -1);
    assert(strlen(buf) < sizeof(buf));
}

static void test_safe_envelope_value(void)
{
    char dst[64];

    assert(mail_safe_envelope_value("user@example.com", dst, sizeof(dst)) == 0);
    assert(strcmp(dst, "user@example.com") == 0);
    assert(mail_safe_envelope_value("bad\ruser", dst, sizeof(dst)) == -1);
    assert(dst[0] == '\0');
}

static void test_append_header_line_no_underflow(void)
{
    char buf[128];
    char line[80];
    int i;

    buf[0] = '\0';
    snprintf(line, sizeof(line), "To: <%s>\r\n",
             "0123456789012345678901234567890123456789012345678901234567890");

    for (i = 0; i < 10; i++) {
        if (mail_append_header_line(buf, sizeof(buf), line) != 0) {
            break;
        }
    }

    assert(strlen(buf) < sizeof(buf));
}

int main(void)
{
    test_cc_guard_sms_only_null_to();
    test_cc_guard_with_recipients();
    test_append_header_line_bounds();
    test_safe_envelope_value();
    test_append_header_line_no_underflow();

    printf("mail_utils_test: OK\n");
    return (0);
}
