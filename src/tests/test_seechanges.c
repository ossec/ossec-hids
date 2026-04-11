/* Copyright (C) 2025
 * Test seechanges/libmagic behavior (report_changes with USE_MAGIC).
 * See https://github.com/ossec/ossec-hids/issues/2190
 */

#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OSHash used by syscheck_config; syscheck.h does not pull in hash_op.h */
#include "hash_op.h"
#include "syscheckd/syscheck.h"

/* Satisfy seechanges.o external reference; we don't use nodiff in this test */
syscheck_config syscheck = {0};

#ifdef USE_MAGIC
#include <magic.h>

/* Satisfy seechanges.o external reference; we init in the test */
magic_t magic_cookie;

extern int is_text(magic_t cookie, const void *buf, size_t len);

static void init_magic_cookie(void)
{
    magic_cookie = magic_open(MAGIC_MIME_TYPE);
    if (!magic_cookie) {
        return;
    }
    if (magic_load(magic_cookie, NULL) != 0) {
        magic_close(magic_cookie);
        magic_cookie = NULL;
    }
}
#endif

#ifdef USE_MAGIC
START_TEST(test_is_text_binary_returns_zero)
{
    unsigned char elf[] = {0x7f, 'E', 'L', 'F'};
    ck_assert_int_eq(0, is_text(magic_cookie, elf, sizeof(elf)));
}
END_TEST

START_TEST(test_is_text_plain_returns_one)
{
    const char *text = "hello world";
    ck_assert_int_eq(1, is_text(magic_cookie, text, strlen(text)));
}
END_TEST
#endif

START_TEST(test_is_nodiff_empty_config_returns_false)
{
    /* With syscheck = {0}, nodiff and nodiff_regex are NULL */
    ck_assert_int_eq(FALSE, is_nodiff("/some/path/file.txt"));
}
END_TEST

static Suite *build_suite(void)
{
    Suite *s = suite_create("seechanges");
    TCase *tc = tcase_create("report_changes");
    tcase_add_test(tc, test_is_nodiff_empty_config_returns_false);
#ifdef USE_MAGIC
    if (magic_cookie) {
        tcase_add_test(tc, test_is_text_binary_returns_zero);
        tcase_add_test(tc, test_is_text_plain_returns_one);
    }
#endif
    suite_add_tcase(s, tc);
    return s;
}

int main(void)
{
#ifdef USE_MAGIC
    init_magic_cookie();
    if (!magic_cookie) {
        fprintf(stderr, "test_seechanges: libmagic init failed, skipping is_text tests\n");
    }
#endif

    Suite *s = build_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

#ifdef USE_MAGIC
    if (magic_cookie) {
        magic_close(magic_cookie);
    }
#endif

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
