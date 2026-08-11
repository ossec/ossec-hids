/* Unit tests for FIM sum placeholder helpers (#1590/#1704). */

#include <stdio.h>
#include <string.h>

#include "fim_sum_op.h"

static int failures = 0;

static void expect_int(const char *name, int got, int want)
{
    if (got != want) {
        printf("FAIL %s: got %d want %d\n", name, got, want);
        failures++;
    }
}

int main(void)
{
    expect_int("placeholder xxx", fim_hash_is_placeholder("xxx"), 1);
    expect_int("placeholder xxx:", fim_hash_is_placeholder("xxx:rest"), 1);
    expect_int("short x not placeholder", fim_hash_is_placeholder("x"), 0);
    expect_int("short xx not placeholder", fim_hash_is_placeholder("xx"), 0);
    expect_int("not placeholder", fim_hash_is_placeholder("abc"), 0);
    expect_int("null is placeholder", fim_hash_is_placeholder(NULL), 1);

    expect_int("offset new format",
               fim_sum_data_offset("++++++-0:0:0:0:aaa:bbb:ccc"), 7);
    expect_int("offset legacy format",
               fim_sum_data_offset("++++++0:0:0:0:aaa:bbb"), 6);
    expect_int("offset attrs format",
               fim_sum_data_offset("++++++++0:0:0:0:aaa:bbb:ccc:32"), 8);

    expect_int("equal sums",
               fim_sum_has_real_change("0:0:0:0:aaa:bbb:xxx",
                                       "0:0:0:0:aaa:bbb:xxx"), 0);
    expect_int("xxx to real sha1",
               fim_sum_has_real_change("0:0:0:0:aaa:xxx:xxx",
                                       "0:0:0:0:aaa:bbb:xxx"), 0);
    expect_int("real to xxx sha1",
               fim_sum_has_real_change("0:0:0:0:aaa:bbb:xxx",
                                       "0:0:0:0:aaa:xxx:xxx"), 0);
    expect_int("malformed short hash field",
               fim_sum_has_real_change("0:0:0:0:x:xx:xxx",
                                       "0:0:0:0:x:yy:xxx"), 1);
    expect_int("real sha1 change",
               fim_sum_has_real_change("0:0:0:0:aaa:bbb:xxx",
                                       "0:0:0:0:aaa:ccc:xxx"), 1);
    expect_int("size change",
               fim_sum_has_real_change("10:0:0:0:aaa:bbb:xxx",
                                       "11:0:0:0:aaa:bbb:xxx"), 1);
    expect_int("attrs change",
               fim_sum_has_real_change("0:0:0:0:aaa:bbb:xxx:32",
                                       "0:0:0:0:aaa:bbb:xxx:34"), 1);
    expect_int("attrs equal",
               fim_sum_has_real_change("0:0:0:0:aaa:bbb:xxx:32",
                                       "0:0:0:0:aaa:bbb:xxx:32"), 0);
    expect_int("attrs added format-only",
               fim_sum_has_real_change("0:0:0:0:aaa:bbb:xxx",
                                       "0:0:0:0:aaa:bbb:xxx:32"), 0);
    expect_int("acl added format-only",
               fim_sum_has_real_change("0:0:0:0:aaa:bbb:xxx:0",
                                       "0:0:0:0:aaa:bbb:xxx:0:deadbeef"), 0);

    expect_int("offset acl format",
               fim_sum_data_offset("++++++++-0:0:0:0:aaa:bbb:ccc:0:deadbeef"), 9);
    expect_int("acl digest change",
               fim_sum_has_real_change("0:0:0:0:aaa:bbb:xxx:0:aaa",
                                       "0:0:0:0:aaa:bbb:xxx:0:bbb"), 1);
    expect_int("acl equal ignores snapshot",
               fim_sum_has_real_change("0:0:0:0:aaa:bbb:xxx:0:aaa\nold",
                                       "0:0:0:0:aaa:bbb:xxx:0:aaa\nnew"), 0);
    expect_int("fim_sum_equal true",
               fim_sum_equal("0:0:0:0:a:b:c\nsnap", "0:0:0:0:a:b:c\nother"), 1);
    expect_int("fim_sum_equal false",
               fim_sum_equal("0:0:0:0:a:b:c", "0:0:0:0:a:b:d"), 0);

    {
        char abuf[128];
        fim_win_attrs_str(0x22, abuf, sizeof(abuf)); /* HIDDEN|ARCHIVE */
        if (strcmp(abuf, "HIDDEN, ARCHIVE") != 0) {
            printf("FAIL attrs str: got '%s'\n", abuf);
            failures++;
        }
        fim_win_attrs_str(0, abuf, sizeof(abuf));
        if (strcmp(abuf, "NONE") != 0) {
            printf("FAIL attrs none: got '%s'\n", abuf);
            failures++;
        }
    }

    if (failures) {
        printf("FAILED: %d assertion(s)\n", failures);
        return (1);
    }

    printf("PASS: fim_sum_test\n");
    return (0);
}
