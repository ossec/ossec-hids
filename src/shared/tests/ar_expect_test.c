/* Unit tests for ar_parse_expect / ar_pick_username (#2104). */

#include <stdio.h>
#include <string.h>
#include "ar.h"

static int failures;

static void expect_eq(const char *label, int got, int want)
{
    if (got != want) {
        fprintf(stderr, "FAIL: %s: got 0%o want 0%o\n", label, got, want);
        failures++;
    }
}

static void expect_str(const char *label, const char *got, const char *want)
{
    if (got == want) {
        return;
    }
    if (got && want && strcmp(got, want) == 0) {
        return;
    }
    fprintf(stderr, "FAIL: %s: got '%s' want '%s'\n",
            label, got ? got : "(null)", want ? want : "(null)");
    failures++;
}

int main(void)
{
    failures = 0;

    expect_eq("null", ar_parse_expect(NULL), 0);
    expect_eq("empty", ar_parse_expect(""), 0);
    expect_eq("spaces", ar_parse_expect("   "), 0);

    expect_eq("user", ar_parse_expect("user"), USERNAME);
    expect_eq("username", ar_parse_expect("username"), USERNAME);
    expect_eq("USER", ar_parse_expect("USER"), USERNAME);
    expect_eq("srcip", ar_parse_expect("srcip"), SRCIP);
    expect_eq("filename", ar_parse_expect("filename"), FILENAME);

    expect_eq("srcip, username",
              ar_parse_expect("srcip, username"),
              SRCIP | USERNAME);
    expect_eq("username,srcip",
              ar_parse_expect("username,srcip"),
              SRCIP | USERNAME);
    expect_eq(" user , srcip , filename ",
              ar_parse_expect(" user , srcip , filename "),
              USERNAME | SRCIP | FILENAME);

    /* Whitespace-separated (no commas) — compatible with older substring match */
    expect_eq("srcip username",
              ar_parse_expect("srcip username"),
              SRCIP | USERNAME);
    expect_eq("srcip\tusername filename",
              ar_parse_expect("srcip\tusername filename"),
              SRCIP | USERNAME | FILENAME);

    /* Unknown tokens ignored; known ones still applied */
    expect_eq("srcip, hostname",
              ar_parse_expect("srcip, hostname"),
              SRCIP);

    /* "user" must not be a substring match of unrelated tokens */
    expect_eq("userextra alone unknown",
              ar_parse_expect("userextra"),
              0);

    /* ar_pick_username */
    expect_str("prefer dstuser",
               ar_pick_username("alice", "bob"), "alice");
    expect_str("fallback srcuser",
               ar_pick_username(NULL, "bob"), "bob");
    expect_str("skip empty dstuser",
               ar_pick_username("", "bob"), "bob");
    expect_str("skip dash dstuser",
               ar_pick_username("-", "bob"), "bob");
    expect_str("skip dash srcuser",
               ar_pick_username(NULL, "-"), NULL);
    expect_str("both absent",
               ar_pick_username(NULL, NULL), NULL);
    expect_str("both dash",
               ar_pick_username("-", "-"), NULL);

    if (failures) {
        fprintf(stderr, "FAIL: ar_expect_test (%d)\n", failures);
        return 1;
    }

    printf("PASS: ar_expect_test\n");
    return 0;
}
