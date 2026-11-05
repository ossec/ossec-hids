/*
 * Regression: unterminated CDB value in address_match_key_value
 *
 * ANT-2026-WI6TBPFX / CWE-170
 *
 * OS_DBSearchKeyAddressValue() copied the CDB value with malloc(vlen) and
 * passed it to OSMatch_Execute(). A check_value of "reject$" is compared with
 * strcasecmp(), which reads the byte after the value. A 24-byte value fills a
 * glibc chunk, so that byte is the next chunk's size and the suffix does not
 * match. The sibling match_key_value lookup already allocates vlen + 1.
 *
 * OS_DBSearch() inverts this lookup type: a value match is returned as 0.
 * That inversion is left as it is. This test fails while the address lookup
 * reports "no value match" (return 1) for a value that does end in "reject".
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_wi6tbpfx_cdb_value
 *
 * Run:
 *   ./issue_wi6tbpfx_cdb_value
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "shared.h"
#include "lists.h"
#include "cdb/cdb_make.h"
#include "os_regex/os_regex.h"

const char *__local_name = "wi6tbpfx-cdb-value";

/* 24 bytes: fills the glibc chunk for malloc(24), so val[24] is not a NUL. */
static const char value[] = "spamhaus-edrop-v4 reject";
#define VALUE_LEN 24

static int failures = 0;

static void expect_eq(const char *what, int got, int want)
{
    if (got != want) {
        fprintf(stderr, "FAIL: %s returned %d, want %d\n", what, got, want);
        failures++;
    }
}

static int write_cdb(const char *path)
{
    char tmp[256];
    struct cdb_make cdbm;
    FILE *fp;
    int rc;

    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) {
        return -1;
    }
    fp = fopen(tmp, "w+");
    if (fp == NULL) {
        return -1;
    }
    if (cdb_make_start(&cdbm, fp) < 0) {
        fclose(fp);
        return -1;
    }
    if (cdb_make_add(&cdbm, "203.0.113.7", 11, (char *)value, VALUE_LEN) != 0 ||
            cdb_make_add(&cdbm, "203.0.113.", 10, (char *)value, VALUE_LEN) != 0) {
        fclose(fp);
        return -1;
    }
    rc = cdb_make_finish(&cdbm);
    if (fclose(fp) != 0 || rc != 0) {
        return -1;
    }
    if (rename(tmp, path) != 0) {
        return -1;
    }
    return 0;
}

int main(void)
{
    char dir[] = "/tmp/ossec-wi6tbpfx-XXXXXX";
    char cdb_path[256];
    char txt_path[256];
    ListNode *node;
    ListRule *address_rule;
    ListRule *string_rule;
    OSMatch address_match;
    OSMatch string_match;

    if (strlen(value) != VALUE_LEN) {
        fprintf(stderr, "FAIL: value length is %zu, want %d\n", strlen(value), VALUE_LEN);
        return 1;
    }
    if (mkdtemp(dir) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    snprintf(cdb_path, sizeof(cdb_path), "%s/reputation.cdb", dir);
    snprintf(txt_path, sizeof(txt_path), "%s/reputation", dir);
    if (write_cdb(cdb_path) != 0) {
        fprintf(stderr, "FAIL: could not write %s\n", cdb_path);
        return 1;
    }

    OS_CreateListsList();
    node = (ListNode *)calloc(1, sizeof(ListNode));
    if (node == NULL) {
        fprintf(stderr, "FAIL: calloc ListNode\n");
        return 1;
    }
    node->cdb_filename = cdb_path;
    node->txt_filename = txt_path;
    OS_AddList(node);

    memset(&address_match, 0, sizeof(address_match));
    memset(&string_match, 0, sizeof(string_match));
    if (!OSMatch_Compile("reject$", &address_match, 0) ||
            !OSMatch_Compile("reject$", &string_match, 0)) {
        fprintf(stderr, "FAIL: OSMatch_Compile\n");
        return 1;
    }

    address_rule = OS_AddListRule(NULL, LR_ADDRESS_MATCH_VALUE, 0, txt_path, &address_match);
    string_rule = OS_AddListRule(NULL, LR_STRING_MATCH_VALUE, 0, txt_path, &string_match);
    if (address_rule == NULL || string_rule == NULL || address_rule->db == NULL) {
        fprintf(stderr, "FAIL: list rule was not attached to the CDB\n");
        return 1;
    }

    /* Already terminated. A value match is 1. */
    expect_eq("match_key_value exact", OS_DBSearch(string_rule, "203.0.113.7"), 1);

    /*
     * A value match is inverted to 0. Before the fix, strcasecmp reads past
     * the 24-byte value and the suffix does not match, so this returns 1.
     */
    expect_eq("address_match_key_value exact", OS_DBSearch(address_rule, "203.0.113.7"), 0);
    expect_eq("address_match_key_value subnet", OS_DBSearch(address_rule, "203.0.113.9"), 0);

    OSMatch_FreePattern(&address_match);
    OSMatch_FreePattern(&string_match);
    unlink(cdb_path);
    rmdir(dir);

    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
