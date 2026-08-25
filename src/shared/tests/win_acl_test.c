/* Unit tests for Windows FIM ACL helpers (portable canonicalize/diff). */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "win_acl_op.h"
#include "os_crypto/md5/md5_op.h"

static int failures = 0;

static void expect_int(const char *name, int got, int want)
{
    if (got != want) {
        printf("FAIL %s: got %d want %d\n", name, got, want);
        failures++;
    }
}

static void expect_str(const char *name, const char *got, const char *want)
{
    if (!got || !want || strcmp(got, want) != 0) {
        printf("FAIL %s: got '%s' want '%s'\n", name,
               got ? got : "(null)", want ? want : "(null)");
        failures++;
    }
}

static void fill_ace(fim_ace_t *a, const char *sid, int type,
                     unsigned int flags, unsigned int mask, unsigned int ord)
{
    memset(a, 0, sizeof(*a));
    snprintf(a->sid, sizeof(a->sid), "%s", sid);
    a->type = type;
    a->flags = flags;
    a->mask = mask;
    a->ord = ord;
}

int main(void)
{
    fim_acl_t a, b;
    char digest1[33], digest2[33];
    char snap[1024];
    char buf[2048];
    os_md5 nodacl_md5;

    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));

    /* Null / absent DACL sentinels */
    a.special = FIM_ACL_NODACL;
    expect_int("nodacl digest", fim_win_acl_digest(&a, digest1), 0);
    OS_MD5_Str("NODACL", nodacl_md5);
    expect_str("nodacl md5", digest1, nodacl_md5);

    a.special = FIM_ACL_NULLDACL;
    expect_int("nulldacl digest", fim_win_acl_digest(&a, digest2), 0);
    OS_MD5_Str("NULLDACL", nodacl_md5);
    expect_str("nulldacl md5", digest2, nodacl_md5);

    /* Digest includes DACL order (ord); same ACEs with different ord differ. */
    a.special = FIM_ACL_NORMAL;
    a.aces = calloc(2, sizeof(fim_ace_t));
    a.count = 2;
    fill_ace(&a.aces[0], "S-1-5-32-545", FIM_ACE_ALLOW, FIM_ACE_OI | FIM_ACE_CI,
             0x00120089, 0);
    fill_ace(&a.aces[1], "S-1-5-18", FIM_ACE_ALLOW, 0, 0x001f01ff, 1);
    fim_acl_sort(&a);
    expect_int("digest a", fim_win_acl_digest(&a, digest1), 0);

    b.special = FIM_ACL_NORMAL;
    b.aces = calloc(2, sizeof(fim_ace_t));
    b.count = 2;
    fill_ace(&b.aces[0], "S-1-5-18", FIM_ACE_ALLOW, 0, 0x001f01ff, 0);
    fill_ace(&b.aces[1], "S-1-5-32-545", FIM_ACE_ALLOW, FIM_ACE_OI | FIM_ACE_CI,
             0x00120089, 1);
    fim_acl_sort(&b);
    expect_int("digest b", fim_win_acl_digest(&b, digest2), 0);
    if (strcmp(digest1, digest2) == 0) {
        printf("FAIL order-sensitive digest: digests unexpectedly equal\n");
        failures++;
    }

    /* Same principals+ord → same digest regardless of array insert order */
    fill_ace(&b.aces[0], "S-1-5-18", FIM_ACE_ALLOW, 0, 0x001f01ff, 1);
    fill_ace(&b.aces[1], "S-1-5-32-545", FIM_ACE_ALLOW, FIM_ACE_OI | FIM_ACE_CI,
             0x00120089, 0);
    fim_acl_sort(&b);
    expect_int("digest b2", fim_win_acl_digest(&b, digest2), 0);
    expect_str("same ord digest", digest1, digest2);

    /* Snapshot round-trip */
    expect_int("snapshot", fim_win_acl_snapshot(&a, snap, sizeof(snap)), 0);
    fim_acl_free(&b);
    memset(&b, 0, sizeof(b));
    expect_int("parse snap", fim_win_acl_parse_snapshot(snap, &b), 0);
    expect_int("parse count", (int)b.count, 2);
    expect_int("digest roundtrip", fim_win_acl_digest(&b, digest2), 0);
    expect_str("roundtrip digest", digest1, digest2);

    /* Diff: Added / Removed / Modified */
    fill_ace(&b.aces[0], "S-1-5-32-545", FIM_ACE_ALLOW, FIM_ACE_OI | FIM_ACE_CI,
             0x001201bf, 0);
    fill_ace(&b.aces[1], "S-1-5-18", FIM_ACE_ALLOW, 0, 0x001f01ff, 1);
    buf[0] = '\0';
    expect_int("diff modified", fim_win_acl_diff(&a, &b, buf, sizeof(buf)) > 0, 1);
    if (!strstr(buf, "Modified:")) {
        printf("FAIL diff missing Modified: got '%s'\n", buf);
        failures++;
    }

    /* Identical ACLs → diff returns 0 (no appendix spam). */
    fill_ace(&b.aces[0], "S-1-5-32-545", FIM_ACE_ALLOW, FIM_ACE_OI | FIM_ACE_CI,
             0x00120089, 0);
    fill_ace(&b.aces[1], "S-1-5-18", FIM_ACE_ALLOW, 0, 0x001f01ff, 1);
    fim_acl_sort(&b);
    expect_int("diff identical", fim_win_acl_diff(&a, &b, buf, sizeof(buf)), 0);

    /* change_text: unchanged digests → no appendix */
    {
        char old_e[2048], new_e[2048];
        char snap2[1024];
        fim_win_acl_snapshot(&a, snap2, sizeof(snap2));
        snprintf(old_e, sizeof(old_e), "0:0:0:0:aaa:bbb:xxx:0:%s\n%s", digest1, snap2);
        snprintf(new_e, sizeof(new_e), "0:0:0:0:aaa:bbb:xxx:0:%s\n%s", digest1, snap2);
        expect_int("change_text same digest",
                   fim_win_acl_change_text(old_e, new_e, buf, sizeof(buf)), 0);
    }

    /* Remove one ACE, add another */
    {
        fim_acl_t neu;
        memset(&neu, 0, sizeof(neu));
        neu.aces = calloc(2, sizeof(fim_ace_t));
        neu.count = 2;
        fill_ace(&neu.aces[0], "S-1-5-18", FIM_ACE_ALLOW, 0, 0x001f01ff, 0);
        fill_ace(&neu.aces[1], "S-1-5-21-1-2-3-1001", FIM_ACE_DENY, FIM_ACE_ID,
                 0x00110000, 1);
        fim_acl_sort(&neu);
        buf[0] = '\0';
        fim_win_acl_diff(&a, &neu, buf, sizeof(buf));
        if (!strstr(buf, "Removed:") || !strstr(buf, "Added:")) {
            printf("FAIL diff add/remove: got '%s'\n", buf);
            failures++;
        }
        fim_acl_free(&neu);
    }

    /* Format includes inheritance markers */
    buf[0] = '\0';
    fim_win_acl_format(&a, buf, sizeof(buf));
    if (!strstr(buf, "Permissions:") || !strstr(buf, "ALLOWED")) {
        printf("FAIL format: got '%s'\n", buf);
        failures++;
    }
    if (!strstr(buf, "[OI,CI]") && !strstr(buf, "[OI")) {
        /* At least one ACE should show inheritance */
        if (!strstr(buf, "OI")) {
            printf("FAIL format inheritance: got '%s'\n", buf);
            failures++;
        }
    }

    fim_acl_free(&a);
    fim_acl_free(&b);

    /* Non-Windows read stub */
#ifndef WIN32
    {
        fim_acl_t stub;
        expect_int("read stub", fim_win_acl_read("/tmp", &stub), -1);
    }
#endif

    if (failures) {
        printf("FAILED: %d assertion(s)\n", failures);
        return (1);
    }

    printf("PASS: win_acl_test\n");
    return (0);
}
