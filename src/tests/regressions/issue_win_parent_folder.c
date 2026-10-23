/*
 * ANT-2026-1IXHWDKW: WIN32 w_ref_parent_folder must not miss "\.." when a
 * later "/..name" appears. CVE-2018-19666 ar.conf traversal check bypass.
 */

#include <stdio.h>

#include "file_op.h"

static int expect(const char *path, int win_seps, int want)
{
    int got = w_ref_parent_folder_ex(path, win_seps);

    if (got != want) {
        printf("  FAIL: '%s' win=%d got %d want %d\n", path, win_seps, got, want);
        return 1;
    }
    printf("  ok: '%s' win=%d -> %d\n", path, win_seps, got);
    return 0;
}

int main(void)
{
    int failed = 0;

    printf("=== ANT-2026-1IXHWDKW: WIN32 parent-folder check ===\n");

    /* Benign AR names */
    failed |= expect("route-null.cmd", 1, 0);
    failed |= expect("a/..b", 1, 0);
    failed |= expect("a\\..b", 1, 0);

    /* Pure backslash traversal — always refused */
    failed |= expect("x\\..\\..\\..\\shared\\..evil.cmd", 1, 1);

    /* Mixed separators: same target, one '/' before ..evil — must refuse */
    failed |= expect("x\\..\\..\\..\\shared/..evil.cmd", 1, 1);
    failed |= expect("\\..\\..\\shared/..payload.cmd", 1, 1);

    /* Unix branch unchanged */
    failed |= expect("../../tmp/evil", 0, 1);
    failed |= expect("agent.conf", 0, 0);

    if (failed) {
        printf("\nFAIL: issue_win_parent_folder\n");
        return 1;
    }

    printf("\nPASS: issue_win_parent_folder\n");
    return 0;
}
