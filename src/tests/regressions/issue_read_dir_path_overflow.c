/*
 * ANT-2026-1UF4D24F: read_dir must not pass a wrapped size to strncpy when
 * composing dir + "/" + d_name near PATH_MAX (4095-char directories).
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_read_dir_path_overflow
 */

#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "shared.h"
#include "syscheckd/syscheck.h"

int main(void)
{
    char f_name[PATH_MAX + 2];
    char dir[PATH_MAX + 1];
    int failed = 0;
    size_t i;

    printf("=== ANT-2026-1UF4D24F: read_dir path join bounds ===\n");
    printf("  PATH_MAX=%d\n", PATH_MAX);

    /* Old formula PATH_MAX - dir_size - 2 wraps at dir_size == PATH_MAX-1. */
    if (OS_SyscheckEntryFits(PATH_MAX - 1, 1, 1)) {
        printf("  FAIL: EntryFits(%d, 1, sep) true — would wrap strncpy size\n",
               PATH_MAX - 1);
        failed = 1;
    } else {
        printf("  ok: EntryFits(%d, 1, sep) rejects (no wrap)\n", PATH_MAX - 1);
    }

    if (OS_SyscheckEntryFits(PATH_MAX - 2, 1, 1)) {
        printf("  FAIL: EntryFits(%d, 1, sep) true — dir+'/' +1-char overflows\n",
               PATH_MAX - 2);
        failed = 1;
    } else {
        printf("  ok: EntryFits(%d, 1, sep) rejects\n", PATH_MAX - 2);
    }

    /* Trailing slash: no extra separator — PATH_MAX-2 dir + 1-char name fits. */
    if (!OS_SyscheckEntryFits(PATH_MAX - 2, 1, 0)) {
        printf("  FAIL: EntryFits(%d, 1, no-sep) rejected trailing-slash fit\n",
               PATH_MAX - 2);
        failed = 1;
    } else {
        printf("  ok: EntryFits(%d, 1, no-sep) accepts\n", PATH_MAX - 2);
    }

    if (!OS_SyscheckEntryFits(100, 10, 1)) {
        printf("  FAIL: short path rejected\n");
        failed = 1;
    } else {
        printf("  ok: short path accepted\n");
    }

    /* Join must refuse a 4095-char directory + entry. */
    for (i = 0; i < (size_t)PATH_MAX - 1; i++) {
        dir[i] = 'a';
    }
    dir[PATH_MAX - 1] = '\0';

    if (OS_SyscheckJoinEntryPath(f_name, sizeof(f_name), dir, PATH_MAX - 1,
                                 "x") == 0) {
        printf("  FAIL: JoinEntryPath accepted %d-char dir\n", PATH_MAX - 1);
        failed = 1;
    } else {
        printf("  ok: JoinEntryPath rejects %d-char dir\n", PATH_MAX - 1);
    }

    /* Trailing-slash dir of length PATH_MAX-2 + 1-char name must succeed. */
    for (i = 0; i < (size_t)PATH_MAX - 3; i++) {
        dir[i] = 'b';
    }
    dir[PATH_MAX - 3] = '/';
    dir[PATH_MAX - 2] = '\0';

    if (OS_SyscheckJoinEntryPath(f_name, sizeof(f_name), dir, PATH_MAX - 2,
                                 "z") != 0) {
        printf("  FAIL: JoinEntryPath rejected trailing-slash dir of len %d\n",
               PATH_MAX - 2);
        failed = 1;
    } else if (strlen(f_name) != (size_t)PATH_MAX - 1 ||
               f_name[PATH_MAX - 2] != 'z') {
        printf("  FAIL: trailing-slash join bad result len=%zu\n", strlen(f_name));
        failed = 1;
    } else {
        printf("  ok: trailing-slash JoinEntryPath fits\n");
    }

    /* Normal join. */
    if (OS_SyscheckJoinEntryPath(f_name, sizeof(f_name), "/tmp", 4, "file") != 0) {
        printf("  FAIL: JoinEntryPath rejected /tmp/file\n");
        failed = 1;
    } else if (strcmp(f_name, "/tmp/file") != 0) {
        printf("  FAIL: JoinEntryPath got '%s'\n", f_name);
        failed = 1;
    } else {
        printf("  ok: JoinEntryPath('/tmp','file') -> '%s'\n", f_name);
    }

    if (failed) {
        printf("\nFAIL: issue_read_dir_path_overflow\n");
        return 1;
    }

    printf("\nPASS: issue_read_dir_path_overflow\n");
    return 0;
}
