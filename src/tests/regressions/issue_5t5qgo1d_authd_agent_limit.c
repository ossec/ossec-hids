/*
 * ANT-2026-5T5QGO1D: OS_AddNewAgent must refuse enrollment once client.keys
 * already holds MAX_AGENTS - 3 loadable entries. OS_ReadKeys() ErrorExits at
 * MAX_AGENTS - 2, so writing that last slot makes remoted unstartable.
 *
 * Built with -DMAX_AGENTS=8 so the ceiling is 5 retained entries (not 2045).
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_5t5qgo1d_authd_agent_limit
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#include "shared.h"
#include "addagent/manage_agents.h"

/* Produced by -Wl,--wrap=isChroot — force AUTH_FILE path like authd chroot. */
int __wrap_isChroot(void)
{
    return (1);
}

int restart_necessary;

#ifndef MAX_AGENTS
#define MAX_AGENTS 8
#endif

#define KEYS_NAME "client.keys"
#define FAKE_KEY "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

static int write_keys(int loadable, int with_noise)
{
    FILE *fp;
    int i;

    fp = fopen(KEYS_NAME, "w");
    if (!fp) {
        fprintf(stderr, "fopen %s: %s\n", KEYS_NAME, strerror(errno));
        return (1);
    }

    if (with_noise) {
        fprintf(fp, "# comment line\n");
        fprintf(fp, "  leading-space skipped\n");
        /* Removed entry — OS_ReadKeys / CountAgents must not count it. */
        fprintf(fp, "9000 #removed any %s\n", FAKE_KEY);
        /* Incomplete records OS_ReadKeys skips — must not consume capacity. */
        fprintf(fp, "1023 host-only\n");
        fprintf(fp, "1022 host-ip-only any\n");
    }

    for (i = 0; i < loadable; i++) {
        /* IDs in the authd bitmap range so MapIDToBitArray marks them. */
        fprintf(fp, "%d host-%d any %s\n", AUTHD_FIRST_ID + i, i, FAKE_KEY);
    }

    fclose(fp);
    return (0);
}

static int count_file_lines(void)
{
    FILE *fp;
    char buf[512];
    int n = 0;

    fp = fopen(KEYS_NAME, "r");
    if (!fp) {
        return (-1);
    }
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        n++;
    }
    fclose(fp);
    return (n);
}

int main(void)
{
    char *added;
    int ceiling = MAX_AGENTS - 3;
    int before_lines;
    int after_lines;
    int failed = 0;
    char tmpdir[] = "/tmp/ossec-5t5qgo1d-XXXXXX";

    printf("=== ANT-2026-5T5QGO1D: authd agent limit vs OS_ReadKeys ===\n");
    printf("  MAX_AGENTS=%d, refuse at >= %d loadable entries\n",
           MAX_AGENTS, ceiling);

    if (!mkdtemp(tmpdir)) {
        fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
        return (1);
    }
    if (chdir(tmpdir) != 0) {
        fprintf(stderr, "chdir %s: %s\n", tmpdir, strerror(errno));
        return (1);
    }

    srandom_init();

    /* Below the ceiling: enrollment must succeed. */
    if (write_keys(ceiling - 1, 1) != 0) {
        return (1);
    }
    before_lines = count_file_lines();
    added = OS_AddNewAgent("under-limit", "any", NULL);
    if (!added) {
        printf("  FAIL: enrollment refused with %d loadable entries\n",
               ceiling - 1);
        failed = 1;
    } else {
        printf("  ok: enrollment allowed with %d loadable entries\n",
               ceiling - 1);
        free(added);
    }

    /* At the ceiling: one more would make OS_ReadKeys ErrorExit. */
    if (write_keys(ceiling, 1) != 0) {
        return (1);
    }
    before_lines = count_file_lines();
    added = OS_AddNewAgent("at-limit", "any", NULL);
    after_lines = count_file_lines();

    if (added != NULL) {
        printf("  FAIL: enrollment accepted at %d loadable entries "
               "(wrote past OS_ReadKeys fatal threshold)\n", ceiling);
        free(added);
        failed = 1;
    } else if (after_lines != before_lines) {
        printf("  FAIL: client.keys grew despite refused enrollment "
               "(%d -> %d lines)\n", before_lines, after_lines);
        failed = 1;
    } else {
        printf("  ok: enrollment refused at %d loadable entries "
               "(file unchanged)\n", ceiling);
    }

    /* Empty key after third space still loads in OS_ReadKeys — counts. */
    if (write_keys(ceiling - 1, 0) != 0) {
        return (1);
    }
    {
        FILE *fp = fopen(KEYS_NAME, "a");
        if (!fp) {
            fprintf(stderr, "fopen append: %s\n", strerror(errno));
            return (1);
        }
        fprintf(fp, "1010 empty-key any \n");
        fclose(fp);
    }
    before_lines = count_file_lines();
    added = OS_AddNewAgent("empty-key-ceiling", "any", NULL);
    after_lines = count_file_lines();
    if (added != NULL) {
        printf("  FAIL: empty-key line did not consume a loadable slot\n");
        free(added);
        failed = 1;
    } else if (after_lines != before_lines) {
        printf("  FAIL: file grew after empty-key ceiling refusal\n");
        failed = 1;
    } else {
        printf("  ok: empty-key line counts toward enrollment ceiling\n");
    }

    unlink(KEYS_NAME);
    chdir("/");
    rmdir(tmpdir);

    if (failed) {
        printf("\nFAIL: issue_5t5qgo1d_authd_agent_limit\n");
        return (1);
    }

    printf("\nPASS: issue_5t5qgo1d_authd_agent_limit\n");
    return (0);
}
