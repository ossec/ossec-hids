/*
 * ANT-2026-B5Y9PIU1: manager/local rootcheck must refuse policy files that
 * the ossec group could have written (non-root owner, group/other-writable,
 * or a symlink), so a replaced rootkit_trojans/system_audit cannot turn
 * root ossec-syscheckd into an oracle over root-only files.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_b5y9piu1_policy_owner
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shared.h"
#include "rootcheck.h"

static char workdir[] = "/tmp/ossec-b5y9piu1-XXXXXX";

static void rm_tree(const char *path)
{
    char cmd[PATH_MAX + 64];

    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    (void)system(cmd);
}

static int write_file(const char *path, const char *body)
{
    FILE *fp = fopen(path, "w");

    if (!fp) {
        return (-1);
    }
    fputs(body, fp);
    fclose(fp);
    return (0);
}

static int check_stat_matrix(void)
{
    struct stat st;
    int failed = 0;

    memset(&st, 0, sizeof(st));
    st.st_mode = S_IFREG | 0640;
    st.st_uid = 0;
    if (!rk_policy_stat_ok(&st)) {
        printf("  FAIL: root-owned 0640 should be accepted\n");
        failed = 1;
    } else {
        printf("  ok: root-owned 0640 accepted by rk_policy_stat_ok\n");
    }

    st.st_mode = S_IFREG | 0660;
    st.st_uid = 0;
    if (rk_policy_stat_ok(&st)) {
        printf("  FAIL: root-owned 0660 should be refused\n");
        failed = 1;
    } else {
        printf("  ok: root-owned 0660 refused by rk_policy_stat_ok\n");
    }

    st.st_mode = S_IFREG | 0640;
    st.st_uid = 1000;
    if (rk_policy_stat_ok(&st)) {
        printf("  FAIL: non-root 0640 should be refused\n");
        failed = 1;
    } else {
        printf("  ok: non-root 0640 refused by rk_policy_stat_ok\n");
    }

    st.st_mode = S_IFREG | 0644;
    st.st_uid = 0;
    /* 0644 is fine (not group/other writable) */
    if (!rk_policy_stat_ok(&st)) {
        printf("  FAIL: root-owned 0644 should be accepted\n");
        failed = 1;
    } else {
        printf("  ok: root-owned 0644 accepted by rk_policy_stat_ok\n");
    }

    st.st_mode = S_IFDIR | 0755;
    st.st_uid = 0;
    if (rk_policy_stat_ok(&st)) {
        printf("  FAIL: directory should be refused\n");
        failed = 1;
    } else {
        printf("  ok: directory refused by rk_policy_stat_ok\n");
    }

    return (failed);
}

int main(void)
{
    char path[sizeof(workdir) + 32];
    char linkpath[sizeof(workdir) + 32];
    char target[sizeof(workdir) + 32];
    FILE *fp;
    int failed = 0;
    uid_t me = geteuid();

    printf("=== ANT-2026-B5Y9PIU1: rootcheck policy ownership ===\n");

    failed |= check_stat_matrix();

    if (!mkdtemp(workdir)) {
        perror("mkdtemp");
        return (1);
    }

    snprintf(path, sizeof(path), "%s/policy.txt", workdir);
    if (write_file(path, "# test policy\n") != 0 || chmod(path, 0640) != 0) {
        perror(path);
        rm_tree(workdir);
        return (1);
    }

    /* Non-root owner must be refused on the open path (manager build). */
    fp = rk_fopen_policy(path);
    if (me != 0) {
        if (fp != NULL) {
            printf("  FAIL: opened non-root-owned policy\n");
            fclose(fp);
            failed = 1;
        } else {
            printf("  ok: non-root-owned policy refused by open path\n");
        }
    } else if (chown(path, 65534, 65534) == 0) {
        fp = rk_fopen_policy(path);
        if (fp != NULL) {
            printf("  FAIL: opened nobody-owned policy as root\n");
            fclose(fp);
            failed = 1;
        } else {
            printf("  ok: non-root-owned policy refused by open path\n");
        }
        (void)chown(path, 0, 0);
    } else {
        printf("  ok: skip nobody-chown (errno=%d)\n", errno);
    }

    /* Symlink must not be followed. */
    snprintf(target, sizeof(target), "%s/target.txt", workdir);
    snprintf(linkpath, sizeof(linkpath), "%s/policy.link", workdir);
    if (write_file(target, "# target\n") != 0) {
        perror(target);
        failed = 1;
    } else {
        if (me == 0) {
            (void)chown(target, 0, 0);
            (void)chmod(target, 0640);
        }
        unlink(linkpath);
        if (symlink(target, linkpath) != 0) {
            perror("symlink");
            failed = 1;
        } else {
            fp = rk_fopen_policy(linkpath);
            if (fp != NULL) {
                printf("  FAIL: followed policy symlink\n");
                fclose(fp);
                failed = 1;
            } else {
                printf("  ok: policy symlink refused by open path\n");
            }
        }
    }

    /* Full open-path accept when we can create root 0640. */
    if (me == 0) {
        if (chmod(path, 0640) != 0 || chown(path, 0, 0) != 0) {
            perror("restore root 0640");
            failed = 1;
        } else {
            fp = rk_fopen_policy(path);
            if (fp == NULL) {
                printf("  FAIL: refused valid root-owned 0640 policy\n");
                failed = 1;
            } else {
                char buf[64];

                if (fgets(buf, sizeof(buf), fp) == NULL ||
                        strstr(buf, "test policy") == NULL) {
                    printf("  FAIL: could not read valid policy contents\n");
                    failed = 1;
                } else {
                    printf("  ok: root-owned 0640 policy accepted by open path\n");
                }
                fclose(fp);
            }

            if (chmod(path, 0660) != 0) {
                perror("chmod 0660");
                failed = 1;
            } else {
                fp = rk_fopen_policy(path);
                if (fp != NULL) {
                    printf("  FAIL: opened root-owned 0660 policy\n");
                    fclose(fp);
                    failed = 1;
                } else {
                    printf("  ok: root-owned 0660 policy refused by open path\n");
                }
            }
        }
    } else {
        printf("  ok: skip root open-path accept/0660 (uid=%d); "
               "covered by rk_policy_stat_ok\n", (int)me);
    }

    rm_tree(workdir);

    if (failed) {
        printf("\nFAIL: issue_b5y9piu1_policy_owner\n");
        return (1);
    }
    printf("\nPASS: issue_b5y9piu1_policy_owner\n");
    return (0);
}
