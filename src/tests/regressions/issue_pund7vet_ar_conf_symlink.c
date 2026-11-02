/*
 * Regression for ANT-2026-PUND7VET: AR_ReadConfig must not follow a
 * symlink planted at etc/shared/ar.conf while still running as root.
 *
 * Built against a private DEFAULTDIR so the test never touches a real
 * /var/ossec install. Path 1 from the finding: replace ar.conf with a
 * symlink to a 0600 victim, then regenerate; the victim must keep its
 * contents and mode.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_pund7vet_ar_conf_symlink
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "shared.h"
#include "analysisd/active-response.h"

#ifndef PUND_DEFAULTDIR
#error "PUND_DEFAULTDIR must be defined for this regression"
#endif

#define VICTIM_MARK "SECRET-do-not-clobber\n"

static int failures;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

static int write_file(const char *path, const char *data, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    size_t n;

    if (fd < 0) {
        perror(path);
        return -1;
    }
    n = strlen(data);
    if (write(fd, data, n) != (ssize_t)n) {
        perror("write");
        close(fd);
        return -1;
    }
    if (fchmod(fd, mode) != 0) {
        perror("fchmod");
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int read_all(const char *path, char *buf, size_t buflen)
{
    int fd = open(path, O_RDONLY);
    ssize_t n;

    if (fd < 0) {
        return -1;
    }
    n = read(fd, buf, buflen - 1);
    close(fd);
    if (n < 0) {
        return -1;
    }
    buf[n] = '\0';
    return 0;
}

static void cleanup(void)
{
    char path[512];

    snprintf(path, sizeof(path), "%s/etc/shared/ar.conf", PUND_DEFAULTDIR);
    unlink(path);
    snprintf(path, sizeof(path), "%s/etc/shared", PUND_DEFAULTDIR);
    rmdir(path);
    snprintf(path, sizeof(path), "%s/etc", PUND_DEFAULTDIR);
    rmdir(path);
    snprintf(path, sizeof(path), "%s/victim", PUND_DEFAULTDIR);
    unlink(path);
    snprintf(path, sizeof(path), "%s/ossec.conf", PUND_DEFAULTDIR);
    unlink(path);
    rmdir(PUND_DEFAULTDIR);
}

int main(void)
{
    char shared[512];
    char arpath[512];
    char victim[512];
    char cfg[512];
    char buf[256];
    struct stat st;
    const char *minimal_cfg =
        "<ossec_config>\n"
        "  <command>\n"
        "    <name>host-deny</name>\n"
        "    <executable>host-deny.sh</executable>\n"
        "    <expect>srcip</expect>\n"
        "    <timeout_allowed>yes</timeout_allowed>\n"
        "  </command>\n"
        "  <active-response>\n"
        "    <command>host-deny</command>\n"
        "    <location>local</location>\n"
        "    <level>7</level>\n"
        "    <timeout>600</timeout>\n"
        "  </active-response>\n"
        "</ossec_config>\n";

    failures = 0;
    printf("=== ANT-2026-PUND7VET: ar.conf symlink not followed ===\n");
    printf("DEFAULTDIR=%s\n", PUND_DEFAULTDIR);

    cleanup();
    if (mkdir(PUND_DEFAULTDIR, 0755) != 0 && errno != EEXIST) {
        perror("mkdir DEFAULTDIR");
        return 1;
    }
    snprintf(shared, sizeof(shared), "%s/etc", PUND_DEFAULTDIR);
    if (mkdir(shared, 0755) != 0 && errno != EEXIST) {
        perror("mkdir etc");
        cleanup();
        return 1;
    }
    snprintf(shared, sizeof(shared), "%s/etc/shared", PUND_DEFAULTDIR);
    if (mkdir(shared, 0770) != 0 && errno != EEXIST) {
        perror("mkdir etc/shared");
        cleanup();
        return 1;
    }

    snprintf(victim, sizeof(victim), "%s/victim", PUND_DEFAULTDIR);
    snprintf(arpath, sizeof(arpath), "%s/etc/shared/ar.conf", PUND_DEFAULTDIR);
    snprintf(cfg, sizeof(cfg), "%s/ossec.conf", PUND_DEFAULTDIR);

    if (write_file(victim, VICTIM_MARK, 0600) != 0 ||
            write_file(cfg, minimal_cfg, 0644) != 0) {
        cleanup();
        return 1;
    }
    if (symlink(victim, arpath) != 0) {
        perror("symlink ar.conf -> victim");
        cleanup();
        return 1;
    }
    printf("planted %s -> %s\n", arpath, victim);

    AR_Init();
    /* Pass the process egid so the exclusive-create path can fchown without
     * needing the real "ossec" group (and without getgrnam(USER)). */
    if (AR_ReadConfig(cfg, getegid()) < 0) {
        printf("  FAIL: AR_ReadConfig returned error\n");
        failures++;
    } else {
        printf("  ok:   AR_ReadConfig completed\n");
    }

    /* Victim must be untouched (path 1: symlink at ar.conf must not be followed). */
    CHECK(stat(victim, &st) == 0, "victim file still exists");
    if (stat(victim, &st) == 0) {
        CHECK((st.st_mode & 0777) == 0600, "victim mode still 0600");
    }
    CHECK(read_all(victim, buf, sizeof(buf)) == 0, "victim readable");
    CHECK(strcmp(buf, VICTIM_MARK) == 0, "victim contents unchanged");

    CHECK(lstat(arpath, &st) == 0, "ar.conf path exists after rewrite");
    if (lstat(arpath, &st) == 0) {
        CHECK(S_ISLNK(st.st_mode) == 0, "ar.conf is no longer a symlink");
        CHECK(S_ISREG(st.st_mode) != 0, "ar.conf is a regular file");
        CHECK((st.st_mode & 0777) == 0440, "ar.conf mode is 0440");
        CHECK(st.st_gid == getegid(), "ar.conf group is the passed gid");
        if (S_ISREG(st.st_mode) && read_all(arpath, buf, sizeof(buf)) == 0) {
            CHECK(strstr(buf, "restart-ossec0") != NULL,
                  "ar.conf contains restart-ossec0");
            CHECK(strstr(buf, "host-deny") != NULL,
                  "ar.conf contains host-deny from config");
        }
    }

    cleanup();

    if (failures) {
        printf("\nFAIL: issue_pund7vet_ar_conf_symlink (%d)\n", failures);
        return 1;
    }
    printf("\nPASS: issue_pund7vet_ar_conf_symlink\n");
    return 0;
}
