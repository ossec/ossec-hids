/*
 * ANT-2026-FZNF7ML7: report_changes temp names must not embed content hashes.
 *
 * Pre-fix, seechanges_addfile() named its tmp symlinks after the SHA-256 of
 * the old and new snapshots and passed those paths to system("diff ...").
 * Any local user could read the unsalted content hash from /proc cmdline.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_fznf7ml7_diff_hash_leak
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shared.h"
#include "syscheckd/syscheck.h"
#include "os_crypto/sha256/sha256_op.h"

syscheck_config syscheck;

static int failures;
static char captured_cmd[OS_MAXSTR + 1];
static int system_calls;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

static int write_bytes(const char *path, const char *data)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (fd < 0) {
        return (-1);
    }
    if (write(fd, data, strlen(data)) != (ssize_t)strlen(data)) {
        close(fd);
        return (-1);
    }
    close(fd);
    return (0);
}

/* Capture the diff command line that would be visible in /proc. */
int system(const char *command)
{
    int (*real_system)(const char *) = dlsym(RTLD_NEXT, "system");

    system_calls++;
    if (command) {
        snprintf(captured_cmd, sizeof(captured_cmd), "%s", command);
    }
    if (!real_system) {
        return (-1);
    }
    return (real_system(command));
}

static int source_has(const char *rel, const char *needle)
{
    char path[512];
    FILE *fp = NULL;
    long len;
    char *buf;
    int found = 0;
    const char *prefixes[] = { "", "src/", "../", NULL };
    int i;

    for (i = 0; prefixes[i] != NULL; i++) {
        snprintf(path, sizeof(path), "%s%s", prefixes[i], rel);
        fp = fopen(path, "rb");
        if (fp) {
            break;
        }
    }
    if (!fp) {
        return (0);
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return (0);
    }
    len = ftell(fp);
    if (len < 0 || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return (0);
    }
    buf = malloc((size_t)len + 1);
    if (!buf) {
        fclose(fp);
        return (0);
    }
    if (fread(buf, 1, (size_t)len, fp) != (size_t)len) {
        free(buf);
        fclose(fp);
        return (0);
    }
    buf[len] = '\0';
    fclose(fp);
    found = (strstr(buf, needle) != NULL);
    free(buf);
    return (found);
}

int main(void)
{
    char tmpdir[] = "/tmp/ossec-fznf7ml7-XXXXXX";
    char file[PATH_MAX];
    char *diff;
    os_sha256 hash_old;
    os_sha256 hash_new;
    char pid_old[64];
    char pid_new[64];

    printf("ANT-2026-FZNF7ML7 report_changes hash leak\n");

    /* Source checks before chdir into the throwaway tree. */
    CHECK(source_has("syscheckd/seechanges.c",
                     "syscheck-changes-%d-old"),
          "seechanges.c builds pid-based -old names");
    CHECK(!source_has("syscheckd/seechanges.c",
                      "syscheck-changes-%s-%d"),
          "seechanges.c no longer embeds hashes in tmp names");

    if (!mkdtemp(tmpdir)) {
        perror("mkdtemp");
        return (1);
    }
    if (chdir(tmpdir) != 0) {
        perror("chdir");
        return (1);
    }
    if (mkdir("queue", 0755) != 0 || mkdir("queue/diff", 0755) != 0 ||
            mkdir("queue/diff/local", 0755) != 0 || mkdir("tmp", 0755) != 0) {
        perror("mkdir");
        return (1);
    }

    snprintf(file, sizeof(file), "%s/secret.conf", tmpdir);
    memset(&syscheck, 0, sizeof(syscheck));
    syscheck.diff_max_size = 0;

    CHECK(write_bytes(file, "pin = 000000\n") == 0, "wrote initial secret file");
    diff = seechanges_addfile(file);
    free(diff);
    CHECK(system_calls == 0, "first snapshot does not run diff");

    CHECK(OS_SHA256_File(file, hash_old, OS_BINARY) == 0, "hashed old content");
    CHECK(write_bytes(file, "pin = 132170\n") == 0, "changed secret file");
    CHECK(OS_SHA256_File(file, hash_new, OS_BINARY) == 0, "hashed new content");

    captured_cmd[0] = '\0';
    system_calls = 0;
    diff = seechanges_addfile(file);
    CHECK(diff != NULL, "content change produces a diff");
    free(diff);
    CHECK(system_calls == 1, "diff was invoked once");
    CHECK(captured_cmd[0] != '\0', "captured the diff command line");

    CHECK(strstr(captured_cmd, hash_old) == NULL,
          "old content SHA-256 is not on the diff command line");
    CHECK(strstr(captured_cmd, hash_new) == NULL,
          "new content SHA-256 is not on the diff command line");

    snprintf(pid_old, sizeof(pid_old), "syscheck-changes-%d-old", (int)getpid());
    snprintf(pid_new, sizeof(pid_new), "syscheck-changes-%d-new", (int)getpid());
    CHECK(strstr(captured_cmd, pid_old) != NULL,
          "tmp link uses pid-old name");
    CHECK(strstr(captured_cmd, pid_new) != NULL,
          "tmp link uses pid-new name");

    if (failures) {
        printf("%d FAILURE(S)\n", failures);
        return (1);
    }
    printf("ALL OK\n");
    return (0);
}
