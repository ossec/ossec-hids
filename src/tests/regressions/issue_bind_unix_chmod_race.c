/*
 * ANT-2026-1EAZN37N: OS_BindUnixDomain must not chmod() the socket path after
 * bind(). chmod() follows symlinks; queue dirs are group-writable and execd
 * binds as root, so a raced symlink can make an arbitrary root-owned file
 * group-writable (e.g. etc/ossec.conf).
 *
 * This regression wraps bind() so that, right after a successful AF_UNIX bind,
 * the socket path is exchanged for a symlink to a 0640 victim file. If the
 * production code still chmod()s the path, the victim becomes group-writable
 * and the test fails.
 *
 * Build (from src/, Linux):
 *   make -f tests/regressions/Makefile issue_bind_unix_chmod_race
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "shared.h"
#include "os_net/os_net.h"

static int g_race;
static char g_link[512];
static char g_victim[512];

int __real_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

int __wrap_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    int rc = __real_bind(sockfd, addr, addrlen);

    if (rc == 0 && g_race && addr && addr->sa_family == AF_UNIX) {
        const struct sockaddr_un *un = (const struct sockaddr_un *)addr;

        /* Replace the just-created socket pathname with the prepared
         * symlink. rename() is enough; the test only needs chmod/fchmodat
         * to see the symlink at path (the bound fd remains valid). */
        if (rename(g_link, un->sun_path) != 0) {
            fprintf(stderr, "FAIL: rename(link -> socket path): %s\n",
                    strerror(errno));
            exit(1);
        }
    }
    return rc;
}

static mode_t file_mode(const char *path)
{
    struct stat st;

    if (stat(path, &st) != 0) {
        fprintf(stderr, "FAIL: stat(%s): %s\n", path, strerror(errno));
        exit(1);
    }
    return st.st_mode & 0777;
}

int main(void)
{
    char tmpl[] = "/tmp/ossec-bind-chmod-XXXXXX";
    char sockpath[512];
    char *dir;
    int fd;
    FILE *fp;
    mode_t victim_mode;
    mode_t sock_mode;

    printf("=== ANT-2026-1EAZN37N: BindUnixDomain chmod symlink race ===\n");

    dir = mkdtemp(tmpl);
    if (!dir) {
        perror("mkdtemp");
        return 1;
    }

    snprintf(g_victim, sizeof(g_victim), "%s/victim", dir);
    snprintf(g_link, sizeof(g_link), "%s/link", dir);
    snprintf(sockpath, sizeof(sockpath), "%s/execq", dir);

    fp = fopen(g_victim, "w");
    if (!fp) {
        perror("fopen victim");
        return 1;
    }
    fputs("secret\n", fp);
    fclose(fp);
    if (chmod(g_victim, 0640) != 0) {
        perror("chmod victim");
        return 1;
    }

    if (symlink(g_victim, g_link) != 0) {
        perror("symlink");
        return 1;
    }

    g_race = 1;
    fd = OS_BindUnixDomain(sockpath, 0660, 2048);
    g_race = 0;

    if (fd < 0) {
        fprintf(stderr, "FAIL: OS_BindUnixDomain returned %d under race\n", fd);
        return 1;
    }
    close(fd);

    victim_mode = file_mode(g_victim);
    printf("  victim mode after bind: %04o (want 0640)\n", (unsigned)victim_mode);
    if (victim_mode != 0640) {
        printf("FAIL: path chmod followed raced symlink; victim is now %04o\n",
               (unsigned)victim_mode);
        return 1;
    }

    /* Second call without the race: socket node itself must be 0660. */
    unlink(sockpath);
    fd = OS_BindUnixDomain(sockpath, 0660, 2048);
    if (fd < 0) {
        fprintf(stderr, "FAIL: clean OS_BindUnixDomain returned %d\n", fd);
        return 1;
    }
    close(fd);
    sock_mode = file_mode(sockpath);
    printf("  socket mode: %04o (want 0660)\n", (unsigned)sock_mode);
    if (sock_mode != 0660) {
        printf("FAIL: socket created with mode %04o, want 0660\n",
               (unsigned)sock_mode);
        return 1;
    }

    printf("PASS: issue_bind_unix_chmod_race\n");
    return 0;
}
