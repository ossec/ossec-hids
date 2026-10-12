/*
 * Regression: UnmergeFiles must refuse merged entry names with '..'.
 *
 * A crafted merged.mg (from a compromised manager) previously could write
 * outside the shared directory via names like ../../tmp/evil.
 *
 * Build (from src/ after shared.a exists):
 *   make -f tests/regressions/Makefile unmerge_path_traversal
 *   ./unmerge_path_traversal
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#include "shared.h"
#include "file_op.h"

static int write_merged_entry(FILE *fp, const char *name, const char *data)
{
    long n = (long)strlen(data);

    if (fprintf(fp, "!%ld %s\n", n, name) < 0) {
        return -1;
    }
    if (fwrite(data, 1, (size_t)n, fp) != (size_t)n) {
        return -1;
    }
    return 0;
}

static int path_exists(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0);
}

int main(void)
{
    char tmpl[] = "/tmp/ossec-unmerge-XXXXXX";
    char *root;
    char outdir[512];
    char outside[512];
    char merged[512];
    char good[512];
    char escaped[512];
    FILE *fp;
    int rc;

    root = mkdtemp(tmpl);
    if (!root) {
        perror("mkdtemp");
        return 1;
    }

    snprintf(outdir, sizeof(outdir), "%s/shared", root);
    snprintf(outside, sizeof(outside), "%s/outside", root);
    snprintf(merged, sizeof(merged), "%s/merged.mg", root);
    snprintf(good, sizeof(good), "%s/agent.conf", outdir);
    snprintf(escaped, sizeof(escaped), "%s/pwned", outside);

    if (mkdir(outdir, 0700) != 0 || mkdir(outside, 0700) != 0) {
        perror("mkdir");
        return 1;
    }

    fp = fopen(merged, "w");
    if (!fp) {
        perror("fopen merged");
        return 1;
    }

    /* Legitimate entry */
    if (write_merged_entry(fp, "agent.conf", "ok\n") != 0) {
        fclose(fp);
        fprintf(stderr, "ERROR: failed to write good entry\n");
        return 1;
    }

    /* Traversal toward sibling outside/ directory */
    {
        char trav[256];
        snprintf(trav, sizeof(trav), "../outside/pwned");
        if (write_merged_entry(fp, trav, "owned\n") != 0) {
            fclose(fp);
            fprintf(stderr, "ERROR: failed to write traversal entry\n");
            return 1;
        }
    }

    fclose(fp);

    rc = UnmergeFiles(merged, outdir);
    if (rc != 0) {
        fprintf(stderr, "ERROR: UnmergeFiles should fail (ret=0) on traversal, got %d\n",
                rc);
        return 1;
    }

    if (!path_exists(good)) {
        fprintf(stderr, "ERROR: expected safe file '%s' to be written\n", good);
        return 1;
    }

    if (path_exists(escaped)) {
        fprintf(stderr, "ERROR: traversal wrote outside shared: '%s'\n", escaped);
        return 1;
    }

    printf("OK: UnmergeFiles refused path traversal and kept safe entry\n");
    return 0;
}
