#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "sha256_op.h"
#include "headers/defs.h"
#include "headers/file_op.h"

/* Local SHA-256 implementation */
#include "sha256.h"

static int OS_SHA256_File_fp(FILE *fp, os_sha256 output, size_t max_size)
{
    SHA256_CTX c;
    unsigned char buf[2048 + 2];
    unsigned char md[32];
    size_t n;
    size_t total = 0;

    memset(output, 0, 65);
    buf[2049] = '\0';

    os_SHA256_Init(&c);
    while ((n = fread(buf, 1, 2048, fp)) > 0) {
        if (max_size > 0) {
            total += n;
            if (total > max_size) {
                output[0] = '\0';
                errno = EFBIG;
                return (-1);
            }
        }
        buf[n] = '\0';
        os_SHA256_Update(&c, buf, n);
    }

    os_SHA256_Final(md, &c);

    for (n = 0; n < 32; n++) {
        snprintf(output + (n * 2), 3, "%02x", md[n]);
    }

    return (0);
}

int OS_SHA256_File_max(const char *fname, os_sha256 output, int mode,
                       size_t max_size)
{
    FILE *fp;
    int rc;

    /* User-controlled paths (report_changes / FIM): refuse FIFO/device
     * without blocking (ANT-2026-KZAJSOET). Follows symlinks. */
#ifndef WIN32
    (void)mode;
    fp = fopen_regular(fname);
#else
    fp = fopen(fname, mode == OS_BINARY ? "rb" : "r");
#endif
    if (!fp) {
        return (-1);
    }

    rc = OS_SHA256_File_fp(fp, output, max_size);
    fclose(fp);
    return (rc);
}

int OS_SHA256_File(const char *fname, os_sha256 output, int mode)
{
    return (OS_SHA256_File_max(fname, output, mode, 0));
}

#ifndef WIN32
int OS_SHA256_File_nofollow(const char *fname, os_sha256 output, int mode)
{
    return (OS_SHA256_File_nofollow_max(fname, output, mode, 0));
}

int OS_SHA256_File_nofollow_max(const char *fname, os_sha256 output, int mode,
                                size_t max_size)
{
    FILE *fp;
    int rc;

    (void)mode;
    fp = fopen_regular_nofollow(fname);
    if (!fp) {
        return (-1);
    }

    rc = OS_SHA256_File_fp(fp, output, max_size);
    fclose(fp);
    return (rc);
}
#endif
