#include <stdio.h>
#include <string.h>

#include "sha256_op.h"
#include "headers/defs.h"
#include "headers/file_op.h"

/* Local SHA-256 implementation */
#include "sha256.h"

static int OS_SHA256_File_fp(FILE *fp, os_sha256 output)
{
    SHA256_CTX c;
    unsigned char buf[2048 + 2];
    unsigned char md[32];
    size_t n;

    memset(output, 0, 65);
    buf[2049] = '\0';

    os_SHA256_Init(&c);
    while ((n = fread(buf, 1, 2048, fp)) > 0) {
        buf[n] = '\0';
        os_SHA256_Update(&c, buf, n);
    }

    os_SHA256_Final(md, &c);

    for (n = 0; n < 32; n++) {
        snprintf(output + (n * 2), 3, "%02x", md[n]);
    }

    return (0);
}

int OS_SHA256_File(const char *fname, os_sha256 output, int mode)
{
    FILE *fp;

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

    OS_SHA256_File_fp(fp, output);
    fclose(fp);
    return (0);
}

#ifndef WIN32
int OS_SHA256_File_nofollow(const char *fname, os_sha256 output, int mode)
{
    FILE *fp;

    (void)mode;
    fp = fopen_regular_nofollow(fname);
    if (!fp) {
        return (-1);
    }

    OS_SHA256_File_fp(fp, output);
    fclose(fp);
    return (0);
}
#endif
