#include <stdio.h>
#include <string.h>

#include "sha256_op.h"
#include "headers/defs.h"

/* Local SHA-256 implementation */
#include "sha256.h"

int OS_SHA256_File(const char *fname, os_sha256 output, int mode)
{
    SHA256_CTX c;
    FILE *fp;
    unsigned char buf[2048 + 2];
    unsigned char md[32];
    size_t n;

    memset(output, 0, 65);
    buf[2049] = '\0';

    fp = fopen(fname, mode == OS_BINARY ? "rb" : "r");
    if (!fp) {
        return (-1);
    }

    os_SHA256_Init(&c);
    while ((n = fread(buf, 1, 2048, fp)) > 0) {
        buf[n] = '\0';
        os_SHA256_Update(&c, buf, n);
    }

    os_SHA256_Final(md, &c);

    for (n = 0; n < 32; n++) {
        snprintf(output + (n * 2), 3, "%02x", md[n]);
    }

    fclose(fp);

    return (0);
}
