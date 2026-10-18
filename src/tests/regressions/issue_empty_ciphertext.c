/*
 * Regression: empty / oversized ciphertext in ReadSecMSG
 *
 * ANT-2026-2L4ECQCA / CWE-305
 *
 * HandleSecure() can pass buffer_size 0 ("!id!:" with no body) or a wrapped
 * UINT_MAX ("!id!" with nothing after the prefix). With size 0, OS_BF_Str()
 * writes nothing and ReadSecMSG() parsed the previous datagram's cleartext
 * as the named agent. With a wrapped size, Blowfish decrypts past the stack
 * buffer and remoted SIGSEGVs.
 *
 * ReadSecMSG() must refuse buffer_size == 0 or > OS_MAXSTR with ENCSIZE_ERROR
 * (1405) before decrypting, and clear cleartext[0] so format dispatch cannot
 * see stale bytes.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_empty_ciphertext
 *
 * Run:
 *   ./issue_empty_ciphertext
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "shared.h"
#include "headers/sec.h"
#include "os_crypto/blowfish/bf_op.h"

const char *__local_name = "empty-ciphertext-test";

void debug1(const char *msg, ...) { (void)msg; }
void debug2(const char *msg, ...) { (void)msg; }
void ErrorExit(const char *msg, ...) { (void)msg; exit(1); }
int getDefine_Int(const char *high, const char *low, int min, int max)
{
    (void)high; (void)low; (void)min; (void)max;
    return 0;
}
void os_mutex_lock(pthread_mutex_t *mutex) { (void)mutex; }
void os_mutex_unlock(pthread_mutex_t *mutex) { (void)mutex; }
unsigned long int os_zlib_compress(const char *src, char *dst,
                                   unsigned long int src_size,
                                   unsigned long int dst_size)
{
    (void)src; (void)dst; (void)src_size; (void)dst_size;
    return 0;
}
unsigned long int os_zlib_uncompress(const char *src, char *dst,
                                     unsigned long int src_size,
                                     unsigned long int dst_size)
{
    (void)src; (void)dst; (void)src_size; (void)dst_size;
    return 0;
}
int randombytes_try(void *ptr, size_t length)
{
    (void)ptr; (void)length;
    return 0;
}
int OS_AES_Str(const char *input, char *output, const char *charkey,
               long size, short int action)
{
    (void)input; (void)output; (void)charkey; (void)size; (void)action;
    return 0;
}

static int failures;
static const char *last_error;

void merror(const char *msg, ...)
{
    last_error = msg;
}

static int expect_encsize(keystore *keys, unsigned int buffer_size,
                          const char *label)
{
    char msg[8];
    char cleartext[OS_MAXSTR + 1];
    size_t final_size = 0;
    char *out;

    /* Blowfish framing with an empty (or ignored) body. cleartext holds a
     * non-'!'/':' stale byte so an unfixed build takes the ENCKEY fallthrough
     * instead of the wrapped uncompress path (which is unsafe to exercise). */
    msg[0] = ':';
    msg[1] = '\0';
    memset(cleartext, 'Z', sizeof(cleartext));
    cleartext[sizeof(cleartext) - 1] = '\0';
    last_error = NULL;

    out = ReadSecMSG(keys, msg, cleartext, 0, buffer_size, &final_size,
                     "127.0.0.1");
    if (out != NULL || last_error == NULL ||
            strstr(last_error, "(1405)") == NULL) {
        fprintf(stderr,
                "FAIL: %s size=%u did not return ENCSIZE_ERROR (1405); "
                "out=%p error=%s\n",
                label, buffer_size, (void *)out,
                last_error ? last_error : "(none)");
        failures++;
        return -1;
    }

    printf("ok: %s size=%u rejected with 1405\n", label, buffer_size);
    return 0;
}

int main(void)
{
    keystore keys;
    keyentry entry;
    keyentry *entries[1];
    os_ip ip;
    const char *key = "empty-ciphertext-test-key";

    printf("=== ANT-2026-2L4ECQCA empty ciphertext regression ===\n");

    memset(&keys, 0, sizeof(keys));
    memset(&entry, 0, sizeof(entry));
    memset(&ip, 0, sizeof(ip));
    ip.ip = "any";
    entry.id = "001";
    entry.name = "empty-ciphertext";
    entry.key = (char *)key;
    entry.ip = &ip;
    entry.crypto_method = W_METH_BLOWFISH;
    entries[0] = &entry;
    keys.keyentries = entries;
    keys.keysize = 1;

    /* Length-0 body: "!001!:" after prefix strip. An unfixed build reaches
     * decrypt and returns 1404; do not probe wrapped sizes until this
     * rejects — UINT_MAX would Blowfish-decrypt into a stack smash. */
    if (expect_encsize(&keys, 0, "empty body") != 0) {
        fprintf(stderr, "FAIL: issue_empty_ciphertext (%d)\n", failures);
        return 1;
    }

    /* Wrapped / absurd lengths from "!001!" (recv_b - 1 underflows). */
    expect_encsize(&keys, OS_MAXSTR + 1, "above OS_MAXSTR");
    expect_encsize(&keys, UINT_MAX, "UINT_MAX wrap");

    if (failures) {
        fprintf(stderr, "FAIL: issue_empty_ciphertext (%d)\n", failures);
        return 1;
    }

    printf("PASS: issue_empty_ciphertext\n");
    return 0;
}
