/* A secure message shorter than the 32-byte checksum used to wrap the
 * hash length and read past the decrypted buffer. CheckSum() must reject
 * it and leave the process running.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "headers/sec.h"
#include "os_crypto/blowfish/bf_op.h"

/* Symbols ReadSecMSG references that this case does not exercise. */
const char *__local_name = "checksum-test";

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

static int try_message(keystore *keys, const char *key, unsigned int plain_len, char marker)
{
    char plain[128];
    char msg[160];
    char cleartext[OS_MAXSTR + 1];
    size_t final_size = 0;
    char *out;

    if (plain_len < 1 || plain_len >= sizeof(plain)) {
        fprintf(stderr, "FAIL: bad length %u\n", plain_len);
        failures++;
        return -1;
    }

    memset(plain, 'A', plain_len);
    plain[0] = marker;
    msg[0] = ':';
    if (!OS_BF_Str(plain, msg + 1, key, (long)plain_len, OS_ENCRYPT)) {
        fprintf(stderr, "FAIL: length %u encrypt failed\n", plain_len);
        failures++;
        return -1;
    }

    memset(cleartext, 0, sizeof(cleartext));
    last_error = NULL;
    out = ReadSecMSG(keys, msg, cleartext, 0, plain_len, &final_size, "127.0.0.1");
    /* 1406 is the checksum mismatch. A decrypt or format failure uses another code. */
    if (out != NULL || last_error == NULL || strstr(last_error, "(1406)") == NULL) {
        fprintf(stderr, "FAIL: length %u did not fail the checksum (error: %s)\n",
                plain_len, last_error ? last_error : "(none)");
        failures++;
        return -1;
    }

    printf("ok: length %u rejected\n", plain_len);
    return 0;
}

int main(void)
{
    keystore keys;
    keyentry entry;
    keyentry *entries[1];
    os_ip ip;
    const char *key = "checksum-test-key";

    memset(&keys, 0, sizeof(keys));
    memset(&entry, 0, sizeof(entry));
    memset(&ip, 0, sizeof(ip));
    ip.ip = "any";
    entry.id = "001";
    entry.name = "checksum-test";
    entry.key = (char *)key;
    entry.ip = &ip;
    entry.crypto_method = W_METH_BLOWFISH;
    entries[0] = &entry;
    keys.keyentries = entries;
    keys.keysize = 1;

    /* Below, equal to, and just above the digest size. */
    try_message(&keys, key, 8, ':');
    try_message(&keys, key, 32, ':');
    try_message(&keys, key, 48, ':');

    if (failures) {
        fprintf(stderr, "FAIL: checksum_short_message (%d)\n", failures);
        return 1;
    }

    printf("ok\n");
    return 0;
}
