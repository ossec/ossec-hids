/*
 * ANT-2026-739QMECR: ReadSecMSG inflate must honor remaining buffer room.
 *
 * HandleSecure advances past "!<id>!" before calling ReadSecMSG, which then
 * steps over "#AES:" and inflates back into that advanced pointer. Using a
 * flat OS_MAXSTR limit overstates the room left in char buffer[OS_MAXSTR+1]
 * and can write past the end of the stack array.
 *
 * This regression stubs decrypt/uncompress and asserts the dst_size passed to
 * os_zlib_uncompress equals buffer_max minus the prefix bytes stepped over
 * (and one for the NUL), not OS_MAXSTR.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_739qmecr_readsecmsg_uncompress
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "headers/sec.h"

const char *__local_name = "issue-739qmecr-readsecmsg-uncompress";

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

static unsigned long last_uncompress_dst;
static int uncompress_calls;

unsigned long int os_zlib_uncompress(const char *src, char *dst,
                                     unsigned long int src_size,
                                     unsigned long int dst_size)
{
    (void)src; (void)dst; (void)src_size;
    last_uncompress_dst = dst_size;
    uncompress_calls++;
    /* Fail inflate: we only care that the limit was correct. */
    return 0;
}

int randombytes_try(void *ptr, size_t length)
{
    (void)ptr; (void)length;
    return 0;
}

int OS_MD5_Bytes(const char *buf, ssize_t size, char *hex)
{
    (void)buf; (void)size;
    if (hex) {
        memset(hex, '0', 32);
        hex[32] = '\0';
    }
    return 1;
}

int OS_AES_Str(const char *input, char *output, const char *charkey,
               long size, short int action)
{
    (void)input; (void)output; (void)charkey; (void)size; (void)action;
    return 0;
}

/* Blowfish path: produce a compressed-looking cleartext so ReadSecMSG
 * reaches os_zlib_uncompress. */
int OS_BF_Str(const char *input, char *output, const char *charkey,
              long size, short int action)
{
    (void)input; (void)charkey; (void)size; (void)action;
    output[0] = '!';
    output[1] = 'Z';
    output[2] = '\0';
    return 1;
}

void merror(const char *msg, ...) { (void)msg; }

static int failures;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

static void test_uncompress_limit_respects_buffer_max(void)
{
    keystore keys;
    keyentry entry;
    keyentry *entries[1];
    os_ip ip;
    char msg[64];
    char cleartext[OS_MAXSTR + 1];
    size_t final_size = 0;
    /* Room left after HandleSecure's "!001!" (5 bytes) in buffer[OS_MAXSTR+1]. */
    const size_t buffer_max = (OS_MAXSTR + 1) - 5;
    /* Blowfish framing: ':' then ciphertext (stubbed). */
    const unsigned int body_len = 8;

    memset(&keys, 0, sizeof(keys));
    memset(&entry, 0, sizeof(entry));
    memset(&ip, 0, sizeof(ip));
    entry.id = (char *)"001";
    entry.name = (char *)"agent1";
    entry.key = (char *)"test-key-for-739qmecr";
    entry.ip = &ip;
    ip.ip = (char *)"any";
    entries[0] = &entry;
    keys.keyentries = entries;
    keys.keysize = 1;

    msg[0] = ':';
    memset(msg + 1, 'x', body_len);
    msg[1 + body_len] = '\0';

    last_uncompress_dst = 0;
    uncompress_calls = 0;
    (void)ReadSecMSG(&keys, msg, buffer_max, cleartext, 0, body_len, &final_size,
                     "127.0.0.1");

    CHECK(uncompress_calls == 1, "compressed path reached os_zlib_uncompress");
    /* After skipping one ':' byte, inflate limit is (buffer_max - 1) - 1 for NUL. */
    CHECK(last_uncompress_dst == buffer_max - 2,
          "uncompress dst_size is remaining room minus NUL, not OS_MAXSTR");
    CHECK(last_uncompress_dst != (unsigned long)OS_MAXSTR,
          "uncompress must not use a flat OS_MAXSTR limit");
}

int main(void)
{
    printf("issue_739qmecr_readsecmsg_uncompress:\n");
    test_uncompress_limit_respects_buffer_max();

    if (failures) {
        printf("%d check(s) failed\n", failures);
        return (1);
    }
    printf("OK\n");
    return (0);
}
