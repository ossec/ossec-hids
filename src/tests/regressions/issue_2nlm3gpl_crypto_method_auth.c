/*
 * ANT-2026-2NLM3GPL: ReadSecMSG must not store crypto_method until auth.
 *
 * Pre-fix, the manager wrote AES vs Blowfish framing into the key entry
 * before decrypt/checksum/replay checks. A forged "!id!:" (or "#AES:")
 * datagram that failed authentication still flipped CreateSecMSG()'s
 * cipher toward that agent, so AR / agent_control / merged.mg pushes were
 * silently unreadable until the agent's next genuine message.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_2nlm3gpl_crypto_method_auth
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "headers/sec.h"

const char *__local_name = "issue-2nlm3gpl-crypto-method-auth";

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

/* 0 = decrypt fails; 1 = decrypt to bad old-format checksum;
 * 2 = decrypt to compressed payload (accept path via uncompress stub). */
static int crypto_stub_mode;

int OS_BF_Str(const char *input, char *output, const char *charkey,
              long size, short int action)
{
    (void)input; (void)charkey; (void)size; (void)action;
    if (crypto_stub_mode == 0) {
        return 0;
    }
    if (crypto_stub_mode == 1) {
        /* Old format that fails CheckSum (MD5 stub expects leading zeros). */
        output[0] = ':';
        memset(output + 1, 'A', 40);
        output[41] = '\0';
        return 1;
    }
    /* Compressed marker; body filled by os_zlib_uncompress stub. */
    output[0] = '!';
    output[1] = 'Z';
    output[2] = '\0';
    return 1;
}

int OS_AES_Str(const char *input, char *output, const char *charkey,
               long size, short int action)
{
    (void)input; (void)charkey; (void)size; (void)action;
    if (crypto_stub_mode == 0) {
        return 0;
    }
    if (crypto_stub_mode == 1) {
        output[0] = ':';
        memset(output + 1, 'A', 40);
        output[41] = '\0';
        return 1;
    }
    output[0] = '!';
    output[1] = 'Z';
    output[2] = '\0';
    return 1;
}

unsigned long int os_zlib_uncompress(const char *src, char *dst,
                                     unsigned long int src_size,
                                     unsigned long int dst_size)
{
    /* 32-zero checksum (matches OS_MD5_Bytes stub) + random(5) +
     * global(10) + ':' + local(5) + payload — counters 1/1 beat zeros. */
    static const char payload[] =
        "00000000000000000000000000000000"
        "rand0"
        "0000000001"
        ":"
        "00001"
        "hi";
    (void)src; (void)src_size;
    if (dst_size < sizeof(payload)) {
        return 0;
    }
    memcpy(dst, payload, sizeof(payload) - 1);
    dst[sizeof(payload) - 1] = '\0';
    return (unsigned long)(sizeof(payload) - 1);
}

void merror(const char *msg, ...) { (void)msg; }

static int failures;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

static void setup_keys(keystore *keys, keyentry *entry, keyentry **entries,
                       os_ip *ip, crypt_method method)
{
    memset(keys, 0, sizeof(*keys));
    memset(entry, 0, sizeof(*entry));
    memset(ip, 0, sizeof(*ip));
    entry->id = (char *)"001";
    entry->name = (char *)"agent1";
    entry->key = (char *)"test-key-for-2nlm3gpl";
    entry->ip = ip;
    entry->crypto_method = method;
    entry->global = 0;
    entry->local = 0;
    entry->inode = 0;
    entry->fp = tmpfile();
    ip->ip = (char *)"any";
    entries[0] = entry;
    keys->keyentries = entries;
    keys->keysize = 1;
}

static void cleanup_entry(keyentry *entry)
{
    if (entry->fp) {
        fclose(entry->fp);
        entry->fp = NULL;
    }
}

static void test_forged_blowfish_checksum_fail_keeps_aes(void)
{
    keystore keys;
    keyentry entry;
    keyentry *entries[1];
    os_ip ip;
    char msg[32];
    char cleartext[OS_MAXSTR + 1];
    size_t final_size = 0;
    char *out;
    const unsigned int body_len = 8;

    setup_keys(&keys, &entry, entries, &ip, W_METH_AES);
    crypto_stub_mode = 1;

    msg[0] = ':';
    memset(msg + 1, '\0', body_len);
    msg[1 + body_len] = '\0';

    out = ReadSecMSG(&keys, msg, sizeof(msg), cleartext, 0, body_len,
                     &final_size, "127.0.0.1");

    CHECK(out == NULL, "forged Blowfish datagram is rejected after decrypt");
    CHECK(entry.crypto_method == W_METH_AES,
          "AES agent crypto_method unchanged after checksum failure");
    cleanup_entry(&entry);
}

static void test_forged_aes_checksum_fail_keeps_blowfish(void)
{
    keystore keys;
    keyentry entry;
    keyentry *entries[1];
    os_ip ip;
    char msg[64];
    char cleartext[OS_MAXSTR + 1];
    size_t final_size = 0;
    char *out;
    const unsigned int body_len = 12;

    setup_keys(&keys, &entry, entries, &ip, W_METH_BLOWFISH);
    crypto_stub_mode = 1;

    memcpy(msg, "#AES:", 5);
    memset(msg + 5, 'x', 8);
    msg[13] = '\0';

    out = ReadSecMSG(&keys, msg, sizeof(msg), cleartext, 0, body_len,
                     &final_size, "127.0.0.1");

    CHECK(out == NULL, "forged AES datagram is rejected after decrypt");
    CHECK(entry.crypto_method == W_METH_BLOWFISH,
          "Blowfish agent crypto_method unchanged after checksum failure");
    cleanup_entry(&entry);
}

static void test_authenticated_blowfish_updates_aes_entry(void)
{
    keystore keys;
    keyentry entry;
    keyentry *entries[1];
    os_ip ip;
    char msg[OS_MAXSTR + 1];
    char cleartext[OS_MAXSTR + 1];
    size_t final_size = 0;
    char *out;
    const unsigned int body_len = 8;

    setup_keys(&keys, &entry, entries, &ip, W_METH_AES);
    crypto_stub_mode = 2;

    memset(msg, 0, sizeof(msg));
    msg[0] = ':';
    memset(msg + 1, 'x', body_len);

    out = ReadSecMSG(&keys, msg, sizeof(msg), cleartext, 0, body_len,
                     &final_size, "127.0.0.1");

    CHECK(out != NULL, "authenticated Blowfish datagram is accepted");
    CHECK(entry.crypto_method == W_METH_BLOWFISH,
          "authenticated Blowfish frame updates AES agent crypto_method");
    cleanup_entry(&entry);
}

int main(void)
{
    printf("issue_2nlm3gpl_crypto_method_auth:\n");
    test_forged_blowfish_checksum_fail_keeps_aes();
    test_forged_aes_checksum_fail_keeps_blowfish();
    test_authenticated_blowfish_updates_aes_entry();

    if (failures) {
        printf("%d check(s) failed\n", failures);
        return (1);
    }
    printf("OK\n");
    return (0);
}
