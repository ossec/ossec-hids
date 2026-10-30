/*
 * ANT-2026-3WKK50NE: OSHash must not let seed-independent colliding keys
 * land in one chain (FTS DoS via arpwatch / if_fts).
 *
 * Adding a 128-byte +1/-1 Thue-Morse pattern to a key left the old
 * polynomial hash (mod 2^32, odd multiplier from os_getprime) unchanged
 * for every seed, so 1024 such keys share one row.
 *
 * Build (from src/ after make TARGET=server / make shared.a):
 *   make -f tests/regressions/Makefile issue_3wkk50ne_oshash_collisions
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "hash_op.h"

const char *__local_name = "issue-3wkk50ne-oshash-collisions";

static int failures = 0;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

/* Build key number by applying Thue-Morse +/-1 at each set bit offset. */
static void colliding_key(char *key, size_t key_len, unsigned int number)
{
    unsigned int shift, n, bits, sign;

    memset(key, 'P', key_len - 1);
    key[key_len - 1] = '\0';

    for (shift = 0; shift < 10; shift++) {
        if (!((number >> shift) & 1U)) {
            continue;
        }
        for (n = 0; n < 128; n++) {
            for (sign = 0, bits = n; bits; bits >>= 1) {
                sign ^= bits & 1U;
            }
            key[shift + n] += sign ? -1 : 1;
        }
    }
}

static unsigned int longest_chain(const OSHash *hash)
{
    unsigned int i, length, longest = 0;
    const OSHashNode *node;

    for (i = 0; i <= hash->rows; i++) {
        length = 0;
        for (node = hash->table[i]; node; node = node->next) {
            length++;
        }
        if (length > longest) {
            longest = length;
        }
    }
    return longest;
}

static void test_thue_morse_keys_do_not_collide(void)
{
    char key[128 + 10];
    unsigned int number;
    unsigned int longest;
    OSHash *hash;

    hash = OSHash_Create();
    CHECK(hash != NULL, "OSHash_Create");
    if (!hash) {
        return;
    }

    for (number = 0; number < 1024; number++) {
        colliding_key(key, sizeof(key), number);
        if (OSHash_Add(hash, key, NULL) != 2) {
            printf("  FAIL: OSHash_Add for key %u\n", number);
            failures++;
            OSHash_Free(hash);
            return;
        }
    }

    longest = longest_chain(hash);
    printf("  info: longest chain after 1024 Thue-Morse keys = %u (rows=%u)\n",
           longest, hash->rows);
    /* Old mod-2^32 hash: all 1024 in one chain. Fixed prime field: ~spread. */
    CHECK(longest < 16, "Thue-Morse family must not share one OSHash row");

    OSHash_Free(hash);
}

int main(void)
{
    printf("ANT-2026-3WKK50NE OSHash seed-independent collisions\n");
    test_thue_morse_keys_do_not_collide();

    if (failures) {
        printf("FAIL: %d check(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
