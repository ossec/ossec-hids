/*
 * Regression: event-log DLL cache grows with every case spelling
 *
 * ANT-2026-ZNO1MXTC / CWE-178
 *
 * el_getEventDLL() keys dll_hash with strcmp(), while RegOpenKeyEx() is
 * case-insensitive. A new spelling of one installed source is a new entry
 * that is never removed. The registry name must stay as the event wrote
 * it. The cache stops accepting entries at EL_DLL_HASH_MAX.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_zno1mxtc_eventlog_dll_cache
 *
 * Run:
 *   ./issue_zno1mxtc_eventlog_dll_cache
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"

/* Keep in step with EL_DLL_HASH_MAX in logcollector/read_win_el.c. */
#define EL_DLL_HASH_MAX 4096

const char *__local_name = "issue-zno1mxtc-eventlog-dll-cache";

extern void *dll_hash;

char *el_getEventDLL(char *evt_name, char *source, char *event);

typedef void *HKEY;
typedef unsigned long DWORD;
typedef unsigned char *LPBYTE;
typedef DWORD *LPDWORD;
typedef long LONG;

static char last_key[512];
static int opens = 0;

static int failures = 0;

static void expect(int cond, const char *msg)
{
    if (cond) {
        printf("  ok:   %s\n", msg);
    } else {
        printf("  FAIL: %s\n", msg);
        failures++;
    }
}

static int hash_count(void)
{
    OSHash *hash = (OSHash *)dll_hash;
    unsigned int row;
    int n = 0;

    if (hash == NULL || hash->table == NULL) {
        return 0;
    }
    for (row = 0; row < hash->rows; row++) {
        OSHashNode *node;

        for (node = hash->table[row]; node != NULL; node = node->next) {
            n++;
        }
    }
    return n;
}

static const char *source_of(const char *key)
{
    const char *slash = strrchr(key, '\\');

    return (slash != NULL) ? slash + 1 : key;
}

LONG RegOpenKeyEx(HKEY hKey, const char *lpSubKey, DWORD ulOptions,
                  DWORD samDesired, HKEY *phkResult)
{
    const char *source;

    (void)hKey;
    (void)ulOptions;
    (void)samDesired;

    snprintf(last_key, sizeof(last_key), "%s", lpSubKey);
    opens++;
    if (phkResult != NULL) {
        *phkResult = (HKEY)1;
    }
    source = source_of(lpSubKey);
    if (strcasecmp(source, "Foo") == 0 ||
            strcasecmp(source, "abcdefghijklmnop") == 0) {
        return 0;
    }
    return 2;
}

LONG RegQueryValueEx(HKEY hKey, const char *lpValueName, LPDWORD lpReserved,
                     LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    const char *path = "eventmsg.dll";
    size_t n = strlen(path) + 1;

    (void)hKey;
    (void)lpValueName;
    (void)lpReserved;
    (void)lpType;

    if (lpcbData == NULL || *lpcbData < n) {
        return 2;
    }
    memcpy(lpData, path, n);
    *lpcbData = (DWORD)n;
    return 0;
}

LONG RegCloseKey(HKEY hKey)
{
    (void)hKey;
    return 0;
}

static void spell(char *out, unsigned int n)
{
    static const char base[] = "abcdefghijklmnop";
    size_t i;

    for (i = 0; i < sizeof(base) - 1; i++) {
        char c = base[i];

        if ((n & (1u << i)) != 0) {
            c = (char)toupper((unsigned char)c);
        }
        out[i] = c;
    }
    out[sizeof(base) - 1] = '\0';
}

/* One spelling is one entry, and the registry sees that spelling. */
static void test_same_spelling(void)
{
    char event[261];
    char *got;
    int i;
    int opens_before = opens;

    printf("--- one spelling, many events ---\n");
    for (i = 0; i < 100; i++) {
        event[0] = '\0';
        got = el_getEventDLL("Application", "Foo", event);
        if (got == NULL || strstr(got, "eventmsg.dll") == NULL) {
            expect(0, "installed source returns its message DLL");
            return;
        }
    }
    expect(hash_count() == 1, "one spelling is one cache entry");
    expect(opens == opens_before + 1, "later events with that spelling skip the registry");
    expect(strstr(last_key, "\\Foo") != NULL, "registry lookup keeps the written spelling");
}

/* A source that is not installed is not stored. */
static void test_unknown_source(void)
{
    char event[261];
    int before = hash_count();

    printf("--- source that is not installed ---\n");
    event[0] = '\0';
    expect(el_getEventDLL("Application", "Nope", event) == NULL,
           "an unknown source is not a message DLL");
    expect(hash_count() == before, "an unknown source is not cached");
}

/* Case variants stop at the cap, and the registry name is not folded. */
static void test_case_variants_are_capped(void)
{
    char event[261];
    char name[32];
    char *got;
    unsigned int n;
    const unsigned int extra = 32;

    printf("--- a new letter-case spelling per event ---\n");
    for (n = 0; n < EL_DLL_HASH_MAX + extra; n++) {
        spell(name, n);
        event[0] = '\0';
        got = el_getEventDLL("Application", name, event);
        if (got == NULL || strstr(got, "eventmsg.dll") == NULL) {
            expect(0, "a respelling still returns the message DLL");
            return;
        }
    }
    expect(hash_count() == EL_DLL_HASH_MAX,
           "case variants do not grow the cache past the cap");
    expect(strcmp(source_of(last_key), name) == 0,
           "the registry is opened with the spelling from the event");
}

int main(void)
{
    dll_hash = OSHash_Create();
    if (dll_hash == NULL) {
        fprintf(stderr, "OSHash_Create failed\n");
        return 1;
    }

    test_same_spelling();
    test_unknown_source();
    test_case_variants_are_capped();

    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
