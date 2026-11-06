/*
 * Regression: ANSI wildcard expansion loops on a non-representable name
 *
 * ANT-2026-WJND95HE / CWE-835
 *
 * expand_win32_wildcards() feeds every FindFirstFile name back into its
 * pattern list and stops only when the first entry has no '*' or '?'. The
 * Windows agent is built without UNICODE, so the ANSI find API returns '?'
 * for a character the code page cannot hold. A file named so that it comes
 * back as "!?.log" is then a pattern that matches itself on every round.
 *
 * The host build supplies that ANSI substitution. A name containing '*' or
 * '?' must be skipped. Paths stay char* for the ANSI open that follows, so
 * this does not switch the walk to FindFirstFileW. The '?' in a \\?\ prefix
 * is still not a wildcard.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_wjnd95he_win_wildcard
 *
 * Run:
 *   ./issue_wjnd95he_win_wildcard
 */

#include <ctype.h>
#include <stdint.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FILE_ATTRIBUTE_DIRECTORY 0x00000010u
#define INVALID_HANDLE_VALUE ((void *)(intptr_t)-1)

typedef void *HANDLE;
typedef struct {
    char cFileName[260];
    unsigned int dwFileAttributes;
} WIN32_FIND_DATA;

char **expand_win32_wildcards(const char *path);

void merror(const char *msg, ...)
{
    (void)msg;
}

void ErrorExit(const char *msg, ...)
{
    (void)msg;
    fprintf(stderr, "FAIL: ErrorExit\n");
    exit(1);
}

struct ent {
    const char *parent;
    const char *name;
    int dir;
};

/* ANSI names, as FindFirstFileA would return them on code page 1252. */
static const struct ent ents[] = {
    { "C:\\logs", "!?.log", 0 },
    { "C:\\logs", "zz?.log", 0 },
    { "C:\\logs", "app.log", 0 },
    { "C:\\logs", "error.log", 0 },
    { "C:\\logs", "app1.log", 0 },
    { "C:\\logs", "!?", 1 },
    { "C:\\logs", "keep", 1 },
    { "\\\\?\\C:\\logs", "!?.log", 0 },
    { "\\\\?\\C:\\logs", "app.log", 0 },
};

struct search {
    char names[8][260];
    unsigned int attrs[8];
    int count;
    int next;
};

static sigjmp_buf expand_jmp;
static int lookups;

static int glob_match(const char *pat, const char *name)
{
    if (*pat == '\0') {
        return (*name == '\0');
    }
    if (*pat == '*') {
        return (glob_match(pat + 1, name) ||
                (*name && glob_match(pat, name + 1)));
    }
    if (*name == '\0') {
        return (0);
    }
    if (*pat == '?' || tolower((unsigned char)*pat) == tolower((unsigned char)*name)) {
        return (glob_match(pat + 1, name + 1));
    }
    return (0);
}

static int name_order(const void *a, const void *b)
{
    return (strcmp((const char *)a, (const char *)b));
}

HANDLE FindFirstFile(const char *pattern, WIN32_FIND_DATA *data)
{
    char parent[512];
    const char *comp;
    const char *sep;
    struct search *s;
    int i;
    char matched[8][260];
    int dirs[8];
    int n = 0;

    if (++lookups > 200) {
        siglongjmp(expand_jmp, 1);
    }

    sep = strrchr(pattern, '\\');
    if (sep == NULL) {
        return (INVALID_HANDLE_VALUE);
    }
    if ((size_t)(sep - pattern) >= sizeof(parent)) {
        return (INVALID_HANDLE_VALUE);
    }
    memcpy(parent, pattern, (size_t)(sep - pattern));
    parent[sep - pattern] = '\0';
    comp = sep + 1;

    for (i = 0; i < (int)(sizeof(ents) / sizeof(ents[0])); i++) {
        if (strcmp(ents[i].parent, parent) != 0) {
            continue;
        }
        if (!glob_match(comp, ents[i].name)) {
            continue;
        }
        snprintf(matched[n], sizeof(matched[n]), "%s", ents[i].name);
        dirs[n] = ents[i].dir;
        n++;
    }
    if (n == 0) {
        return (INVALID_HANDLE_VALUE);
    }
    qsort(matched, (size_t)n, sizeof(matched[0]), name_order);

    s = calloc(1, sizeof(*s));
    if (s == NULL) {
        return (INVALID_HANDLE_VALUE);
    }
    s->count = n;
    for (i = 0; i < n; i++) {
        snprintf(s->names[i], sizeof(s->names[i]), "%s", matched[i]);
        s->attrs[i] = dirs[i] ? FILE_ATTRIBUTE_DIRECTORY : 0;
    }
    /* qsort reordered names but not dirs. Rebuild attrs by name. */
    for (i = 0; i < n; i++) {
        int e;

        s->attrs[i] = 0;
        for (e = 0; e < (int)(sizeof(ents) / sizeof(ents[0])); e++) {
            if (strcmp(ents[e].parent, parent) == 0 &&
                    strcmp(ents[e].name, s->names[i]) == 0) {
                s->attrs[i] = ents[e].dir ? FILE_ATTRIBUTE_DIRECTORY : 0;
                break;
            }
        }
    }
    s->next = 0;
    snprintf(data->cFileName, sizeof(data->cFileName), "%s", s->names[0]);
    data->dwFileAttributes = s->attrs[0];
    s->next = 1;
    return (s);
}

int FindNextFile(HANDLE handle, WIN32_FIND_DATA *data)
{
    struct search *s = handle;

    if (s->next >= s->count) {
        return (0);
    }
    snprintf(data->cFileName, sizeof(data->cFileName), "%s", s->names[s->next]);
    data->dwFileAttributes = s->attrs[s->next];
    s->next++;
    return (1);
}

int FindClose(HANDLE handle)
{
    free(handle);
    return (1);
}

static void free_list(char **list)
{
    int i;

    if (list == NULL) {
        return;
    }
    for (i = 0; list[i] != NULL; i++) {
        free(list[i]);
    }
    free(list);
}

static int same_list(const char *pattern, char **got, const char **want)
{
    int i;
    int nwant = 0;
    int ngot = 0;

    if (got == NULL) {
        fprintf(stderr, "FAIL: %s returned no paths\n", pattern);
        return (1);
    }
    while (want[nwant] != NULL) {
        nwant++;
    }
    while (got[ngot] != NULL) {
        ngot++;
    }
    if (ngot != nwant) {
        fprintf(stderr, "FAIL: %s returned %d paths, want %d\n", pattern, ngot, nwant);
        for (i = 0; i < ngot; i++) {
            fprintf(stderr, "  got %s\n", got[i]);
        }
        return (1);
    }
    for (i = 0; i < nwant; i++) {
        if (strcmp(got[i], want[i]) != 0) {
            fprintf(stderr, "FAIL: %s path %d is '%s', want '%s'\n",
                    pattern, i, got[i], want[i]);
            return (1);
        }
    }
    return (0);
}

static int run_case(const char *pattern, const char **want)
{
    char **got;
    int rc;

    lookups = 0;
    if (sigsetjmp(expand_jmp, 1) != 0) {
        fprintf(stderr, "FAIL: %s did not finish (lookup %d)\n", pattern, lookups);
        return (1);
    }
    got = expand_win32_wildcards(pattern);
    rc = same_list(pattern, got, want);
    free_list(got);
    return (rc);
}

int main(void)
{
    static const char *logs[] = {
        "C:\\logs\\app.log",
        "C:\\logs\\app1.log",
        "C:\\logs\\error.log",
        NULL
    };
    static const char *subdir[] = {
        "C:\\logs\\keep\\app.log",
        NULL
    };
    static const char *extended[] = {
        "\\\\?\\C:\\logs\\app.log",
        NULL
    };
    static const char *one_char[] = {
        "C:\\logs\\app1.log",
        NULL
    };
    int rc = 0;

    rc |= run_case("C:\\logs\\*.log", logs);
    rc |= run_case("C:\\logs\\*\\app.log", subdir);
    rc |= run_case("\\\\?\\C:\\logs\\*.log", extended);
    rc |= run_case("C:\\logs\\app?.log", one_char);

    if (rc == 0) {
        printf("ok\n");
    }
    return (rc == 0 ? 0 : 1);
}
