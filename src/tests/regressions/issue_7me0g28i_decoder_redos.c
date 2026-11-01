/*
 * Regression for ANT-2026-7ME0G28I: windows1 and barracuda-svf1 decoder
 * patterns must not backtrack cubically on crafted messages.
 *
 * Loads the concatenated <pcre2> patterns from etc/decoder.xml (same join
 * decode-xml.c uses) and runs them the way OSPcre2_Execute_pcre2_match does
 * (PCRE2_CASELESS), with a match-step budget that the old patterns exceed on
 * the hostile lines while the fixed ones finish cleanly.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_7me0g28i_decoder_redos
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

/* Below default 10M so a still-vulnerable pattern fails the test quickly. */
#define MATCH_LIMIT 200000

static char *read_file(const char *path, size_t *out_len)
{
    FILE *fp;
    struct stat st;
    char *buf;
    size_t n;

    if (stat(path, &st) != 0 || st.st_size <= 0) {
        return NULL;
    }
    fp = fopen(path, "rb");
    if (!fp) {
        return NULL;
    }
    buf = malloc((size_t)st.st_size + 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    n = fread(buf, 1, (size_t)st.st_size, fp);
    fclose(fp);
    buf[n] = '\0';
    if (out_len) {
        *out_len = n;
    }
    return buf;
}

/* Concatenate consecutive <tag>...</tag> bodies after marker, until a
 * different child or </decoder>. open_tag is e.g. "<pcre2" / "<prematch_pcre2";
 * close_tag is e.g. "</pcre2>" / "</prematch_pcre2>". */
static char *extract_concat_tag(const char *xml, const char *decoder_marker,
                                const char *open_tag, const char *close_tag)
{
    const char *p = strstr(xml, decoder_marker);
    char *out = NULL;
    size_t out_len = 0;
    size_t open_len = strlen(open_tag);
    size_t close_len = strlen(close_tag);

    if (!p) {
        return NULL;
    }
    p = strstr(p, open_tag);
    while (p && strncmp(p, "</decoder>", 10) != 0) {
        const char *gt;
        const char *end;
        size_t piece;

        if (strncmp(p, open_tag, open_len) != 0) {
            if (*p == '<') {
                break;
            }
            p++;
            continue;
        }
        /* Do not treat "<pcre2" as a hit inside "<prematch_pcre2". */
        if (p > xml && ((p[-1] >= 'a' && p[-1] <= 'z') || p[-1] == '_')) {
            p++;
            continue;
        }
        gt = strchr(p, '>');
        if (!gt) {
            break;
        }
        end = strstr(gt + 1, close_tag);
        if (!end) {
            break;
        }
        piece = (size_t)(end - (gt + 1));
        {
            char *nbuf = realloc(out, out_len + piece + 1);
            if (!nbuf) {
                free(out);
                return NULL;
            }
            out = nbuf;
            memcpy(out + out_len, gt + 1, piece);
            out_len += piece;
            out[out_len] = '\0';
        }
        p = end + close_len;
        while (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t') {
            p++;
        }
    }
    return out;
}

static int run_match(const char *label, const char *pattern, const char *subject,
                     int want_match, int reject_matchlimit,
                     const char *expect_cap1)
{
    int errnum;
    PCRE2_SIZE erroff;
    pcre2_code *re;
    pcre2_match_data *md;
    pcre2_match_context *ctx;
    int rc;

    re = pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED, PCRE2_CASELESS,
                       &errnum, &erroff, NULL);
    if (!re) {
        printf("FAIL: %s: compile error %d at %zu\n", label, errnum, (size_t)erroff);
        return 1;
    }
    md = pcre2_match_data_create_from_pattern(re, NULL);
    ctx = pcre2_match_context_create(NULL);
    if (!md || !ctx) {
        printf("FAIL: %s: alloc\n", label);
        pcre2_match_data_free(md);
        pcre2_match_context_free(ctx);
        pcre2_code_free(re);
        return 1;
    }
    pcre2_set_match_limit(ctx, MATCH_LIMIT);
    rc = pcre2_match(re, (PCRE2_SPTR)subject, (PCRE2_SIZE)strlen(subject), 0, 0,
                     md, ctx);

    if (reject_matchlimit && rc == PCRE2_ERROR_MATCHLIMIT) {
        printf("FAIL: %s: hit PCRE2_ERROR_MATCHLIMIT (pattern still backtracks)\n",
               label);
        pcre2_match_data_free(md);
        pcre2_match_context_free(ctx);
        pcre2_code_free(re);
        return 1;
    }
    if (want_match && rc <= 0) {
        printf("FAIL: %s: expected match, got %d\n", label, rc);
        pcre2_match_data_free(md);
        pcre2_match_context_free(ctx);
        pcre2_code_free(re);
        return 1;
    }
    if (!want_match && rc > 0) {
        printf("FAIL: %s: expected no match, got %d\n", label, rc);
        pcre2_match_data_free(md);
        pcre2_match_context_free(ctx);
        pcre2_code_free(re);
        return 1;
    }
    if (want_match && expect_cap1 && rc >= 2) {
        PCRE2_SIZE *ov = pcre2_get_ovector_pointer(md);
        size_t len = (size_t)(ov[3] - ov[2]);
        if (len != strlen(expect_cap1) ||
            memcmp(subject + ov[2], expect_cap1, len) != 0) {
            printf("FAIL: %s: capture 1 want '%s', got '%.*s'\n",
                   label, expect_cap1, (int)len, subject + ov[2]);
            pcre2_match_data_free(md);
            pcre2_match_context_free(ctx);
            pcre2_code_free(re);
            return 1;
        }
    }

    pcre2_match_data_free(md);
    pcre2_match_context_free(ctx);
    pcre2_code_free(re);
    printf("ok: %s (rc=%d)\n", label, rc);
    return 0;
}

static char *build_windows_hostile(void)
{
    /* Application: INFORMATION(1): MyApp: bob: CORP: WIN01: + "a : " x 500 */
    const char *prefix =
        "Application: INFORMATION(1): MyApp: bob: CORP: WIN01: ";
    size_t i;
    size_t plen = strlen(prefix);
    char *buf = malloc(plen + 500 * 4 + 1);

    if (!buf) {
        return NULL;
    }
    memcpy(buf, prefix, plen);
    for (i = 0; i < 500; i++) {
        memcpy(buf + plen + i * 4, "a : ", 4);
    }
    buf[plen + 500 * 4] = '\0';
    return buf;
}

static char *build_barracuda_hostile(void)
{
    /* a + 1900 '[' + x] 1- + 3800 '-' + " 1 x" */
    const char *tail = "x] 1-";
    const char *end = " 1 x";
    size_t n = 1 + 1900 + strlen(tail) + 3800 + strlen(end);
    char *buf = malloc(n + 1);
    size_t off = 0;

    if (!buf) {
        return NULL;
    }
    buf[off++] = 'a';
    memset(buf + off, '[', 1900);
    off += 1900;
    memcpy(buf + off, tail, strlen(tail));
    off += strlen(tail);
    memset(buf + off, '-', 3800);
    off += 3800;
    memcpy(buf + off, end, strlen(end));
    off += strlen(end);
    buf[off] = '\0';
    return buf;
}

int main(void)
{
    int failed = 0;
    char *xml;
    char *win_pat;
    char *bar_pat;
    char *bar_pre;
    char *win_hostile;
    char *bar_hostile;
    const char *paths[] = {
        "../etc/decoder.xml",
        "etc/decoder.xml",
        NULL
    };
    const char *path = NULL;
    int i;

    printf("=== ANT-2026-7ME0G28I: windows1/barracuda-svf1 ReDoS ===\n");

    for (i = 0; paths[i]; i++) {
        xml = read_file(paths[i], NULL);
        if (xml) {
            path = paths[i];
            break;
        }
    }
    if (!xml) {
        printf("FAIL: cannot read etc/decoder.xml\n");
        return 1;
    }
    printf("using %s\n", path);

    win_pat = extract_concat_tag(xml, "<decoder name=\"windows1\">",
                                 "<pcre2", "</pcre2>");
    bar_pat = extract_concat_tag(xml, "<decoder name=\"barracuda-svf1\">",
                                 "<pcre2", "</pcre2>");
    bar_pre = extract_concat_tag(xml, "<decoder name=\"barracuda-svf1\">",
                                 "<prematch_pcre2", "</prematch_pcre2>");
    if (!win_pat || !bar_pat || !bar_pre) {
        printf("FAIL: could not extract patterns (win=%p bar=%p pre=%p)\n",
               (void *)win_pat, (void *)bar_pat, (void *)bar_pre);
        free(win_pat);
        free(bar_pat);
        free(bar_pre);
        free(xml);
        return 1;
    }

    /* Fixed patterns: lazy log prefix + [^:]+ for source/user/domain; no
     * "(\\S+)\\]" on barracuda. Reject the old greedy ".+: " header form. */
    if (strstr(win_pat, ".+: (") != NULL || strstr(win_pat, "(.+):") != NULL) {
        printf("FAIL: windows1 pattern still uses greedy .+: fields: %s\n",
               win_pat);
        failed = 1;
    } else if (strstr(win_pat, "[^:]+") == NULL) {
        printf("FAIL: windows1 pattern missing [^:]+: %s\n", win_pat);
        failed = 1;
    } else if (strstr(win_pat, "(?:.+?):") == NULL && strstr(win_pat, "^[^:]+:") == NULL) {
        printf("FAIL: windows1 log prefix must be non-capturing or [^:]+: %s\n",
               win_pat);
        failed = 1;
    } else {
        printf("ok: windows1 pattern bounds header fields\n");
    }
    if (strstr(bar_pat, "(\\S+)\\]") != NULL || strstr(bar_pre, "\\[\\S+\\]") != NULL) {
        printf("FAIL: barracuda-svf1 still uses \\S+ inside brackets "
               "(pcre2='%s' prematch='%s')\n", bar_pat, bar_pre);
        failed = 1;
    } else if (strstr(bar_pat, "[^\\s\\[\\]]+") == NULL) {
        printf("FAIL: barracuda-svf1 missing bracket-safe class: %s\n", bar_pat);
        failed = 1;
    } else {
        printf("ok: barracuda-svf1 pattern tightens bracket/id classes\n");
    }

    win_hostile = build_windows_hostile();
    bar_hostile = build_barracuda_hostile();
    if (!win_hostile || !bar_hostile) {
        printf("FAIL: OOM building subjects\n");
        free(win_pat);
        free(bar_pat);
        free(bar_pre);
        free(win_hostile);
        free(bar_hostile);
        free(xml);
        return 1;
    }

    failed |= run_match("windows1 benign header", win_pat,
                        "Application: INFORMATION(1): MyApp: bob: CORP: WIN01: hello",
                        1, 1, "INFORMATION");
    failed |= run_match("windows1 colon in log name", win_pat,
                        "c:\\program files\\7-zip\\7z.dll: INFORMATION(1): MyApp: "
                        "bob: CORP: WIN01: hello",
                        1, 1, "INFORMATION");
    failed |= run_match("windows1 hostile ': ' message", win_pat, win_hostile,
                        1, 1, "INFORMATION");
    failed |= run_match(
        "barracuda-svf1 benign", bar_pat,
        "host[192.0.2.25] 1184286052-1b2c3d-4e5f 1184286052 1184286054 RECV ",
        1, 1, "192.0.2.25");
    /* Second alternative: group 1 is unset; OSSEC skips empty groups for order. */
    failed |= run_match(
        "barracuda-svf1 bare-IP SEND", bar_pat,
        "127.0.0.1 1406248798-06f4a35b4de6bd0001-3QeedR 0 0 SEND ",
        1, 1, NULL);
    failed |= run_match(
        "barracuda-svf1 prematch benign", bar_pre,
        "host[192.0.2.25] 1184286052-1b2c3d-4e5f 1184286052 1184286054 RECV ",
        1, 1, NULL);
    /* Hostile line must not burn the match budget (no match is fine). */
    failed |= run_match("barracuda-svf1 hostile brackets/dashes", bar_pat,
                        bar_hostile, 0, 1, NULL);
    failed |= run_match("barracuda-svf1 prematch hostile", bar_pre,
                        bar_hostile, 1, 1, NULL);

    free(win_pat);
    free(bar_pat);
    free(bar_pre);
    free(win_hostile);
    free(bar_hostile);
    free(xml);

    if (failed) {
        printf("FAIL: ANT-2026-7ME0G28I regression\n");
        return 1;
    }
    printf("PASS: ANT-2026-7ME0G28I regression\n");
    return 0;
}
