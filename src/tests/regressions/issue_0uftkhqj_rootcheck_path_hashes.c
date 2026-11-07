/*
 * ANT-2026-0UFTKHQJ: rootcheck decoder must not take path/hashes from
 * attacker-shaped text inside the file name.
 *
 * Pre-fix, rk_extract_hashes() ended the path at the first quote after
 * " file '" and took each hash from the first " MD5="/" SHA1="/" SHA256=".
 * A directory name that embeds those tokens can spoof SyscheckFile fields.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_0uftkhqj_rootcheck_path_hashes
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "eventinfo.h"
#include "config.h"

const char *__local_name = "issue-0uftkhqj-rootcheck-path-hashes";

_Config Config;

int getDecoderfromlist(const char *name)
{
    (void)name;
    return (1);
}

void Rootcheck_TestExtractHashes(Eventinfo *lf);

static int failures;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

static void clear_lf(Eventinfo *lf)
{
    free(lf->filename);
    free(lf->md5_after);
    free(lf->sha1_after);
    free(lf->sha256_after);
    memset(lf, 0, sizeof(*lf));
}

static void run_extract(Eventinfo *lf, const char *log)
{
    clear_lf(lf);
    lf->log = (char *)log;
    Rootcheck_TestExtractHashes(lf);
}

static void test_crafted_path_spoof(void)
{
    Eventinfo lf;
    const char *real_path =
        "/tmp/nobody/notes.txt' MD5=940b8bef2fbf03312c39b4636cc886ff "
        "SHA1=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "
        "SHA256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb "
        "x/hidef";
    const char *spoof_md5 = "940b8bef2fbf03312c39b4636cc886ff";
    const char *real_md5 = "cccccccccccccccccccccccccccccccc";
    const char *real_sha1 = "dddddddddddddddddddddddddddddddddddddddd";
    const char *real_sha256 =
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    char log[OS_SIZE_2048];

    memset(&lf, 0, sizeof(lf));
    snprintf(log, sizeof(log),
             "Rootkit 'Knark' detected by the presence of file '%s'. "
             "MD5=%s SHA1=%s SHA256=%s",
             real_path, real_md5, real_sha1, real_sha256);

    run_extract(&lf, log);

    CHECK(lf.filename != NULL && strcmp(lf.filename, real_path) == 0,
          "crafted name keeps the full real path");
    CHECK(lf.md5_after != NULL && strcmp(lf.md5_after, real_md5) == 0,
          "crafted name keeps the real MD5 at the end");
    CHECK(lf.sha1_after != NULL && strcmp(lf.sha1_after, real_sha1) == 0,
          "crafted name keeps the real SHA1 at the end");
    CHECK(lf.sha256_after != NULL && strcmp(lf.sha256_after, real_sha256) == 0,
          "crafted name keeps the real SHA256 at the end");
    CHECK(lf.md5_after == NULL || strcmp(lf.md5_after, spoof_md5) != 0,
          "spoofed MD5 inside the path is not used");

    clear_lf(&lf);
}

static void test_ordinary_rootkit(void)
{
    Eventinfo lf;
    const char *path = "/tmp/nobody/plain/hidef";
    const char *md5 = "ca61e8b7a0c7f9e4d2b1a0f9e8d7c6b5";
    const char *sha1 = "48d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6";
    const char *sha256 =
        "790abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456";
    char log[OS_SIZE_1024];

    memset(&lf, 0, sizeof(lf));
    snprintf(log, sizeof(log),
             "Rootkit 'Knark' detected by the presence of file '%s'. "
             "MD5=%s SHA1=%s SHA256=%s",
             path, md5, sha1, sha256);

    run_extract(&lf, log);

    CHECK(lf.filename != NULL && strcmp(lf.filename, path) == 0,
          "ordinary Rootkit path extracted");
    CHECK(lf.md5_after != NULL && strcmp(lf.md5_after, md5) == 0,
          "ordinary Rootkit MD5 extracted");
    CHECK(lf.sha1_after != NULL && strcmp(lf.sha1_after, sha1) == 0,
          "ordinary Rootkit SHA1 extracted");
    CHECK(lf.sha256_after != NULL && strcmp(lf.sha256_after, sha256) == 0,
          "ordinary Rootkit SHA256 extracted");

    clear_lf(&lf);
}

static void test_apostrophe_path(void)
{
    Eventinfo lf;
    const char *path = "/tmp/it's mine/hidef";
    const char *md5 = "11111111111111111111111111111111";
    const char *sha1 = "2222222222222222222222222222222222222222";
    const char *sha256 =
        "3333333333333333333333333333333333333333333333333333333333333333";
    char log[OS_SIZE_1024];

    memset(&lf, 0, sizeof(lf));
    snprintf(log, sizeof(log),
             "Rootkit 'Knark' detected by the presence of file '%s'. "
             "MD5=%s SHA1=%s SHA256=%s",
             path, md5, sha1, sha256);

    run_extract(&lf, log);

    CHECK(lf.filename != NULL && strcmp(lf.filename, path) == 0,
          "apostrophe in path is not truncated");
    CHECK(lf.md5_after != NULL && strcmp(lf.md5_after, md5) == 0,
          "apostrophe path still gets real MD5");

    clear_lf(&lf);
}

static void test_na_hashes_and_no_hashes(void)
{
    Eventinfo lf;
    const char *path = "/tmp/plain/hidef";

    memset(&lf, 0, sizeof(lf));
    run_extract(&lf,
                "Rootkit 'Knark' detected by the presence of file "
                "'/tmp/plain/hidef'. MD5=n/a SHA1=n/a SHA256=n/a");
    CHECK(lf.filename != NULL && strcmp(lf.filename, path) == 0,
          "n/a hashes still yield the path");
    CHECK(lf.md5_after == NULL && lf.sha1_after == NULL && lf.sha256_after == NULL,
          "n/a hashes leave md5/sha1/sha256 unset");
    clear_lf(&lf);

    run_extract(&lf,
                "Rootkit 'Knark' detected by the presence of file "
                "'/tmp/plain/hidef'.");
    CHECK(lf.filename != NULL && strcmp(lf.filename, path) == 0,
          "pre-hash agent message still yields the path");
    CHECK(lf.md5_after == NULL && lf.sha1_after == NULL && lf.sha256_after == NULL,
          "message without hashes leaves digests unset");
    clear_lf(&lf);
}

static void test_reject_non_hex_and_file_prefix(void)
{
    Eventinfo lf;

    memset(&lf, 0, sizeof(lf));
    run_extract(&lf,
                "Rootkit 'Knark' detected by the presence of file "
                "'/tmp/plain/hidef'. "
                "MD5=ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ "
                "SHA1=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "
                "SHA256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    CHECK(lf.filename == NULL && lf.md5_after == NULL,
          "non-hex MD5 rejects the whole hash triple");
    clear_lf(&lf);

    run_extract(&lf,
                "File '/etc/passwd' is owned by root and has write "
                "permissions to others.");
    CHECK(lf.filename == NULL && lf.md5_after == NULL,
          "unrelated File ' message yields no SyscheckFile fields");
    clear_lf(&lf);
}

static void test_anomaly_and_trojaned(void)
{
    Eventinfo lf;
    const char *path = "/tmp/plain/hidef";
    const char *md5 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const char *sha1 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const char *sha256 =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    char log[OS_SIZE_2048];

    memset(&lf, 0, sizeof(lf));
    snprintf(log, sizeof(log),
             "Anomaly detected in file '%s'. File size doesn't match what we "
             "found. Possible kernel level rootkit. MD5=%s SHA1=%s SHA256=%s",
             path, md5, sha1, sha256);
    run_extract(&lf, log);
    CHECK(lf.filename != NULL && strcmp(lf.filename, path) == 0,
          "Anomaly size-mismatch path extracted");
    CHECK(lf.md5_after != NULL && strcmp(lf.md5_after, md5) == 0,
          "Anomaly size-mismatch MD5 extracted");
    clear_lf(&lf);

    run_extract(&lf,
                "Anomaly detected in file '/tmp/hidden'. "
                "Hidden from stats, but showing up on readdir. "
                "Possible kernel level rootkit.");
    CHECK(lf.filename != NULL && strcmp(lf.filename, "/tmp/hidden") == 0,
          "hash-less Anomaly path extracted");
    clear_lf(&lf);

    run_extract(&lf,
                "Trojaned version of file '/bin/ls' detected. "
                "Look for something unusual.");
    CHECK(lf.filename != NULL && strcmp(lf.filename, "/bin/ls") == 0,
          "Trojaned path still ends at the first quote");
    clear_lf(&lf);
}

int main(void)
{
    printf("ANT-2026-0UFTKHQJ rootcheck path/hash framing regression\n");
    test_crafted_path_spoof();
    test_ordinary_rootkit();
    test_apostrophe_path();
    test_na_hashes_and_no_hashes();
    test_reject_non_hex_and_file_prefix();
    test_anomaly_and_trojaned();

    if (failures) {
        printf("%d failure(s)\n", failures);
        return (1);
    }
    printf("all checks passed\n");
    return (0);
}
