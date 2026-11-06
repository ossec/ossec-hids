/*
 * Regression: BMPString common name compared as raw ASCII bytes
 *
 * ANT-2026-5BG289FD / CWE-297
 *
 * asn1_to_cstr() copied an ASN.1 string's content bytes without decoding
 * the type. A BMPString whose code units are the bytes of a host name
 * therefore matched that host name. The same bytes in a UTF8String, and
 * the same characters decoded, must not.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_5bg289fd_bmpstring_cn
 *
 * Run:
 *   ./issue_5bg289fd_bmpstring_cn
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/x509.h>

#include "check_cert.h"

const char *__local_name = "issue-5bg289fd-bmpstring-cn";

#define HOST "manager.ops.example.test"
#define OTHER "web01.ops.example.test"
#define WILD "*.ops.example.test"
#define DOTTED "manager.ops.example.org."
#define DOTTED_HOST "manager.ops.example.org"

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

static ASN1_STRING *make_str(int type, const void *data, int len)
{
    ASN1_STRING *astr;

    astr = ASN1_STRING_type_new(type);
    if (astr == NULL) {
        return NULL;
    }
    if (ASN1_STRING_set(astr, data, len) != 1) {
        ASN1_STRING_free(astr);
        return NULL;
    }
    return astr;
}

/* UTF-16BE of an ASCII host name: a real Latin BMPString. */
static int latin_bmp(const char *ascii, unsigned char *out, size_t outlen)
{
    size_t n = strlen(ascii);
    size_t i;

    if (outlen < n * 2) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        out[i * 2] = 0;
        out[i * 2 + 1] = (unsigned char)ascii[i];
    }
    return (int)(n * 2);
}

static void test_hostname(int type, const void *data, int len,
                           const char *manager, int want, const char *msg)
{
    ASN1_STRING *astr;
    int got;

    astr = make_str(type, data, len);
    expect(astr != NULL, "string allocated");
    if (astr == NULL) {
        return;
    }
    got = check_hostname(astr, manager);
    expect(got == want, msg);
    ASN1_STRING_free(astr);
}

static X509 *cert_org_then_cn(int type, const void *data, int len)
{
    X509 *cert;
    X509_NAME *name;
    X509_NAME_ENTRY *org;
    X509_NAME_ENTRY *cn;

    cert = X509_new();
    name = X509_NAME_new();
    if (cert == NULL || name == NULL) {
        X509_free(cert);
        X509_NAME_free(name);
        return NULL;
    }

    /* O= comes first. check_subject_cn() starts at index 0 and skips the
     * entry at that index, so a leading CN is never examined. */
    org = X509_NAME_ENTRY_create_by_NID(NULL, NID_organizationName,
                                        MBSTRING_ASC,
                                        (unsigned char *)"Example", -1);
    cn = X509_NAME_ENTRY_create_by_NID(NULL, NID_commonName, type,
                                       (unsigned char *)data, len);
    if (org == NULL || cn == NULL ||
            X509_NAME_add_entry(name, org, -1, 0) != 1 ||
            X509_NAME_add_entry(name, cn, -1, 0) != 1 ||
            X509_set_subject_name(cert, name) != 1) {
        X509_NAME_ENTRY_free(org);
        X509_NAME_ENTRY_free(cn);
        X509_NAME_free(name);
        X509_free(cert);
        return NULL;
    }
    X509_NAME_ENTRY_free(org);
    X509_NAME_ENTRY_free(cn);
    X509_NAME_free(name);
    return cert;
}

int main(void)
{
    unsigned char latin[128];
    int latin_len;
    ASN1_STRING *astr;
    char *decoded;
    X509 *cert;
    unsigned char nulhost[sizeof(HOST) + 4];

    printf("issue_5bg289fd_bmpstring_cn\n");

    latin_len = latin_bmp(HOST, latin, sizeof(latin));
    expect(latin_len > 0, "latin bmpstring built");

    /* The bug: content bytes are the host name, type is BMPString. */
    test_hostname(V_ASN1_BMPSTRING, HOST, (int)strlen(HOST), HOST,
                  VERIFY_FALSE,
                  "bmpstring bytes of the host name do not match");
    test_hostname(V_ASN1_BMPSTRING, WILD, (int)strlen(WILD), OTHER,
                  VERIFY_FALSE,
                  "bmpstring wildcard bytes do not match a host in the domain");
    test_hostname(V_ASN1_UNIVERSALSTRING, HOST, (int)strlen(HOST), HOST,
                  VERIFY_FALSE,
                  "universalstring bytes of the host name do not match");
    test_hostname(V_ASN1_BMPSTRING, DOTTED, (int)strlen(DOTTED), DOTTED_HOST,
                  VERIFY_FALSE,
                  "odd-length bmpstring with a trailing dot does not match");

    /* A BMPString that really is the host name, in UTF-16, does match. */
    test_hostname(V_ASN1_BMPSTRING, latin, latin_len, HOST, VERIFY_TRUE,
                  "latin bmpstring matches the host name");

    /* Names that were already compared correctly stay that way. */
    test_hostname(V_ASN1_UTF8STRING, HOST, (int)strlen(HOST), HOST,
                  VERIFY_TRUE, "utf8 host name matches");
    test_hostname(V_ASN1_IA5STRING, HOST, (int)strlen(HOST), HOST,
                  VERIFY_TRUE, "ia5 host name matches");
    test_hostname(V_ASN1_PRINTABLESTRING, HOST, (int)strlen(HOST), HOST,
                  VERIFY_TRUE, "printable host name matches");
    test_hostname(V_ASN1_UTF8STRING, WILD, (int)strlen(WILD), OTHER,
                  VERIFY_TRUE, "utf8 wildcard matches a host in the domain");
    test_hostname(V_ASN1_UTF8STRING, HOST, (int)strlen(HOST), OTHER,
                  VERIFY_FALSE, "different host name does not match");

    /* NUL after a complete host name. A copy that stops at the first NUL
     * would match HOST, so this fails unless the embedded-NUL check runs. */
    memcpy(nulhost, HOST, sizeof(HOST));
    memcpy(nulhost + sizeof(HOST), "evil", 4);
    test_hostname(V_ASN1_UTF8STRING, nulhost, (int)(sizeof(HOST) + 4), HOST,
                  VERIFY_FALSE, "embedded nul is rejected");

    astr = make_str(V_ASN1_BMPSTRING, HOST, (int)strlen(HOST));
    expect(astr != NULL, "bmpstring allocated");
    if (astr != NULL) {
        decoded = asn1_to_cstr(astr);
        expect(decoded == NULL || strcmp(decoded, HOST) != 0,
               "decoded bmpstring is not the raw host name");
        free(decoded);
        ASN1_STRING_free(astr);
    }

    astr = make_str(V_ASN1_BMPSTRING, latin, latin_len);
    expect(astr != NULL, "latin bmpstring allocated");
    if (astr != NULL) {
        decoded = asn1_to_cstr(astr);
        expect(decoded != NULL && strcmp(decoded, HOST) == 0,
               "decoded latin bmpstring is the host name");
        free(decoded);
        ASN1_STRING_free(astr);
    }

    cert = cert_org_then_cn(V_ASN1_BMPSTRING, HOST, (int)strlen(HOST));
    expect(cert != NULL, "certificate allocated");
    if (cert != NULL) {
        expect(check_subject_cn(cert, HOST) == VERIFY_FALSE,
               "common name bmpstring bytes do not match");
        X509_free(cert);
    }

    cert = cert_org_then_cn(V_ASN1_UTF8STRING, HOST, (int)strlen(HOST));
    expect(cert != NULL, "utf8 certificate allocated");
    if (cert != NULL) {
        expect(check_subject_cn(cert, HOST) == VERIFY_TRUE,
               "utf8 common name matches");
        X509_free(cert);
    }

    if (failures) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
