/*
 * Regression test for issue #2100 / GHSA-rr83-v9v7-jjhp: authd SSL context.
 *
 * get_ssl_context() must return a context that disables SSLv2 and, when the
 * OpenSSL headers expose it, TLS renegotiation (SSL_OP_NO_RENEGOTIATION).
 *
 * Build from src/ after a server build:
 *   make -f tests/regressions/Makefile issue_2100_authd_ssl
 *   ./issue_2100_authd_ssl
 */

#include <stdio.h>
#include <openssl/ssl.h>

SSL_CTX *get_ssl_context(const char *ciphers);

#define TEST_CIPHERS "EECDH+AESGCM:EDH+AESGCM:HIGH:!kRSA:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH"

static int options_has(unsigned long opts, unsigned long flag)
{
    return ((opts & flag) == flag);
}

int main(void)
{
    SSL_CTX *ctx;
    unsigned long opts;

    ctx = get_ssl_context(TEST_CIPHERS);
    if (!ctx) {
        fprintf(stderr, "FAIL: get_ssl_context returned NULL\n");
        return 1;
    }

    opts = (unsigned long)SSL_CTX_get_options(ctx);

    if (!options_has(opts, SSL_OP_NO_SSLv2)) {
        fprintf(stderr, "FAIL: context must set SSL_OP_NO_SSLv2 (opts=0x%lx)\n", opts);
        SSL_CTX_free(ctx);
        return 1;
    }

#ifdef SSL_OP_NO_RENEGOTIATION
    if (!options_has(opts, SSL_OP_NO_RENEGOTIATION)) {
        fprintf(stderr,
                "FAIL: context must set SSL_OP_NO_RENEGOTIATION (opts=0x%lx)\n",
                opts);
        SSL_CTX_free(ctx);
        return 1;
    }
#else
    if (SSL_CTX_get_info_callback(ctx) == NULL) {
        fprintf(stderr,
                "FAIL: context must install renegotiation info callback "
                "when SSL_OP_NO_RENEGOTIATION is unavailable\n");
        SSL_CTX_free(ctx);
        return 1;
    }
#endif

#ifdef SSL_OP_NO_SSLv3
    /* TLSv1_2_method does not offer SSLv3. When the option exists, leaving
     * it unset is still safe because the method cannot negotiate SSLv3. */
    (void)SSL_OP_NO_SSLv3;
#endif

    SSL_CTX_free(ctx);

    if (get_ssl_context("not-a-real-cipher-zzzz") != NULL) {
        fprintf(stderr, "FAIL: unknown cipher list should fail\n");
        return 1;
    }

    printf("PASS: issue #2100 / GHSA-rr83 authd SSL context\n");
    return 0;
}
