/*
 * ANT-2026-8TB11KJO: read_ossecalert must not let ';' in user/srcip (or
 * other forwarded fields) start a new field on the central manager, and
 * must keep the closing ';' when values approach the 255-byte buffer.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_ossecalert_field_injection
 */

#include <stdio.h>
#include <string.h>

#include "logcollector/ossecalert_field.h"

/* Mimic OSSECAlert_Decoder_Exec: after Location, take " name: value;"
 * until two spaces. A later srcip: overwrites the earlier one. */
static int decode_srcip_from_fields(const char *fields, char *out, size_t out_sz)
{
    const char *p = fields;
    char buf[512];
    size_t n;

    out[0] = '\0';
    while (*p == ' ' && p[1] != ' ' && p[1] != '\0') {
        const char *semi = strchr(p, ';');
        if (!semi) {
            return (-1);
        }
        n = (size_t)(semi - p);
        if (n >= sizeof(buf)) {
            return (-1);
        }
        memcpy(buf, p, n);
        buf[n] = '\0';
        if (strncmp(buf, " srcip: ", 8) == 0) {
            strncpy(out, buf + 8, out_sz - 1);
            out[out_sz - 1] = '\0';
        }
        p = semi + 1;
    }
    return (0);
}

int main(void)
{
    char user[512];
    char srcip[] = "198.51.100.7";
    char user_msg[256];
    char srcip_msg[256];
    char fields[600];
    char decoded[128];
    char long_user[300];
    size_t i;
    int failed = 0;

    printf("=== ANT-2026-8TB11KJO: ossecalert field injection ===\n");

    /* Spoof: user carries "; srcip: <fake>" like a PIX-captured name. */
    snprintf(user, sizeof(user), "admin; srcip: 10.9.9.9");
    OS_OaCleanField(user);
    if (strchr(user, ';') != NULL) {
        printf("  FAIL: OS_OaCleanField left ';' in user ('%s')\n", user);
        failed = 1;
    } else if (strcmp(user, "admin, srcip: 10.9.9.9") != 0) {
        printf("  FAIL: unexpected cleaned user ('%s')\n", user);
        failed = 1;
    } else {
        printf("  ok: CleanField maps ';' -> ','\n");
    }

    OS_OaCleanField(srcip);
    if (OS_OaFormatTaggedField(srcip_msg, sizeof(srcip_msg), "srcip", srcip) != 0 ||
            OS_OaFormatTaggedField(user_msg, sizeof(user_msg), "user", user) != 0) {
        printf("  FAIL: FormatTaggedField rejected\n");
        failed = 1;
    } else {
        snprintf(fields, sizeof(fields), "%s%s  log", srcip_msg, user_msg);
        if (decode_srcip_from_fields(fields, decoded, sizeof(decoded)) != 0) {
            printf("  FAIL: decode helper failed on '%s'\n", fields);
            failed = 1;
        } else if (strcmp(decoded, "198.51.100.7") != 0) {
            printf("  FAIL: decoder saw srcip '%s' (want 198.51.100.7) fields='%s'\n",
                   decoded, fields);
            failed = 1;
        } else {
            printf("  ok: forwarded fields keep real srcip\n");
        }
    }

    /* Closing ';' must survive a near-full user value. */
    for (i = 0; i < 247; i++) {
        long_user[i] = 'A';
    }
    long_user[247] = '\0';
    OS_OaCleanField(long_user);
    if (OS_OaFormatTaggedField(user_msg, sizeof(user_msg), "user", long_user) != 0) {
        printf("  FAIL: FormatTaggedField rejected long user\n");
        failed = 1;
    } else {
        size_t len = strlen(user_msg);
        if (len == 0 || user_msg[len - 1] != ';') {
            printf("  FAIL: long user field missing closing ';' ('%s')\n", user_msg);
            failed = 1;
        } else if (len > 255) {
            printf("  FAIL: user_msg longer than historical buffer (%zu)\n", len);
            failed = 1;
        } else {
            printf("  ok: long user keeps closing ';'\n");
        }
    }

    if (failed) {
        printf("\nFAIL: issue_ossecalert_field_injection\n");
        return 1;
    }

    printf("\nPASS: issue_ossecalert_field_injection\n");
    return 0;
}
