/*
 * GetAlertData must not underflow when stripping the trailing quote from
 * an empty "Integrity checksum changed for: '" payload.
 *
 * Build from src/ after a server build:
 *   make -f tests/regressions/Makefile getalert_empty_filename
 *   ./getalert_empty_filename
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "shared.h"
#include "read-alert.h"

const char *__local_name = "getalert-empty-filename";

static int write_alert(const char *path, const char *integrity_line)
{
    FILE *fp;

    fp = fopen(path, "w");
    if (!fp) {
        perror(path);
        return 0;
    }

    fprintf(fp,
            "** Alert 1609459200.123456: - syscheck,\n"
            "2021 Jan 01 00:00:00 host->/var/log/test\n"
            "Rule: 550 (level 7) -> 'Integrity checksum changed.'\n"
            "%s\n"
            "\n",
            integrity_line);
    fclose(fp);
    return 1;
}

static int run_case(const char *label, const char *integrity_line,
                    const char *expect_filename)
{
    char path[] = "/tmp/ossec-getalert-XXXXXX";
    int fd;
    FILE *fp;
    alert_data *al;

    fd = mkstemp(path);
    if (fd < 0) {
        perror("mkstemp");
        return 0;
    }
    close(fd);

    if (!write_alert(path, integrity_line)) {
        unlink(path);
        return 0;
    }

    fp = fopen(path, "r");
    if (!fp) {
        perror(path);
        unlink(path);
        return 0;
    }

    al = GetAlertData(0, fp);
    fclose(fp);
    unlink(path);

    if (!al) {
        fprintf(stderr, "FAIL %s: GetAlertData returned NULL\n", label);
        return 0;
    }

    if (expect_filename == NULL) {
        if (al->filename != NULL) {
            fprintf(stderr, "FAIL %s: expected NULL filename, got '%s'\n",
                    label, al->filename);
            FreeAlertData(al);
            return 0;
        }
    } else if (!al->filename || strcmp(al->filename, expect_filename) != 0) {
        fprintf(stderr, "FAIL %s: expected '%s', got '%s'\n",
                label, expect_filename,
                al->filename ? al->filename : "(null)");
        FreeAlertData(al);
        return 0;
    }

    FreeAlertData(al);
    return 1;
}

int main(void)
{
    /* Empty payload after the opening quote: previously wrote filename[-1]. */
    if (!run_case("empty", "Integrity checksum changed for: '", NULL)) {
        return 1;
    }

    /* Explicit empty quotes also become NULL, not "". */
    if (!run_case("empty_quotes", "Integrity checksum changed for: ''", NULL)) {
        return 1;
    }

    /* Normal quoted path still strips the trailing quote. */
    if (!run_case("quoted_path", "Integrity checksum changed for: '/etc/passwd'",
                  "/etc/passwd")) {
        return 1;
    }

    printf("PASS: GetAlertData empty filename\n");
    return 0;
}
