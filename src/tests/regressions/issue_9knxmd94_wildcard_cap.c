/*
 * Regression: a wildcard <location> has no limit on the files it adds
 *
 * ANT-2026-9KNXMD94 / CWE-770
 *
 * Read_Localfile() appends one logreader for every glob() match. A local
 * account that can create files in that directory can make ossec-logcollector
 * open more files than RLIMIT_NOFILE, so later logs and command monitors
 * are dropped. One pattern must stop at logcollector.max_wildcard_files.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_9knxmd94_wildcard_cap
 *
 * Run:
 *   ./issue_9knxmd94_wildcard_cap
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "os_xml/os_xml.h"
#include "config/config.h"
#include "config/localfile-config.h"

const char *__local_name __attribute__((weak)) =
    "issue-9knxmd94-wildcard-cap";

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

static int count_files(const logreader *logf)
{
    int n = 0;

    if (!logf) {
        return 0;
    }
    while (logf[n].file) {
        n++;
    }
    return n;
}

static int has_suffix(const logreader *logf, const char *suffix)
{
    int i;

    for (i = 0; logf[i].file; i++) {
        size_t flen = strlen(logf[i].file);
        size_t slen = strlen(suffix);

        if (flen >= slen && strcmp(logf[i].file + flen - slen, suffix) == 0) {
            return 1;
        }
    }
    return 0;
}

int main(void)
{
    char dir[] = "/tmp/9knxmd94-XXXXXX";
    char pattern[256];
    char plain[256];
    char path[256];
    const char *names[] = {"a.log", "b.log", "c.log", "d.log", "e.log"};
    xml_node location;
    xml_node format;
    xml_node *nodes[3];
    xml_node plain_loc;
    xml_node plain_fmt;
    xml_node *plain_nodes[3];
    logreader_config cfg;
    int i;
    FILE *fp;

    printf("wildcard localfile expansion cap\n");
    if (!mkdtemp(dir)) {
        perror("mkdtemp");
        return 1;
    }

    for (i = 0; i < 5; i++) {
        snprintf(path, sizeof(path), "%s/%s", dir, names[i]);
        fp = fopen(path, "w");
        if (!fp) {
            perror(path);
            return 1;
        }
        fclose(fp);
    }

    snprintf(pattern, sizeof(pattern), "%s/*.log", dir);
    memset(&location, 0, sizeof(location));
    memset(&format, 0, sizeof(format));
    location.element = "location";
    location.content = pattern;
    format.element = "log_format";
    format.content = "syslog";
    nodes[0] = &location;
    nodes[1] = &format;
    nodes[2] = NULL;

    memset(&cfg, 0, sizeof(cfg));
    cfg.max_wildcard_files = 2;
    expect(Read_Localfile(nodes, &cfg, NULL) == 0, "wildcard block is accepted");
    expect(count_files(cfg.config) == 2, "one wildcard keeps only the first 2 matches");
    expect(has_suffix(cfg.config, "/a.log"), "a.log is monitored");
    expect(has_suffix(cfg.config, "/b.log"), "b.log is monitored");
    expect(!has_suffix(cfg.config, "/c.log"), "c.log is past the cap");
    expect(!has_suffix(cfg.config, "/e.log"), "e.log is past the cap");

    snprintf(plain, sizeof(plain), "%s/auth.log", dir);
    fp = fopen(plain, "w");
    if (!fp) {
        perror(plain);
        return 1;
    }
    fclose(fp);

    memset(&plain_loc, 0, sizeof(plain_loc));
    memset(&plain_fmt, 0, sizeof(plain_fmt));
    plain_loc.element = "location";
    plain_loc.content = plain;
    plain_fmt.element = "log_format";
    plain_fmt.content = "syslog";
    plain_nodes[0] = &plain_loc;
    plain_nodes[1] = &plain_fmt;
    plain_nodes[2] = NULL;
    expect(Read_Localfile(plain_nodes, &cfg, NULL) == 0, "a later plain file is accepted");
    expect(count_files(cfg.config) == 3, "the plain file is kept after the capped wildcard");
    expect(has_suffix(cfg.config, "/auth.log"), "auth.log is monitored");

    if (cfg.config) {
        for (i = 0; cfg.config[i].file; i++) {
            free(cfg.config[i].file);
            free(cfg.config[i].ffile);
            free(cfg.config[i].logformat);
        }
        free(cfg.config);
    }
    for (i = 0; i < 5; i++) {
        snprintf(path, sizeof(path), "%s/%s", dir, names[i]);
        unlink(path);
    }
    unlink(plain);
    rmdir(dir);

    if (failures) {
        printf("FAIL: %d wildcard cap check(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
