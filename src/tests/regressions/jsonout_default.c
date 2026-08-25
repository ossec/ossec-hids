/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * jsonout_output defaults on when <jsonout_output> is omitted.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "shared.h"
#include "analysisd/config.h"

static int failures;

static int write_cfg(const char *path, const char *xml)
{
    FILE *fp = fopen(path, "w");
    if (!fp) {
        fprintf(stderr, "FAIL: fopen %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (fputs(xml, fp) == EOF) {
        fprintf(stderr, "FAIL: write %s\n", path);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

static void expect_jsonout(const char *label, const char *xml, int want)
{
    char path[] = "/tmp/jsonout-default-XXXXXX";
    int fd;
    char cfg[64];

    fd = mkstemp(path);
    if (fd < 0) {
        fprintf(stderr, "FAIL: mkstemp: %s\n", strerror(errno));
        failures++;
        return;
    }
    close(fd);
    snprintf(cfg, sizeof(cfg), "%s.conf", path);
    unlink(path);
    if (write_cfg(cfg, xml) != 0) {
        failures++;
        return;
    }

    if (GlobalConf(cfg) < 0) {
        fprintf(stderr, "FAIL: %s: GlobalConf() rejected config\n", label);
        failures++;
        unlink(cfg);
        return;
    }
    unlink(cfg);

    if (Config.jsonout_output != want) {
        fprintf(stderr, "FAIL: %s: jsonout_output=%u want %d\n",
                label, Config.jsonout_output, want);
        failures++;
        return;
    }
    printf("OK: %s (jsonout_output=%u)\n", label, Config.jsonout_output);
}

int main(void)
{
    expect_jsonout(
        "no ossec_config children",
        "<ossec_config>\n</ossec_config>\n",
        1);

    expect_jsonout(
        "global without jsonout_output",
        "<ossec_config>\n"
        "  <global>\n"
        "    <email_notification>no</email_notification>\n"
        "  </global>\n"
        "</ossec_config>\n",
        1);

    expect_jsonout(
        "jsonout_output no",
        "<ossec_config>\n"
        "  <global>\n"
        "    <jsonout_output>no</jsonout_output>\n"
        "  </global>\n"
        "</ossec_config>\n",
        0);

    expect_jsonout(
        "jsonout_output yes",
        "<ossec_config>\n"
        "  <global>\n"
        "    <jsonout_output>yes</jsonout_output>\n"
        "  </global>\n"
        "</ossec_config>\n",
        1);

    if (failures) {
        fprintf(stderr, "FAIL: jsonout default (%d)\n", failures);
        return 1;
    }
    printf("PASS: jsonout_output defaults on when undeclared\n");
    return 0;
}
