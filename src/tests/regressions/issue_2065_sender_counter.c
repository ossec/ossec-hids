/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Issue 2065: persisting the outbound sender counter must not write into
 * agent 0's rids file when keysize has been zeroed (OS_FreeKeys race).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "shared.h"
#include "headers/sec.h"

static int failures;

static int write_counter(const char *path, unsigned int g, unsigned int l)
{
    FILE *fp = fopen(path, "w+");
    if (!fp) {
        fprintf(stderr, "FAIL: fopen %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (fprintf(fp, "%u:%u:", g, l) < 0) {
        fprintf(stderr, "FAIL: write %s\n", path);
        fclose(fp);
        return -1;
    }
    fflush(fp);
    fclose(fp);
    return 0;
}

static int read_counter(const char *path, unsigned int *g, unsigned int *l)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "FAIL: reopen %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (fscanf(fp, "%u:%u", g, l) != 2) {
        fprintf(stderr, "FAIL: parse %s\n", path);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

static FILE *open_rw(const char *path)
{
    FILE *fp = fopen(path, "r+");
    if (!fp) {
        fprintf(stderr, "FAIL: r+ %s: %s\n", path, strerror(errno));
    }
    return fp;
}

static int expect_pair(const char *label, const char *path, unsigned int want_g, unsigned int want_l)
{
    unsigned int g = 0, l = 0;

    if (read_counter(path, &g, &l) != 0) {
        failures++;
        return -1;
    }
    if (g != want_g || l != want_l) {
        fprintf(stderr, "FAIL: %s is %u:%u (want %u:%u)\n", label, g, l, want_g, want_l);
        failures++;
        return -1;
    }
    printf("OK: %s %u:%u\n", label, g, l);
    return 0;
}

int main(void)
{
    char agent_path[] = "/tmp/ossec-2065-agent-XXXXXX";
    char sender_path[] = "/tmp/ossec-2065-sender-XXXXXX";
    int agent_fd, sender_fd;
    keystore keys;
    keyentry agent;
    keyentry *agent_ptr;
    FILE *agent_fp;
    FILE *sender_fp;

    agent_fd = mkstemp(agent_path);
    sender_fd = mkstemp(sender_path);
    if (agent_fd < 0 || sender_fd < 0) {
        fprintf(stderr, "FAIL: mkstemp: %s\n", strerror(errno));
        return 1;
    }
    close(agent_fd);
    close(sender_fd);

    if (write_counter(agent_path, 1, 2) != 0 ||
            write_counter(sender_path, 100, 200) != 0) {
        unlink(agent_path);
        unlink(sender_path);
        return 1;
    }

    memset(&keys, 0, sizeof(keys));
    memset(&agent, 0, sizeof(agent));
    agent_ptr = &agent;
    keys.keyentries = &agent_ptr;
    keys.keysize = 1;

    agent_fp = open_rw(agent_path);
    sender_fp = open_rw(sender_path);
    if (!agent_fp || !sender_fp) {
        if (agent_fp) {
            fclose(agent_fp);
        }
        if (sender_fp) {
            fclose(sender_fp);
        }
        unlink(agent_path);
        unlink(sender_path);
        return 1;
    }

    agent.fp = agent_fp;
    keys.sender_fp = sender_fp;

    /* Normal path: keysize is still the agent count. */
    OS_StoreSenderCounter(&keys, 300, 400);
    expect_pair("agent rids after keyed write", agent_path, 1, 2);
    expect_pair("sender after keyed write", sender_path, 300, 400);

    /* Simulate OS_FreeKeys: keysize is zeroed while sender_fp stays open. */
    keys.keysize = 0;
    OS_StoreSenderCounter(&keys, 99999, 8888);

    fclose(agent_fp);
    fclose(sender_fp);
    keys.sender_fp = NULL;

    expect_pair("agent 0 rids while keysize==0", agent_path, 1, 2);
    expect_pair("sender counter dedicated file", sender_path, 99999, 8888);

    /* NULL sender_fp must be a no-op (reload window after close). */
    OS_StoreSenderCounter(&keys, 1, 1);

    unlink(agent_path);
    unlink(sender_path);

    if (failures) {
        fprintf(stderr, "FAIL: issue 2065 sender-counter isolation\n");
        return 1;
    }

    printf("PASS: issue #2065 sender counter does not overwrite agent 0\n");
    return 0;
}
