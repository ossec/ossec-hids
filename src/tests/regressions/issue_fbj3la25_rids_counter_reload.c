/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * ANT-2026-FBJ3LA25: freeing the keystore (client.keys reload) must persist
 * each agent's in-memory receive counter to its rids file. ReadSecMSG only
 * stores it every recv_counter_flush messages, so without this
 * OS_StartCounter rewinds the replay check and recorded agent datagrams
 * are accepted again.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_fbj3la25_rids_counter_reload
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

/* One heap-allocated entry, as __chash() builds them, so OS_FreeKeys can free it. */
static keyentry *make_entry(const char *id, FILE *fp, unsigned int g, unsigned int l)
{
    keyentry *entry;

    os_calloc(1, sizeof(keyentry), entry);
    os_strdup(id, entry->id);
    os_strdup(id, entry->name);
    os_strdup("", entry->key);
    os_calloc(1, sizeof(os_ip), entry->ip);
    os_strdup("any", entry->ip->ip);
    pthread_mutex_init(&entry->mutex, NULL);
    entry->fp = fp;
    entry->global = g;
    entry->local = l;
    return entry;
}

int main(void)
{
    char rids_path[] = "/tmp/ossec-rids-reload-XXXXXX";
    int fd;
    keystore keys;
    FILE *fp;

    fd = mkstemp(rids_path);
    if (fd < 0) {
        fprintf(stderr, "FAIL: mkstemp: %s\n", strerror(errno));
        return 1;
    }
    close(fd);

    /* The file holds the last periodic flush; memory is ahead of it. */
    if (write_counter(rids_path, 0, 0) != 0) {
        unlink(rids_path);
        return 1;
    }

    fp = fopen(rids_path, "r+");
    if (!fp) {
        fprintf(stderr, "FAIL: r+ %s: %s\n", rids_path, strerror(errno));
        unlink(rids_path);
        return 1;
    }

    memset(&keys, 0, sizeof(keys));
    os_calloc(2, sizeof(keyentry *), keys.keyentries);
    keys.keyentries[0] = make_entry("001", fp, 0, 4);
    /* No counter file opened (CLI tools never call OS_StartCounter). */
    keys.keyentries[1] = make_entry("002", NULL, 7, 7);
    keys.keysize = 2;

    /* Direct call, as the shutdown path does. */
    OS_StoreAgentCounters(&keys);
    expect_pair("rids after OS_StoreAgentCounters", rids_path, 0, 4);

    keys.keyentries[0]->local = 9;

    /* Reload path: OS_UpdateKeys frees the keystore before OS_StartCounter
     * reads the counters back from the rids files.
     */
    OS_FreeKeys(&keys);
    expect_pair("rids after OS_FreeKeys", rids_path, 0, 9);

    if (keys.keysize != 0 || keys.keyentries != NULL) {
        fprintf(stderr, "FAIL: keystore not freed\n");
        failures++;
    }

    unlink(rids_path);

    if (failures) {
        fprintf(stderr, "FAIL: receive counters lost on keystore free\n");
        return 1;
    }

    printf("PASS: agent receive counters are stored before the keystore is freed\n");
    return 0;
}
