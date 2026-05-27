/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_xml/os_xml.h"
#include "os_regex/os_regex.h"
#include "os_net/os_net.h"
#include "remoted.h"
#include "config/config.h"


/* Read the config file (the remote access) */
int RemotedConfig(const char *cfgfile, remoted *cfg)
{
    int modules = 0;

    modules |= CREMOTE;

    cfg->port = NULL;
    cfg->conn = NULL;
    cfg->proto = NULL;
    cfg->ipv6 = NULL;
    cfg->lip = NULL;
    cfg->allowips = NULL;
    cfg->denyips = NULL;

    if (ReadConfig(modules, cfgfile, cfg, NULL) < 0) {
        return (OS_INVALID);
    }

    return (1);
}

/* Free the remote configuration */
void FreeRemotedConfig(remoted *cfg)
{
    int i = 0;

    if (cfg->port) {
        while (cfg->port[i]) {
            free(cfg->port[i]);
            i++;
        }
        free(cfg->port);
        cfg->port = NULL;
    }

    if (cfg->lip) {
        i = 0;
        while (cfg->lip[i]) {
            free(cfg->lip[i]);
            i++;
        }
        free(cfg->lip);
        cfg->lip = NULL;
    }

    free(cfg->conn);
    free(cfg->proto);
    free(cfg->ipv6);

    cfg->conn = NULL;
    cfg->proto = NULL;
    cfg->ipv6 = NULL;

    if (cfg->allowips) {
        i = 0;
        while (cfg->allowips[i]) {
            free(cfg->allowips[i]->ip);
            free(cfg->allowips[i]);
            i++;
        }
        free(cfg->allowips);
        cfg->allowips = NULL;
    }

    if (cfg->denyips) {
        i = 0;
        while (cfg->denyips[i]) {
            free(cfg->denyips[i]->ip);
            free(cfg->denyips[i]);
            i++;
        }
        free(cfg->denyips);
        cfg->denyips = NULL;
    }
}

static int remoted_str_array_changed(char **old_a, char **new_a)
{
    int i = 0;

    if (!old_a && !new_a) {
        return (0);
    }
    if (!old_a || !new_a) {
        return (1);
    }

    while (old_a[i] || new_a[i]) {
        if (!old_a[i] || !new_a[i]) {
            return (1);
        }
        if (strcmp(old_a[i], new_a[i]) != 0) {
            return (1);
        }
        i++;
    }

    return (0);
}

static int remoted_int_array_changed(int *old_a, int *new_a)
{
    int i = 0;

    if (!old_a && !new_a) {
        return (0);
    }
    if (!old_a || !new_a) {
        return (1);
    }

    while (1) {
        if (!old_a[i] && !new_a[i]) {
            break;
        }
        if (old_a[i] != new_a[i]) {
            return (1);
        }
        i++;
    }

    return (0);
}

/* Listener count: conn[] uses 0 only as end-of-list sentinel (see remote-config.c). */
static int remoted_listener_count(const remoted *cfg)
{
    int pl = 0;

    if (!cfg || !cfg->conn) {
        return (0);
    }

    while (cfg->conn[pl] != 0) {
        pl++;
    }

    return (pl);
}

/* Per-listener int arrays (ipv6, proto): 0 may be a valid entry; use conn[] count. */
static int remoted_listener_int_array_changed(const remoted *old_cfg, const remoted *new_cfg,
                                              int *old_a, int *new_a)
{
    int old_n;
    int new_n;
    int i;

    old_n = remoted_listener_count(old_cfg);
    new_n = remoted_listener_count(new_cfg);

    if (old_n != new_n) {
        return (1);
    }

    if (old_n == 0) {
        return (0);
    }

    if (!old_a || !new_a) {
        return (old_a != new_a);
    }

    for (i = 0; i < old_n; i++) {
        if (old_a[i] != new_a[i]) {
            return (1);
        }
    }

    return (0);
}

/* Return 1 if listen/bind-related remote settings differ */
int RemotedBindSettingsChanged(const remoted *old_cfg, const remoted *new_cfg)
{
    if (!old_cfg || !new_cfg) {
        return (0);
    }

    if (remoted_str_array_changed(old_cfg->port, new_cfg->port)) {
        return (1);
    }
    if (remoted_int_array_changed(old_cfg->conn, new_cfg->conn)) {
        return (1);
    }
    if (remoted_listener_int_array_changed(old_cfg, new_cfg, old_cfg->proto, new_cfg->proto)) {
        return (1);
    }
    if (remoted_listener_int_array_changed(old_cfg, new_cfg, old_cfg->ipv6, new_cfg->ipv6)) {
        return (1);
    }
    if (remoted_str_array_changed(old_cfg->lip, new_cfg->lip)) {
        return (1);
    }

    return (0);
}

#ifndef WIN32
static void remoted_sigmask_for_lock(sigset_t *block_set, sigset_t *old_set, int unblock)
{
    if (block_set && old_set) {
        if (unblock) {
            sigprocmask(SIG_SETMASK, old_set, NULL);
        } else {
            sigprocmask(SIG_BLOCK, block_set, NULL);
        }
    }
}
#else
static void remoted_sigmask_for_lock(sigset_t *block_set, sigset_t *old_set, int unblock)
{
    (void)block_set;
    (void)old_set;
    (void)unblock;
}
#endif

void RemotedConfigSwap(remoted *logr, remoted *new_logr, sigset_t *block_set, sigset_t *old_set)
{
    remoted_sigmask_for_lock(block_set, old_set, 1);
    send_msg_lock();
    remoted_sigmask_for_lock(block_set, old_set, 0);

    FreeRemotedConfig(logr);
    memcpy(logr, new_logr, sizeof(remoted));

    send_msg_unlock();
}

int RemotedReloadFromSighup(const char *cfgfile, remoted *logr, sigset_t *block_set, sigset_t *old_set)
{
    remoted new_logr;

    memset(&new_logr, 0, sizeof(remoted));
    new_logr.m_queue = logr->m_queue;
    new_logr.netinfo = logr->netinfo;

    if (RemotedConfig(cfgfile, &new_logr) < 0) {
        merror("%s: ERROR: Error reloading configuration (using old config)", ARGV0);
        FreeRemotedConfig(&new_logr);
        return (-1);
    }

    if (RemotedBindSettingsChanged(logr, &new_logr)) {
        merror("%s: INFO: Bind settings changed; restart ossec-remoted required (using old config).", ARGV0);
        FreeRemotedConfig(&new_logr);
        return (0);
    }

    RemotedConfigSwap(logr, &new_logr, block_set, old_set);
    return (1);
}

