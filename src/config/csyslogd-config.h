/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"

#ifndef _CSYSLOGCONFIG__H
#define _CSYSLOGCONFIG__H

/* Syslog transport */
#define CSYSLOG_UDP  0
#define CSYSLOG_TCP  1

/* Database config structure */
typedef struct _SyslogConfig {
    char *port;
    unsigned int format;
    unsigned int level;
    unsigned int *rule_id;
    unsigned int priority;
    unsigned int use_fqdn;
    unsigned int protocol;   /* CSYSLOG_UDP or CSYSLOG_TCP */
    unsigned int tls;        /* 1 = wrap TCP in TLS */
    unsigned int tls_verify; /* 1 = verify peer (default) */
    int socket;

    char *server;
    char *tls_ca;            /* optional CA file path (pre-chroot) */
    OSMatch *group;
    OSMatch *location;

    /* Runtime transport state (updated on reconnect; not from XML). */
    void *ssl;               /* SSL* when tls */
    void *ssl_ctx;           /* SSL_CTX* when tls */
} SyslogConfig;

struct SyslogConfig_holder {
    SyslogConfig **data;
};

/* Syslog formats */
#define DEFAULT_CSYSLOG  0
#define CEF_CSYSLOG      1
#define JSON_CSYSLOG     2
#define SPLUNK_CSYSLOG   3

/* Syslog severities */
#define SLOG_EMERG   0   /* system is unusable */
#define SLOG_ALERT   1   /* action must be taken immediately */
#define SLOG_CRIT    2   /* critical conditions */
#define SLOG_ERR     3   /* error conditions */
#define SLOG_WARNING 4   /* warning conditions */
#define SLOG_NOTICE  5   /* normal but significant condition */
#define SLOG_INFO    6   /* informational */
#define SLOG_DEBUG   7   /* debug-level messages */

#endif /* _CSYSLOGCONFIG__H */
