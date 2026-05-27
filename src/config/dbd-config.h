/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _DBDCONFIG__H
#define _DBDCONFIG__H

/* Database config structure */
typedef struct _DBConfig {
    unsigned int db_type;
    unsigned int alert_id;
    unsigned int server_id;
    unsigned int error_count;
    unsigned int maxreconnect;
    unsigned int port;

    char *host;
    char *user;
    char *pass;
    char *db;
    char *sock;

    void *conn;
    OSHash *location_hash;

    void *(*db_connect)(const char *host, const char *user, const char *pass, const char *db, unsigned int port, const char *sock);
    int (*db_query_insert)(struct _DBConfig *config, const char *query);
    int (*db_query_select)(struct _DBConfig *config, const char *query);
    void (*db_close)(void *conn);
    void (*db_escapestr)(char *str);

    char **includes;
} DBConfig;

#define MYSQLDB 0x002
#define POSTGDB 0x004

#endif /* _DBDCONFIG__H */

