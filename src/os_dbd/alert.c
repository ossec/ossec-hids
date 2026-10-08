/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "dbd.h"
#include "config/config.h"
#include "config/dbd-config.h"
#include "rules_op.h"

/* Prototypes */
static int __DBSelectLocation(const char *location, const DBConfig *db_config) __attribute__((nonnull));
static int __DBInsertLocation(const char *location, const DBConfig *db_config) __attribute__((nonnull));

/*
 * Build a SQL token for a nullable string column: unquoted NULL, or a
 * single-quoted literal. Escapes the field in place when present (same
 * allow-list path as other os_dbd inserts).
 *
 * out must hold at least strlen(field) + 3 bytes when field is non-NULL
 * (quotes + NUL). IP fields use INET6_ADDRSTRLEN-scale buffers.
 */
static void sql_nullable_str(char *out, size_t outlen, char *field)
{
    if (!field) {
        snprintf(out, outlen, "NULL");
        return;
    }

    osdb_escapestr(field);
    snprintf(out, outlen, "'%s'", field);
}


/* Select the maximum ID from the alert table
 * Returns 0 if not found
 */
int OS_SelectMaxID(const DBConfig *db_config)
{
    int result = 0;
    char sql_query[OS_SIZE_1024];

    memset(sql_query, '\0', OS_SIZE_1024);

    /* Generate SQL */
    snprintf(sql_query, OS_SIZE_1024 - 1,
             "SELECT MAX(id) FROM "
             "alert WHERE server_id = '%u'",
             db_config->server_id);

    result = osdb_query_select(db_config->conn, sql_query);

    return (result);
}


/* Select the location ID from the db
 * Returns 0 if not found
 */
static int __DBSelectLocation(const char *location, const DBConfig *db_config)
{
    int result = 0;
    char sql_query[OS_SIZE_1024];

    memset(sql_query, '\0', OS_SIZE_1024);

    /* Generate SQL */
    snprintf(sql_query, OS_SIZE_1024 - 1,
             "SELECT id FROM "
             "location WHERE name = '%s' AND server_id = '%d' "
             "LIMIT 1",
             location, db_config->server_id);

    result = osdb_query_select(db_config->conn, sql_query);

    return (result);
}

/* Insert location in to the db */
static int __DBInsertLocation(const char *location, const DBConfig *db_config)
{
    char sql_query[OS_SIZE_1024];

    memset(sql_query, '\0', OS_SIZE_1024);

    /* Generate SQL */
    snprintf(sql_query, OS_SIZE_1024 - 1,
             "INSERT INTO "
             "location(server_id, name) "
             "VALUES ('%u', '%s')",
             db_config->server_id, location);

    if (!osdb_query_insert(db_config->conn, sql_query)) {
        merror(DB_GENERROR, ARGV0);
    }

    return (0);
}

/* Cap a mutable SQL string field so snprintf into OS_SIZE_8192 cannot
 * cut mid-quote (#1959). max_len is the max strlen; buffer must hold max_len+1.
 */
static void osdb_cap_field(char *str, size_t max_len)
{
    size_t len;

    if (!str || max_len < 2) {
        return;
    }

    len = strlen(str);
    if (len <= max_len) {
        return;
    }

    str[max_len - 2] = '.';
    str[max_len - 1] = '.';
    str[max_len] = '\0';
}

/* Insert alert into to the db
 * Returns 1 on success or 0 on error
 */
int OS_Alert_InsertDB(const alert_data *al_data, DBConfig *db_config)
{
    int i;
    int n;
    unsigned int location_id = 0;
    unsigned short s_port = 0, d_port = 0;
    int *loc_id;
    char sql_query[OS_SIZE_8192 + 1];
    char *fulllog = NULL;
    /* Quoted IP or SQL NULL (max IPv6 textual form + quotes). */
    char srcip_sql[46 + 2 + 1];
    char dstip_sql[46 + 2 + 1];
    /* Bounded user literal so a huge dstuser cannot blow the INSERT (#1959). */
    char user_sql[512 + 1];
    size_t room;

    /* Clear the memory before insert */
    sql_query[0] = '\0';
    sql_query[OS_SIZE_8192] = '\0';

    /* Source Port */
    s_port = al_data->srcport;

    /* Destination Port */
    d_port = al_data->dstport;

    /* Escape strings */
    osdb_escapestr(al_data->location);

    user_sql[0] = '\0';
    if (al_data->user) {
        osdb_escapestr(al_data->user);
        strncpy(user_sql, al_data->user, sizeof(user_sql) - 1);
        user_sql[sizeof(user_sql) - 1] = '\0';
        osdb_cap_field(user_sql, sizeof(user_sql) - 1);
    }

    /* Nullable IP columns: true SQL NULL when absent (not the string 'NULL'). */
    sql_nullable_str(srcip_sql, sizeof(srcip_sql), (char *)al_data->srcip);
    sql_nullable_str(dstip_sql, sizeof(dstip_sql), (char *)al_data->dstip);
    
    /* We first need to insert the location */
    loc_id = (int *) OSHash_Get(db_config->location_hash, al_data->location);

    /* If we dont have location id, we must select and/or insert in the db */
    if (!loc_id) {
        location_id = __DBSelectLocation(al_data->location, db_config);
        if (location_id == 0) {
            /* Insert it */
            __DBInsertLocation(al_data->location, db_config);
            location_id = __DBSelectLocation(al_data->location, db_config);
        }

        if (!location_id) {
            merror("%s: Unable to insert location: '%s'.",
                   ARGV0, al_data->location);
            return (0);
        }

        /* Add to hash */
        os_calloc(1, sizeof(int), loc_id);
        *loc_id = location_id;
        OSHash_Add(db_config->location_hash, al_data->location, loc_id);
    }

    i = 0;
    while (al_data->log[i]) {
        size_t len = strlen(al_data->log[i]);
        char templog[len + 2];
        if (al_data->log[i + 1]) {
            snprintf(templog, len + 2, "%s\n", al_data->log[i]);
        } else {
            snprintf(templog, len + 1, "%s", al_data->log[i]);
        }
        fulllog = os_LoadString(fulllog, templog);
        i++;
    }

    if (fulllog == NULL) {
        merror("%s: Unable to process log.", ARGV0);
        return (0);
    }

    osdb_escapestr(fulllog);

    /* Measure INSERT length with an empty full_log, then cap full_log to the
     * remaining space so the final snprintf cannot truncate mid-quote.
     */
    switch (db_config->db_type) {
      case MYSQLDB:
        n = snprintf(sql_query, sizeof(sql_query),
                     "INSERT INTO "
                     "alert(server_id,rule_id,level,timestamp,location_id,src_ip,src_port,dst_ip,dst_port,alertid,user,full_log,tld) "
                     "VALUES ('%u', '%u','%u','%u', '%u', %s, '%u', %s, '%u', '%s', '%s', '%s','%.2s')",
                     db_config->server_id, al_data->rule,
                     al_data->level,
                     (unsigned int)time(0), *loc_id,
                     srcip_sql,
                     (unsigned short)s_port,
                     dstip_sql,
                     (unsigned short)d_port,
                     al_data->alertid,
                     user_sql,
                     "",
                     al_data->srcgeoip ? al_data->srcgeoip : "");
        break;

      case POSTGDB:
      default:
        n = snprintf(sql_query, sizeof(sql_query),
                     "INSERT INTO "
                     "alert(server_id,rule_id,level,timestamp,location_id,src_ip,src_port,dst_ip,dst_port,alertid,\"user\",full_log) "
                     "VALUES ('%u', '%u','%u','%u', '%u', %s, '%u', %s, '%u', '%s', '%s', '%s')",
                     db_config->server_id, al_data->rule,
                     al_data->level,
                     (unsigned int)time(0), *loc_id,
                     srcip_sql,
                     (unsigned short)s_port,
                     dstip_sql,
                     (unsigned short)d_port,
                     al_data->alertid,
                     user_sql,
                     "");
        break;
    }

    if (n < 0) {
        free(fulllog);
        merror("%s: Unable to build alert SQL.", ARGV0);
        return (0);
    }

    room = ((size_t)n < OS_SIZE_8192) ? (OS_SIZE_8192 - (size_t)n) : 0;
    if (room < 2) {
        fulllog[0] = '\0';
    } else {
        osdb_cap_field(fulllog, room);
    }

    /* Generate final SQL */
    switch (db_config->db_type) {
      case MYSQLDB:
        snprintf(sql_query, OS_SIZE_8192,
                 "INSERT INTO "
                 "alert(server_id,rule_id,level,timestamp,location_id,src_ip,src_port,dst_ip,dst_port,alertid,user,full_log,tld) "
                 "VALUES ('%u', '%u','%u','%u', '%u', %s, '%u', %s, '%u', '%s', '%s', '%s','%.2s')",
                 db_config->server_id, al_data->rule,
                 al_data->level,
                 (unsigned int)time(0), *loc_id,
                 srcip_sql,
                 (unsigned short)s_port,
                 dstip_sql,
                 (unsigned short)d_port,
                 al_data->alertid,
                 user_sql,
                 fulllog,
                 al_data->srcgeoip ? al_data->srcgeoip : "");
        break;

      case POSTGDB:
        snprintf(sql_query, OS_SIZE_8192,
                 "INSERT INTO "
                 "alert(server_id,rule_id,level,timestamp,location_id,src_ip,src_port,dst_ip,dst_port,alertid,\"user\",full_log) "
                 "VALUES ('%u', '%u','%u','%u', '%u', %s, '%u', %s, '%u', '%s', '%s', '%s')",
                 db_config->server_id, al_data->rule,
                 al_data->level,
                 (unsigned int)time(0), *loc_id,
                 srcip_sql,
                 (unsigned short)s_port,
                 dstip_sql,
                 (unsigned short)d_port,
                 al_data->alertid,
                 /* user is NOT NULL in schema — empty string, not SQL NULL */
                 user_sql,
                 fulllog);
        break;
    }

    free(fulllog);
    fulllog = NULL;

    /* Insert into the db */
    if (!osdb_query_insert(db_config->conn, sql_query)) {
        merror(DB_GENERROR, ARGV0);
    }

    db_config->alert_id++;
    return (1);
}
