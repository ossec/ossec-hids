/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "dbd.h"
#include "config/config.h"

/* Prototypes */
static void __Agent_CopyField(char *dst, size_t dstlen, const char *src);
static int __Agent_Upsert(const DBConfig *db_config, const char *name, const char *ip,
                          const char *version, const char *information,
                          unsigned int last_contact, int have_contact) __attribute__((nonnull));
static int __Agent_ReadInfo(const char *name, const char *ip, char *version, size_t version_len,
                            char *information, size_t information_len,
                            unsigned int *last_contact) __attribute__((nonnull));


/* Cap to the column width, then run the dbd allow-list in place. */
static void __Agent_CopyField(char *dst, size_t dstlen, const char *src)
{
    size_t n;

    if (dstlen < 2) {
        return;
    }

    if (!src || src[0] == '\0') {
        snprintf(dst, dstlen, "Unknown");
        return;
    }

    snprintf(dst, dstlen, "%s", src);
    /* snprintf already capped. Drop a partial UTF-8 sequence at the cut. */
    if (strlen(src) >= dstlen) {
        n = strlen(dst);
        while (n > 0 && ((unsigned char)dst[n - 1] & 0xc0) == 0x80) {
            n--;
        }
        if (n > 0 && ((unsigned char)dst[n - 1] & 0xc0) == 0xc0) {
            n--;
        }
        dst[n] = '\0';
    }

    osdb_escapestr(dst);
    if (dst[0] == '\0') {
        snprintf(dst, dstlen, "Unknown");
    }
}

/* Insert or update one agent. name is matched with server_id.
 * The table has no OSSEC agent-id column, and no unique key on name,
 * so REPLACE would add a second row.
 */
static int __Agent_Upsert(const DBConfig *db_config, const char *name, const char *ip,
                          const char *version, const char *information,
                          unsigned int last_contact, int have_contact)
{
    int agent_id;
    char sql_query[OS_SIZE_1024];
    char name_sql[64 + 1];
    char ip_sql[46 + 1];
    char version_sql[32 + 1];
    char info_sql[128 + 1];

    __Agent_CopyField(name_sql, sizeof(name_sql), name);
    __Agent_CopyField(ip_sql, sizeof(ip_sql), ip);
    __Agent_CopyField(version_sql, sizeof(version_sql), version);
    __Agent_CopyField(info_sql, sizeof(info_sql), information);

    snprintf(sql_query, OS_SIZE_1024 - 1,
             "SELECT id FROM "
             "agent WHERE server_id = '%u' AND name = '%s' "
             "LIMIT 1",
             db_config->server_id, name_sql);

    agent_id = osdb_query_select(db_config->conn, sql_query);
    if (agent_id == 0) {
        snprintf(sql_query, OS_SIZE_1024 - 1,
                 "INSERT INTO "
                 "agent(server_id, last_contact, ip_address, version, name, information) "
                 "VALUES ('%u', '%u', '%s', '%s', '%s', '%s')",
                 db_config->server_id, last_contact,
                 ip_sql, version_sql, name_sql, info_sql);
    } else if (have_contact) {
        snprintf(sql_query, OS_SIZE_1024 - 1,
                 "UPDATE agent SET "
                 "last_contact='%u', ip_address='%s', version='%s', information='%s' "
                 "WHERE id = '%d' AND server_id = '%u'",
                 last_contact, ip_sql, version_sql, info_sql,
                 agent_id, db_config->server_id);
    } else {
        /* Keepalive file is gone. Update the address from client.keys,
         * leave last_contact / version / information alone.
         */
        snprintf(sql_query, OS_SIZE_1024 - 1,
                 "UPDATE agent SET "
                 "ip_address='%s' "
                 "WHERE id = '%d' AND server_id = '%u'",
                 ip_sql, agent_id, db_config->server_id);
    }

    if (!osdb_query_insert(db_config->conn, sql_query)) {
        merror(DB_GENERROR, ARGV0);
        return (0);
    }

    return (1);
}

/* queue/agent-info/<name>-<ip> is written by remoted. The first line is
 * "uname - OSSEC ...". The file mtime is the last keepalive.
 * Returns 1 when the keepalive file exists.
 */
static int __Agent_ReadInfo(const char *name, const char *ip, char *version, size_t version_len,
                            char *information, size_t information_len,
                            unsigned int *last_contact)
{
    FILE *fp;
    char path[OS_SIZE_1024 + 1];
    char buf[OS_SIZE_1024 + 1];
    char ip_file[64];
    char *sep;
    char *slash;
    struct stat st;

    version[0] = '\0';
    information[0] = '\0';
    *last_contact = 0;

    snprintf(ip_file, sizeof(ip_file), "%s", ip);
    slash = strchr(ip_file, '/');
    if (slash) {
        *slash = '\0';
    }

    /* client.keys is admin-owned. Do not use it as a path. */
    if (strchr(name, '/') || strstr(name, "..") ||
            strchr(ip_file, '/') || strstr(ip_file, "..")) {
        return (0);
    }

    snprintf(path, sizeof(path), "%s/%s-%s", AGENTINFO_DIR, name, ip_file);
    if (stat(path, &st) < 0) {
        return (0);
    }
    if (st.st_mtime > 0) {
        *last_contact = (unsigned int)st.st_mtime;
    }

    fp = fopen(path, "r");
    if (!fp) {
        return (1);
    }

    if (!fgets(buf, sizeof(buf), fp)) {
        fclose(fp);
        return (1);
    }
    fclose(fp);

    sep = strchr(buf, '\n');
    if (sep) {
        *sep = '\0';
    }

    sep = strstr(buf, " - ");
    if (sep) {
        *sep = '\0';
        snprintf(version, version_len, "%s", sep + 3);
    }
    snprintf(information, information_len, "%s", buf);
    return (1);
}

/* Read etc/client.keys and upsert each agent.
 * Returns 0. A missing keys file is not fatal: alerts still insert.
 */
int OS_Agents_InsertDB(const DBConfig *db_config)
{
    FILE *fp;
    char buffer[OS_MAXSTR + 1];
    int inserted = 0;

    fp = fopen(KEYS_FILE, "r");
    if (!fp) {
        /* The refresh loop calls this every minute. Warn once. */
        static int warned = 0;
        if (!warned) {
            merror("%s: Unable to read agent keys from '%s'.", ARGV0, KEYS_FILE);
            warned = 1;
        }
        return (0);
    }

    while (fgets(buffer, OS_MAXSTR, fp) != NULL) {
        char *cursor;
        char *name;
        char *ip;
        char version[OS_SIZE_1024 + 1];
        char information[OS_SIZE_1024 + 1];
        unsigned int last_contact = 0;
        int have_contact;

        if (buffer[0] == '#' || buffer[0] == ' ' || buffer[0] == '\n') {
            continue;
        }

        /* id */
        cursor = strchr(buffer, ' ');
        if (!cursor) {
            continue;
        }
        cursor++;

        /* Removed entry: "id #name ..." */
        if (*cursor == '#') {
            continue;
        }

        /* name */
        name = cursor;
        cursor = strchr(cursor, ' ');
        if (!cursor) {
            continue;
        }
        *cursor = '\0';
        cursor++;

        /* ip. The key itself is not stored. */
        ip = cursor;
        cursor = strchr(cursor, ' ');
        if (!cursor) {
            continue;
        }
        *cursor = '\0';

        if (name[0] == '\0' || ip[0] == '\0') {
            continue;
        }

        have_contact = __Agent_ReadInfo(name, ip, version, sizeof(version),
                                        information, sizeof(information),
                                        &last_contact);
        if (__Agent_Upsert(db_config, name, ip, version, information,
                           last_contact, have_contact)) {
            inserted++;
        }
    }

    fclose(fp);
    debug1("%s: DEBUG: Updated %d agent row(s).", ARGV0, inserted);
    return (0);
}
