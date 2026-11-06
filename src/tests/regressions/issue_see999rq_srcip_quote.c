/*
 * Regression: a long srcip drops the SQL closing quote
 *
 * ANT-2026-SEE999RQ / CWE-149
 *
 * sql_nullable_str() writes '<field>' into a 49-byte buffer. A srcip or
 * dstip of 47 characters or more fills that buffer before the closing
 * quote, so MySQL and PostgreSQL reject the INSERT and ossec-dbd
 * reconnects. The value must be cut to the 46-character column width
 * and the quote must stay.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_see999rq_srcip_quote
 *
 * Run:
 *   ./issue_see999rq_srcip_quote
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "shared.h"
#include "os_dbd/dbd.h"
#include "config/dbd-config.h"

static int failures;
static char last_sql[OS_SIZE_8192 + 1];

static void expect(int cond, const char *msg)
{
    if (cond) {
        printf("  ok:   %s\n", msg);
    } else {
        printf("  FAIL: %s\n", msg);
        failures++;
    }
}

static int capture_insert(void *db_conn, const char *query)
{
    (void)db_conn;
    if (query) {
        snprintf(last_sql, sizeof(last_sql), "%s", query);
    } else {
        last_sql[0] = '\0';
    }
    return (1);
}

static int capture_select(void *db_conn, const char *query)
{
    (void)db_conn;
    (void)query;
    return (1);
}

static void fill_char(char *dst, size_t n, char c)
{
    memset(dst, c, n);
    dst[n] = '\0';
}

static alert_data *make_alert(char *srcip, char *dstip)
{
    alert_data *al;
    char **log;

    al = calloc(1, sizeof(*al));
    if (!al) {
        return NULL;
    }
    al->rule = 5710;
    al->level = 5;
    al->location = strdup("agent01->/var/log/auth.log");
    al->srcip = srcip;
    al->dstip = dstip;
    al->srcport = 22;
    log = calloc(2, sizeof(char *));
    if (!log || !al->location) {
        free(al->location);
        free(log);
        free(al);
        return NULL;
    }
    log[0] = strdup("failed password");
    log[1] = NULL;
    al->log = log;
    return al;
}

static void free_alert(alert_data *al)
{
    if (!al) {
        return;
    }
    free(al->location);
    if (al->log) {
        free(al->log[0]);
        free(al->log);
    }
    free(al);
}

static DBConfig *make_db(unsigned int db_type)
{
    DBConfig *db;
    int *loc_id;

    db = calloc(1, sizeof(*db));
    if (!db) {
        return NULL;
    }
    db->db_type = db_type;
    db->server_id = 1;
    db->conn = (void *)(intptr_t)1;
    db->location_hash = OSHash_Create();
    if (!db->location_hash) {
        free(db);
        return NULL;
    }
    os_calloc(1, sizeof(int), loc_id);
    *loc_id = 1;
    if (OSHash_Add(db->location_hash, "agent01->/var/log/auth.log", loc_id) != 2) {
        free(loc_id);
        free(db);
        return NULL;
    }
    return db;
}

/* Quoted form that fits VARCHAR(46): quote, 46 chars, quote. */
static void quoted46(char *out, size_t outlen, char c)
{
    out[0] = '\'';
    memset(out + 1, c, 46);
    out[47] = '\'';
    out[48] = '\0';
    (void)outlen;
}

int main(void)
{
    DBConfig *mysql_db;
    DBConfig *pg_db;
    alert_data *al;
    char ip46[47];
    char ip47[48];
    char dst47[48];
    char want46[50];
    char short_ip[] = "192.0.2.1";

    failures = 0;
    printf("ossec-dbd long srcip keeps its closing quote\n");
    osdb_query_insert = capture_insert;
    osdb_query_select = capture_select;

    mysql_db = make_db(MYSQLDB);
    pg_db = make_db(POSTGDB);
    if (!mysql_db || !pg_db) {
        printf("FAIL: could not set up DBConfig stub\n");
        return 1;
    }

    fill_char(ip46, 46, 'A');
    fill_char(ip47, 47, 'A');
    fill_char(dst47, 47, 'B');
    quoted46(want46, sizeof(want46), 'A');

    al = make_alert(ip46, NULL);
    expect(al != NULL && OS_Alert_InsertDB(al, mysql_db) == 1,
           "46-character srcip is inserted");
    expect(strstr(last_sql, want46) != NULL,
           "46-character srcip keeps both quotes");
    free_alert(al);

    al = make_alert(NULL, NULL);
    expect(al != NULL && OS_Alert_InsertDB(al, mysql_db) == 1,
           "missing addresses are inserted");
    expect(strstr(last_sql, ", NULL, '22', NULL,") != NULL,
           "a missing address is SQL NULL");
    free_alert(al);

    al = make_alert(ip47, short_ip);
    expect(al != NULL && OS_Alert_InsertDB(al, mysql_db) == 1,
           "47-character srcip is still inserted");
    expect(strstr(last_sql, want46) != NULL,
           "47-character srcip is cut to 46 and keeps the closing quote");
    free_alert(al);

    quoted46(want46, sizeof(want46), 'B');
    al = make_alert(short_ip, dst47);
    expect(al != NULL && OS_Alert_InsertDB(al, mysql_db) == 1,
           "47-character dstip is still inserted");
    expect(strstr(last_sql, want46) != NULL,
           "47-character dstip is cut to 46 and keeps the closing quote");
    free_alert(al);

    fill_char(ip47, 47, 'A');
    quoted46(want46, sizeof(want46), 'A');
    al = make_alert(ip47, NULL);
    expect(al != NULL && OS_Alert_InsertDB(al, pg_db) == 1,
           "PostgreSQL insert accepts a long srcip");
    expect(strstr(last_sql, want46) != NULL,
           "PostgreSQL srcip keeps the closing quote");
    free_alert(al);

    if (failures) {
        printf("FAIL: %d srcip quote check(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
