/*
 * ANT-2026-SINT56KO: OS_Alert_InsertDB must escape alertid (and related
 * string columns) before building the alert INSERT, so a forged
 * "** Alert …" line cannot inject SQL via GetAlertData()'s id field.
 *
 * srcip/dstip/srcgeoip unescaped; this
 * tree already routes IPs through sql_nullable_str()/osdb_escapestr().
 * Cover alertid (this finding) and the MySQL tld=srcgeoip %.2s path.
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_sint56ko_dbd_alertid_sqli
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
static int insert_calls;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

static int capture_insert(void *db_conn, const char *query)
{
    (void)db_conn;
    insert_calls++;
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

static void reset_capture(void)
{
    insert_calls = 0;
    last_sql[0] = '\0';
}

static alert_data *make_alert(const char *alertid, const char *srcgeoip)
{
    alert_data *al;
    char **log;

    al = calloc(1, sizeof(*al));
    if (!al) {
        return (NULL);
    }
    al->rule = 2501;
    al->level = 5;
    al->location = strdup("agent01->/var/log/auth.log");
    al->alertid = alertid ? strdup(alertid) : NULL;
    al->user = NULL;
    al->srcip = NULL;
    al->dstip = NULL;
    al->srcgeoip = srcgeoip ? strdup(srcgeoip) : NULL;
    log = calloc(2, sizeof(char *));
    if (!log) {
        free(al->location);
        free(al->alertid);
        free(al->srcgeoip);
        free(al);
        return (NULL);
    }
    log[0] = strdup("authentication failure");
    log[1] = NULL;
    al->log = log;
    return (al);
}

static void free_alert(alert_data *al)
{
    if (!al) {
        return;
    }
    free(al->location);
    free(al->alertid);
    free(al->srcgeoip);
    if (al->log) {
        free(al->log[0]);
        free(al->log);
    }
    free(al);
}

static DBConfig *make_db(void)
{
    DBConfig *db;
    int *loc_id;

    db = calloc(1, sizeof(*db));
    if (!db) {
        return (NULL);
    }
    db->db_type = MYSQLDB;
    db->server_id = 1;
    db->conn = (void *)(intptr_t)1;
    db->location_hash = OSHash_Create();
    if (!db->location_hash) {
        free(db);
        return (NULL);
    }
    os_calloc(1, sizeof(int), loc_id);
    *loc_id = 1;
    if (OSHash_Add(db->location_hash, "agent01->/var/log/auth.log", loc_id) != 2) {
        free(loc_id);
        /* OSHash_Free not always available; leak on setup failure only. */
        free(db);
        return (NULL);
    }
    return (db);
}

static void check_alertid_injection(DBConfig *db)
{
    /* Payload from the REPORT: closes alertid quotes and injects a row. */
    const char *payload =
        "9', '', '', ''), ('1','31106','15','1791702496','1',NULL,'0',NULL,'0',"
        "'1','root','FORGED ROW','xx'), ('1','0','0','0','1',NULL,'0',NULL,'0','";
    alert_data *al;

    printf("--- alertid quote injection ---\n");
    reset_capture();
    al = make_alert(payload, NULL);
    CHECK(al != NULL, "allocate forged alert");
    CHECK(OS_Alert_InsertDB(al, db) == 1, "InsertDB succeeds");
    CHECK(insert_calls == 1, "one INSERT captured");
    /* Escaped quotes become backticks, so the payload cannot close the
     * alertid literal or open a second VALUES tuple. */
    CHECK(strstr(last_sql, "'), ('") == NULL &&
              strstr(last_sql, "'),('") == NULL,
          "no injected VALUES row boundary");
    CHECK(strstr(last_sql, "','root','FORGED ROW'") == NULL,
          "injected columns are not separate SQL string literals");
    CHECK(strchr(al->alertid, '\'') == NULL,
          "osdb_escapestr cleared quotes in alertid");
    CHECK(strstr(last_sql, "9`") != NULL,
          "escaped alertid uses backticks in SQL");
    free_alert(al);
}

static void check_srcgeoip_tld(DBConfig *db)
{
    alert_data *al;

    printf("--- srcgeoip tld path ---\n");
    reset_capture();
    /* First two chars would be O' if left raw under %.2s. */
    al = make_alert("1791702496.1", "O'Somewhere");
    CHECK(al != NULL, "allocate geoip alert");
    CHECK(OS_Alert_InsertDB(al, db) == 1, "InsertDB succeeds with geoip");
    CHECK(strstr(last_sql, "O'") == NULL,
          "raw quote does not appear in tld fragment");
    free_alert(al);
}

static void check_genuine_id(DBConfig *db)
{
    alert_data *al;

    printf("--- genuine epoch.offset id ---\n");
    reset_capture();
    al = make_alert("1791702496.12", NULL);
    CHECK(al != NULL, "allocate genuine alert");
    CHECK(OS_Alert_InsertDB(al, db) == 1, "InsertDB succeeds");
    CHECK(strstr(last_sql, "'1791702496.12'") != NULL,
          "genuine alertid unchanged in SQL");
    free_alert(al);
}

int main(void)
{
    DBConfig *db;

    failures = 0;
    printf("=== ANT-2026-SINT56KO: ossec-dbd alertid SQL escape ===\n");

    osdb_query_insert = capture_insert;
    osdb_query_select = capture_select;

    db = make_db();
    if (!db) {
        printf("FAIL: could not set up DBConfig stub\n");
        return (1);
    }

    check_alertid_injection(db);
    check_srcgeoip_tld(db);
    check_genuine_id(db);

    if (failures) {
        printf("\nFAIL: issue_sint56ko_dbd_alertid_sqli (%d)\n", failures);
        return (1);
    }

    printf("\nPASS: issue_sint56ko_dbd_alertid_sqli\n");
    return (0);
}
