/*
 * Regression: MySQL location ids are a 16-bit counter
 *
 * ANT-2026-C82AB02V / CWE-770
 *
 * location.id and alert.location_id are SMALLINT UNSIGNED. An agent that
 * raises alerts from 65535 distinct locations fills the counter, and
 * ossec-dbd then drops every alert whose location is not already in the
 * table. Fresh schemas and the IPv6 conversion table must use INT
 * UNSIGNED, and an upgrade script must widen an existing database.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_c82ab02v_location_id
 *
 * Run from the repo root, src/, or elsewhere; paths are resolved by walking
 * parents for src/os_dbd/ assets and ossec-hids.spec (all tracked in the tree).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>

static int failures = 0;

static void expect(int cond, const char *msg)
{
    if (cond) {
        printf("  ok:   %s\n", msg);
    } else {
        printf("  FAIL: %s\n", msg);
        failures++;
    }
}

static char *read_file(const char *path)
{
    FILE *fp;
    long n;
    char *buf;

    fp = fopen(path, "r");
    if (!fp) {
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    n = ftell(fp);
    if (n < 0) {
        fclose(fp);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }
    buf = malloc((size_t)n + 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    if (fread(buf, 1, (size_t)n, fp) != (size_t)n) {
        free(buf);
        fclose(fp);
        return NULL;
    }
    buf[n] = '\0';
    fclose(fp);
    return buf;
}

/* Resolve a repo-relative path from cwd or argv0, walking parents. */
static int find_repo_file(const char *argv0, const char *rel,
                          char *found, size_t found_sz)
{
    char start[PATH_MAX];
    char dir[PATH_MAX];
    int depth;
    int n;
    size_t rlen = strlen(rel);

    if (access(rel, R_OK) == 0) {
        n = snprintf(found, found_sz, "%s", rel);
        return (n > 0 && (size_t)n < found_sz) ? 0 : -1;
    }

    start[0] = '\0';
    if (argv0 && argv0[0]) {
        if (argv0[0] == '/') {
            n = snprintf(start, sizeof(start), "%s", argv0);
        } else if (getcwd(dir, sizeof(dir))) {
            n = snprintf(start, sizeof(start), "%s/%s", dir, argv0);
        } else {
            n = -1;
        }
        if (n > 0 && (size_t)n < sizeof(start)) {
            char *slash = strrchr(start, '/');
            if (slash) {
                *slash = '\0';
            }
        } else {
            start[0] = '\0';
        }
    }
    if (!start[0] && !getcwd(start, sizeof(start))) {
        return -1;
    }

    n = snprintf(dir, sizeof(dir), "%s", start);
    if (n < 0 || (size_t)n >= sizeof(dir)) {
        return -1;
    }
    for (depth = 0; depth < 8; depth++) {
        if (strlen(dir) + 1 + rlen + 1 > found_sz) {
            break;
        }
        n = snprintf(found, found_sz, "%s/%s", dir, rel);
        if (n > 0 && (size_t)n < found_sz && access(found, R_OK) == 0) {
            return 0;
        }
        {
            char *slash = strrchr(dir, '/');
            if (!slash || slash == dir) {
                break;
            }
            *slash = '\0';
        }
    }
    return -1;
}

static char *read_repo_file(const char *argv0, const char *rel_a, const char *rel_b)
{
    char path[PATH_MAX];
    char *buf;

    if (find_repo_file(argv0, rel_a, path, sizeof(path)) == 0) {
        buf = read_file(path);
        if (buf) {
            return buf;
        }
    }
    if (rel_b && find_repo_file(argv0, rel_b, path, sizeof(path)) == 0) {
        return read_file(path);
    }
    return NULL;
}

/* Body of "CREATE TABLE ... <name>" through the closing paren. */
static const char *table_body(const char *sql, const char *name, const char **end_out)
{
    const char *p;
    const char *q;
    size_t nlen;
    int depth;

    nlen = strlen(name);
    for (p = sql; (q = strstr(p, name)) != NULL; p = q + 1) {
        if (q > sql && (isalnum((unsigned char)q[-1]) || q[-1] == '_')) {
            continue;
        }
        if (isalnum((unsigned char)q[nlen]) || q[nlen] == '_') {
            continue;
        }
        /* The table name in CREATE TABLE is followed by '(', not a later
         * paren. A mention in a comment must not select another table. */
        q += nlen;
        while (*q && isspace((unsigned char)*q)) {
            q++;
        }
        if (*q != '(') {
            continue;
        }
        q++;
        depth = 1;
        for (p = q; *p && depth > 0; p++) {
            if (*p == '(') {
                depth++;
            } else if (*p == ')') {
                depth--;
            }
        }
        if (depth != 0) {
            return NULL;
        }
        *end_out = p - 1;
        return q;
    }
    return NULL;
}

/* The column's type token is INT (not SMALLINT) and the line says UNSIGNED. */
static int column_is_int_unsigned(const char *body, const char *body_end, const char *column)
{
    const char *p;
    size_t clen;

    clen = strlen(column);
    for (p = body; p < body_end; p++) {
        const char *line;
        const char *type;
        const char *eol;
        char token[32];
        size_t i;

        if (*p != '\n' && p != body) {
            continue;
        }
        line = (p == body) ? p : p + 1;
        while (line < body_end && isspace((unsigned char)*line)) {
            line++;
        }
        if ((size_t)(body_end - line) < clen || strncmp(line, column, clen) != 0) {
            continue;
        }
        if (isalnum((unsigned char)line[clen]) || line[clen] == '_') {
            continue;
        }
        type = line + clen;
        while (type < body_end && isspace((unsigned char)*type)) {
            type++;
        }
        i = 0;
        while (type + i < body_end && i + 1 < sizeof(token) &&
                (isalnum((unsigned char)type[i]) || type[i] == '_')) {
            token[i] = type[i];
            i++;
        }
        token[i] = '\0';
        eol = type;
        while (eol < body_end && *eol != '\n') {
            eol++;
        }
        if (strcmp(token, "INT") != 0) {
            return 0;
        }
        for (; type + 8 <= eol; type++) {
            if (strncmp(type, "UNSIGNED", 8) == 0) {
                return 1;
            }
        }
        return 0;
    }
    return 0;
}

static void check_table(const char *sql, const char *table, const char *column, const char *msg)
{
    const char *end = NULL;
    const char *body;

    body = table_body(sql, table, &end);
    expect(body != NULL && column_is_int_unsigned(body, end, column), msg);
}

int main(int argc, char **argv)
{
    char *mysql;
    char *convert;
    char *upgrade;
    char *spec;
    const char *argv0 = (argc > 0) ? argv[0] : NULL;
    const char *alert_alter = "ALTER TABLE alert MODIFY location_id INT UNSIGNED NOT NULL;";
    const char *loc_alter = "ALTER TABLE location MODIFY id INT UNSIGNED NOT NULL AUTO_INCREMENT;";
    const char *alert_at;
    const char *loc_at;

    printf("MySQL location id width\n");

    mysql = read_repo_file(argv0, "src/os_dbd/mysql.schema", "os_dbd/mysql.schema");
    expect(mysql != NULL, "mysql.schema is readable");
    if (mysql) {
        check_table(mysql, "location", "id", "location.id is INT UNSIGNED");
        check_table(mysql, "alert", "location_id", "alert.location_id is INT UNSIGNED");
    }

    convert = read_repo_file(argv0, "src/os_dbd/convert-db-ipv6.sql",
                             "os_dbd/convert-db-ipv6.sql");
    expect(convert != NULL, "convert-db-ipv6.sql is readable");
    if (convert) {
        check_table(convert, "alert_ipv6", "location_id",
                    "alert_ipv6.location_id is INT UNSIGNED");
    }

    upgrade = read_repo_file(argv0, "src/os_dbd/upgrade-location-id-mysql.sql",
                             "os_dbd/upgrade-location-id-mysql.sql");
    expect(upgrade != NULL, "upgrade script is present");
    if (upgrade) {
        alert_at = strstr(upgrade, alert_alter);
        loc_at = strstr(upgrade, loc_alter);
        expect(alert_at != NULL, "upgrade widens alert.location_id");
        expect(loc_at != NULL, "upgrade widens location.id");
        expect(alert_at && loc_at && alert_at < loc_at,
               "alert.location_id is widened before location.id");
        expect(strstr(upgrade, "table_name = 'alert_ipv6'") != NULL,
               "upgrade widens alert_ipv6 only when that table exists");
    }

    spec = read_repo_file(argv0, "ossec-hids.spec", NULL);
    expect(spec != NULL, "ossec-hids.spec is readable");
    if (spec) {
        expect(strstr(spec, "upgrade-location-id-mysql.sql") != NULL,
               "the rpm installs the upgrade script");
    }

    free(mysql);
    free(convert);
    free(upgrade);
    free(spec);

    if (failures) {
        printf("FAIL: %d location id check(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
