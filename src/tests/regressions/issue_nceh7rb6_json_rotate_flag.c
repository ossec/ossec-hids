/*
 * Regression: stale JSON queue flag drops the first alert after rotation
 *
 * ANT-2026-NCEH7RB6 / CWE-372
 *
 * jqueue_next() reopens alerts.json when the inode changes or the file
 * shrinks, then returns that read directly. An empty new file sets
 * JQUEUE_READ_FAILED and the flag is not cleared. The next call parses a
 * real alert and deletes it because the flag is still set. The read
 * position has already moved past the record.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_nceh7rb6_json_rotate_flag
 *
 * Run:
 *   ./issue_nceh7rb6_json_rotate_flag
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "shared.h"
#include "cJSON.h"
#include "json-queue.h"

const char *__local_name __attribute__((weak)) =
    "issue-nceh7rb6-json-rotate-flag";

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

static int write_all(const char *path, const char *text)
{
    FILE *fp = fopen(path, "w");

    if (!fp) {
        return -1;
    }
    if (fputs(text, fp) == EOF) {
        fclose(fp);
        return -1;
    }
    return fclose(fp) == 0 ? 0 : -1;
}

static int append_line(const char *path, const char *id)
{
    FILE *fp = fopen(path, "a");
    int rc;

    if (!fp) {
        return -1;
    }
    rc = fprintf(fp, "{\"id\":\"%s\"}\n", id);
    if (fclose(fp) != 0 || rc < 0) {
        return -1;
    }
    return 0;
}

static const char *alert_id(cJSON *obj)
{
    cJSON *id;

    if (!obj) {
        return NULL;
    }
    id = cJSON_GetObjectItem(obj, "id");
    if (!id || id->type != cJSON_String || !id->valuestring) {
        return NULL;
    }
    return id->valuestring;
}

static void take(file_queue *queue, const char *want, const char *msg)
{
    cJSON *obj = jqueue_next(queue);
    const char *got = alert_id(obj);

    expect(got != NULL && strcmp(got, want) == 0, msg);
    cJSON_Delete(obj);
}

/* New empty alerts.json, then the first alert of the day. */
static void test_inode_rotation(const char *dir)
{
    char path[256];
    file_queue queue;

    snprintf(path, sizeof(path), "%s/rotate.json", dir);
    expect(write_all(path, "{\"id\":\"before\"}\n") == 0, "write the old day's file");

    jqueue_init(&queue);
    expect(jqueue_open_path(&queue, path, 0) == 0, "open the old day's file");
    take(&queue, "before", "alert before rotation is forwarded");

    expect(unlink(path) == 0, "unlink the old day's file");
    expect(write_all(path, "") == 0, "new day's file is empty");
    expect(jqueue_next(&queue) == NULL, "empty new file yields nothing");

    expect(append_line(path, "attacker") == 0, "first alert of the day is written");
    take(&queue, "attacker", "first alert after rotation is forwarded");

    expect(append_line(path, "after") == 0, "later alert is written");
    take(&queue, "after", "alert after the first of the day is forwarded");
    jqueue_close(&queue);
}

/* Alert already in the new file when the inode change is noticed. */
static void test_alert_already_present(const char *dir)
{
    char path[256];
    file_queue queue;

    snprintf(path, sizeof(path), "%s/present.json", dir);
    expect(write_all(path, "{\"id\":\"before\"}\n") == 0, "write file before a filled rotation");

    jqueue_init(&queue);
    expect(jqueue_open_path(&queue, path, 0) == 0, "open file before a filled rotation");
    take(&queue, "before", "pre-rotation alert is forwarded");

    expect(unlink(path) == 0, "replace the file");
    expect(write_all(path, "{\"id\":\"already\"}\n") == 0, "new file already holds an alert");
    take(&queue, "already", "alert written before the reopen is forwarded");
    jqueue_close(&queue);
}

/* Same inode, file truncated, then one new alert. */
static void test_truncate(const char *dir)
{
    char path[256];
    file_queue queue;
    FILE *fp;

    snprintf(path, sizeof(path), "%s/trunc.json", dir);
    expect(write_all(path, "{\"id\":\"before\"}\n") == 0, "write file before truncate");

    jqueue_init(&queue);
    expect(jqueue_open_path(&queue, path, 0) == 0, "open file before truncate");
    take(&queue, "before", "alert before truncate is forwarded");

    fp = fopen(path, "w");
    expect(fp != NULL, "truncate the same inode");
    if (fp) {
        fclose(fp);
    }
    expect(jqueue_next(&queue) == NULL, "truncated empty file yields nothing");

    expect(append_line(path, "attacker") == 0, "first alert after truncate is written");
    take(&queue, "attacker", "first alert after truncate is forwarded");
    jqueue_close(&queue);
}

int main(void)
{
    char dir[] = "/tmp/nceh7rb6-XXXXXX";

    printf("JSON queue flag after alerts.json rotation\n");
    if (!mkdtemp(dir)) {
        perror("mkdtemp");
        return 1;
    }

    test_inode_rotation(dir);
    test_alert_already_present(dir);
    test_truncate(dir);

    {
        const char *names[] = {"rotate.json", "present.json", "trunc.json", NULL};
        char path[256];
        int i;

        for (i = 0; names[i]; i++) {
            snprintf(path, sizeof(path), "%s/%s", dir, names[i]);
            unlink(path);
        }
    }
    rmdir(dir);

    if (failures) {
        printf("FAIL: %d JSON rotation check(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
