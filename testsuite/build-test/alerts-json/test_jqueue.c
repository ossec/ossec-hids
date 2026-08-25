/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * jqueue unit checks for alerts.json forwarding.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "shared.h"
#include "json-queue.h"

static char testdir[256];
static char testpath[256];
static int have_dir;

static void cleanup(void)
{
    if (testpath[0]) {
        unlink(testpath);
    }
    if (have_dir) {
        rmdir(testdir);
    }
}

static int fail(const char *msg)
{
    fprintf(stderr, "FAIL: %s\n", msg);
    cleanup();
    return 1;
}

int main(void)
{
    file_queue q;
    cJSON *obj;
    cJSON *name;
    cJSON *field;
    FILE *fp;
    char dir[] = "/tmp/ossec-jqueue-XXXXXX";

    OS_SetName("test_jqueue");
    testdir[0] = '\0';
    testpath[0] = '\0';

    if (!mkdtemp(dir)) {
        return fail("mkdtemp");
    }
    have_dir = 1;
    snprintf(testdir, sizeof(testdir), "%s", dir);
    snprintf(testpath, sizeof(testpath), "%s/alerts.json", testdir);

    /* Missing file */
    jqueue_init(&q);
    if (jqueue_open_path(&q, testpath, 0) == 0) {
        jqueue_close(&q);
        return fail("open missing file should fail");
    }

    fp = fopen(testpath, "w");
    if (!fp) {
        return fail("fopen write");
    }
    fputs("{\"agent_name\":\"agent123\",\"rule\":{\"sidid\":5715,\"level\":5}}\n", fp);
    fputs("{\"incomplete\"", fp);
    fflush(fp);
    fclose(fp);

    jqueue_init(&q);
    if (jqueue_open_path(&q, testpath, 0) != 0) {
        return fail("open alerts.json");
    }

    obj = jqueue_next(&q);
    if (!obj) {
        jqueue_close(&q);
        return fail("expected first JSON object");
    }
    name = cJSON_GetObjectItem(obj, "agent_name");
    if (!cJSON_IsString(name) || strcmp(name->valuestring, "agent123") != 0) {
        cJSON_Delete(obj);
        jqueue_close(&q);
        return fail("agent_name mismatch");
    }
    cJSON_Delete(obj);

    obj = jqueue_next(&q);
    if (obj) {
        cJSON_Delete(obj);
        jqueue_close(&q);
        return fail("incomplete line should not parse");
    }

    fp = fopen(testpath, "a");
    if (!fp) {
        jqueue_close(&q);
        return fail("reopen for complete line");
    }
    fputs(":true}\n", fp);
    fclose(fp);

    obj = jqueue_next(&q);
    if (!obj) {
        jqueue_close(&q);
        return fail("completed JSON line should parse");
    }
    cJSON_Delete(obj);

    /* copytruncate: same inode, shorter file */
    fp = fopen(testpath, "w");
    if (!fp) {
        jqueue_close(&q);
        return fail("truncate rewrite");
    }
    fputs("{\"agent_name\":\"after-truncate\"}\n", fp);
    fclose(fp);

    obj = jqueue_next(&q);
    if (!obj) {
        jqueue_close(&q);
        return fail("truncated file should rewind and parse");
    }
    field = cJSON_GetObjectItem(obj, "agent_name");
    if (!cJSON_IsString(field) || strcmp(field->valuestring, "after-truncate") != 0) {
        cJSON_Delete(obj);
        jqueue_close(&q);
        return fail("truncated-file agent_name mismatch");
    }
    cJSON_Delete(obj);
    jqueue_close(&q);

    /* rename() replacement: new inode, smaller file */
    {
        char newpath[256];

        fp = fopen(testpath, "w");
        if (!fp) {
            return fail("rewrite before rename");
        }
        fputs("{\"agent_name\":\"before-rename\"}\n", fp);
        fclose(fp);

        jqueue_init(&q);
        if (jqueue_open_path(&q, testpath, 0) != 0) {
            return fail("open before rename");
        }
        obj = jqueue_next(&q);
        if (!obj) {
            jqueue_close(&q);
            return fail("expected before-rename object");
        }
        cJSON_Delete(obj);

        /* Drain EOF on the still-open descriptor so the next call stats the path. */
        obj = jqueue_next(&q);
        if (obj) {
            cJSON_Delete(obj);
            jqueue_close(&q);
            return fail("expected EOF before rename replacement");
        }

        snprintf(newpath, sizeof(newpath), "%s/alerts.json.new", testdir);
        fp = fopen(newpath, "w");
        if (!fp) {
            jqueue_close(&q);
            return fail("open rename source");
        }
        fputs("{\"agent_name\":\"after-rename\"}\n", fp);
        fclose(fp);
        if (rename(newpath, testpath) != 0) {
            unlink(newpath);
            jqueue_close(&q);
            return fail("rename replacement");
        }

        obj = jqueue_next(&q);
        if (!obj) {
            jqueue_close(&q);
            return fail("renamed file should parse from start");
        }
        field = cJSON_GetObjectItem(obj, "agent_name");
        if (!cJSON_IsString(field) || strcmp(field->valuestring, "after-rename") != 0) {
            cJSON_Delete(obj);
            jqueue_close(&q);
            return fail("renamed-file agent_name mismatch");
        }
        cJSON_Delete(obj);
        jqueue_close(&q);
    }

    cleanup();
    printf("PASS: jqueue agent_name / incomplete / missing file / truncate / rename\n");
    return 0;
}
