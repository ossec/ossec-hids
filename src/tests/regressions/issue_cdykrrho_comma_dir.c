/*
 * ANT-2026-CDYKRRHO: rk_check_dir must not let rk_check_file() cut a
 * readdir() path at ',' — that turns "…/,/a.php" into the parent and
 * re-enters the walk forever (or until MAX_DIR_DEPTH).
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_cdykrrho_comma_dir
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shared.h"
#include "rootcheck.h"

rkconfig rootcheck;
char **rk_sys_file;
char **rk_sys_name;
int rk_sys_count;

int notify_rk(int rk_type, const char *msg)
{
    (void)rk_type;
    (void)msg;
    return (0);
}

static char workdir[] = "/tmp/ossec-cdykrrho-XXXXXX";
static volatile sig_atomic_t timed_out;

static void on_alarm(int sig)
{
    (void)sig;
    timed_out = 1;
}

static void rm_tree(const char *path)
{
    char cmd[PATH_MAX + 64];

    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    (void)system(cmd);
}

static int alert_has(const char *needle)
{
    int i;

    for (i = 0; i < 256 && rootcheck.alert_msg[i]; i++) {
        if (strstr(rootcheck.alert_msg[i], needle) != NULL) {
            return (1);
        }
    }
    return (0);
}

static void clear_alerts(void)
{
    int i;

    for (i = 0; i < 256 && rootcheck.alert_msg[i]; i++) {
        free(rootcheck.alert_msg[i]);
        rootcheck.alert_msg[i] = NULL;
    }
}

int main(void)
{
    char uploads[sizeof(workdir) + 16];
    char comma_dir[sizeof(uploads) + 4];
    char marker[sizeof(comma_dir) + 16];
    char comma_file[sizeof(uploads) + 20];
    char *alert_slot[256];
    int rc;
    int failed = 0;
    int i;

    printf("=== ANT-2026-CDYKRRHO: comma in readdir path ===\n");

    if (!mkdtemp(workdir)) {
        perror("mkdtemp");
        return (1);
    }

    memset(&rootcheck, 0, sizeof(rootcheck));
    memset(alert_slot, 0, sizeof(alert_slot));
    rootcheck.alert_msg = alert_slot;
    rootcheck.notify = SYSLOG;

    snprintf(uploads, sizeof(uploads), "%s/uploads", workdir);
    snprintf(comma_dir, sizeof(comma_dir), "%s/,", uploads);
    snprintf(marker, sizeof(marker), "%s/marker.php", comma_dir);
    snprintf(comma_file, sizeof(comma_file), "%s/evil,name.php", uploads);

    if (mkdir(uploads, 0755) < 0 || mkdir(comma_dir, 0755) < 0) {
        perror("mkdir");
        rm_tree(workdir);
        return (1);
    }
    {
        FILE *fp = fopen(marker, "w");
        if (!fp) {
            perror(marker);
            rm_tree(workdir);
            return (1);
        }
        fputs("ok\n", fp);
        fclose(fp);
    }
    {
        FILE *fp = fopen(comma_file, "w");
        if (!fp) {
            perror(comma_file);
            rm_tree(workdir);
            return (1);
        }
        fputs("ok\n", fp);
        fclose(fp);
    }

    timed_out = 0;
    signal(SIGALRM, on_alarm);
    alarm(3);
    rc = rk_check_dir(uploads, "r:.php$", NULL);
    alarm(0);

    if (timed_out) {
        printf("  FAIL: rk_check_dir hung on comma-named directory\n");
        failed = 1;
    } else if (rc < 0) {
        /* Depth-capped incomplete walk is still the comma-split bug. */
        printf("  FAIL: walk returned incomplete (rc=%d) on comma dir\n", rc);
        failed = 1;
    } else if (!alert_has("marker.php")) {
        printf("  FAIL: marker.php under ',' not reported (rc=%d)\n", rc);
        failed = 1;
    } else if (!alert_has("/,/marker.php") && !alert_has(",/marker.php")) {
        printf("  FAIL: alert path lost the comma directory component\n");
        for (i = 0; i < 256 && rootcheck.alert_msg[i]; i++) {
            printf("    alert: %s\n", rootcheck.alert_msg[i]);
        }
        failed = 1;
    } else {
        printf("  ok: comma directory walk finished and found marker.php\n");
    }

    clear_alerts();
    timed_out = 0;
    alarm(3);
    rc = rk_check_dir(uploads, "r:.php$", NULL);
    alarm(0);
    if (timed_out || !alert_has("evil,name.php")) {
        printf("  FAIL: file with comma in name not inspected (timeout=%d)\n",
               (int)timed_out);
        failed = 1;
    } else {
        printf("  ok: evil,name.php inspected with comma preserved\n");
    }

    /* Policy list form must still split on commas. */
    {
        char list[PATH_MAX * 2];
        char a[PATH_MAX];
        char b[PATH_MAX];
        FILE *fp;

        snprintf(a, sizeof(a), "%s/list_a", workdir);
        snprintf(b, sizeof(b), "%s/list_b", workdir);
        fp = fopen(a, "w");
        if (fp) {
            fclose(fp);
        }
        fp = fopen(b, "w");
        if (fp) {
            fclose(fp);
        }
        snprintf(list, sizeof(list), "%s,%s", a, b);
        clear_alerts();
        if (!rk_check_file(list, NULL) || !alert_has("list_a")) {
            printf("  FAIL: policy comma-list no longer splits\n");
            failed = 1;
        } else {
            printf("  ok: policy file list still splits on commas\n");
        }
    }

    clear_alerts();
    rm_tree(workdir);

    if (failed) {
        printf("\nFAIL: issue_cdykrrho_comma_dir\n");
        return (1);
    }
    printf("\nPASS: issue_cdykrrho_comma_dir\n");
    return (0);
}
