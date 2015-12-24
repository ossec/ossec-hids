/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "read-agents.h"
#include "os_net/os_net.h"

#ifndef WIN32
static int _do_print_attrs_syscheck(const char *prev_attrs, const char *attrs, int csv_output,
                                    int is_win, int number_of_changes) __attribute__((nonnull(2)));
static int _do_print_file_syscheck(FILE *fp, const char *fname,
                                   int update_counter, int csv_output) __attribute__((nonnull));
static int _do_print_syscheck(FILE *fp, int all_files, int csv_output) __attribute__((nonnull));
static int _do_get_rootcheckscan(FILE *fp) __attribute__((nonnull));
static int _do_print_rootcheck(FILE *fp, int resolved, time_t time_last_scan,
                               int csv_output, int show_last) __attribute__((nonnull));
#endif /* !WIN32*/

static int _get_time_rkscan(const char *agent_name, const char *agent_ip, agent_info *agt_info) __attribute__((nonnull(2, 3)));
static char *_get_agent_keepalive(const char *agent_name, const char *agent_ip) __attribute__((nonnull(2)));
static int _get_agent_os(const char *agent_name, const char *agent_ip, agent_info *agt_info) __attribute__((nonnull(2, 3)));


/* Free the agent list in memory */
void free_agents(char **agent_list)
{
    int i;
    if (!agent_list) {
        return;
    }

    for (i = 0;; i++) {
        if (agent_list[i] == NULL) {
            break;
        }

        free(agent_list[i]);
        agent_list[i] = NULL;
    }

    free(agent_list);
    agent_list = NULL;
}

#ifndef WIN32

/* Print syscheck attributes */
#define sk_strchr(x,y,z) z = strchr(x, y); if(z == NULL) return(0); else { *z = '\0'; z++; }

static int _do_print_attrs_syscheck(const char *prev_attrs, const char *attrs, __attribute__((unused)) int csv_output,
                                    int is_win, int number_of_changes)
{
    const char *p_size, *size;
    char *p_perm, *p_uid, *p_gid, *p_md5, *p_sha1;
    char *perm, *uid, *gid, *md5, *sha1;
    int perm_int;
    char perm_str[36];


    /* A deleted file has no attributes */
    if (strcmp(attrs, "-1") == 0) {
        printf("File deleted.\n");
        return (0);
    }

    /* Set each value */
    size = attrs;
    sk_strchr(size, ':', perm);
    sk_strchr(perm, ':', uid);
    sk_strchr(uid, ':', gid);
    sk_strchr(gid, ':', md5);
    sk_strchr(md5, ':', sha1);

    p_size = size;
    p_perm = perm;
    p_uid = uid;
    p_gid = gid;
    p_md5 = md5;
    p_sha1 = sha1;

    if (prev_attrs && (strcmp(prev_attrs, "-1") == 0)) {
        printf("File restored. ");
    } else if (prev_attrs) {
        printf("File changed. ");
        p_size = prev_attrs;
        sk_strchr(p_size, ':', p_perm);
        sk_strchr(p_perm, ':', p_uid);
        sk_strchr(p_uid, ':', p_gid);
        sk_strchr(p_gid, ':', p_md5);
        sk_strchr(p_md5, ':', p_sha1);
    } else {
        printf("File added to the database. ");
    }

    /* Fix number of changes */
    if (prev_attrs && !number_of_changes) {
        number_of_changes = 1;
    }

    if (number_of_changes) {
        switch (number_of_changes) {
            case 1:
                printf("- 1st time modified.\n");
                break;
            case 2:
                printf("- 2nd time modified.\n");
                break;
            case 3:
                printf("- 3rd time modified.\n");
                break;
            default:
                printf("- Being ignored (3 or more changes).\n");
                break;
        }
    } else {
        printf("\n");
    }

    perm_str[35] = '\0';
    perm_int = atoi(perm);
    snprintf(perm_str, 35,
             "%c%c%c%c%c%c%c%c%c",
             (perm_int & S_IRUSR) ? 'r' : '-',
             (perm_int & S_IWUSR) ? 'w' : '-',

             (perm_int & S_ISUID) ? 's' :
             (perm_int & S_IXUSR) ? 'x' : '-',

             (perm_int & S_IRGRP) ? 'r' : '-',
             (perm_int & S_IWGRP) ? 'w' : '-',

             (perm_int & S_ISGID) ? 's' :
             (perm_int & S_IXGRP) ? 'x' : '-',

             (perm_int & S_IROTH) ? 'r' : '-',
             (perm_int & S_IWOTH) ? 'w' : '-',
             (perm_int & S_ISVTX) ? 't' :
             (perm_int & S_IXOTH) ? 'x' : '-');

    printf("Integrity checking values:\n");
    printf("   Size:%s%s\n", (strcmp(size, p_size) == 0) ? " " : " >", size);
    if (!is_win) {
        printf("   Perm:%s%s\n", (strcmp(perm, p_perm) == 0) ? " " : " >", perm_str);
        printf("   Uid: %s%s\n", (strcmp(uid, p_uid) == 0) ? " " : " >", uid);
        printf("   Gid: %s%s\n", (strcmp(gid, p_gid) == 0) ? " " : " >", gid);
    }
    printf("   Md5: %s%s\n", (strcmp(md5, p_md5) == 0) ? " " : " >", md5);
    printf("   Sha1:%s%s\n", (strcmp(sha1, p_sha1) == 0) ? " " : " >", sha1);

    /* Fix entries */
    perm[-1] = ':';
    uid[-1] = ':';
    gid[-1] = ':';
    md5[-1] = ':';
    sha1[-1] = ':';

    return (0);
}

/* Print information about a specific file */
static int _do_print_file_syscheck(FILE *fp, const char *fname,
                                   int update_counter, int csv_output)
{
    int f_found = 0;
    struct tm *tm_time;
    char read_day[24 + 1];
    char buf[OS_MAXSTR + 1];
    OSMatch reg;
    OSStore *files_list = NULL;
    fpos_t init_pos;

    buf[OS_MAXSTR] = '\0';
    read_day[24] = '\0';

    /* If the compilation failed, we don't need to free anything */
    if (!OSMatch_Compile(fname, &reg, 0)) {
        printf("\n** ERROR: Invalid file name: '%s'\n", fname);
        return (0);
    }

    /* Create list with files */
    files_list = OSStore_Create();
    if (!files_list) {
        OSMatch_FreePattern(&reg);
        goto cleanup;
    }

    /* Get initial position */
    if (fgetpos(fp, &init_pos) != 0) {
        printf("\n** ERROR: fgetpos failed.\n");
        goto cleanup;
    }

    while (fgets(buf, OS_MAXSTR, fp) != NULL) {
        if (buf[0] == '!' || buf[0] == '#' || buf[0] == '+') {
            int number_changes = 0;
            time_t change_time = 0;
            char *changed_file_name;
            char *changed_attrs;
            char *prev_attrs;

            if (strlen(buf) < 16) {
                fgetpos(fp, &init_pos);
                continue;
            }

            /* Remove newline */
            buf[strlen(buf) - 1] = '\0';

            /* With update counter, we only modify the last entry */
            if (update_counter && buf[0] == '#') {
                fgetpos(fp, &init_pos);
                continue;
            }

            /* Check the number of changes */
            if (buf[1] == '!') {
                number_changes = 2;
                if (buf[2] == '!') {
                    number_changes = 3;
                } else if (buf[2] == '?') {
                    number_changes = 4;
                }
            }

            changed_attrs = buf + 3;

            changed_file_name = strchr(changed_attrs, '!');
            if (!changed_file_name) {
                fgetpos(fp, &init_pos);
                continue;
            }

            /* Get time of change */
            changed_file_name[-1] = '\0';
            changed_file_name++;
            change_time = (time_t)atoi(changed_file_name);

            changed_file_name = strchr(changed_file_name, ' ');
            if (!changed_file_name) {
                printf("\n** ERROR: Invalid line: '%s'.\n", buf);
                goto cleanup;
            }
            changed_file_name++;

            /* Check if the name should be printed */
            if (!OSMatch_Execute(changed_file_name, strlen(changed_file_name),
                                 &reg)) {
                fgetpos(fp, &init_pos);
                continue;
            }

            f_found = 1;

            /* Reset the values */
            if (update_counter) {
                if (fsetpos(fp, &init_pos) != 0) {
                    printf("\n** ERROR: fsetpos failed (unable to update "
                           "counter).\n");
                    goto cleanup;
                }

                if (update_counter == 2) {
                    if (fprintf(fp, "!!?") <= 0) {
                        printf("\n** ERROR: fputs failed (unable to update "
                               "counter).\n");
                        goto cleanup;
                    }
                }

                else {
                    if (fprintf(fp, "!++") <= 0) {
                        printf("\n** ERROR: fputs failed (unable to update "
                               "counter).\n");
                        goto cleanup;
                    }
                }

                printf("\n**Counter updated for file '%s'\n\n",
                       changed_file_name);
                goto cleanup;
            }


            tm_time = localtime(&change_time);
            strftime(read_day, 23, "%Y %h %d %T", tm_time);

            if (!csv_output)
                printf("\n%s,%d - %s\n", read_day, number_changes,
                       changed_file_name);
            else
                printf("%s,%s,%d\n", read_day, changed_file_name,
                       number_changes);


            prev_attrs = (char *) OSStore_Get(files_list, changed_file_name);
            if (prev_attrs) {
                char *new_attrs;
                os_strdup(changed_attrs, new_attrs);
                _do_print_attrs_syscheck(prev_attrs, changed_attrs,
                                         csv_output,
                                         changed_file_name[0] == '/' ? 0 : 1,
                                         number_changes);

                free(files_list->cur_node->data);
                files_list->cur_node->data = new_attrs;
            } else {
                char *new_attrs;

                os_strdup(changed_attrs, new_attrs);
                OSStore_Put(files_list, changed_file_name, new_attrs);
                _do_print_attrs_syscheck(NULL,
                                         changed_attrs, csv_output,
                                         changed_file_name[0] == '/' ? 0 : 1,
                                         number_changes);
            }

            fgetpos(fp, &init_pos);
        }
    }

    if (!f_found) {
        printf("\n** No entries found.\n");
    }

cleanup:
    OSMatch_FreePattern(&reg);
    if (files_list) {
        OSStore_Free(files_list);
    }

    return (0);
}

/* Print syscheck db (of modified files) */
static int _do_print_syscheck(FILE *fp, __attribute__((unused)) int all_files, int csv_output)
{
    int f_found = 0;
    struct tm *tm_time;

    char read_day[24 + 1];
    char saved_read_day[24 + 1];
    char buf[OS_MAXSTR + 1];

    buf[OS_MAXSTR] = '\0';
    read_day[24] = '\0';
    saved_read_day[0] = '\0';
    saved_read_day[24] = '\0';

    while (fgets(buf, OS_MAXSTR, fp) != NULL) {
        if (buf[0] == '!' || buf[0] == '#') {
            int number_changes = 0;
            time_t change_time = 0;
            char *changed_file_name;

            if (strlen(buf) < 16) {
                continue;
            }

            /* Remove newline */
            buf[strlen(buf) - 1] = '\0';

            /* Check the number of changes */
            if (buf[1] == '!') {
                number_changes = 2;
                if (buf[2] == '!') {
                    number_changes = 3;
                } else if (buf[2] == '?') {
                    number_changes = 4;
                }
            }

            changed_file_name = strchr(buf + 3, '!');
            if (!changed_file_name) {
                continue;
            }

            f_found = 1;

            /* Get time of change */
            changed_file_name++;
            change_time = atoi(changed_file_name);

            changed_file_name = strchr(changed_file_name, ' ');
            if (!changed_file_name) {
                printf("\n** ERROR: Invalid line: '%s'.\n", buf);
                return (-1);
            }
            changed_file_name++;

            tm_time = localtime(&change_time);
            strftime(read_day, 23, "%Y %h %d", tm_time);
            if (strcmp(read_day, saved_read_day) != 0) {
                if (!csv_output) {
                    printf("\nChanges for %s:\n", read_day);
                }
                strncpy(saved_read_day, read_day, 23);
            }
            strftime(read_day, 23, "%Y %h %d %T", tm_time);

            if (!csv_output)
                printf("%s,%d - %s\n", read_day, number_changes,
                       changed_file_name);
            else
                printf("%s,%s,%d\n", read_day, changed_file_name,
                       number_changes);
        }
    }

    if (!f_found && !csv_output) {
        printf("\n** No entries found.\n");
    }

    return (0);
}

/* Print syscheck db (of modified files) */
int print_syscheck(const char *sk_name, const char *sk_ip, const char *fname,
                   int print_registry, int all_files, int csv_output,
                   int update_counter)
{
    FILE *fp;
    char tmp_file[513];

    tmp_file[512] = '\0';

    if (sk_name == NULL) {
        /* Print database */
        snprintf(tmp_file, 512, "%s/syscheck",
                 SYSCHECK_DIR);

        fp = fopen(tmp_file, "r+");
    }

    else if (sk_ip == NULL) {
        /* Print database */
        snprintf(tmp_file, 512, "%s/%s->syscheck", SYSCHECK_DIR, sk_name);

        fp = fopen(tmp_file, "r+");
    }

    else if (!print_registry) {
        /* Print database */
        snprintf(tmp_file, 512, "%s/(%s) %s->syscheck",
                 SYSCHECK_DIR,
                 sk_name,
                 sk_ip);

        fp = fopen(tmp_file, "r+");
    }

    else {
        /* Print database for the Windows registry */
        snprintf(tmp_file, 512, "%s/(%s) %s->syscheck-registry",
                 SYSCHECK_DIR,
                 sk_name,
                 sk_ip);

        fp = fopen(tmp_file, "r+");
    }

    if (fp) {
        if (!fname) {
            _do_print_syscheck(fp, all_files, csv_output);
        } else {
            _do_print_file_syscheck(fp, fname, update_counter, csv_output);
        }
        fclose(fp);
    }

    return (0);
}

static int _do_get_rootcheckscan(FILE *fp)
{
    char *tmp_str;
    char buf[OS_MAXSTR + 1];

    while (fgets(buf, OS_MAXSTR, fp) != NULL) {
        tmp_str = strstr(buf, "Starting rootcheck scan");
        if (tmp_str) {
            time_t s_time = 0;
            tmp_str = buf + 1;

            s_time = (time_t)atoi(tmp_str);

            return ((int)s_time);
        }
    }

    return ((int)time(NULL));
}

/* Print syscheck db (of modified files) */
static int _do_print_rootcheck(FILE *fp, int resolved, time_t time_last_scan,
                               int csv_output, int show_last)
{
    int i = 0;
    int f_found = 0;

    /* Time from the message */
    time_t s_time = 0;
    time_t i_time = 0;
    struct tm *tm_time;

    char old_day[24 + 1];
    char read_day[24 + 1];
    char buf[OS_MAXSTR + 1];
    char *tmp_str;

    const char *(ig_events[]) = {"Starting rootcheck scan",
                                 "Ending rootcheck scan",
                                 "Starting syscheck scan",
                                 "Ending syscheck scan",
                                 NULL
                                };

    const char *(ns_events[]) = {"Application Found:",
                                 "Windows Audit:",
                                 "Windows Malware:",
                                 NULL
                                };

    buf[OS_MAXSTR] = '\0';
    old_day[24] = '\0';
    read_day[24] = '\0';

    fseek(fp, 0, SEEK_SET);

    if (!csv_output) {
        if (show_last) {
            tm_time = localtime(&time_last_scan);
            strftime(read_day, 23, "%Y %h %d %T", tm_time);

            printf("\nLast scan: %s\n\n", read_day);
        } else if (resolved) {
            printf("\nResolved events: \n\n");
        } else {
            printf("\nOutstanding events: \n\n");
        }
    }

    while (fgets(buf, OS_MAXSTR, fp) != NULL) {
        /* Remove first ! */
        tmp_str = buf + 1;
        s_time = (time_t)atoi(tmp_str);

        /* Remove newline */
        tmp_str = strchr(buf, '\n');
        if (tmp_str) {
            *tmp_str = '\0';
        }

        /* Get initial time */
        tmp_str = strchr(buf + 1, '!');
        if (!tmp_str) {
            continue;
        }
        tmp_str++;

        i_time = (time_t)atoi(tmp_str);

        /* Get the actual message */
        tmp_str = strchr(tmp_str, ' ');
        if (!tmp_str) {
            continue;
        }
        tmp_str++;

        /* Check for resolved */
        if (time_last_scan > (s_time + 86400)) {
            if (!resolved) {
                continue;
            }
        } else {
            if (resolved) {
                continue;
            }
        }

        /* Check events to ignore */
        i = 0;
        while (ig_events[i]) {
            if (strncmp(tmp_str, ig_events[i], strlen(ig_events[i]) - 1) == 0) {
                break;
            }
            i++;
        }
        if (ig_events[i]) {
            continue;
        }

        /* Check events that are not system audit */
        i = 0;
        while (ns_events[i]) {
            if (strncmp(tmp_str, ns_events[i], strlen(ns_events[i]) - 1) == 0) {
                break;
            }
            i++;
        }

        tm_time = localtime((time_t *)&s_time);
        strftime(read_day, 23, "%Y %h %d %T", tm_time);
        tm_time = localtime((time_t *)&i_time);
        strftime(old_day, 23, "%Y %h %d %T", tm_time);

        if (!csv_output) {
            if (!show_last) {
                printf("%s (first time detected: %s)\n", read_day, old_day);
            }

            if (ns_events[i]) {
                printf("%s\n\n", tmp_str);
            } else {
                printf("System Audit: %s\n\n", tmp_str);
            }
        } else {
            printf("%s,%s,%s,%s%s\n", resolved == 0 ? "outstanding" : "resolved",
                   read_day, old_day,
                   ns_events[i] != NULL ? "" : "System Audit: ",
                   tmp_str);
        }

        f_found++;
    }

    if (!f_found && !csv_output) {
        printf("** No entries found.\n");
    }

    return (0);
}

/* Print rootcheck db */
int print_rootcheck(const char *sk_name, const char *sk_ip, const char *fname, int resolved,
                    int csv_output, int show_last)
{
    int ltime = 0;
    FILE *fp;
    char tmp_file[513];

    tmp_file[512] = '\0';

    if (sk_name == NULL) {
        /* Print database */
        snprintf(tmp_file, 512, "%s/rootcheck",
                 ROOTCHECK_DIR);

        fp = fopen(tmp_file, "r+");
    } else {
        /* Print database */
        snprintf(tmp_file, 512, "%s/(%s) %s->rootcheck",
                 ROOTCHECK_DIR,
                 sk_name,
                 sk_ip);

        fp = fopen(tmp_file, "r+");
    }

    if (fp) {
        /* Get last time of scan */
        ltime = _do_get_rootcheckscan(fp);
        if (!fname) {
            if (resolved == 1) {
                _do_print_rootcheck(fp, 1, ltime, csv_output, 0);
            } else if (resolved == 2) {
                _do_print_rootcheck(fp, 0, ltime, csv_output, show_last);
            } else {
                _do_print_rootcheck(fp, 1, ltime, csv_output, 0);
                _do_print_rootcheck(fp, 0, ltime, csv_output, show_last);
            }
        } else {
        }
        fclose(fp);
    }

    return (0);
}

#endif

/* Delete syscheck db */
int delete_syscheck(const char *sk_name, const char *sk_ip, int full_delete)
{
    FILE *fp;
    char tmp_file[513];

    tmp_file[512] = '\0';

    /* Delete related files */
    snprintf(tmp_file, 512, "%s/(%s) %s->syscheck",
             SYSCHECK_DIR,
             sk_name,
             sk_ip);

    fp = fopen(tmp_file, "w");
    if (fp) {
        fclose(fp);
    }

    if (full_delete) {
        unlink(tmp_file);
    }

    /* Delete cpt files */
    snprintf(tmp_file, 512, "%s/.(%s) %s->syscheck.cpt",
             SYSCHECK_DIR,
             sk_name,
             sk_ip);

    fp = fopen(tmp_file, "w");
    if (fp) {
        fclose(fp);
    }
    unlink(tmp_file);

    /* Delete registry entries */
    snprintf(tmp_file, 512, "%s/(%s) %s->syscheck-registry",
             SYSCHECK_DIR,
             sk_name,
             sk_ip);

    fp = fopen(tmp_file, "w");
    if (fp) {
        fclose(fp);
    }
    if (full_delete) {
        unlink(tmp_file);
    }

    /* Delete cpt files */
    snprintf(tmp_file, 512, "%s/.(%s) %s->syscheck-registry.cpt",
             SYSCHECK_DIR,
             sk_name,
             sk_ip);

    fp = fopen(tmp_file, "w");
    if (fp) {
        fclose(fp);
    }
    unlink(tmp_file);

    return (1);
}

/* Delete rootcheck db */
int delete_rootcheck(const char *sk_name, const char *sk_ip, int full_delete)
{
    FILE *fp;
    char tmp_file[513];

    tmp_file[512] = '\0';

    /* Delete related files */
    snprintf(tmp_file, 512, "%s/(%s) %s->rootcheck",
             ROOTCHECK_DIR,
             sk_name,
             sk_ip);

    fp = fopen(tmp_file, "w");
    if (fp) {
        fclose(fp);
    }

    if (full_delete) {
        unlink(tmp_file);
    }

    return (1);
}

/* Delete agent */
int delete_agentinfo(const char *name)
{
    const char *sk_name;
    char *sk_ip;
    char tmp_file[513];

    tmp_file[512] = '\0';

    /* Delete agent info */
    snprintf(tmp_file, 512, "%s/%s", AGENTINFO_DIR, name);
    unlink(tmp_file);

    /* Delete syscheck */
    sk_name = name;
    sk_ip = strrchr(name, '-');
    if (!sk_ip) {
        return (0);
    }

    *sk_ip = '\0';
    sk_ip++;

    /* Delete syscheck */
    delete_syscheck(sk_name, sk_ip, 1);

    return (1);
}

/* Print the text representation of the agent status */
const char *print_agent_status(int status)
{
    const char *status_str = "Never connected";

    if (status == GA_STATUS_ACTIVE) {
        status_str = "Active";
    } else if (status == GA_STATUS_NACTIVE) {
        status_str = "Disconnected";
    }

    return (status_str);
}

#ifndef WIN32
/* Non-windows functions from now on */

/* Send a message to an agent
 * Returns -1 on error
 */
int send_msg_to_agent(int msocket, const char *msg, const char *agt_id, const char *exec)
{
    int rc;
    char agt_msg[OS_SIZE_1024 + 1];

    agt_msg[OS_SIZE_1024] = '\0';

    if (!exec) {
        snprintf(agt_msg, OS_SIZE_1024,
                 "%s %c%c%c %s %s",
                 "(msg_to_agent) []",
                 (agt_id == NULL) ? ALL_AGENTS_C : NONE_C,
                 NO_AR_C,
                 (agt_id != NULL) ? SPECIFIC_AGENT_C : NONE_C,
                 agt_id != NULL ? agt_id : "(null)",
                 msg);
    } else {
        snprintf(agt_msg, OS_SIZE_1024,
                 "%s %c%c%c %s %s - %s (from_the_server) (no_rule_id)",
                 "(msg_to_agent) []",
                 (agt_id == NULL) ? ALL_AGENTS_C : NONE_C,
                 NONE_C,
                 (agt_id != NULL) ? SPECIFIC_AGENT_C : NONE_C,
                 agt_id != NULL ? agt_id : "(null)",
                 msg, exec);

    }

    if ((rc = OS_SendUnix(msocket, agt_msg, 0)) < 0) {
        if (rc == OS_SOCKBUSY) {
            merror("%s: ERROR: Remoted socket busy.", __local_name);
        } else {
            merror("%s: ERROR: Remoted socket error.", __local_name);
        }
        merror("%s: Error communicating with remoted queue (%d).",
               __local_name, rc);

        return (-1);
    }

    return (0);
}

/* Connect to remoted to be able to send messages to the agents
 * Returns the socket on success or -1 on failure
 */
int connect_to_remoted()
{
    int arq = -1;

    if ((arq = StartMQ(ARQUEUE, WRITE)) < 0) {
        merror(ARQ_ERROR, __local_name);
        return (-1);
    }

    return (arq);
}

#endif /* !WIN32 */

/* Internal funtion. Extract last time of scan from rootcheck/syscheck. */
static int _get_time_rkscan(const char *agent_name, const char *agent_ip, agent_info *agt_info)
{
    FILE *fp;
    char buf[1024 + 1];

    /* Agent name of null, means it is the server info */
    if (agent_name == NULL) {
        snprintf(buf, 1024, "%s/rootcheck",
                 ROOTCHECK_DIR);
    } else {
        snprintf(buf, 1024, "%s/(%s) %s->rootcheck",
                 ROOTCHECK_DIR, agent_name, agent_ip);
    }

    /* If file is not there, set to unknown */
    fp = fopen(buf, "r");
    if (!fp) {
        os_strdup("Unknown", agt_info->rootcheck_time);
        os_strdup("Unknown", agt_info->rootcheck_endtime);
        os_strdup("Unknown", agt_info->syscheck_time);
        os_strdup("Unknown", agt_info->syscheck_endtime);
        return (0);
    }

    while (fgets(buf, 1024, fp) != NULL) {
        char *tmp_str = NULL;

        /* Remove newline */
        tmp_str = strchr(buf, '\n');
        if (tmp_str) {
            *tmp_str = '\0';
        }

        tmp_str = strstr(buf, "Starting syscheck scan");
        if (tmp_str) {
            time_t s_time = 0;
            tmp_str = buf + 1;

            s_time = (time_t)atoi(tmp_str);
            os_strdup(ctime(&s_time), agt_info->syscheck_time);

            /* Remove newline */
            tmp_str = strchr(agt_info->syscheck_time, '\n');
            if (tmp_str) {
                *tmp_str = '\0';
            }

            continue;
        }

        tmp_str = strstr(buf, "Ending syscheck scan");
        if (tmp_str) {
            time_t s_time = 0;
            tmp_str = buf + 1;

            s_time = (time_t)atoi(tmp_str);

            os_strdup(ctime(&s_time), agt_info->syscheck_endtime);

            /* Remove newline */
            tmp_str = strchr(agt_info->syscheck_endtime, '\n');
            if (tmp_str) {
                *tmp_str = '\0';
            }

            continue;
        }

        tmp_str = strstr(buf, "Starting rootcheck scan");
        if (tmp_str) {
            time_t s_time = 0;
            tmp_str = buf + 1;

            s_time = (time_t)atoi(tmp_str);

            os_strdup(ctime(&s_time), agt_info->rootcheck_time);

            /* Remove newline */
            tmp_str = strchr(agt_info->rootcheck_time, '\n');
            if (tmp_str) {
                *tmp_str = '\0';
            }

            continue;
        }

        tmp_str = strstr(buf, "Ending rootcheck scan");
        if (tmp_str) {
            time_t s_time = 0;
            tmp_str = buf + 1;
            s_time = (time_t)atoi(tmp_str);
            os_strdup(ctime(&s_time), agt_info->rootcheck_endtime);

            /* Remove newline */
            tmp_str = strchr(agt_info->rootcheck_endtime, '\n');
            if (tmp_str) {
                *tmp_str = '\0';
            }

            continue;
        }
    }

    /* Set unknown values */
    if (!agt_info->rootcheck_time) {
        os_strdup("Unknown", agt_info->rootcheck_time);
    }
    if (!agt_info->rootcheck_endtime) {
        os_strdup("Unknown", agt_info->rootcheck_endtime);
    }
    if (!agt_info->syscheck_time) {
        os_strdup("Unknown", agt_info->syscheck_time);
    }
    if (!agt_info->syscheck_endtime) {
        os_strdup("Unknown", agt_info->syscheck_endtime);
    }

    fclose(fp);
    return (0);
}

/* Internal funtion. Extract last time of scan from rootcheck/syscheck. */
static char *_get_agent_keepalive(const char *agent_name, const char *agent_ip)
{
    char buf[1024 + 1];
    struct stat file_status;

    /* No keepalive for the server */
    if (!agent_name) {
        return (strdup("Not available"));
    }

    snprintf(buf, 1024, "%s/%s-%s", AGENTINFO_DIR, agent_name, agent_ip);
    if (stat(buf, &file_status) < 0) {
        return (strdup("Unknown"));
    }

    return (strdup(ctime(&file_status.st_mtime)));
}

/* Internal function. Extract operating system. */
static int _get_agent_os(const char *agent_name, const char *agent_ip, agent_info *agt_info)
{
    FILE *fp;
    char buf[1024 + 1];

    /* Get server info */
    if (!agent_name) {
        char *ossec_version = NULL;
        agt_info->os = getuname();
        os_strdup(__ossec_name " " __version, agt_info->version);

        /* Remove newline */
        ossec_version = strchr(agt_info->os, '\n');
        if (ossec_version) {
            *ossec_version = '\0';
        }

        ossec_version = strstr(agt_info->os, " - ");
        if (ossec_version) {
            *ossec_version = '\0';
        }

        return (0);
    }

    snprintf(buf, 1024, "%s/%s-%s", AGENTINFO_DIR, agent_name, agent_ip);
    fp = fopen(buf, "r");
    if (!fp) {
        os_strdup("Unknown", agt_info->os);
        os_strdup("Unknown", agt_info->version);
        return (0);
    }

    if (fgets(buf, 1024, fp)) {
        char *ossec_version = NULL;

        /* Remove newline */
        ossec_version = strchr(buf, '\n');
        if (ossec_version) {
            *ossec_version = '\0';
        }

        ossec_version = strstr(buf, " - ");
        if (ossec_version) {
            *ossec_version = '\0';
            ossec_version += 3;

            os_calloc(1024 + 1, sizeof(char), agt_info->version);
            strncpy(agt_info->version, ossec_version, 1024);
        }

        os_strdup(buf, agt_info->os);
        fclose(fp);

        return (1);
    }

    fclose(fp);

    os_strdup("Unknown", agt_info->os);
    os_strdup("Unknown", agt_info->version);

    return (0);
}

/* Get information from an agent */
agent_info *get_agent_info(const char *agent_name, const char *agent_ip)
{
    char *agent_ip_pt = NULL;
    char *tmp_str = NULL;

    agent_info *agt_info = NULL;

    /* Remove the "/", since it is not present on the file */
    if ((agent_ip_pt = strchr(agent_ip, '/'))) {
        *agent_ip_pt = '\0';
    }

    /* Allocate memory for the info structure */
    os_calloc(1, sizeof(agent_info), agt_info);

    /* Zero the values */
    agt_info->rootcheck_time = NULL;
    agt_info->rootcheck_endtime = NULL;
    agt_info->syscheck_time = NULL;
    agt_info->syscheck_endtime = NULL;
    agt_info->os = NULL;
    agt_info->version = NULL;
    agt_info->last_keepalive = NULL;

    /* Get information about the OS */
    _get_agent_os(agent_name, agent_ip, agt_info);
    _get_time_rkscan(agent_name, agent_ip, agt_info);
    agt_info->last_keepalive = _get_agent_keepalive(agent_name, agent_ip);

    /* Remove newline from keepalive */
    tmp_str = strchr(agt_info->last_keepalive, '\n');
    if (tmp_str) {
        *tmp_str = '\0';
    }

    /* Set back the IP address */
    if (agent_ip_pt) {
        *agent_ip_pt = '/';
    }

    return (agt_info);
}

/* Gets the status of an agent, based on the name / IP address */
int get_agent_status(const char *agent_name, const char *agent_ip)
{
    char tmp_file[513];
    char *agent_ip_pt = NULL;
    struct stat file_status;

    tmp_file[512] = '\0';

    /* Server info */
    if (agent_name == NULL) {
        return (GA_STATUS_ACTIVE);
    }

    /* Remove the  "/", since it is not present on the file */
    if ((agent_ip_pt = strchr(agent_ip, '/'))) {
        *agent_ip_pt = '\0';
    }

    snprintf(tmp_file, 512, "%s/%s-%s", AGENTINFO_DIR, agent_name, agent_ip);

    /* Set back the IP address */
    if (agent_ip_pt) {
        *agent_ip_pt = '/';
    }

    if (stat(tmp_file, &file_status) < 0) {
        return (GA_STATUS_INV);
    }

    if (file_status.st_mtime > (time(0) - (3 * NOTIFY_TIME + 30))) {
        return (GA_STATUS_ACTIVE);
    }

    return (GA_STATUS_NACTIVE);
}

/* List available agents */
char **get_agents(int flag)
{
    size_t f_size = 0;
    char **f_files = NULL;
    DIR *dp;
    struct dirent *entry;

    /* Open the directory */
    dp = opendir(AGENTINFO_DIR);
    if (!dp) {
        merror("%s: Error opening directory: '%s': %s ",
               __local_name,
               AGENTINFO_DIR,
               strerror(errno));
        return (NULL);
    }

    /* Read directory */
    while ((entry = readdir(dp)) != NULL) {
        int status = 0;
        char tmp_file[513];
        tmp_file[512] = '\0';

        /* Ignore . and ..  */
        if ((strcmp(entry->d_name, ".") == 0) ||
                (strcmp(entry->d_name, "..") == 0)) {
            continue;
        }

        snprintf(tmp_file, 512, "%s/%s", AGENTINFO_DIR, entry->d_name);

        if (flag != GA_ALL) {
            struct stat file_status;

            if (stat(tmp_file, &file_status) < 0) {
                continue;
            }

            if (file_status.st_mtime > (time(0) - (3 * NOTIFY_TIME + 30))) {
                status = 1;
                if (flag == GA_NOTACTIVE) {
                    continue;
                }
            } else {
                if (flag == GA_ACTIVE) {
                    continue;
                }
            }
        }

        f_files = (char **)realloc(f_files, (f_size + 2) * sizeof(char *));
        if (!f_files) {
            ErrorExit(MEM_ERROR, __local_name, errno, strerror(errno));
        }

        /* Add agent entry */
        if (flag == GA_ALL_WSTATUS) {
            char agt_stat[512];

            snprintf(agt_stat, sizeof(agt_stat) - 1, "%s %s",
                     entry->d_name, status == 1 ? "active" : "disconnected");

            os_strdup(agt_stat, f_files[f_size]);
        } else {
            os_strdup(entry->d_name, f_files[f_size]);
        }

        f_files[f_size + 1] = NULL;

        f_size++;
    }

    closedir(dp);
    return (f_files);
}
