/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "addagent/manage_agents.h"
#include "sec.h"

#undef ARGV0
#define ARGV0 "syscheck_control"

/* Prototypes */
static void helpmsg(void) __attribute__((noreturn));


static void helpmsg()
{
    printf("\nOSSEC HIDS %s: Manages the integrity checking database.\n",
           ARGV0);
    printf("Available options:\n");
    printf("\t-h          This help message.\n");
    printf("\t-l          List available (active or inactive) agents.\n");
    printf("\t-lc         List only active agents.\n");
    printf("\t-u <id>     Updates (clears) the database for the agent.\n");
    printf("\t-u all      Updates (clears) the database for all agents.\n");
    printf("\t-i <id>     List modified files for the agent.\n");
    printf("\t-r -i <id>  List modified registry entries for the agent "
           "(Windows only).\n");
    printf("\t-f <file>   Prints information about a modified file.\n");
    printf("\t            Must be used with -i <id>.\n");
    printf("\t-z          Used with -f, zeroes the auto-ignore counter.\n");
    printf("\t-d          Used with -f, ignores that file.\n");
    printf("\t-s          Changes the output to CSV (comma delimited).\n");
    printf("\n");
    printf("\tExamples:\n");
    printf("\n");
    printf("\t'Show information about /etc/passwd from agent with ID 019'\n");
    printf("\t%s -i 019 -f /etc/passwd\n", ARGV0);
    exit(1);
}

int main(int argc, char **argv)
{
    const char *dir = DEFAULTDIR;
    const char *group = GROUPGLOBAL;
    const char *user = USER;
    const char *agent_id = NULL;
    const char *fname = NULL;

    gid_t gid;
    uid_t uid;
    int c = 0, info_agent = 0, update_syscheck = 0,
        list_agents = 0, zero_counter = 0,
        registry_only = 0;
    int active_only = 0, csv_output = 0;

    char shost[512];

    /* Set the name */
    OS_SetName(ARGV0);

    /* User arguments */
    if (argc < 2) {
        helpmsg();
    }

    while ((c = getopt(argc, argv, "VhzrDdlcsu:i:f:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                helpmsg();
                break;
            case 'D':
                nowDebug();
                break;
            case 'l':
                list_agents++;
                break;
            case 'z':
                zero_counter = 1;
                break;
            case 'd':
                zero_counter = 2;
                break;
            case 's':
                csv_output = 1;
                break;
            case 'c':
                active_only++;
                break;
            case 'r':
                registry_only = 1;
                break;
            case 'i':
                info_agent++;
                if (!optarg) {
                    merror("%s: -u needs an argument", ARGV0);
                    helpmsg();
                }
                agent_id = optarg;
                break;
            case 'f':
                if (!optarg) {
                    merror("%s: -u needs an argument", ARGV0);
                    helpmsg();
                }
                fname = optarg;
                break;
            case 'u':
                if (!optarg) {
                    merror("%s: -u needs an argument", ARGV0);
                    helpmsg();
                }
                agent_id = optarg;
                update_syscheck = 1;
                break;
            default:
                helpmsg();
                break;
        }
    }

    /* Get the group name */
    gid = Privsep_GetGroup(group);
    uid = Privsep_GetUser(user);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        ErrorExit(USER_ERROR, ARGV0, user, group);
    }

    /* Set the group */
    if (Privsep_SetGroup(gid) < 0) {
        ErrorExit(SETGID_ERROR, ARGV0, group, errno, strerror(errno));
    }

    /* Chroot to the default directory */
    if (Privsep_Chroot(dir) < 0) {
        ErrorExit(CHROOT_ERROR, ARGV0, dir, errno, strerror(errno));
    }

    /* Inside chroot now */
    nowChroot();

    /* Set the user */
    if (Privsep_SetUser(uid) < 0) {
        ErrorExit(SETUID_ERROR, ARGV0, user, errno, strerror(errno));
    }

    /* Get server hostname */
    memset(shost, '\0', 512);
    if (gethostname(shost, 512 - 1) != 0) {
        strncpy(shost, "localhost", 32);
        return (0);
    }

    /* List available agents */
    if (list_agents) {
        if (!csv_output) {
            printf("\nOSSEC HIDS %s. List of available agents:",
                   ARGV0);
            printf("\n   ID: 000, Name: %s (server), IP: 127.0.0.1, "
                   "Active/Local\n", shost);
        } else {
            printf("000,%s (server),127.0.0.1,Active/Local,\n", shost);
        }
        print_agents(1, active_only, csv_output);
        printf("\n");
        exit(0);
    }

    /* Update syscheck database */
    if (update_syscheck) {
        /* Clean all agents (and server) db */
        if (strcmp(agent_id, "all") == 0) {
            DIR *sys_dir;
            struct dirent *entry;

            sys_dir = opendir(SYSCHECK_DIR);
            if (!sys_dir) {
                ErrorExit("%s: Unable to open: '%s'", ARGV0, SYSCHECK_DIR);
            }

            while ((entry = readdir(sys_dir)) != NULL) {
                FILE *fp;
                char full_path[OS_MAXSTR + 1];

                /* Do not even attempt to delete . and .. :) */
                if ((strcmp(entry->d_name, ".") == 0) ||
                        (strcmp(entry->d_name, "..") == 0)) {
                    continue;
                }

                snprintf(full_path, OS_MAXSTR, "%s/%s", SYSCHECK_DIR,
                         entry->d_name);

                fp = fopen(full_path, "w");
                if (fp) {
                    fclose(fp);
                }
                if (entry->d_name[0] == '.') {
                    unlink(full_path);
                }
            }

            closedir(sys_dir);
            printf("\n** Integrity check database updated.\n\n");
            exit(0);
        }

        else if ((strcmp(agent_id, "000") == 0) ||
                 (strcmp(agent_id, "local") == 0)) {
            char final_dir[1024];
            FILE *fp;
            snprintf(final_dir, 1020, "/%s/syscheck", SYSCHECK_DIR);

            fp = fopen(final_dir, "w");
            if (fp) {
                fclose(fp);
            }
            unlink(final_dir);


            /* Deleting cpt file */
            snprintf(final_dir, 1020, "/%s/.syscheck.cpt", SYSCHECK_DIR);

            fp = fopen(final_dir, "w");
            if (fp) {
                fclose(fp);
            }
            unlink(final_dir);

            printf("\n** Integrity check database updated.\n\n");
            exit(0);
        }

        /* Database from remote agents */
        else {
            int i;
            keystore keys;

            OS_ReadKeys(&keys);

            i = OS_IsAllowedID(&keys, agent_id);
            if (i < 0) {
                printf("\n** Invalid agent id '%s'.\n", agent_id);
                helpmsg();
            }

            /* Delete syscheck */
            delete_syscheck(keys.keyentries[i]->name,
                            keys.keyentries[i]->ip->ip, 0);

            printf("\n** Integrity check database updated.\n\n");
            exit(0);
        }
    }

    /* Print information from an agent */
    if (info_agent) {
        int i;
        char final_ip[IPSIZE + 4];
        keystore keys;

        if ((strcmp(agent_id, "000") == 0) ||
                (strcmp(agent_id, "local") == 0)) {
            printf("\nIntegrity checking changes for local system '%s - %s':\n",
                   shost, "127.0.0.1");
            if (fname) {
                printf("Detailed information for entries matching: '%s'\n",
                       fname);
            }

            print_syscheck(NULL,
                           NULL, fname, 0, 0,
                           csv_output, zero_counter);
        } else if (strchr(agent_id, '@')) {
            if (fname) {
                printf("Detailed information for entries matching: '%s'\n",
                       fname);
            }
            print_syscheck(agent_id, NULL, fname, registry_only, 0,
                           csv_output, zero_counter);
        } else {
            OS_ReadKeys(&keys);

            i = OS_IsAllowedID(&keys, agent_id);
            if (i < 0) {
                printf("\n** Invalid agent id '%s'.\n", agent_id);
                helpmsg();
            }

            /* Getting full address/prefix length from ip. */
            final_ip[(sizeof final_ip) - 1] = '\0';
            snprintf(final_ip, sizeof final_ip, "%s/%u",
                     keys.keyentries[i]->ip->ip,
                     keys.keyentries[i]->ip->prefixlength);

            if (registry_only) {
                printf("\nIntegrity changes for 'Windows Registry' of"
                       " agent '%s (%s) - %s':\n",
                       keys.keyentries[i]->name, keys.keyentries[i]->id,
                       final_ip);
            } else {
                printf("\nIntegrity changes for agent "
                       "'%s (%s) - %s':\n",
                       keys.keyentries[i]->name, keys.keyentries[i]->id,
                       final_ip);
            }

            if (fname) {
                printf("Detailed information for entries matching: '%s'\n",
                       fname);
            }
            print_syscheck(keys.keyentries[i]->name,
                           keys.keyentries[i]->ip->ip, fname,
                           registry_only, 0, csv_output, zero_counter);

        }

        exit(0);
    }

    printf("\n** Invalid argument combination.\n");
    helpmsg();

    return (0);
}

