/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "manage_agents.h"
#include "os_crypto/md5/md5_op.h"

#ifdef WIN32
    #define chmod(x,y)
    #define mkdir(x,y) 0
    #define link(x,y)
    #define difftime(x,y) 0
#endif

/* Global variables */
fpos_t fp_pos;


char *OS_AddNewAgent(const char *name, const char *ip, const char *id)
{
    FILE *fp;
    os_md5 md1;
    os_md5 md2;
    char str1[STR_SIZE + 1];
    char str2[STR_SIZE + 1];
    char *muname;
    char *finals;
    char nid[9] = { '\0' };
    char agentinfo_path[OS_FLSIZE];
    char timestamp[40];
    time_t timer;

    srandom_init();
    muname = getuname();

    snprintf(str1, STR_SIZE, "%d%s%d%s", (int)time(0), name, (int)random(), muname);
    snprintf(str2, STR_SIZE, "%s%s%ld", ip, id, (long int)random());
    OS_MD5_Str(str1, md1);
    OS_MD5_Str(str2, md2);

    free(muname);

    if (id == NULL) {
#ifdef REUSE_ID
        int i = 1024;
        snprintf(nid, 6, "%d", i);
        while (IDExist(nid)) {
            i++;
            snprintf(nid, 6, "%d", i);
            if (i >= (MAX_AGENTS + 1024))
                return (NULL);
        }
#else
        char nid_p[9] = { '\0' };
        int i = AUTHD_FIRST_ID;
        int j = MAX_AGENTS + AUTHD_FIRST_ID;
        int m = (i + j) / 2;

        snprintf(nid, 8, "%d", m);
        snprintf(nid_p, 8, "%d", m - 1);

        /* Dichotomic search */

        while (1) {
            if (IDExist(nid)) {
                if (m == i)
                    return NULL;

                i = m;
            } else if (!IDExist(nid_p) && m > i )
                j = m;
            else
                break;

            m = (i + j) / 2;
            snprintf(nid, 8, "%d", m);
            snprintf(nid_p, 8, "%d", m - 1);
        }
#endif
        id = nid;
    }

    fp = fopen(KEYSFILE_PATH, "a");
    if (!fp) {
        return (NULL);
    }

    os_calloc(2048, sizeof(char), finals);
    if (ip == NULL) {
        snprintf(finals, 2048, "%s %s any %s%s", id, name, md1, md2);
    } else {
        snprintf(finals, 2048, "%s %s %s %s%s", id, name, ip, md1, md2);
    }
    fprintf(fp, "%s\n", finals);
    fclose(fp);

    if (ip == NULL) {
        snprintf(agentinfo_path, OS_FLSIZE, "%s/%s-any", AGENTINFO_DIR, name);
    } else {
        snprintf(agentinfo_path, OS_FLSIZE, "%s/%s-%s", AGENTINFO_DIR, name, ip);
    }

    fp = fopen(agentinfo_path, "w");

    if (fp) {
        timer = time(NULL);
        strftime(timestamp, 40, "%Y-%m-%d %H:%M:%S", localtime(&timer));
        fprintf(fp, "\n%s\n", timestamp);
        fclose(fp);
        chmod(agentinfo_path, 0660);
    } else {
        merror("%s: ERROR: Couldn't write on agent-info file.", ARGV0);
    }

    return (finals);
}


int OS_IsValidID(const char *id)
{
    size_t id_len, i;

    /* ID must not be null */
    if (!id) {
        return (0);
    }

    id_len = strlen(id);

    /* Check ID length, it should contain max. 8 characters */
    if (id_len > 8) {
        return (0);
    }

    /* Check ID if it contains only numeric characters [0-9] */
    for (i = 0; i < id_len; i++) {
        if (!(isdigit((int)id[i]))) {
            return (0);
        }
    }

    return (1);
}

/* Get full agent name (name + IP) of ID */
char *getFullnameById(const char *id)
{
    FILE *fp;
    char line_read[FILE_SIZE + 1];
    line_read[FILE_SIZE] = '\0';

    /* ID must not be null */
    if (!id) {
        return (NULL);
    }

    fp = fopen(AUTH_FILE, "r");
    if (!fp) {
        return (NULL);
    }

    while (fgets(line_read, FILE_SIZE - 1, fp) != NULL) {
        char *name;
        char *ip;
        char *tmp_str;

        if (line_read[0] == '#') {
            continue;
        }

        name = strchr(line_read, ' ');
        if (name) {
            *name = '\0';
            /* Didn't match */
            if (strcmp(line_read, id) != 0) {
                continue;
            }

            name++;

            /* Removed entry */
            if (*name == '#' || *name == '!') {
                continue;
            }

            ip = strchr(name, ' ');
            if (ip) {
                *ip = '\0';
                ip++;

                /* Clean up IP */
                tmp_str = strchr(ip, ' ');
                if (tmp_str) {
                    char *final_str;
                    *tmp_str = '\0';
                    tmp_str = strchr(ip, '/');
                    if (tmp_str) {
                        *tmp_str = '\0';
                    }

                    /* If we reached here, we found the IP and name */
                    os_calloc(1, FILE_SIZE, final_str);
                    snprintf(final_str, FILE_SIZE - 1, "%s-%s", name, ip);

                    fclose(fp);
                    return (final_str);
                }
            }
        }
    }

    fclose(fp);
    return (NULL);
}

/* ID Search (is valid ID) */
int IDExist(const char *id)
{
    FILE *fp;
    char line_read[FILE_SIZE + 1];
    line_read[FILE_SIZE] = '\0';

    /* ID must not be null */
    if (!id) {
        return (0);
    }

    if (isChroot()) {
        fp = fopen(AUTH_FILE, "r");
    } else {
        fp = fopen(KEYSFILE_PATH, "r");
    }

    if (!fp) {
        return (0);
    }

    fseek(fp, 0, SEEK_SET);
    fgetpos(fp, &fp_pos);

    while (fgets(line_read, FILE_SIZE - 1, fp) != NULL) {
        char *name;

        if (line_read[0] == '#') {
            fgetpos(fp, &fp_pos);
            continue;
        }

        name = strchr(line_read, ' ');
        if (name) {
            *name = '\0';
            name++;

            if (strcmp(line_read, id) == 0) {
                fclose(fp);
                return (1); /*(fp_pos);*/
            }
        }

        fgetpos(fp, &fp_pos);
    }

    fclose(fp);
    return (0);
}

/* Validate agent name */
int OS_IsValidName(const char *u_name)
{
    size_t i, uname_length = strlen(u_name);

    /* We must have something in the name */
    if (uname_length < 2 || uname_length > 128) {
        return (0);
    }

    /* Check if it contains any non-alphanumeric characters */
    for (i = 0; i < uname_length; i++) {
        if (!isalnum((int)u_name[i]) && (u_name[i] != '-') &&
                (u_name[i] != '_') && (u_name[i] != '.')) {
            return (0);
        }
    }

    return (1);
}

int NameExist(const char *u_name)
{
    FILE *fp;
    char line_read[FILE_SIZE + 1];
    line_read[FILE_SIZE] = '\0';

    if ((!u_name) ||
            (*u_name == '\0') ||
            (*u_name == '\r') ||
            (*u_name == '\n')) {
        return (0);
    }

    if (isChroot()) {
        fp = fopen(AUTH_FILE, "r");
    } else {
        fp = fopen(KEYSFILE_PATH, "r");
    }

    if (!fp) {
        return (0);
    }

    fseek(fp, 0, SEEK_SET);
    fgetpos(fp, &fp_pos);

    while (fgets(line_read, FILE_SIZE - 1, fp) != NULL) {
        char *name;

        if (line_read[0] == '#') {
            continue;
        }

        name = strchr(line_read, ' ');
        if (name) {
            char *ip;
            name++;

            if (*name == '#' || *name == '!') {
                continue;
            }

            ip = strchr(name, ' ');
            if (ip) {
                *ip = '\0';
                if (strcmp(u_name, name) == 0) {
                    fclose(fp);
                    return (1);
                }
            }
        }
        fgetpos(fp, &fp_pos);
    }

    fclose(fp);
    return (0);
}

/* Print available agents */
int print_agents(int print_status, int active_only, int csv_output)
{
    int total = 0;
    FILE *fp;
    char line_read[FILE_SIZE + 1];
    line_read[FILE_SIZE] = '\0';

    fp = fopen(AUTH_FILE, "r");
    if (!fp) {
        return (0);
    }

    fseek(fp, 0, SEEK_SET);

    memset(line_read, '\0', FILE_SIZE);

    while (fgets(line_read, FILE_SIZE - 1, fp) != NULL) {
        char *name;

        if (line_read[0] == '#') {
            continue;
        }

        name = strchr(line_read, ' ');
        if (name) {
            char *ip;
            *name = '\0';
            name++;

            /* Removed agent */
            if (*name == '#' || *name == '!') {
                continue;
            }

            ip = strchr(name, ' ');
            if (ip) {
                char *key;
                *ip = '\0';
                ip++;
                key = strchr(ip, ' ');
                if (key) {
                    *key = '\0';
                    if (!total && !print_status) {
                        printf(PRINT_AVAILABLE);
                    }
                    total++;

                    if (print_status) {
                        int agt_status = get_agent_status(name, ip);
                        if (active_only && (agt_status != GA_STATUS_ACTIVE)) {
                            continue;
                        }

                        if (csv_output) {
                            printf("%s,%s,%s,%s,\n", line_read, name, ip,
                                   print_agent_status(agt_status));
                        } else {
                            printf(PRINT_AGENT_STATUS, line_read, name, ip,
                                   print_agent_status(agt_status));
                        }
                    } else {
                        printf(PRINT_AGENT, line_read, name, ip);
                    }
                }
            }
        }
    }

    /* Only print agentless for non-active only searches */
    if (!active_only && print_status) {
        const char *aip = NULL;
        DIR *dirp;
        struct dirent *dp;

        if (!csv_output) {
            printf("\nList of agentless devices:\n");
        }

        dirp = opendir(AGENTLESS_ENTRYDIR);
        if (dirp) {
            while ((dp = readdir(dirp)) != NULL) {
                if (strncmp(dp->d_name, ".", 1) == 0) {
                    continue;
                }

                aip = strchr(dp->d_name, '@');
                if (aip) {
                    aip++;
                } else {
                    aip = "<na>";
                }

                if (csv_output) {
                    printf("na,%s,%s,agentless,\n", dp->d_name, aip);
                } else {
                    printf("   ID: na, Name: %s, IP: %s, agentless\n",
                           dp->d_name, aip);
                }
            }
            closedir(dirp);
        }
    }

    fclose(fp);
    if (total) {
        return (1);
    }

    return (0);
}

void FormatID(char *id) {
    int number;
    char *end;

    if (id && *id) {
        number = strtol(id, &end, 10);

        if (!*end) {
            sprintf(id, "%03d", number);
        }
    }
}

/* Backup agent information before force deleting */
void OS_BackupAgentInfo(const char *id)
{
    char path_backup[OS_FLSIZE];
    char path_src[OS_FLSIZE];
    char path_dst[OS_FLSIZE];
    char timestamp[40];
    char *name = getFullnameById(id);
    char *ip;
    time_t timer = time(NULL);

    if (!name) {
        merror("%s: ERROR: Agent id %s not found.", ARGV0, id);
        return;
    }

    snprintf(path_src, OS_FLSIZE, "%s/%s", AGENTINFO_DIR, name);

    ip = strchr(name, '-');
    *(ip++) = 0;

    strftime(timestamp, 40, "%Y-%m-%d %H:%M:%S", localtime(&timer));
    snprintf(path_backup, OS_FLSIZE, "%s/%s-%s %s", AGNBACKUP_DIR, name, ip, timestamp);

    if (mkdir(path_backup, 0750) >= 0) {
        /* agent-info */
        snprintf(path_dst, OS_FLSIZE, "%s/agent-info", path_backup);
        link(path_src, path_dst);

        /* syscheck */
        snprintf(path_src, OS_FLSIZE, "%s/(%s) %s->syscheck", SYSCHECK_DIR, name, ip);
        snprintf(path_dst, OS_FLSIZE, "%s/syscheck", path_backup);
        link(path_src, path_dst);

        snprintf(path_src, OS_FLSIZE, "%s/.(%s) %s->syscheck.cpt", SYSCHECK_DIR, name, ip);
        snprintf(path_dst, OS_FLSIZE, "%s/syscheck.cpt", path_backup);
        link(path_src, path_dst);

        snprintf(path_src, OS_FLSIZE, "%s/(%s) %s->syscheck-registry", SYSCHECK_DIR, name, ip);
        snprintf(path_dst, OS_FLSIZE, "%s/syscheck-registry", path_backup);
        link(path_src, path_dst);

        snprintf(path_src, OS_FLSIZE, "%s/.(%s) %s->syscheck-registry.cpt", SYSCHECK_DIR, name, ip);
        snprintf(path_dst, OS_FLSIZE, "%s/syscheck-registry.cpt", path_backup);
        link(path_src, path_dst);

        /* rootcheck */
        snprintf(path_src, OS_FLSIZE, "%s/(%s) %s->rootcheck", ROOTCHECK_DIR, name, ip);
        snprintf(path_dst, OS_FLSIZE, "%s/rootcheck", path_backup);
        link(path_src, path_dst);
    } else {
        merror("%s: ERROR: Couldn't create backup directory.", ARGV0);
    }

    free(name);
}
