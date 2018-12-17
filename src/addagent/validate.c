/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <time.h>
#include "manage_agents.h"
#include "os_crypto/md5/md5_op.h"

/* Global variables */
fpos_t fp_pos;

/*Number bit of int type*/
#define INT_BIT_SIZE          (sizeof(int)*CHAR_BIT)
/*Enable bit at a position*/
#define SetBit(Array,pos)     ( Array[(pos/INT_BIT_SIZE)] |= (1 << (pos%INT_BIT_SIZE)) )
/*Check state of bit at a */
#define TestBit(Array,pos)    ( Array[(pos/INT_BIT_SIZE)] & (1 << (pos%INT_BIT_SIZE)) )

int *MapIDToBitArray()
{
    FILE *fp;
    char line_read[FILE_SIZE + 1];
    line_read[FILE_SIZE] = '\0';
    int *arrayID;
    int max = MAX_AGENTS + AUTHD_FIRST_ID;
    if (isChroot()) {
        fp = fopen(AUTH_FILE, "r");
    } else {
        fp = fopen(KEYSFILE_PATH, "r");
    }

    if (!fp) {
        return (NULL);
    }

    os_calloc(MAX_AGENTS/INT_BIT_SIZE + 1, sizeof(int), arrayID);

    while (fgets(line_read, FILE_SIZE - 1, fp) != NULL) {
        char *name;

        if (line_read[0] == '#') {
            continue;
        }

        name = strchr(line_read, ' ');
        if (name) {
            *name = '\0';
            int name_num=atoi(line_read);
            /*Enable bit at ID already allocated*/
            if (name_num >= AUTHD_FIRST_ID && name_num < max) {
                SetBit(arrayID, (name_num-AUTHD_FIRST_ID));
            }
        }

    }
    fclose(fp);
    return arrayID;
}

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

    srandom_init();
    muname = getuname();

    snprintf(str1, STR_SIZE, "%d%s%d%s", (int)time(0), name, (int)random(), muname);
    snprintf(str2, STR_SIZE, "%s%s%ld", ip, id, (long int)random());
    OS_MD5_Str(str1, md1);
    OS_MD5_Str(str2, md2);

    free(muname);

    if (id == NULL) {
        int *arrayID;
        int i;
        arrayID=(int *)MapIDToBitArray();
        if (arrayID != NULL) {
            /*Find first item in bit array which is not marked as allocated*/
            for (i=0; i<MAX_AGENTS; i++) {
                if(!TestBit(arrayID, i)) {
                    snprintf(nid, 8, "%d", (i + AUTHD_FIRST_ID));
                    break;
                }
            }
            os_free(arrayID);

            if (i == MAX_AGENTS) {
                return (NULL);
            }
        }
        else {
            return (NULL);
        }

        id = nid;
    }

    char authentication_file[2048 + 1];
    snprintf(authentication_file, 2048, "%s%s", DEFAULTDIR, AUTH_FILE);

    fp = fopen(authentication_file, "a");
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
    return (finals);
}

int OS_RemoveAgent(const char *u_id) {
    FILE *fp;
    int id_exist;

    id_exist = IDExist(u_id);

    if (!id_exist)
        return 0;

    fp = fopen(isChroot() ? AUTH_FILE : KEYSFILE_PATH, "r+");

    if (!fp)
        return 0;

#ifndef WIN32
    if((chmod(AUTH_FILE, 0440)) < 0) {
        merror("addagent: ERROR: Cannot chmod %s: %s", AUTH_FILE, strerror(errno));
    }
#endif

#ifdef REUSE_ID
    long fp_seek;
    size_t fp_read;
    char *buffer;
    char buf_discard[OS_BUFFER_SIZE];
    struct stat fp_stat;

    if (stat(AUTH_FILE, &fp_stat) < 0) {
        fclose(fp);
        return 0;
    }

    buffer = malloc(fp_stat.st_size);
    if (!buffer) {
        fclose(fp);
        return 0;
    }

    fsetpos(fp, &fp_pos);
    fp_seek = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    fp_read = fread(buffer, sizeof(char), fp_seek, fp);
    fgets(buf_discard, OS_BUFFER_SIZE - 1, fp);

    if (!feof(fp))
        fp_read += fread(buffer + fp_read, sizeof(char), fp_stat.st_size, fp);

    fclose(fp);
    fp = fopen(AUTH_FILE, "w");

    if (!fp) {
        free(buffer);
        return 0;
    }

    fwrite(buffer, sizeof(char), fp_read, fp);

#else
    /* Remove the agent, but keep the id */
    fsetpos(fp, &fp_pos);
    fprintf(fp, "%s #*#*#*#*#*#*#*#*#*#*#", u_id);
#endif
    fclose(fp);

    /* Remove counter for ID */
    OS_RemoveCounter(u_id);
    return 1;
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
            if (*name == '#') {
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
        if ( !( isalnum((int)u_name[i]) || (u_name[i] == '-') ||
                (u_name[i] == '_') || (u_name[i] == '.') ||
                (u_name[i] == ':') ) ) {
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

            if (*name == '#') {
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

/* Returns the ID of an agent, or NULL if not found */
char *IPExist(const char *u_ip)
{
    FILE *fp;
    char *name, *ip, *pass;
    char line_read[FILE_SIZE + 1];
    line_read[FILE_SIZE] = '\0';

    if (!(u_ip && strncmp(u_ip, "any", 3)))
        return NULL;

    if (isChroot())
        fp = fopen(AUTH_FILE, "r");
    else
        fp = fopen(KEYSFILE_PATH, "r");

    if (!fp)
        return NULL;

    fseek(fp, 0, SEEK_SET);
    fgetpos(fp, &fp_pos);

    while (fgets(line_read, FILE_SIZE - 1, fp) != NULL) {
        if (line_read[0] == '#') {
            continue;
        }

        name = strchr(line_read, ' ');
        if (name) {
            name++;

            if (*name == '#') {
                continue;
            }

            ip = strchr(name, ' ');
            if (ip) {
                ip++;

                pass = strchr(ip, ' ');
                if (pass) {
                    *pass = '\0';
                    if (strcmp(u_ip, ip) == 0) {
                        fclose(fp);
                        name[-1] = '\0';
                        return strdup(line_read);
                    }
                }
            }
        }

        fgetpos(fp, &fp_pos);
    }

    fclose(fp);
    return NULL;
}

/* Returns the number of seconds since last agent connection, or -1 if error. */
double OS_AgentAntiquity(const char *id)
{
    struct stat file_stat;
    char file_name[OS_FLSIZE];
    char *full_name = getFullnameById(id);

    if (!full_name) {
        return -1;
    }

    snprintf(file_name, OS_FLSIZE - 1, "%s/%s", AGENTINFO_DIR, full_name);

    if (stat(file_name, &file_stat) < 0) {
        if(full_name) {
            free(full_name);
        }
        return -1;
    }

    free(full_name);

    return difftime(time(NULL), file_stat.st_mtime);
}

/* Print available agents */
int print_agents(int print_status, int active_only, int csv_output, int json_output)
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
            if (*name == '#') {
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
                            printf("%s,%s,%s,%s,\n", line_read, name, ip, print_agent_status(agt_status));
			}else if (json_output) {
			   printf(", { \"ID\" : \"%s\", \"Name\" : \"%s\", \"IP\": \"%s\", \"Status\" : \"%s\" }",line_read, name, ip, print_agent_status(agt_status));
			} else {
                            printf(PRINT_AGENT_STATUS, line_read, name, ip, print_agent_status(agt_status));
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

        if (!csv_output && !json_output) {
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
