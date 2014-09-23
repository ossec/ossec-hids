/* @(#) $Id: ./src/rootcheck/check_rc_readproc.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WIN32
#include "shared.h"
#include "rootcheck.h"

#define PROC    0
#define PID     1
#define TASK    2

int proc_pid_found;


/** Prototypes **/
int read_proc_dir(char *dir_name, char *pid, int position);


int read_proc_file(char *file_name, char *pid, int position)
{
    struct stat statbuf;

    if(lstat(file_name, &statbuf) < 0) {
        return(-1);
    }

    /* If directory, read the directory */
    else if(S_ISDIR(statbuf.st_mode)) {
        return(read_proc_dir(file_name, pid, position));
    }

    return(0);
}

/* read_dir v0.1
 *
 */
int read_proc_dir(char *dir_name, char *pid, int position)
{
    DIR *dp;

    struct dirent *entry;


    if((dir_name == NULL) || (strlen(dir_name) > PATH_MAX)) {
        merror("%s: Invalid directory given", ARGV0);
        return(-1);
    }

    /* Opening the directory given */
    dp = opendir(dir_name);
    if(!dp) {
        return(0);
    }

    while((entry = readdir(dp)) != NULL) {
        char f_name[PATH_MAX + 2];

        /* Just ignore . and ..  */
        if((strcmp(entry->d_name, ".") == 0) ||
                (strcmp(entry->d_name, "..") == 0)) {
            continue;
        }

        if(position == PROC) {
            char *tmp_str;

            tmp_str = entry->d_name;

            while(*tmp_str != '\0') {
                if(!isdigit((int)*tmp_str)) {
                    break;
                }
                tmp_str++;
            }

            if(*tmp_str != '\0') {
                continue;
            }


            snprintf(f_name, PATH_MAX + 1, "%s/%s", dir_name, entry->d_name);

            read_proc_file(f_name, pid, position + 1);
        }

        else if(position == PID) {
            if(strcmp(entry->d_name, "task") == 0) {
                snprintf(f_name, PATH_MAX + 1, "%s/%s", dir_name, entry->d_name);
                read_proc_file(f_name, pid, position + 1);
            }
        }

        else if(position == TASK) {
            /* checking under proc/pid/task/lwp */
            if(strcmp(entry->d_name, pid) == 0) {
                proc_pid_found = 1;
                break;
            }
        } else {
            break;
        }
    }

    closedir(dp);

    return(0);
}


/*  int check_rc_readproc(int pid): v0.1
 *  Reads the /proc directory (if present) and checks
 *  if the given pid is there (or as a PID or as a thread).
 */
int check_rc_readproc(int pid)
{
    char char_pid[32];

    proc_pid_found = 0;

    /* NL threads */
    snprintf(char_pid, 31, "/proc/.%d", pid);
    if(is_file(char_pid)) {
        return(1);
    }


    snprintf(char_pid, 31, "%d", pid);

    read_proc_dir("/proc", char_pid, PROC);

    return(proc_pid_found);
}

/* EOF */
#endif
