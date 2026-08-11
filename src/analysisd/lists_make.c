/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "rules.h"
#include "cdb/cdb.h"
#include "cdb/cdb_make.h"
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "lists_make.h"

/* Trailing comment marker for CDB list text files (#1527). */
#define LIST_COMMENT_MARK "###"

/*
 * Strip a trailing "###" comment and any spaces/tabs immediately before it.
 * Full-line comments become an empty string. Returns the (possibly empty) line.
 */
static char *lists_strip_comment(char *str)
{
    char *comment;
    char *p;

    comment = strstr(str, LIST_COMMENT_MARK);
    if (!comment) {
        return str;
    }

    p = comment;
    while (p > str && (p[-1] == ' ' || p[-1] == '\t')) {
        p--;
    }
    *p = '\0';
    return str;
}

void Lists_OP_MakeAll(int force)
{
    ListNode *lnode = OS_GetFirstList();
    while (lnode) {
        Lists_OP_MakeCDB(lnode->txt_filename,
                         lnode->cdb_filename,
                         force);
        lnode = lnode->next;
    }
}

void Lists_OP_MakeCDB(const char *txt_filename, const char *cdb_filename, int force)
{
    struct cdb_make cdbm;
    FILE *tmp_fd;
    FILE *txt_fd;
    char *tmp_str;
    char *key, *val;
    char str[OS_MAXSTR + 1];

    str[OS_MAXSTR] = '\0';
    char tmp_filename[OS_MAXSTR];
    tmp_filename[OS_MAXSTR - 2] = '\0';
    snprintf(tmp_filename, OS_MAXSTR - 2, "%s.tmp", txt_filename);

    if (File_DateofChange(txt_filename) > File_DateofChange(cdb_filename) ||
            force) {
        printf(" * File %s needs to be updated\n", cdb_filename);
        tmp_fd = fopen(tmp_filename, "w+");
        cdb_make_start(&cdbm, tmp_fd);
        if (!(txt_fd = fopen(txt_filename, "r"))) {
            merror(FOPEN_ERROR, ARGV0, txt_filename, errno, strerror(errno));
            return;
        }
        while ((fgets(str, OS_MAXSTR - 1, txt_fd)) != NULL) {
            /* Remove newlines and carriage returns */
            tmp_str = strchr(str, '\r');
            if (tmp_str) {
                *tmp_str = '\0';
            }
            tmp_str = strchr(str, '\n');
            if (tmp_str) {
                *tmp_str = '\0';
            }

            lists_strip_comment(str);

            /* Skip blank lines and full-line comments */
            if (str[0] == '\0') {
                continue;
            }

            if ((val = strchr(str, ':'))) {
                *val = '\0';
                val++;
            } else {
                continue;
            }
            key = str;
            cdb_make_add(&cdbm, key, strlen(key), val, strlen(val));
            if (force) {
                print_out("  * adding - key: %s value: %s", key, val);
            }
        }

        fclose(txt_fd);

        cdb_make_finish(&cdbm);
        if (rename(tmp_filename, cdb_filename) == -1) {
            merror(RENAME_ERROR, ARGV0, tmp_filename, cdb_filename, errno, strerror(errno));
            return;
        }
    } else {
        printf(" * File %s does not need to be compiled\n", cdb_filename);
    }
}
