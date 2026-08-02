/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* First time seen functions */

#include "fts.h"
#include "eventinfo.h"
#include "shared.h"

#ifndef WIN32
#include <time.h>
#include "queue_op.h"

/* Declared in pipeline.c; avoid including pipeline.h (circular with fts). */
extern os_queue *writer_queue_fts;
#endif

/* Timed wait for FTS writer queue space before sync fallback (seconds). */
#define FTS_QUEUE_PUSH_WAIT_SEC 1

/* Local variables */
static unsigned int fts_minsize_for_str = 0;

static OSList *fts_list = NULL;
static OSHash *fts_store = NULL;

static FILE *fp_list = NULL;
static FILE *fp_ignore = NULL;
#ifndef WIN32
static pthread_mutex_t fts_mutex = PTHREAD_MUTEX_INITIALIZER;
/* File I/O only — keep separate from fts_mutex (in-memory hash/list). */
static pthread_mutex_t fts_write_lock = PTHREAD_MUTEX_INITIALIZER;
#endif


void FTS_Fprintf(char *_line)
{
    if (!_line || !fp_list) {
        return;
    }

#ifndef WIN32
    os_mutex_lock(&fts_write_lock);
#endif
    fseek(fp_list, 0, SEEK_END);
    fprintf(fp_list, "%s\n", _line);
#ifndef WIN32
    os_mutex_unlock(&fts_write_lock);
#endif
}

void FTS_Flush(void)
{
    if (!fp_list) {
        return;
    }

#ifndef WIN32
    os_mutex_lock(&fts_write_lock);
#endif
    fflush(fp_list);
#ifndef WIN32
    os_mutex_unlock(&fts_write_lock);
#endif
}

/* Start the FTS module */
int FTS_Init()
{
    int fts_list_size;
    char _line[OS_FLSIZE + 1];

    _line[OS_FLSIZE] = '\0';

    fts_list = OSList_Create();
    if (!fts_list) {
        merror(LIST_ERROR, ARGV0);
        return (0);
    }

    /* Create store data */
    fts_store = OSHash_Create();
    if (!fts_store) {
        merror(LIST_ERROR, ARGV0);
        return (0);
    }
    if (!OSHash_setSize(fts_store, 2048)) {
        merror(LIST_ERROR, ARGV0);
        return (0);
    }

    /* Get default list size */
    fts_list_size = getDefine_Int("analysisd",
                                  "fts_list_size",
                                  12, 512);

    /* Get minimum string size */
    fts_minsize_for_str = (unsigned int) getDefine_Int("analysisd",
                          "fts_min_size_for_str",
                          6, 128);

    if (!OSList_SetMaxSize(fts_list, fts_list_size)) {
        merror(LIST_SIZE_ERROR, ARGV0);
        return (0);
    }

    /* Create fts list */
    fp_list = fopen(FTS_QUEUE, "r+");
    if (!fp_list) {
        /* Create the file if we cant open it */
        fp_list = fopen(FTS_QUEUE, "w+");
        if (fp_list) {
            fclose(fp_list);
        }

        if (chmod(FTS_QUEUE, 0640) == -1) {
            merror(CHMOD_ERROR, ARGV0, FTS_QUEUE, errno, strerror(errno));
            return 0;
        }

        uid_t uid = Privsep_GetUser(USER);
        gid_t gid = Privsep_GetGroup(GROUPGLOBAL);
        if (uid != (uid_t) - 1 && gid != (gid_t) - 1) {
            if (chown(FTS_QUEUE, uid, gid) == -1) {
                merror(CHOWN_ERROR, ARGV0, FTS_QUEUE, errno, strerror(errno));
                return (0);
            }
        }

        fp_list = fopen(FTS_QUEUE, "r+");
        if (!fp_list) {
            merror(FOPEN_ERROR, ARGV0, FTS_QUEUE, errno, strerror(errno));
            return (0);
        }
    }

    /* Add content from the files to memory */
    fseek(fp_list, 0, SEEK_SET);
    while (fgets(_line, OS_FLSIZE , fp_list) != NULL) {
        char *tmp_s;

        /* Remove newlines */
        tmp_s = strchr(_line, '\n');
        if (tmp_s) {
            *tmp_s = '\0';
        }

        os_strdup(_line, tmp_s);
        if (OSHash_Add(fts_store, tmp_s, tmp_s) <= 0) {
            free(tmp_s);
            merror(LIST_ADD_ERROR, ARGV0);
        }
    }

    /* Create ignore list */
    fp_ignore = fopen(IG_QUEUE, "r+");
    if (!fp_ignore) {
        /* Create the file if we cannot open it */
        fp_ignore = fopen(IG_QUEUE, "w+");
        if (fp_ignore) {
            fclose(fp_ignore);
        }

        if (chmod(IG_QUEUE, 0640) == -1) {
            merror(CHMOD_ERROR, ARGV0, IG_QUEUE, errno, strerror(errno));
            return (0);
        }

        uid_t uid = Privsep_GetUser(USER);
        gid_t gid = Privsep_GetGroup(GROUPGLOBAL);
        if (uid != (uid_t) - 1 && gid != (gid_t) - 1) {
            if (chown(IG_QUEUE, uid, gid) == -1) {
                merror(CHOWN_ERROR, ARGV0, IG_QUEUE, errno, strerror(errno));
                return (0);
            }
        }

        fp_ignore = fopen(IG_QUEUE, "r+");
        if (!fp_ignore) {
            merror(FOPEN_ERROR, ARGV0, IG_QUEUE, errno, strerror(errno));
            return (0);
        }
    }

    debug1("%s: DEBUG: FTSInit completed.", ARGV0);

    return (1);
}

/* Add a pattern to be ignored */
void AddtoIGnore(Eventinfo *lf)
{
#ifndef WIN32
    os_mutex_lock(&fts_mutex);
#endif
    fseek(fp_ignore, 0, SEEK_END);

#ifdef TESTRULE
#ifndef WIN32
    os_mutex_unlock(&fts_mutex);
#endif
    return;
#endif

    /* Assign the values to the FTS */
    fprintf(fp_ignore, "%s %s %s %s %s %s %s %s\n",
            (lf->decoder_info->name && (lf->generated_rule->ignore & FTS_NAME)) ?
            lf->decoder_info->name : "",
            (lf->id && (lf->generated_rule->ignore & FTS_ID)) ? lf->id : "",
            (lf->dstuser && (lf->generated_rule->ignore & FTS_DSTUSER)) ?
            lf->dstuser : "",
            (lf->srcip && (lf->generated_rule->ignore & FTS_SRCIP)) ?
            lf->srcip : "",
            (lf->dstip && (lf->generated_rule->ignore & FTS_DSTIP)) ?
            lf->dstip : "",
            (lf->data && (lf->generated_rule->ignore & FTS_DATA)) ?
            lf->data : "",
            (lf->systemname && (lf->generated_rule->ignore & FTS_SYSTEMNAME)) ?
            lf->systemname : "",
            (lf->generated_rule->ignore & FTS_LOCATION) ? lf->location : "");

    fflush(fp_ignore);
#ifndef WIN32
    os_mutex_unlock(&fts_mutex);
#endif

    return;
}

/* Check if the event is to be ignored.
 * Only after an event is matched (generated_rule must be set).
 */
int IGnore(Eventinfo *lf)
{
    char _line[OS_FLSIZE + 1];
    char _fline[OS_FLSIZE + 1];
    int matched = 0;

    _line[OS_FLSIZE] = '\0';

    /* Assign the values to the FTS */
    snprintf(_line, OS_FLSIZE, "%s %s %s %s %s %s %s %s\n",
             (lf->decoder_info->name && (lf->generated_rule->ckignore & FTS_NAME)) ?
             lf->decoder_info->name : "",
             (lf->id && (lf->generated_rule->ckignore & FTS_ID)) ? lf->id : "",
             (lf->dstuser && (lf->generated_rule->ckignore & FTS_DSTUSER)) ?
             lf->dstuser : "",
             (lf->srcip && (lf->generated_rule->ckignore & FTS_SRCIP)) ?
             lf->srcip : "",
             (lf->dstip && (lf->generated_rule->ckignore & FTS_DSTIP)) ?
             lf->dstip : "",
             (lf->data && (lf->generated_rule->ignore & FTS_DATA)) ?
             lf->data : "",
             (lf->systemname && (lf->generated_rule->ignore & FTS_SYSTEMNAME)) ?
             lf->systemname : "",
             (lf->generated_rule->ckignore & FTS_LOCATION) ? lf->location : "");

    _fline[OS_FLSIZE] = '\0';

#ifndef WIN32
    os_mutex_lock(&fts_mutex);
#endif
    /** Check if the ignore is present **/
    /* Point to the beginning of the file */
    fseek(fp_ignore, 0, SEEK_SET);
    while (fgets(_fline, OS_FLSIZE , fp_ignore) != NULL) {
        if (strcmp(_fline, _line) != 0) {
            continue;
        }

        /* If we match, we can return 1 */
        matched = 1;
        break;
    }
#ifndef WIN32
    os_mutex_unlock(&fts_mutex);
#endif

    return matched;
}

/*  Check if the word "msg" is present on the "queue".
 *  If it is not, write it there.
 */
int FTS(Eventinfo *lf)
{
    int number_of_matches = 0;
    int result = 0;
    char _line[OS_FLSIZE + 1];
    char *line_for_list = NULL;
    char *persist_line = NULL;
    OSListNode *fts_node;

    _line[OS_FLSIZE] = '\0';

    /* Assign the values to the FTS */
    snprintf(_line, OS_FLSIZE, "%s %s %s %s %s %s %s %s %s",
             lf->decoder_info->name,
             (lf->id && (lf->decoder_info->fts & FTS_ID)) ? lf->id : "",
             (lf->dstuser && (lf->decoder_info->fts & FTS_DSTUSER)) ? lf->dstuser : "",
             (lf->srcuser && (lf->decoder_info->fts & FTS_SRCUSER)) ? lf->srcuser : "",
             (lf->srcip && (lf->decoder_info->fts & FTS_SRCIP)) ? lf->srcip : "",
             (lf->dstip && (lf->decoder_info->fts & FTS_DSTIP)) ? lf->dstip : "",
             (lf->data && (lf->decoder_info->fts & FTS_DATA)) ? lf->data : "",
             (lf->systemname && (lf->decoder_info->fts & FTS_SYSTEMNAME)) ? lf->systemname : "",
             (lf->decoder_info->fts & FTS_LOCATION) ? lf->location : "");

#ifndef WIN32
    os_mutex_lock(&fts_mutex);
#endif
    /** Check if FTS is already present **/
    if (OSHash_Get(fts_store, _line)) {
        result = 0;
        goto out;
    }

    /* Check if from the last FTS events, we had at least 3 "similars" before.
     * If yes, we just ignore it.
     */
    if (lf->decoder_info->type == IDS) {
        fts_node = OSList_GetLastNode(fts_list);
        while (fts_node) {
            if (OS_StrHowClosedMatch((char *)fts_node->data, _line) >
                    fts_minsize_for_str) {
                number_of_matches++;

                /* We go and add this new entry to the list */
                if (number_of_matches > 2) {
                    _line[fts_minsize_for_str] = '\0';
                    break;
                }
            }

            fts_node = OSList_GetPrevNode(fts_list);
        }

        os_strdup(_line, line_for_list);
        OSList_AddData(fts_list, line_for_list);
    }

    /* Store new entry */
    if (line_for_list == NULL) {
        os_strdup(_line, line_for_list);
    }

    if (OSHash_Add(fts_store, line_for_list, line_for_list) <= 1) {
        result = 0;
        goto out;
    }


#ifdef TESTRULE
    result = 1;
    goto out;
#endif

    /* Disk persist happens off the match thread (async queue or sync fallback). */
    os_strdup(_line, persist_line);
    result = 1;

out:
#ifndef WIN32
    os_mutex_unlock(&fts_mutex);
#endif

#ifndef TESTRULE
#ifndef WIN32
    if (persist_line) {
        if (writer_queue_fts) {
            struct timespec ts;

            if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
                ts.tv_sec += FTS_QUEUE_PUSH_WAIT_SEC;
                if (os_queue_push_ex_timedwait(writer_queue_fts, persist_line, &ts) == 0) {
                    persist_line = NULL;
                }
            } else if (os_queue_push_ex(writer_queue_fts, persist_line) == 0) {
                persist_line = NULL;
            }

            if (persist_line) {
                /* Queue full/timeout: sync-write so the FTS entry is not lost. */
                FTS_Fprintf(persist_line);
                FTS_Flush();
                free(persist_line);
                persist_line = NULL;
            }
        } else {
            FTS_Fprintf(persist_line);
            FTS_Flush();
            free(persist_line);
            persist_line = NULL;
        }
    }
#else
    if (persist_line) {
        FTS_Fprintf(persist_line);
        FTS_Flush();
        free(persist_line);
    }
#endif /* !WIN32 */
#endif /* !TESTRULE */

    return result;
}
