/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Rootcheck decoder */

#include "config.h"
#include "shared.h"
#include "os_regex/os_regex.h"
#include "eventinfo.h"
#include "alerts/alerts.h"
#include "decoder.h"

/* Local variables */
static char *rk_agent_ips[MAX_AGENTS];
static FILE *rk_agent_fps[MAX_AGENTS];
static int rk_err;
#ifndef WIN32
/* Table mutex: agent slot alloc / lookup. Per-agent mutex: FILE* I/O. */
static pthread_mutex_t rk_table_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t rk_agent_mutex[MAX_AGENTS];
static int rk_agent_mutex_ready = 0;
#endif

/* Rootcheck decoders: one for entries already in the database and one, with
 * FTS_DONE, for new entries. Events keep pointing at theirs after they left the
 * decode thread, so they are never written after RootcheckInit().
 */
static OSDecoderInfo *rootcheck_dec = NULL;
static OSDecoderInfo *rootcheck_dec_fts = NULL;

/* Initialize the necessary information to process the rootcheck information */
void RootcheckInit()
{
    int i = 0;

    rk_err = 0;

    for (; i < MAX_AGENTS; i++) {
        rk_agent_ips[i] = NULL;
        rk_agent_fps[i] = NULL;
#ifndef WIN32
        os_mutex_init(&rk_agent_mutex[i], NULL);
#endif
    }
#ifndef WIN32
    rk_agent_mutex_ready = 1;
#endif

    /* Decoders once per process (never rewrite after first Init). */
    if (rootcheck_dec == NULL) {
        os_calloc(1, sizeof(OSDecoderInfo), rootcheck_dec);
        rootcheck_dec->id = getDecoderfromlist(ROOTCHECK_MOD);
        rootcheck_dec->type = OSSEC_RL;
        rootcheck_dec->name = ROOTCHECK_MOD;
        rootcheck_dec->fts = 0;

        os_calloc(1, sizeof(OSDecoderInfo), rootcheck_dec_fts);
        *rootcheck_dec_fts = *rootcheck_dec;
        rootcheck_dec_fts->fts = FTS_DONE;
    }

    debug1("%s: RootcheckInit completed.", ARGV0);

    return;
}

/* Return the file pointer to be used */
static FILE *RK_File(const char *agent, int *agent_id)
{
    int i = 0;
    char rk_buf[OS_SIZE_1024 + 1];
    const char *paren = strchr(agent, ')');
    /* Remoted builds "(name) ip->module". Anchor after ')' so a name that
     * itself contains "->" is not mistaken for remoted's separator; do not
     * use the last "->" or "(name) ip->x->rootcheck" would take a slot.
     */
    const char *rk_name = paren ? strstr(paren, "->") : strstr(agent, "->");

    /* Everything after remoted's "->" is chosen by the agent. Each distinct
     * location takes one of MAX_AGENTS slots and an open database for good,
     * so only the name rootcheck really sends gets one; otherwise one agent
     * can fill the table.
     */
    if (rk_name && strcmp(rk_name + 2, ROOTCHECK_MOD) != 0) {
        merror("%s: Ignoring rootcheck event from unexpected location '%s'.",
               ARGV0, agent);
        return (NULL);
    }

    while (i < MAX_AGENTS && rk_agent_ips[i] != NULL) {
        if (strcmp(rk_agent_ips[i], agent) == 0) {
            /* Pointing to the beginning of the file */
            fseek(rk_agent_fps[i], 0, SEEK_SET);
            *agent_id = i;
            return (rk_agent_fps[i]);
        }

        i++;
    }

    /* If here, our agent wasn't found */
    if (i == MAX_AGENTS) {
        merror("%s: Unable to open rootcheck file. Increase MAX_AGENTS.", ARGV0);
        return (NULL);
    }

    /* If here, our agent wasn't found */
    rk_agent_ips[i] = strdup(agent);

    if (rk_agent_ips[i] != NULL) {
        snprintf(rk_buf, OS_SIZE_1024, "%s/%s", ROOTCHECK_DIR, agent);

        /* r+ to read and write. Do not truncate */
        rk_agent_fps[i] = fopen(rk_buf, "r+");
        if (!rk_agent_fps[i]) {
            /* Try opening with a w flag, file probably does not exist */
            rk_agent_fps[i] = fopen(rk_buf, "w");
            if (rk_agent_fps[i]) {
                fclose(rk_agent_fps[i]);
                rk_agent_fps[i] = fopen(rk_buf, "r+");
            }
        }
        if (!rk_agent_fps[i]) {
            merror(FOPEN_ERROR, ARGV0, rk_buf, errno, strerror(errno));

            free(rk_agent_ips[i]);
            rk_agent_ips[i] = NULL;

            return (NULL);
        }

        /* Return the opened pointer (the beginning of it) */
        fseek(rk_agent_fps[i], 0, SEEK_SET);
        *agent_id = i;
        return (rk_agent_fps[i]);
    }

    else {
        merror(MEM_ERROR, ARGV0, errno, strerror(errno));
        return (NULL);
    }

    return (NULL);
}

/* A value as written by rk_append_file_hash: "n/a" or a digest of len hex digits */
static int rk_is_hash(const char *val, size_t len)
{
    return (strcmp(val, "n/a") == 0 ||
            (strlen(val) == len && strspn(val, "0123456789abcdef") == len));
}

/* Parse MD5/SHA1/SHA256 values appended by rk_append_file_hash into lf.
 * Also extracts the detected file path into lf->filename.
 * All rootcheck alert messages share the pattern: file 'PATH'
 *
 * PATH is sent as it is on disk, so it may itself hold quotes and text that
 * looks like the rest of the message. Nothing is therefore searched for from
 * the start of PATH on: the hashes are the last thing in the message and must
 * fill it up to its end, and PATH ends where the fixed text in front of them
 * (or in front of the end of the message) starts.
 * ANT-2026-0UFTKHQJ.
 */
static void rk_extract_hashes(Eventinfo *lf)
{
    /* The fixed text that follows a PATH read from the file system */
    static const char *const after_path[] = {
        "'.",
        "'. File size doesn't match what we found. "
        "Possible kernel level rootkit.",
        "'. Hidden from stats, but showing up on readdir. "
        "Possible kernel level rootkit.",
        NULL
    };
    const char *p;
    const char *hashes = NULL;
    char md5[65];
    char sha1[65];
    char sha256[65];
    int trojan;
    int used = 0;

    /* Only these messages carry a path. Any other one may hold the
     * patterns below inside a path of its own.
     */
    trojan = (strncmp(lf->log, "Trojaned version of file '", 26) == 0);
    if (!trojan && strncmp(lf->log, "Rootkit '", 9) != 0 &&
            strncmp(lf->log, "Anomaly detected in file '", 26) != 0) {
        return;
    }

    /* The hashes are appended last: only the last " MD5=" can be theirs, and
     * only if a complete triple follows it up to the end of the message. A
     * message that did not fit the sender's buffer ends in a lone space.
     */
    for (p = strstr(lf->log, " MD5="); p; p = strstr(p + 1, " MD5=")) {
        hashes = p;
    }
    if (hashes && (sscanf(hashes, " MD5=%64s SHA1=%64s SHA256=%64s%n",
                          md5, sha1, sha256, &used) != 3 ||
                   hashes[used] != '\0' || !rk_is_hash(md5, 32) ||
                   !rk_is_hash(sha1, 40) || !rk_is_hash(sha256, 64))) {
        hashes = NULL;
    }

    /* Extract file path from message (pattern: file 'PATH') */
    p = strstr(lf->log, " file '");
    if (p) {
        const char *start = p + 7;
        const char *end = NULL;

        if (trojan) {
            /* PATH comes from the trojans database; free text follows it */
            end = strchr(start, '\'');
        } else {
            const char *text_end = hashes ? hashes : start + strlen(start);
            int i;

            for (i = 0; after_path[i]; i++) {
                size_t len = strlen(after_path[i]);

                if ((size_t)(text_end - start) > len &&
                        strncmp(text_end - len, after_path[i], len) == 0) {
                    end = text_end - len;
                    break;
                }
            }
        }

        if (end && end > start) {
            size_t len = (size_t)(end - start);
            lf->filename = (char *)malloc(len + 1);
            if (lf->filename) {
                memcpy(lf->filename, start, len);
                lf->filename[len] = '\0';
            }
        }
    }

    if (!hashes) {
        return;
    }

    if (strcmp(md5, "n/a") != 0) {
        free(lf->md5_after);
        lf->md5_after = NULL;
        os_strdup(md5, lf->md5_after);
    }

    if (strcmp(sha1, "n/a") != 0) {
        free(lf->sha1_after);
        lf->sha1_after = NULL;
        os_strdup(sha1, lf->sha1_after);
    }

    if (strcmp(sha256, "n/a") != 0) {
        free(lf->sha256_after);
        lf->sha256_after = NULL;
        os_strdup(sha256, lf->sha256_after);
    }
}

/* Special decoder for rootcheck
 * Not using the default rendering tools for simplicity
 * and to be less resource intensive
 */
static int DecodeRootcheck_with_fp(Eventinfo *lf, FILE *fp)
{
    char *tmpstr;
    char rk_buf[OS_SIZE_4096 + 1];
    fpos_t fp_pos;

    /* Zero rk_buf */
    rk_buf[0] = '\0';
    rk_buf[OS_SIZE_4096] = '\0';

    /* Get initial position */
    if (fgetpos(fp, &fp_pos) == -1) {
        merror("%s: Error handling rootcheck database (fgetpos).", ARGV0);
        return (0);
    }


    /* Reads the file and search for a possible entry */
    while (fgets(rk_buf, OS_SIZE_4096 - 1, fp) != NULL) {
        /* Ignore blank lines and lines with a comment */
        if (rk_buf[0] == '\n' || rk_buf[0] == '#') {
            if (fgetpos(fp, &fp_pos) == -1) {
                merror("%s: Error handling rootcheck database "
                       "(fgetpos2).", ARGV0);
                return (0);
            }
            continue;
        }

        /* Remove newline */
        tmpstr = strchr(rk_buf, '\n');
        if (tmpstr) {
            *tmpstr = '\0';
        }

        /* Old format without the time stamps */
        if (rk_buf[0] != '!') {
            /* Cannot use strncmp to avoid errors with crafted files */
            if (strcmp(lf->log, rk_buf) == 0) {
                lf->decoder_info = rootcheck_dec;
                rk_extract_hashes(lf);
                return (1);
            }
        }
        /* New format */
        else {
            /* Going past time: !1183431603!1183431603  (last, first seen) */
            tmpstr = rk_buf + 23;

            /* Matches, we need to upgrade last time saw */
            if (strcmp(lf->log, tmpstr) == 0) {
                if(fsetpos(fp, &fp_pos)) {
                    merror("%s: Error handling rootcheck database "
                           "(fsetpos).", ARGV0);
                    return (0);
                }
                fprintf(fp, "!%ld", (long int)lf->time);
                lf->decoder_info = rootcheck_dec;
                rk_extract_hashes(lf);
                return (1);
            }
        }

        /* Get current position */
        if (fgetpos(fp, &fp_pos) == -1) {
            merror("%s: Error handling rootcheck database (fgetpos3).", ARGV0);
            return (0);
        }
    }

    /* Add the new entry at the end of the file */
    fseek(fp, 0, SEEK_END);
    fprintf(fp, "!%ld!%ld %s\n", (long int)lf->time, (long int)lf->time, lf->log);
    fflush(fp);

    lf->decoder_info = rootcheck_dec_fts;
    rk_extract_hashes(lf);
    return (1);
}

int DecodeRootcheck(Eventinfo *lf)
{
    int result;
    int agent_id = -1;
    FILE *fp;

#ifndef WIN32
    os_mutex_lock(&rk_table_mutex);
#endif
    fp = RK_File(lf->location, &agent_id);
    if (!fp) {
#ifndef WIN32
        os_mutex_unlock(&rk_table_mutex);
#endif
        merror("%s: Error handling rootcheck database.", ARGV0);
        rk_err++;
        return (0);
    }

#ifndef WIN32
    /* Lock the agent FILE before releasing the table (finer than global lock). */
    os_mutex_lock(&rk_agent_mutex[agent_id]);
    os_mutex_unlock(&rk_table_mutex);
#endif

    result = DecodeRootcheck_with_fp(lf, fp);

#ifndef WIN32
    os_mutex_unlock(&rk_agent_mutex[agent_id]);
#endif
    return result;
}

#ifdef OSSEC_ROOTCHECK_TEST
/* ANT-2026-0UFTKHQJ: drive rk_extract_hashes() from the regression. */
void Rootcheck_TestExtractHashes(Eventinfo *lf)
{
    rk_extract_hashes(lf);
}

/* ANT-2026-RBAKY685: how many rootcheck DB slots are currently allocated. */
int Rootcheck_TestSlotCount(void)
{
    int i;
    int n = 0;

    for (i = 0; i < MAX_AGENTS; i++) {
        if (rk_agent_ips[i] != NULL) {
            n++;
        }
    }
    return (n);
}

/*
 * ANT-2026-RBAKY685: try RK_File for location under the same locking as
 * DecodeRootcheck, without writing an entry. Returns 1 on open, 0 on refuse.
 */
int Rootcheck_TestOpenDB(const char *location)
{
    int agent_id = -1;
    FILE *fp;

#ifndef WIN32
    os_mutex_lock(&rk_table_mutex);
#endif
    fp = RK_File(location, &agent_id);
    if (!fp) {
#ifndef WIN32
        os_mutex_unlock(&rk_table_mutex);
#endif
        return (0);
    }
#ifndef WIN32
    os_mutex_lock(&rk_agent_mutex[agent_id]);
    os_mutex_unlock(&rk_table_mutex);
    os_mutex_unlock(&rk_agent_mutex[agent_id]);
#endif
    return (1);
}
#endif

