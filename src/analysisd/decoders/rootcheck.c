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
#include "os_regex/os_regex.h"
#include "eventinfo.h"
#include "alerts/alerts.h"
#include "decoder.h"

#define ROOTCHECK_DIR    "/queue/rootcheck"

/* Local variables */
static char *rk_agent_ips[MAX_AGENTS];
static FILE *rk_agent_fps[MAX_AGENTS];
static int rk_err;

/* Rootcheck decoder */
static OSDecoderInfo *rootcheck_dec = NULL;


/* Initialize the necessary information to process the rootcheck information */
void RootcheckInit()
{
    int i = 0;

    rk_err = 0;

    for (; i < MAX_AGENTS; i++) {
        rk_agent_ips[i] = NULL;
        rk_agent_fps[i] = NULL;
    }

    /* Zero decoder */
    os_calloc(1, sizeof(OSDecoderInfo), rootcheck_dec);
    rootcheck_dec->id = getDecoderfromlist(ROOTCHECK_MOD);
    rootcheck_dec->type = OSSEC_RL;
    rootcheck_dec->name = ROOTCHECK_MOD;
    rootcheck_dec->fts = 0;

    debug1("%s: RootcheckInit completed.", ARGV0);

    return;
}

/* Return the file pointer to be used */
static FILE *RK_File(const char *agent, int *agent_id)
{
    int i = 0;
    char rk_buf[OS_SIZE_1024 + 1];

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

/* Parse MD5/SHA1/SHA256 values appended by rk_append_file_hash into lf.
 * Also extracts the detected file path into lf->filename.
 * All rootcheck alert messages share the pattern: file 'PATH'
 */
static void rk_extract_hashes(Eventinfo *lf)
{
    const char *p;
    char val[65];

    /* Extract file path from message (pattern: file 'PATH') */
    p = strstr(lf->log, " file '");
    if (p) {
        const char *start = p + 7;
        const char *end = strchr(start, '\'');
        if (end && end > start) {
            size_t len = (size_t)(end - start);
            lf->filename = (char *)malloc(len + 1);
            if (lf->filename) {
                memcpy(lf->filename, start, len);
                lf->filename[len] = '\0';
            }
        }
    }

    p = strstr(lf->log, " MD5=");
    if (p && sscanf(p + 5, "%64s", val) == 1 && strcmp(val, "n/a") != 0 && strlen(val) == 32) {
        free(lf->md5_after);
        lf->md5_after = NULL;
        os_strdup(val, lf->md5_after);
    }

    p = strstr(lf->log, " SHA1=");
    if (p && sscanf(p + 6, "%64s", val) == 1 && strcmp(val, "n/a") != 0 && strlen(val) == 40) {
        free(lf->sha1_after);
        lf->sha1_after = NULL;
        os_strdup(val, lf->sha1_after);
    }

    p = strstr(lf->log, " SHA256=");
    if (p && sscanf(p + 8, "%64s", val) == 1 && strcmp(val, "n/a") != 0 && strlen(val) == 64) {
        free(lf->sha256_after);
        lf->sha256_after = NULL;
        os_strdup(val, lf->sha256_after);
    }
}

/* Special decoder for rootcheck
 * Not using the default rendering tools for simplicity
 * and to be less resource intensive
 */
int DecodeRootcheck(Eventinfo *lf)
{
    int agent_id;

    char *tmpstr;
    char rk_buf[OS_SIZE_4096 + 1];

    FILE *fp;

    fpos_t fp_pos;

    /* Zero rk_buf */
    rk_buf[0] = '\0';
    rk_buf[OS_SIZE_4096] = '\0';

    fp = RK_File(lf->location, &agent_id);

    if (!fp) {
        merror("%s: Error handling rootcheck database.", ARGV0);
        rk_err++;

        return (0);
    }

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
                rootcheck_dec->fts = 0;
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
                rootcheck_dec->fts = 0;
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

    rootcheck_dec->fts = 0;
    rootcheck_dec->fts |= FTS_DONE;
    lf->decoder_info = rootcheck_dec;
    rk_extract_hashes(lf);
    return (1);
}

