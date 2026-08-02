/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Syscheck decoder */

#include "eventinfo.h"
#include "os_regex/os_regex.h"
#include "config.h"
#include "alerts/alerts.h"
#include "decoder.h"

#ifdef SQLITE_ENABLED
#include <sqlite3.h>
#endif

typedef struct _sk_db_entry {
    fpos_t pos;
    char prefix_sum[OS_MAXSTR + 1];
} sk_db_entry;

typedef struct __sdb {
    char buf[OS_MAXSTR + 1];
    char comment[OS_MAXSTR + 1];

    char size[OS_FLSIZE + 1];
    char perm[OS_FLSIZE + 1];
    char owner[OS_FLSIZE + 1];
    char gowner[OS_FLSIZE + 1];
    char md5[OS_FLSIZE + 1];
    char sha1[OS_FLSIZE + 1];
    char sha256[OS_FLSIZE + 1];

    int db_err;

    /* Ids for decoder */
    int id1;
    int id2;
    int id3;
    int idn;
    int idd;

    /* Syscheck rule */
    OSDecoderInfo  *syscheck_dec;

    /* File search variables */
    fpos_t init_pos;

} _sdb; /* per-thread working buffers / decoder ids */

/* Per-thread comment/decode buffers (safe under parallel decode workers). */
static __thread _sdb sdb;

/*
 * Shared agent integrity DB table — process-global so concurrent syscheck
 * workers serialize FILE* / hash-index mutations for the same agent.
 */
static char sk_agent_cp[MAX_AGENTS + 1][1];
static char *sk_agent_ips[MAX_AGENTS + 1];
static FILE *sk_agent_fps[MAX_AGENTS + 1];
static OSHash *sk_agent_index[MAX_AGENTS + 1];
#ifndef WIN32
static pthread_mutex_t sk_table_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t sk_agent_mutex[MAX_AGENTS + 1];
static int sk_shared_ready = 0;
#endif

/* Extract a token from a string */
char *extract_token(const char *s, char *delim, int position) {
    int count = 0;
    char tmp[OS_MAXSTR + 1];
    char *token;
    strncpy(tmp,s, OS_MAXSTR);
    token = strtok(tmp, delim);
    while (token != NULL) {
        count++;
        token = strtok(NULL, delim);
        if (count == position) {
            return(token);
        }
    }
    return(NULL);
}


/* Validate a MD5 string format */
int validate_md5(char *s) {
    unsigned int i;
    char *hex_chars = "abcdefABCDEF0123456789";
    if (strlen(s) != 32) {
        return(0);
    }
    for (i = 0; i < strlen(s); i++) {
        if (!strchr(hex_chars, s[i])) return(0);
    }
    return(1);
}


/* Initialize the necessary information to process the syscheck information */
void SyscheckInit()
{
    int i = 0;

    sdb.db_err = 0;

    /* Clear per-thread working buffers */
    memset(sdb.buf, '\0', OS_MAXSTR + 1);
    memset(sdb.comment, '\0', OS_MAXSTR + 1);

    memset(sdb.size, '\0', OS_FLSIZE + 1);
    memset(sdb.perm, '\0', OS_FLSIZE + 1);
    memset(sdb.owner, '\0', OS_FLSIZE + 1);
    memset(sdb.gowner, '\0', OS_FLSIZE + 1);
    memset(sdb.md5, '\0', OS_FLSIZE + 1);
    memset(sdb.sha1, '\0', OS_FLSIZE + 1);
    memset(sdb.sha256, '\0', OS_FLSIZE + 1);

    /* Create decoder (TLS — each worker owns its own) */
    os_calloc(1, sizeof(OSDecoderInfo), sdb.syscheck_dec);
    sdb.syscheck_dec->id = getDecoderfromlist(SYSCHECK_MOD);
    sdb.syscheck_dec->name = SYSCHECK_MOD;
    sdb.syscheck_dec->type = OSSEC_RL;
    sdb.syscheck_dec->fts = 0;

    sdb.id1 = getDecoderfromlist(SYSCHECK_MOD);
    sdb.id2 = getDecoderfromlist(SYSCHECK_MOD2);
    sdb.id3 = getDecoderfromlist(SYSCHECK_MOD3);
    sdb.idn = getDecoderfromlist(SYSCHECK_NEW);
    sdb.idd = getDecoderfromlist(SYSCHECK_DEL);

#ifndef WIN32
    /* Shared agent table + locks: once per process (workers each call Init). */
    os_mutex_lock(&sk_table_mutex);
    if (!sk_shared_ready) {
        for (i = 0; i <= MAX_AGENTS; i++) {
            sk_agent_ips[i] = NULL;
            sk_agent_fps[i] = NULL;
            sk_agent_index[i] = NULL;
            sk_agent_cp[i][0] = '0';
            os_mutex_init(&sk_agent_mutex[i], NULL);
        }
        sk_shared_ready = 1;
    }
    os_mutex_unlock(&sk_table_mutex);
#else
    for (i = 0; i <= MAX_AGENTS; i++) {
        sk_agent_ips[i] = NULL;
        sk_agent_fps[i] = NULL;
        sk_agent_index[i] = NULL;
        sk_agent_cp[i][0] = '0';
    }
#endif

    debug1("%s: SyscheckInit completed.", ARGV0);
    return;
}

/* Check if the db is completed for that specific agent */
#define DB_IsCompleted(x) (sk_agent_cp[x][0] == '1')?1:0

static void __setcompleted(const char *agent)
{
    FILE *fp;

    /* Get agent file */
    snprintf(sdb.buf, OS_FLSIZE , "%s/.%s.cpt", SYSCHECK_DIR, agent);

    fp = fopen(sdb.buf, "w");
    if (fp) {
        fprintf(fp, "#!X");
        fclose(fp);
    }
}

static int __iscompleted(const char *agent)
{
    FILE *fp;

    /* Get agent file */
    snprintf(sdb.buf, OS_FLSIZE , "%s/.%s.cpt", SYSCHECK_DIR, agent);

    fp = fopen(sdb.buf, "r");
    if (fp) {
        fclose(fp);
        return (1);
    }
    return (0);
}

/* Set the database of a specific agent as completed */
static void DB_SetCompleted(const Eventinfo *lf)
{
    int i = 0;

#ifndef WIN32
    os_mutex_lock(&sk_table_mutex);
#endif

    /* Find file pointer */
    while (sk_agent_ips[i] != NULL &&  i < MAX_AGENTS) {
        if (strcmp(sk_agent_ips[i], lf->location) == 0) {
            /* Return if already set as completed */
            if (DB_IsCompleted(i)) {
#ifndef WIN32
                os_mutex_unlock(&sk_table_mutex);
#endif
                return;
            }

#ifndef WIN32
            os_mutex_lock(&sk_agent_mutex[i]);
            os_mutex_unlock(&sk_table_mutex);
#endif
            __setcompleted(lf->location);

            /* Set as completed in memory */
            sk_agent_cp[i][0] = '1';
#ifndef WIN32
            os_mutex_unlock(&sk_agent_mutex[i]);
#endif
            return;
        }

        i++;
    }

#ifndef WIN32
    os_mutex_unlock(&sk_table_mutex);
#endif
}


/* Return the file pointer to be used to verify the integrity.
 * On success (non-WIN32), the matching sk_agent_mutex[agent_id] is held;
 * caller must unlock it when finished with FILE I/O.
 */
static FILE *DB_File(const char *agent, int *agent_id)
{
    int i = 0;

#ifndef WIN32
    os_mutex_lock(&sk_table_mutex);
#endif

    /* Find file pointer */
    while (sk_agent_ips[i] != NULL  &&  i < MAX_AGENTS) {
        if (strcmp(sk_agent_ips[i], agent) == 0) {
#ifndef WIN32
            os_mutex_lock(&sk_agent_mutex[i]);
            os_mutex_unlock(&sk_table_mutex);
#endif
            /* Point to the beginning of the file */
            fseek(sk_agent_fps[i], 0, SEEK_SET);
            *agent_id = i;
            return (sk_agent_fps[i]);
        }

        i++;
    }

    /* If here, our agent wasn't found */
    if (i == MAX_AGENTS) {
#ifndef WIN32
        os_mutex_unlock(&sk_table_mutex);
#endif
        merror("%s: Unable to open integrity file. Increase MAX_AGENTS.", ARGV0);
        return (NULL);
    }

    os_strdup(agent, sk_agent_ips[i]);

    /* Get agent file */
    snprintf(sdb.buf, OS_FLSIZE , "%s/%s", SYSCHECK_DIR, agent);

    /* r+ to read and write. Do not truncate */
    sk_agent_fps[i] = fopen(sdb.buf, "r+");
    if (!sk_agent_fps[i]) {
        /* Try opening with a w flag, file probably does not exist */
        sk_agent_fps[i] = fopen(sdb.buf, "w");
        if (sk_agent_fps[i]) {
            fclose(sk_agent_fps[i]);
            sk_agent_fps[i] = fopen(sdb.buf, "r+");
        }
    }

    /* Check again */
    if (!sk_agent_fps[i]) {
        merror("%s: Unable to open '%s'", ARGV0, sdb.buf);

        free(sk_agent_ips[i]);
        sk_agent_ips[i] = NULL;
#ifndef WIN32
        os_mutex_unlock(&sk_table_mutex);
#endif
        return (NULL);
    }

    /* Return the opened pointer (the beginning of it) */
    fseek(sk_agent_fps[i], 0, SEEK_SET);
    *agent_id = i;

    /* Check if the agent was completed */
    if (__iscompleted(agent)) {
        sk_agent_cp[i][0] = '1';
    }

#ifndef WIN32
    os_mutex_lock(&sk_agent_mutex[i]);
    os_mutex_unlock(&sk_table_mutex);
#endif

    return (sk_agent_fps[i]);
}

/* Parse a syscheck db line and return the filename within line_buf. */
static int DB_ParseEntryFilename(char *line_buf, char **fname_out)
{
    char *saved_name;

    if (line_buf[0] == '\n' || line_buf[0] == '#') {
        return (-1);
    }

    saved_name = strchr(line_buf, ' ');
    if (saved_name == NULL) {
        return (-1);
    }

    *saved_name = '\0';
    saved_name++;

    if (*saved_name == '!') {
        saved_name = strchr(saved_name, ' ');
        if (saved_name == NULL) {
            return (-1);
        }
        saved_name++;
    }

    if (saved_name[0] != '\0' && saved_name[strlen(saved_name) - 1] == '\n') {
        saved_name[strlen(saved_name) - 1] = '\0';
    }

    *fname_out = saved_name;
    return (0);
}

/* Build an in-memory index for O(1) syscheck db lookups per agent. */
static void DB_BuildIndex(int agent_id, FILE *fp)
{
    fpos_t line_pos;
    char line_copy[OS_MAXSTR + 1];

    if (sk_agent_index[agent_id] != NULL) {
        return;
    }

    sk_agent_index[agent_id] = OSHash_Create();
    if (!sk_agent_index[agent_id]) {
        merror("%s: Unable to create syscheck index for agent.", ARGV0);
        return;
    }

    if (!OSHash_setSize(sk_agent_index[agent_id], 4096)) {
        merror("%s: Unable to size syscheck index for agent.", ARGV0);
    }

    fseek(fp, 0, SEEK_SET);
    while (fgetpos(fp, &line_pos) == 0 && fgets(sdb.buf, OS_MAXSTR, fp) != NULL) {
        char *fname;
        sk_db_entry *ent;

        if (sdb.buf[0] == '\n' || sdb.buf[0] == '#') {
            continue;
        }

        strncpy(line_copy, sdb.buf, OS_MAXSTR);
        line_copy[OS_MAXSTR] = '\0';
        if (DB_ParseEntryFilename(line_copy, &fname) != 0) {
            continue;
        }

        ent = (sk_db_entry *)OSHash_Get(sk_agent_index[agent_id], fname);
        if (!ent) {
            ent = (sk_db_entry *)calloc(1, sizeof(sk_db_entry));
            if (!ent) {
                continue;
            }
            if (OSHash_Add(sk_agent_index[agent_id], fname, ent) != 2) {
                free(ent);
                continue;
            }
        }

        ent->pos = line_pos;
        strncpy(ent->prefix_sum, line_copy, OS_MAXSTR);
        ent->prefix_sum[OS_MAXSTR] = '\0';
    }

    fseek(fp, 0, SEEK_SET);
}


/* Return an existing index entry or allocate one when the index is available. */
static sk_db_entry *DB_GetOrCreateIndexEntry(int agent_id, const char *f_name)
{
    sk_db_entry *ent;

    if (!sk_agent_index[agent_id]) {
        return (NULL);
    }

    ent = (sk_db_entry *)OSHash_Get(sk_agent_index[agent_id], f_name);
    if (ent) {
        return (ent);
    }

    ent = (sk_db_entry *)calloc(1, sizeof(sk_db_entry));
    if (!ent) {
        return (NULL);
    }

    if (OSHash_Add(sk_agent_index[agent_id], f_name, ent) != 2) {
        free(ent);
        return (NULL);
    }

    return (ent);
}

/* Process a located syscheck db entry. sdb.buf holds the prefix sum and
 * sdb.init_pos points at the line in fp. Returns 0 if checksum matched,
 * 1 if a change alert was generated. */
static int DB_ProcessFoundEntry(const char *f_name, const char *c_sum,
                                Eventinfo *lf, FILE *fp,
                                sk_db_entry *db_entry)
{
    int p = 0;
    char *saved_sum = sdb.buf + 3;

    /* Checksum match, we can just return and keep going */
    if (strcmp(saved_sum, c_sum) == 0) {
        lf->data = NULL;
        return (0);
    }




    /* If we reached here, the checksum of the file has changed */
    if (saved_sum[-3] == '!') {
        p++;
        if (saved_sum[-2] == '!') {
            p++;
            if (saved_sum[-1] == '!') {
                p++;
            } else if (saved_sum[-1] == '?') {
                p += 2;
            }
        }
    }

    /* Check the number of changes */
    if (!Config.syscheck_auto_ignore) {
        sdb.syscheck_dec->id = sdb.id1;
    } else {
        switch (p) {
            case 0:
                sdb.syscheck_dec->id = sdb.id1;
                break;

            case 1:
                sdb.syscheck_dec->id = sdb.id2;
                break;

            case 2:
                sdb.syscheck_dec->id = sdb.id3;
                break;

            default:
                lf->data = NULL;
                return (0);
                break;
        }
    }

    /* Add new checksum to the database */
    /* Commenting the file entry and adding a new one later */
    if (fsetpos(fp, &sdb.init_pos)) {
        merror("%s: Error handling integrity database (fsetpos).", ARGV0);
        return (0);
    }
    fputc('#', fp);

    /* Add the new entry at the end of the file */
    fseek(fp, 0, SEEK_END);
    fprintf(fp, "%c%c%c%s !%ld %s\n",
            '!',
            p >= 1 ? '!' : '+',
            p == 2 ? '!' : (p > 2) ? '?' : '+',
            c_sum,
            (long int)lf->time,
            f_name);
    fflush(fp);

    if (db_entry) {
        snprintf(db_entry->prefix_sum, OS_MAXSTR, "%c%c%c%s",
                 '!',
                 p >= 1 ? '!' : '+',
                 p == 2 ? '!' : (p > 2) ? '?' : '+',
                 c_sum);
        fseek(fp, 0, SEEK_END);
        fgetpos(fp, &db_entry->pos);
    }

    /* File deleted */
    if (c_sum[0] == '-' && c_sum[1] == '1') {
        sdb.syscheck_dec->id = sdb.idd;
        snprintf(sdb.comment, OS_MAXSTR,
                 "File '%.756s' was deleted. Unable to retrieve "
                 "checksum.", f_name);
    }

    /* If file was re-added, do not compare changes */
    else if (saved_sum[0] == '-' && saved_sum[1] == '1') {
        sdb.syscheck_dec->id = sdb.idn;
        snprintf(sdb.comment, OS_MAXSTR,
                 "File '%.756s' was re-added.", f_name);
    }

    else {
        int oldperm = 0, newperm = 0;

        /* Provide more info about the file change */
        const char *oldsize = NULL, *newsize = NULL;
        char *olduid = NULL, *newuid = NULL;
        char *c_oldperm = NULL, *c_newperm = NULL;
        char *oldgid = NULL, *newgid = NULL;
        char *oldmd5 = NULL, *newmd5 = NULL;
        char *oldsha1 = NULL, *newsha1 = NULL;
        char *oldsha256 = NULL, *newsha256 = NULL;

        oldsize = saved_sum;
        newsize = c_sum;

        c_oldperm = strchr(saved_sum, ':');
        c_newperm = strchr(c_sum, ':');

        /* Get old/new permissions */
        if (c_oldperm && c_newperm) {
            *c_oldperm = '\0';
            c_oldperm++;

            *c_newperm = '\0';
            c_newperm++;

            /* Get old/new uid/gid */
            olduid = strchr(c_oldperm, ':');
            newuid = strchr(c_newperm, ':');

            if (olduid && newuid) {
                *olduid = '\0';
                *newuid = '\0';
                olduid++;
                newuid++;

                oldgid = strchr(olduid, ':');
                newgid = strchr(newuid, ':');

                if (oldgid && newgid) {
                    *oldgid = '\0';
                    *newgid = '\0';
                    oldgid++;
                    newgid++;

                    /* Get MD5 */
                    oldmd5 = strchr(oldgid, ':');
                    newmd5 = strchr(newgid, ':');

                    if (oldmd5 && newmd5) {
                        *oldmd5 = '\0';
                        *newmd5 = '\0';
                        oldmd5++;
                        newmd5++;

                        /* Get SHA-1 */
                        oldsha1 = strchr(oldmd5, ':');
                        newsha1 = strchr(newmd5, ':');

                        if (oldsha1 && newsha1) {
                            *oldsha1 = '\0';
                            *newsha1 = '\0';
                            oldsha1++;
                            newsha1++;

                            /* Get SHA-256 */
                            oldsha256 = strchr(oldsha1, ':');
                            newsha256 = strchr(newsha1, ':');

                            if (oldsha256 && newsha256) {
                                *oldsha256 = '\0';
                                *newsha256 = '\0';
                                oldsha256++;
                                newsha256++;
                            }
                        }
                    }
                }
            }
        }

        /* Get integer values */
        if (c_newperm && c_oldperm) {
            newperm = atoi(c_newperm);
            oldperm = atoi(c_oldperm);
        }

        /* Generate size message */
        if (!oldsize || !newsize || strcmp(oldsize, newsize) == 0) {
            sdb.size[0] = '\0';
        } else {
            snprintf(sdb.size, OS_FLSIZE,
                     "Size changed from '%s' to '%s'\n",
                     oldsize, newsize);

            os_strdup(oldsize, lf->size_before);
            os_strdup(newsize, lf->size_after);
        }

        /* Permission message */
        if (oldperm == newperm) {
            sdb.perm[0] = '\0';
        } else if (oldperm > 0 && newperm > 0) {
    char opstr[10];
    char npstr[10];

    strncpy(opstr, agent_file_perm(c_oldperm), sizeof(opstr) - 1);
    strncpy(npstr, agent_file_perm(c_newperm), sizeof(npstr) - 1);

            snprintf(sdb.perm, OS_FLSIZE, "Permissions changed from "
                     "'%9.9s' to '%9.9s'\n", opstr, npstr);

            lf->perm_before = oldperm;
            lf->perm_after = newperm;
        }

        /* Ownership message */
        if (!newuid || !olduid || strcmp(newuid, olduid) == 0) {
            sdb.owner[0] = '\0';
        } else {
            snprintf(sdb.owner, OS_FLSIZE, "Ownership was '%s', "
                     "now it is '%s'\n",
                     olduid, newuid);


            os_strdup(olduid, lf->owner_before);
            os_strdup(newuid, lf->owner_after);
        }

        /* Group ownership message */
        if (!newgid || !oldgid || strcmp(newgid, oldgid) == 0) {
            sdb.gowner[0] = '\0';
        } else {
            snprintf(sdb.gowner, OS_FLSIZE, "Group ownership was '%s', "
                     "now it is '%s'\n",
                     oldgid, newgid);
            os_strdup(oldgid, lf->gowner_before);
            os_strdup(newgid, lf->gowner_after);
        }

        /* MD5 message */
        if (!newmd5 || !oldmd5 || strcmp(newmd5, oldmd5) == 0) {
            sdb.md5[0] = '\0';
        } else {
            snprintf(sdb.md5, OS_FLSIZE, "Old md5sum was: '%s'\n"
                     "New md5sum is : '%s'\n",
                     oldmd5, newmd5);
            os_strdup(oldmd5, lf->md5_before);
            os_strdup(newmd5, lf->md5_after);
        }

        /* SHA-1 message */
        if (!newsha1 || !oldsha1 || strcmp(newsha1, oldsha1) == 0) {
            sdb.sha1[0] = '\0';
        } else {
            snprintf(sdb.sha1, OS_FLSIZE, "Old sha1sum was: '%s'\n"
                     "New sha1sum is : '%s'\n",
                     oldsha1, newsha1);
            os_strdup(oldsha1, lf->sha1_before);
            os_strdup(newsha1, lf->sha1_after);
        }

        /* SHA-256 message */
        if (!newsha256 || !oldsha256 || strcmp(newsha256, oldsha256) == 0) {
            sdb.sha256[0] = '\0';
        } else {
            snprintf(sdb.sha256, OS_FLSIZE, "Old sha256sum was: '%s'\n"
                     "New sha256sum is : '%s'\n",
                     oldsha256, newsha256);
            os_strdup(oldsha256, lf->sha256_before);
            os_strdup(newsha256, lf->sha256_after);
        }

        /* Provide information about the file */
        snprintf(sdb.comment, OS_MAXSTR, "Integrity checksum changed for: "
                 "'%.756s'\n"
                 "%s"
                 "%s"
                 "%s"
                 "%s"
                 "%s"
                 "%s"
                 "%s"
                 "%s%s",
                 f_name,
                 sdb.size,
                 sdb.perm,
                 sdb.owner,
                 sdb.gowner,
                 sdb.md5,
                 sdb.sha1,
                 sdb.sha256,
                 lf->data == NULL ? "" : "What changed:\n",
                 lf->data == NULL ? "" : lf->data
                );
    }

    /* Preserve program_name and hostname before freeing full_log */
    if (lf->program_name && !(lf->flags & EF_FREE_PNAME)) {
        /* Only duplicate if we don't already own it */
        char *tmp_pname = NULL;
        os_strdup(lf->program_name, tmp_pname);
        lf->program_name = tmp_pname;
        lf->flags |= EF_FREE_PNAME;
    }
    if (lf->hostname && !(lf->flags & EF_FREE_HNAME)) {
        /* Only duplicate if we don't already own it */
        char *tmp_hname = NULL;
        os_strdup(lf->hostname, tmp_hname);
        lf->hostname = tmp_hname;
        lf->flags |= EF_FREE_HNAME;
    }

    /* Create a new log message */
    free(lf->full_log);
    os_strdup(sdb.comment, lf->full_log);
    lf->log = lf->full_log;
    lf->data = NULL;

    /* Set decoder */
    lf->decoder_info = sdb.syscheck_dec;

    return (1);
}


/* Fall back to a linear scan when the hash index is unavailable or incomplete. */
static int DB_SearchLinear(const char *f_name, const char *c_sum, Eventinfo *lf,
                           FILE *fp, int agent_id)
{
    size_t sn_size;
    char *saved_name;

    fseek(fp, 0, SEEK_SET);
    while (fgetpos(fp, &sdb.init_pos) == 0 &&
           fgets(sdb.buf, OS_MAXSTR, fp) != NULL) {
        if (sdb.buf[0] == '\n' || sdb.buf[0] == '#') {
            continue;
        }

        saved_name = strchr(sdb.buf, ' ');
        if (saved_name == NULL) {
            continue;
        }
        *saved_name = '\0';
        saved_name++;

        if (*saved_name == '!') {
            saved_name = strchr(saved_name, ' ');
            if (saved_name == NULL) {
                continue;
            }
            saved_name++;
        }

        sn_size = strlen(saved_name);
        if (sn_size > 0 && saved_name[sn_size - 1] == '\n') {
            saved_name[sn_size - 1] = '\0';
        }

        if (strcmp(f_name, saved_name) != 0) {
            continue;
        }

        return DB_ProcessFoundEntry(f_name, c_sum, lf, fp,
                                    DB_GetOrCreateIndexEntry(agent_id, f_name));
    }

    return (-1);
}

/* Search the DB for any entry related to the file being received */
static int DB_Search(const char *f_name, const char *c_sum, Eventinfo *lf)
{
    int agent_id;
    int result = 0;
    FILE *fp;

    /* Expose filename variable for active response */
    os_strdup(f_name, lf->filename);

    /* Get db pointer (holds sk_agent_mutex[agent_id] on success) */
    fp = DB_File(lf->location, &agent_id);
    if (!fp) {
        merror("%s: Error handling integrity database.", ARGV0);
        sdb.db_err++;
        lf->data = NULL;
        return (0);
    }

    DB_BuildIndex(agent_id, fp);

    {
        sk_db_entry *db_entry = NULL;
        int linear_rc;

        if (sk_agent_index[agent_id]) {
            db_entry = (sk_db_entry *)OSHash_Get(sk_agent_index[agent_id], f_name);
        }

        if (db_entry) {
            strncpy(sdb.buf, db_entry->prefix_sum, OS_MAXSTR);
            sdb.buf[OS_MAXSTR] = '\0';
            sdb.init_pos = db_entry->pos;
            result = DB_ProcessFoundEntry(f_name, c_sum, lf, fp, db_entry);
            goto out;
        }

        linear_rc = DB_SearchLinear(f_name, c_sum, lf, fp, agent_id);
        if (linear_rc >= 0) {
            result = linear_rc;
            goto out;
        }
    }

    /* If we reach here, this file is not present in our database */
    fseek(fp, 0, SEEK_END);
    if (sk_agent_index[agent_id]) {
        sk_db_entry *db_entry = DB_GetOrCreateIndexEntry(agent_id, f_name);

        if (db_entry && fgetpos(fp, &db_entry->pos) == 0) {
            snprintf(db_entry->prefix_sum, OS_MAXSTR, "+++%s", c_sum);
        }
    }

    fprintf(fp, "+++%s !%ld %s\n", c_sum, (long int)lf->time, f_name);
    fflush(fp);

    /* Alert if configured to notify on new files */
    /* TODO: debugging this - Scott */
    /* if ((Config.syscheck_alert_new == 1) && (DB_IsCompleted(agent_id))) { */
    if (Config.syscheck_alert_new == 1)  {
        sdb.syscheck_dec->id = sdb.idn;

        char *newfilec_sum = NULL;
        char *newfilemd5 = NULL;
        char *newfilesha1 = NULL;
        char *newfilesha256 = NULL;

        os_strdup(c_sum, newfilec_sum);

        char *token = strtok(newfilec_sum, ":");

        int tok_count = 1;

        while (token != NULL)
        {
            if(tok_count == 5)
            {
                newfilemd5 = token;
            }
            if(tok_count == 6)
            {
                newfilesha1 = token;
            }
            if(tok_count == 7)
            {
                newfilesha256 = token;
            }

            token = strtok(NULL, ":");
            tok_count++;
        }

        /* SHA-256 message */
        if (newfilesha256) {
            snprintf(sdb.sha256, OS_FLSIZE,
                     "New sha256sum is : '%s'\n",
                     newfilesha256);
            os_strdup(newfilesha256, lf->sha256_after);
        } else {
            sdb.sha256[0] = '\0';
        }

        if (!newfilemd5) {
            newfilemd5 = "Unknown";
        }
        if (!newfilesha1) {
            newfilesha1 = "Unknown";
        }
        /* SHA-1 message */
        snprintf(sdb.sha1, OS_FLSIZE,
                 "New sha1sum is : '%s'\n",
                 newfilesha1);
        os_strdup(newfilesha1, lf->sha1_after);

        /* MD5 message */
        snprintf(sdb.md5, OS_FLSIZE,
                 "New md5sum is : '%s'\n",
                 newfilemd5);
        os_strdup(newfilemd5, lf->md5_after);

        /* New file message */
        snprintf(sdb.comment, OS_MAXSTR,
                 "New file '%.756s' "
                 "added to the file system.\n"
                 "%s"
                 "%s"
                 "%s",
                 f_name,
                 sdb.sha1,
                 sdb.md5,
                 sdb.sha256
                );

        /* Preserve program_name and hostname before freeing full_log */
        if (lf->program_name && !(lf->flags & EF_FREE_PNAME)) {
            /* Only duplicate if we don't already own it */
            char *tmp_pname = NULL;
            os_strdup(lf->program_name, tmp_pname);
            lf->program_name = tmp_pname;
            lf->flags |= EF_FREE_PNAME;
        }
        if (lf->hostname && !(lf->flags & EF_FREE_HNAME)) {
            /* Only duplicate if we don't already own it */
            char *tmp_hname = NULL;
            os_strdup(lf->hostname, tmp_hname);
            lf->hostname = tmp_hname;
            lf->flags |= EF_FREE_HNAME;
        }

        /* Create a new log message */
        free(lf->full_log);
        os_strdup(sdb.comment, lf->full_log);
        lf->log = lf->full_log;

        /* Set decoder */
        lf->decoder_info = sdb.syscheck_dec;
        lf->data = NULL;

        free(newfilec_sum);
        result = 1;
        goto out;
    }

    lf->data = NULL;
    result = 0;

out:
#ifndef WIN32
    os_mutex_unlock(&sk_agent_mutex[agent_id]);
#endif
    return (result);
}

/* Special decoder for syscheck
 * Not using the default decoding lib for simplicity
 * and to be less resource intensive
 */
int DecodeSyscheck(Eventinfo *lf)
{
    const char *c_sum;
    char *f_name;

#ifdef SQLITE_ENABLED
    char *p;
    char stmt[OS_MAXSTR + 1];
    sqlite3_stmt *res;
    int error = 0;
    int rec_count = 0;
    const char *tail;
#endif // SQLITE_ENABLED

    /* Every syscheck message must be in the following format:
     * checksum filename
     */
    f_name = strchr(lf->log, ' ');
    if (f_name == NULL) {
        /* If we don't have a valid syscheck message, it may be
         * a database completed message
         */
        if (strcmp(lf->log, HC_SK_DB_COMPLETED) == 0) {
            DB_SetCompleted(lf);
            return (0);
        }

        merror(SK_INV_MSG, ARGV0);
        return (0);
    }

    /* Zero to get the check sum */
    *f_name = '\0';
    f_name++;

    /* Get diff */
    lf->data = strchr(f_name, '\n');
    if (lf->data) {
        *lf->data = '\0';
        lf->data++;
    } else {
        lf->data = NULL;
    }

    /* Check if file is supposed to be ignored */
    if (Config.syscheck_ignore) {
        char **ff_ig = Config.syscheck_ignore;

        while (*ff_ig) {
            if (strncasecmp(*ff_ig, f_name, strlen(*ff_ig)) == 0) {
                lf->data = NULL;
                return (0);
            }

            ff_ig++;
        }
    }

    /* Checksum is at the beginning of the log */
    c_sum = lf->log;

    /* Extract the MD5 hash and search for it in the allowlist
     * Sample message:
     * 0:0:0:0:78f5c869675b1d09ddad870adad073f9:bd6c8d7a58b462aac86475e59af0e22954039c50
     */
#ifdef SQLITE_ENABLED
    if (Config.md5_allowlist)  {
        extern sqlite3 *conn;
        if ((p = extract_token(c_sum, ":", 4))) {
            if (!validate_md5(p)) { /* Never trust input from other origin */
                merror("%s: Not a valid MD5 hash: '%s'", ARGV0, p);
                return(0);
            }
            debug1("%s: Checking MD5 '%s' in %s", ARGV0, p, Config.md5_allowlist);
            sprintf(stmt, "select md5sum from files where md5sum = \"%s\"", p);
            error = sqlite3_prepare_v2(conn, stmt, 1000, &res, &tail);
            if (error == SQLITE_OK) {
                while (sqlite3_step(res) == SQLITE_ROW) {
                    rec_count++;
                }
                if (rec_count) {    
                    sqlite3_finalize(res);
                    //sqlite3_close(conn);
                    merror(MD5_NOT_CHECKED, ARGV0, p);
                    return(0);
                }
            }
            sqlite3_finalize(res);
        }
    }
#endif
 

    /* Search for file changes */
    return (DB_Search(f_name, c_sum, lf));
}

