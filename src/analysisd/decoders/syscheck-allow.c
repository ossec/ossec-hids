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
#include "decoder.h"

/* We write allowed filenames in a database located at /queue/syscheck-allowchange/<agent>
 * Each line represents an entry which is structured as
 *     <is_valid> <validity_timestamp> <path>
 * where <is_valid> is either the char '0' or '1',
 * and indicate whereas this entry have already been consummed.
 */


/* Determine if this filename have at least one allowed change, and
   consumme it */
static int consumeAllowchange(const char *filename, Eventinfo *lf){
    FILE *db_file;
    char db_filename[OS_FLSIZE];
    char line[OS_FLSIZE*2];
    int allowed = 0;
    time_t current;
    snprintf(db_filename, OS_FLSIZE , "%s/%s", ALLOWCHANGE_DIR, lf->hostname);
    db_file = fopen(db_filename, "r+");
    if (!db_file) {
        db_file = fopen(db_filename, "w+");
        if (!db_file) {
            verbose("failed to open %s", db_filename);
            return 0;
        }
    }
    rewind(db_file);
    current = time(0);

    while (fgets(line, OS_FLSIZE*2, db_file) != NULL) {
        /* Attempt to parse the line */
        int validity;
        time_t until;
        char path[OS_FLSIZE];
        sscanf(line, "%d %d %s", &validity, &until, path);
        if (validity) {
            if (until > current) {
                if (strcmp(path, filename) == 0){
                    int len = strlen(line);
                    /* Rewrite current entry */
                    fseek(db_file, -len, SEEK_CUR);
                    fprintf(db_file, "0");
                    fclose(db_file);
                    return until;
                }
            }
        }
    }

    fclose(db_file);
    return allowed;
}

/* Save an Allowchange record in our "database"
*/
static int produceAllowchange(time_t timestamp, const char *filename, Eventinfo *lf){
    FILE *db_file;
    char db_filename[OS_FLSIZE];
    snprintf(db_filename, OS_FLSIZE , "%s/%s", ALLOWCHANGE_DIR, lf->hostname);
    verbose("opening %s", db_filename);
    db_file = fopen(db_filename, "a");
    if (db_file) {
        fprintf(db_file, "%d %d %s\n", 1, timestamp, filename);
        fclose(db_file);
        return timestamp;
    }
    verbose("failed to write to %s", db_filename);
    return 0;
}



/* A special decoder to read an AllowChange event */
int DecodeAllowchange(Eventinfo *lf)
{
    int status;
    time_t timestamp;
    char *f_name;

    /* Allowchange messages must be in the following format:
     * timestamp filename
     */
    f_name = strchr(lf->log, ' ');
    if (f_name == NULL) {
        merror(SK_INV_MSG, ARGV0);
        return (0);
    }

    /* Zero to get the timestamp */
    *f_name = '\0';
    f_name++;

    /* Get timestamp */
    timestamp = atoi(lf->log);
    produceAllowchange(timestamp, f_name, lf);
    return timestamp;
}
