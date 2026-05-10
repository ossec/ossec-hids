/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "dbd.h"

#ifndef ARGV0
#define ARGV0 "ossec-dbd"
#endif


/* Monitor the alerts and insert them into the database
 * Only returns in case of error
 */
void OS_DBD(DBConfig *db_config)
{
    time_t tm;
    struct tm *p;
    file_queue *fileq;
    alert_data *al_data;

    /* Get current time before starting */
    tm = time(NULL);
    p = localtime(&tm);

    /* Initialize file queue to read the alerts */
    os_calloc(1, sizeof(file_queue), fileq);
    Init_FileQueue(fileq, p, 0);

    /* Create location hash */
    db_config->location_hash = OSHash_Create();
    if (!db_config->location_hash) {
        ErrorExit(MEM_ERROR, ARGV0, errno, strerror(errno));
    }

    /* Get maximum ID */
    db_config->alert_id = OS_SelectMaxID(db_config);
    db_config->alert_id++;
    /* Infinite loop reading the alerts and inserting them */
    sigset_t set, old_set;
    sigemptyset(&set);
    sigaddset(&set, SIGHUP);
    sigprocmask(SIG_BLOCK, &set, &old_set);

    while (1) {

        if (sighup_received) {
            DBConfig new_db_config;
            memset(&new_db_config, 0, sizeof(DBConfig));

            sighup_received = 0;
            merror("%s: INFO: SIGHUP received. Reloading configuration.", ARGV0);

            if (OS_ReadDBConf(0, cfgfile, &new_db_config) <= 0) {
                merror("%s: ERROR: Error reloading configuration (using old config)", ARGV0);
            } else {
                /* Reconnect to database */
                unsigned int d = 0;
                while (d <= (new_db_config.maxreconnect * 10)) {
                    new_db_config.conn = new_db_config.db_connect(new_db_config.host, new_db_config.user,
                                                  new_db_config.pass, new_db_config.db,
                                                  new_db_config.port, new_db_config.sock);
                    if (new_db_config.conn) {
                        break;
                    }
                    d++;
                    sleep(d * 10); // Faster reconnect than in main for reload
                }

                if (!new_db_config.conn) {
                    merror(DB_CONFIGERR, ARGV0);
                    FreeDBConfig(&new_db_config);
                    merror("%s: ERROR: Error connecting to database (using old config)", ARGV0);
                } else {
                    /* Create location hash for the new config */
                    new_db_config.location_hash = OSHash_Create();
                    if (!new_db_config.location_hash) {
                        merror("%s: ERROR: Unable to create location hash for new config", ARGV0);
                        FreeDBConfig(&new_db_config);
                    } else {
                        /* Get maximum ID for the new config */
                        new_db_config.alert_id = OS_SelectMaxID(&new_db_config);
                        new_db_config.alert_id++;

                        /* Atomic swap */
                        FreeDBConfig(db_config);
                        memcpy(db_config, &new_db_config, sizeof(DBConfig));
                        osdb_setconfig(db_config);

                        verbose("%s: Connected to database '%s' at '%s' (reloaded).",
                                ARGV0, db_config->db, db_config->host);
                    }
                }
            }
        }

        tm = time(NULL);
        p = localtime(&tm);

        /* Get message if available (timeout of 5 seconds) - unblock SIGHUP during wait */
        sigprocmask(SIG_SETMASK, &old_set, NULL);
        al_data = Read_FileMon(fileq, p, 5);
        sigprocmask(SIG_BLOCK, &set, NULL);

        if (!al_data) {
            continue;
        }

        /* Insert into the db */
        OS_Alert_InsertDB(al_data, db_config);

        /* Clear the memory */
        FreeAlertData(al_data);
    }
}

