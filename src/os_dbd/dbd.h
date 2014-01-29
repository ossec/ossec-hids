/* @(#) $Id: ./src/os_dbd/dbd.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */


#ifndef _DBD_H
#define _DBD_H


#include "shared.h"
#include "db_op.h"
#include "config/dbd-config.h"


/** Prototypes **/

/* Read database config */
int OS_ReadDBConf(char *cfgfile, DBConfig *db_config);


/* Inserts server info to the db. */
int OS_Server_ReadInsertDB(void *db_config);


/* Insert rules in to the database */
int OS_InsertRulesDB(DBConfig *db_config);


/* Get maximum ID */
int OS_SelectMaxID(DBConfig *db_config);


/* Insert alerts in to the database */
int OS_Alert_InsertDB(alert_data *al_data, DBConfig *db_config);


/* Database inserting main function */
void OS_DBD(DBConfig *db_config);


/* Setting config pointer for osbd_op */
void osdb_setconfig(DBConfig *db_config);



/** Global vars **/

/* System hostname */
char __shost[512];


#endif
