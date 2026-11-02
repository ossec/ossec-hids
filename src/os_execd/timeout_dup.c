/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "list_op.h"
#include "execd.h"

/* Walk the timeout list for a duplicate of timeout_args.
 * Returns 1 if the request is incomplete or already pending (caller must
 * not ExecCmd / re-add). Incomplete requests (missing user/IP) must not
 * strcmp NULL slots (ANT-2026-SNXGRHGA). Match script, user, and IP so
 * user-keyed commands like disable-account (IP always '-') do not suppress
 * other accounts (ANT-2026-2LGOJR12).
 */
int ExecdTimeoutDupCheck(OSList *timeout_list, char **timeout_args,
                         time_t curr_time, OSHash *repeated_hash)
{
    OSListNode *timeout_node;
    int added_before = 0;

    if (!timeout_args) {
        return (1);
    }

    /* Check for the username and IP argument */
    if (!timeout_args[2] || !timeout_args[3]) {
        added_before = 1;
        merror("%s: Invalid number of arguments.", ARGV0);
    }

    timeout_node = timeout_list ? OSList_GetFirstNode(timeout_list) : NULL;

    /* An incomplete request is dropped, so there is nothing to compare. */
    while (timeout_node && !added_before) {
        timeout_data *list_entry;

        list_entry = (timeout_data *)timeout_node->data;
        if (!list_entry || !list_entry->command || !list_entry->command[0] ||
                !list_entry->command[2] || !list_entry->command[3]) {
            timeout_node = OSList_GetNextNode(timeout_list);
            continue;
        }

        if ((strcmp(list_entry->command[3], timeout_args[3]) == 0) &&
                (strcmp(list_entry->command[2], timeout_args[2]) == 0) &&
                (strcmp(list_entry->command[0], timeout_args[0]) == 0)) {
            added_before = 1;
            list_entry->time_of_addition = curr_time;

            if (repeated_offenders_timeout[0] != 0 &&
                    repeated_hash != NULL &&
                    timeout_args[3] &&
                    strncmp(timeout_args[3], "-", 1) != 0) {
                char *ntimes = NULL;
                char rkey[256];

                rkey[255] = '\0';
                snprintf(rkey, 255, "%s %s %s", list_entry->command[0],
                         timeout_args[2], timeout_args[3]);

                if ((ntimes = (char *) OSHash_Get(repeated_hash, rkey))) {
                    int ntimes_int = 0;
                    int i2 = 0;
                    int new_timeout = 0;

                    ntimes_int = atoi(ntimes);
                    while (repeated_offenders_timeout[i2] != 0) {
                        i2++;
                    }
                    if (ntimes_int >= i2) {
                        new_timeout = repeated_offenders_timeout[i2 - 1] * 60;
                    } else {
                        free(ntimes);
                        os_calloc(16, sizeof(char), ntimes);
                        new_timeout = repeated_offenders_timeout[ntimes_int] * 60;
                        ntimes_int++;
                        snprintf(ntimes, 16, "%d", ntimes_int);
                        OSHash_Update(repeated_hash, rkey, ntimes);
                    }
                    list_entry->time_to_block = new_timeout;
                }
            }
            break;
        }

        timeout_node = OSList_GetNextNode(timeout_list);
    }

    return (added_before);
}
