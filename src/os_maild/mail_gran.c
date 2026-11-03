/* Copyright (C) 2026 Atomicorp LLC
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "maild.h"

/* After handing a grouped batch to a worker, clear live granular routing.
 *
 * DONOTGROUP placeholders in mail->gran_set belong to a parked s_msg alert
 * (do_not_group), not to the batch just committed. Promote those to
 * FULL_FORMAT so the later if (s_msg) path can mail the held alert to its
 * granular recipient; clear every other entry. Matches pre-5220f105 / Wazuh.
 */
void Mail_CommitGranClear(MailConfig *mail, int holding_s_msg)
{
    int i;

    if (!mail || !mail->gran_to || !mail->gran_set) {
        return;
    }

    i = 0;
    while (mail->gran_to[i] != NULL) {
        if (holding_s_msg && mail->gran_set[i] == DONOTGROUP) {
            mail->gran_set[i] = FULL_FORMAT;
        } else {
            mail->gran_set[i] = 0;
        }
        i++;
    }
}
