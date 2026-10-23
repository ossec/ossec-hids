/* Syscheck in-memory DB index entry (analysisd).
 * Shared so regressions can enforce the per-entry size contract
 * (ANT-2026-VUTSB5RB).
 */

#ifndef SYSCHECK_DB_ENTRY_H
#define SYSCHECK_DB_ENTRY_H

#include <stdio.h>

#include "shared.h"

typedef struct _sk_db_entry {
    fpos_t pos;
    char *prefix_sum; /* NULL until set; heap copy of "+++sum" / "!+++sum" */
} sk_db_entry;

#endif /* SYSCHECK_DB_ENTRY_H */
