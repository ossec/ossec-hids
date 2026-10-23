/*
 * ANT-2026-VUTSB5RB: sk_db_entry must not embed OS_MAXSTR for the checksum
 * prefix. One entry is kept per reported file name; a fixed 6KB buffer made
 * a single agent able to pin ~6.2KB of manager RSS per 45-byte message.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_syscheck_prefix_sum_size
 */

#include <stdio.h>
#include <stdlib.h>

#include "shared.h"
#include "analysisd/decoders/syscheck_db_entry.h"

int main(void)
{
    size_t n = sizeof(sk_db_entry);

    printf("=== ANT-2026-VUTSB5RB: syscheck index entry size ===\n");
    printf("sizeof(sk_db_entry)=%zu (OS_MAXSTR=%d)\n", n, OS_MAXSTR);

    /* fpos_t + pointer (plus padding) should stay well under 1KB. The old
     * layout was fpos_t + OS_MAXSTR+1 (~6168 bytes). */
    if (n >= 1024) {
        printf("FAIL: index entry still embeds a large prefix buffer (%zu bytes)\n",
               n);
        return 1;
    }

    printf("PASS: issue_syscheck_prefix_sum_size\n");
    return 0;
}
