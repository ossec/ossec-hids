/*
 * ANT-2026-R4SS008F: os_check_ads() BackupRead destination must hold any
 * NTFS stream name BackupRead can return (UTF-16 ":name:$DATA", up to
 * 524 bytes for a 255-character name). The old MAX_PATH+1 (261) buffer
 * overflowed for names longer than 123 characters.
 */

#include <stdio.h>
#include <stddef.h>

#include "rootcheck.h"

/* Longest NTFS stream name: ":" + 255 chars + ":$DATA", UTF-16. */
#define ADS_NAME_MAX_BYTES ((1 + 255 + 6) * 2)

int main(void)
{
    int failed = 0;

    printf("=== ANT-2026-R4SS008F: ADS stream name buffer bounds ===\n");
    printf("  OS_ADS_STREAM_NAME_BYTES=%d\n", (int)OS_ADS_STREAM_NAME_BYTES);
    printf("  longest NTFS name bytes=%d\n", ADS_NAME_MAX_BYTES);

    if (!os_ads_stream_name_fits(260)) {
        printf("  FAIL: 260-byte name (fits old buffer) rejected\n");
        failed = 1;
    } else {
        printf("  ok: 260-byte name fits\n");
    }

    if (!os_ads_stream_name_fits(ADS_NAME_MAX_BYTES)) {
        printf("  FAIL: %d-byte name (255-char NTFS) does not fit — stack overflow risk\n",
               ADS_NAME_MAX_BYTES);
        failed = 1;
    } else {
        printf("  ok: longest NTFS stream name fits\n");
    }

    if (os_ads_stream_name_fits((size_t)OS_ADS_STREAM_NAME_BYTES + 1)) {
        printf("  FAIL: oversized name accepted\n");
        failed = 1;
    } else {
        printf("  ok: oversized name rejected\n");
    }

    if (failed) {
        printf("\nFAIL: issue_ads_stream_overflow\n");
        return 1;
    }

    printf("\nPASS: issue_ads_stream_overflow\n");
    return 0;
}
