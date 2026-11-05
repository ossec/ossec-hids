#ifndef __SHA256_OP_H
#define __SHA256_OP_H

#include <stddef.h>

typedef char os_sha256[65];

int OS_SHA256_File(const char *fname, os_sha256 output, int mode) __attribute((nonnull));
/* max_size 0 means no byte cap. Returns -1 with errno EFBIG past the cap. */
int OS_SHA256_File_max(const char *fname, os_sha256 output, int mode,
                       size_t max_size) __attribute((nonnull(1, 2)));
#ifndef WIN32
/* Same as OS_SHA256_File but opens with fopen_regular_nofollow() so no
 * symlink component is followed (report_changes snapshots). */
int OS_SHA256_File_nofollow(const char *fname, os_sha256 output, int mode) __attribute((nonnull));
/* max_size 0 means no byte cap. Returns -1 with errno EFBIG past the cap. */
int OS_SHA256_File_nofollow_max(const char *fname, os_sha256 output, int mode,
                                size_t max_size) __attribute((nonnull(1, 2)));
#endif

#endif
