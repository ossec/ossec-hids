#ifndef __SHA256_OP_H
#define __SHA256_OP_H

typedef char os_sha256[65];

int OS_SHA256_File(const char *fname, os_sha256 output, int mode) __attribute((nonnull));
#ifndef WIN32
/* Same as OS_SHA256_File but opens with fopen_regular_nofollow() so no
 * symlink component is followed (report_changes snapshots). */
int OS_SHA256_File_nofollow(const char *fname, os_sha256 output, int mode) __attribute((nonnull));
#endif

#endif
