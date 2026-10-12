/* Paths that start with \\ or // make a Windows open authenticate
 * the service account. \\?\C:\ is a local extended path.
 */

#include <stdio.h>

#include "file_op.h"

static int expect(const char *path, int want)
{
    int got;

    got = os_win_network_path(path);
    if (got != want) {
        fprintf(stderr, "FAIL: '%s' got %d want %d\n",
                path ? path : "(null)", got, want);
        return (1);
    }
    return (0);
}

int main(void)
{
    int rc = 0;

    rc |= expect(NULL, 0);
    rc |= expect("", 0);
    rc |= expect("C:\\Windows\\a.log", 0);
    rc |= expect("/var/log/a.log", 0);
    rc |= expect("\\\\?\\C:\\Windows\\a.log", 0);
    rc |= expect("//?/C:/Windows/a.log", 0);
    rc |= expect("\\\\192.168.56.103\\x\\x", 1);
    rc |= expect("//192.168.56.103/x/x", 1);
    rc |= expect("  \\\\server\\share\\file.log", 1);
    rc |= expect("\\\\?\\UNC\\localhost\\e\\file.log", 1);
    rc |= expect("//?/UNC/localhost/e/file.log", 1);
    rc |= expect("\\\\.\\pipe\\evil", 1);

    if (rc == 0) {
        printf("ok\n");
    }
    return (rc == 0 ? 0 : 1);
}
