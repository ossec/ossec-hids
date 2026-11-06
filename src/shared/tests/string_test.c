#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "string_op.h"


/* Split like ossec-execd does and compare with the expected arguments */
static int check_split(char *request, const char **expected)
{
    char *next;

    printf("Split: '%s'\n", request);
    for (; request; request = next, expected++) {
        next = os_shell_escape_strchr(request, ' ');
        if (next) {
            *next++ = '\0';
        }
        if (!*expected || strcmp(request, *expected) != 0) {
            fprintf(stderr, "FAIL: got '%s', expected '%s'\n", request,
                    *expected ? *expected : "(end)");
            return (1);
        }
    }

    if (*expected) {
        fprintf(stderr, "FAIL: missing '%s'\n", *expected);
        return (1);
    }

    return (0);
}

int main(int argc, char **argv)
{
    char *tmp;
    char buf[] = "/var/www/html/Testing This Interface$%^&*().txt";
    char request[128];
    int failures = 0;
    const char *plain_args[] = { "-", "(a)", "1.2.3.4->C:\\x", "/tmp/f", NULL };
    const char *space_args[] = { "syscheck", "/tmp/x\\ /etc/shadow", NULL };
    const char *slash_args[] = { "syscheck", "/tmp/x\\\\\\ y\\\\", NULL };

    (void)argc;
    (void)argv;

    tmp = os_shell_escape(buf);
    char clean[] = "/var/www/html/index.html";

    printf("Sent: '%s'\n", buf);
    printf("Fixed: '%s'\n", tmp);
    free(tmp);

    tmp = os_shell_escape(clean);
    printf("Sent: '%s'\n", clean);
    printf("Fixed: '%s'\n", tmp);
    free(tmp);

    /* An escaped file name stays one argument of a request */
    strcpy(request, "- (a) 1.2.3.4->C:\\x /tmp/f");
    failures += check_split(request, plain_args);

    tmp = os_shell_escape("/tmp/x /etc/shadow");
    snprintf(request, sizeof(request), "syscheck %s", tmp);
    free(tmp);
    failures += check_split(request, space_args);

    tmp = os_shell_escape("/tmp/x\\ y\\");
    snprintf(request, sizeof(request), "syscheck %s", tmp);
    free(tmp);
    failures += check_split(request, slash_args);

    return (failures ? 1 : 0);
}

