#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "string_op.h"


int main(int argc, char **argv)
{
    char *tmp;
    char buf[] = "/var/www/html/Testing This Interface$%^&*().txt";

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

    return (0);
}

