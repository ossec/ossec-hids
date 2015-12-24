#include <stdio.h>
#include <string.h>

#include "validate_op.h"


int main(int argc, char **argv)
{
    os_ip myip;

    if (!argv[1]) {
        return (1);
    }

    if (!OS_IsValidIP(argv[1], &myip)) {
        printf("Invalid ip\n");
    }

    if (OS_IPFound(argv[2], &myip)) {
        printf("IP MATCHED!\n");
    }

    return (0);
}

