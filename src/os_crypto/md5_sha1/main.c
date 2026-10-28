#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../md5/md5_op.h"
#include "../sha1/sha1_op.h"
#include "md5_sha1_op.h"


void usage(char **argv)
{
    printf("%s file <path>\n%s str string\n", argv[0], argv[0]);
    exit(1);
}

int main(int argc, char **argv)
{
    os_md5 filesum1;
    os_sha1 filesum2;

    if (argc < 3) {
        usage(argv);
    }

    if (strcmp(argv[1], "file") == 0) {
        if (argc < 3) {
            usage(argv);
        }
        if (OS_MD5_SHA1_File(argv[2], filesum1, filesum2, OS_BINARY) != 0) {
            fprintf(stderr, "Unable to hash file: %s\n", argv[2]);
            return (1);
        }
    } else {
        usage(argv);
    }

    printf("MD5Sha1Sum for \"%s\" is: %s - %s\n", argv[2], filesum1, filesum2);
    return (0);
}
