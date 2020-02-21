#include <stdio.h>
#include <stdlib.h>

#include "defs.h"

void dbd_print_version()
{
    printf(" ");
    printf("%s %s - %s", __ossec_name, __version, __author);
    printf(" ");
    printf("%s", __license);

    printf("\n");

#ifdef MYSQL_DATABASE_ENABLED
    printf("** Compiled with MySQL support\n");
#endif

#ifdef PGSQL_DATABASE_ENABLED
    printf("** Compiled with PostgreSQL support\n");
#endif

#if !defined(MYSQL_DATABASE_ENABLED) && !defined(PGSQL_DATABASE_ENABLED)
    printf("** Compiled without any database support\n");
#endif

    exit(1);
}
