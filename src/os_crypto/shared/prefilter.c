#include <unistd.h>
#include "shared.h"
#include "prefilter.h"

/* Applies prefilter if any specified,
 * or open the file and return fd
 */
FILE *prefilter(char *file_name, char *prefilter_cmd)
{
	char cmd[OS_MAXSTR];

	if (prefilter_cmd == NULL)
		return (fopen(file_name, "r"));

	snprintf(cmd, OS_MAXSTR, "%s %s", prefilter_cmd, file_name);

	return (popen(cmd, "r"));
}

/* Closes the file descriptor correctly, regarding if prefilter_cmd is set
 */
int prefilter_close(FILE *fp, char *prefilter_cmd)
{
	if (prefilter_cmd == NULL)
    	return (fclose(fp));
    else
        return (pclose(fp));
}