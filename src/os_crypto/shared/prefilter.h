#ifndef HEADER_PREFILTER_H
# define HEADER_PREFILTER_H

/* Applies prefilter if any specified,
 * or open the file and return fd
 */
FILE *prefilter(char *file_name, char *prefilter_cmd);

/* Closes the file correctly, regarding if prefilter_cmd is set
 */
int prefilter_close(FILE *fp, char *prefilter_cmd);

#endif
