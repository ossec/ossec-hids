/* Regression for the multi-line logcollector underflow.
 * Three lines that each fill an fgets() read used to wrap
 * OS_MAXSTR - buffer_size - 2 and strncpy() past the stack buffer.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "logcollector/logcollector.h"

int logr_queue = -1;
logreader *logff = NULL;

/* The reader is compiled with FORTIFY off, so this is the strncpy
 * it calls. This glibc treats a length above SSIZE_MAX as a no-op,
 * so the wrapped size does not fault here. Reject it directly.
 */
#undef strncpy
char *strncpy(char *dst, const char *src, size_t n)
{
    size_t i;

    if (n > OS_MAXSTR) {
        fprintf(stderr, "FAIL: strncpy length wrapped to %zu\n", n);
        exit(1);
    }
    for (i = 0; i < n && src[i] != '\0'; i++) {
        dst[i] = src[i];
    }
    for (; i < n; i++) {
        dst[i] = '\0';
    }
    return (dst);
}

#define MAX_SENT 4
static char sent[MAX_SENT][OS_MAXSTR + 2];
static int sends;

int SendMSG(int queue, const char *message, const char *locmsg, char loc)
{
    size_t len;

    (void)queue;
    (void)locmsg;
    (void)loc;
    len = strlen(message);
    if (len > OS_MAXSTR) {
        fprintf(stderr, "FAIL: queued message length %zu\n", len);
        exit(1);
    }
    if (sends >= MAX_SENT) {
        fprintf(stderr, "FAIL: too many queued messages\n");
        exit(1);
    }
    memcpy(sent[sends], message, len + 1);
    sends++;
    return (0);
}

int StartMQ(const char *key, short int type)
{
    (void)key;
    (void)type;
    return (-1);
}

void debug1(const char *msg, ...)
{
    (void)msg;
}

void debug2(const char *msg, ...)
{
    (void)msg;
}

void merror(const char *msg, ...)
{
    (void)msg;
}

void ErrorExit(const char *msg, ...)
{
    (void)msg;
    fprintf(stderr, "FAIL: ErrorExit\n");
    exit(1);
}

static int run_reader(const char *text, int expect)
{
    char path[] = "/tmp/ossec-multiline-XXXXXX";
    int fd;
    FILE *fp;
    int rc = -1;
    logreader readers[2];
    ssize_t wrote;

    fd = mkstemp(path);
    if (fd < 0) {
        perror("mkstemp");
        return (1);
    }
    wrote = write(fd, text, strlen(text));
    if (wrote < 0 || (size_t)wrote != strlen(text)) {
        perror("write");
        close(fd);
        unlink(path);
        return (1);
    }
    close(fd);

    fp = fopen(path, "r");
    if (!fp) {
        perror("fopen");
        unlink(path);
        return (1);
    }

    memset(readers, 0, sizeof(readers));
    readers[0].file = path;
    readers[0].logformat = "3";
    readers[0].fp = fp;
    logff = readers;
    sends = 0;
    sent[0][0] = '\0';

    if (read_multiline(0, &rc, 0) != NULL || rc != 0) {
        fprintf(stderr, "FAIL: read_multiline did not finish\n");
        fclose(fp);
        unlink(path);
        return (1);
    }
    fclose(fp);
    unlink(path);

    if (sends != expect) {
        fprintf(stderr, "FAIL: expected %d message(s), got %d\n", expect, sends);
        return (1);
    }
    return (0);
}

int main(void)
{
    char line[OS_MAXSTR];
    char *long_text;
    size_t line_len = OS_MAXSTR - OS_LOG_HEADER - 2;
    size_t i;
    size_t long_len;

    if (run_reader("one\ntwo\nthree\n", 1) != 0) {
        return (1);
    }
    if (strcmp(sent[0], "one two three") != 0) {
        fprintf(stderr, "FAIL: short message is '%s'\n", sent[0]);
        return (1);
    }

    memset(line, 'A', line_len);
    line[line_len] = '\n';
    line[line_len + 1] = '\0';
    long_len = strlen(line);

    long_text = malloc(long_len * 3 + sizeof("NEXT\n"));
    if (!long_text) {
        perror("malloc");
        return (1);
    }
    for (i = 0; i < 3; i++) {
        memcpy(long_text + i * long_len, line, long_len);
    }
    memcpy(long_text + long_len * 3, "NEXT\n", sizeof("NEXT\n"));

    /* The third line used to pass a wrapped size to strncpy.
     * NEXT must be queued on its own. Treating the full buffer as
     * an unfinished line used to drain it away.
     */
    if (run_reader(long_text, 2) != 0) {
        free(long_text);
        return (1);
    }
    free(long_text);

    if (strlen(sent[0]) > OS_MAXSTR || sent[0][0] != 'A') {
        fprintf(stderr, "FAIL: long message was not truncated inside the buffer\n");
        return (1);
    }
    if (strcmp(sent[1], "NEXT") != 0) {
        fprintf(stderr, "FAIL: following line is '%s'\n", sent[1]);
        return (1);
    }
    printf("ok\n");
    return (0);
}
