/*
 * Regression Test for Issue 1814: Control Characters in OS_CleanMSG
 *
 * Compilation Check:
 * This test requires linking against ossec-analysisd object files.
 *
 * Build Command (Server-side):
 * cd src
 * make TARGET=server
 * cc -I./ -I./headers -o issue_1814_repro tests/regressions/issue_1814_repro.c \
 *   analysisd/cleanevent-live.o analysisd/analysisd-live.o \
 *   analysisd/eventinfo-live.o \
 *   analysisd/decoders/decoders_list-live.o analysisd/decoders/decoder-live.o \
 *   analysisd/decoders/decode-xml-live.o analysisd/decoders/plugin_decoders-live.o \
 *   analysisd/decoders/plugins/*-live.o config.a shared.a os_net.a os_regex.a \
 *   os_xml.a os_zlib.a libcJSON.a -lm -lpthread -lpcre2-8
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include "shared.h"
#include "analysisd/eventinfo.h"
#include "analysisd/config.h"

/* Mocks */
_Config Config;
time_t c_time;
OSDecoderInfo *NULL_Decoder = NULL;
char *__shost = "localhost";
int __crt_hour = 0;
int __crt_wday = 0;

EventNode *OS_GetLastEvent(void) {
    return NULL;
}

/* Declarations */
int OS_CleanMSG(char *msg, Eventinfo *lf);

int main(void) {
    char msg[2048];
    // Format: id:location:message
    // We inject \n (newline) and \x07 (bell) in the message
    snprintf(msg, sizeof(msg), "1:agent1:Test message with \n and \x07 control chars");
    
    Eventinfo lf;
    memset(&lf, 0, sizeof(Eventinfo));
    c_time = time(NULL);

    printf("Original message: %s\n", msg);
    
    // OS_CleanMSG modifies msg in place (via pieces)
    if (OS_CleanMSG(msg, &lf) < 0) {
        printf("OS_CleanMSG returned error\n");
        return 1;
    }

    printf("Processed log: %s\n", lf.full_log);

    // Check for newline
    if (strchr(lf.full_log, '\n')) {
        printf("VULNERABLE: Newline found in processed log!\n");
        return 1;
    }

    // Check for control char (bell)
    if (strchr(lf.full_log, '\x07')) {
        printf("VULNERABLE: Control char \\x07 found in processed log!\n");
        return 1;
    }

    printf("SAFE: No control characters found.\n");
    return 0;
}
