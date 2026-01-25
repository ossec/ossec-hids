/*
 * Regression Test for Issue 1813: Path Traversal in Syscheck
 *
 * Compilation Check:
 * This test requires linking against ossec-analysisd object files.
 *
 * Build Command (Server-side):
 * cd src
 * make TARGET=server
 * cc -I./ -I./headers -o issue_1813_path_traversal tests/regressions/issue_1813_path_traversal.c \
 *   analysisd/decoders/syscheck-live.o analysisd/eventinfo-live.o \
 *   analysisd/decoders/decoders_list-live.o analysisd/decoders/decoder-live.o \
 *   analysisd/decoders/decode-xml-live.o analysisd/decoders/plugin_decoders-live.o \
 *   analysisd/decoders/plugins/*-live.o config.a shared.a os_net.a os_regex.a \
 *   os_xml.a os_zlib.a libcJSON.a -lm -lpthread -lpcre2-8
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>

#include "shared.h"
#include "analysisd/eventinfo.h"
#include "analysisd/config.h"

/* Mocks */
_Config Config;
time_t c_time;
OSDecoderInfo *NULL_Decoder = NULL;

EventNode *OS_GetLastEvent(void) {
    return NULL;
}

/* Declarations */
void SyscheckInit();
int DecodeSyscheck(Eventinfo *lf);

/* Mock or Stub needed symbols if linking fails */
/* For now assume we link against needed libs */

int main(void) {
    const char *payload = "../../../../../../../../../../../../../tmp/vuln_test_file";
    const char *target_file = "/tmp/vuln_test_file";
    Eventinfo lf;
    memset(&lf, 0, sizeof(Eventinfo));

    /* Ensure clean start */
    unlink(target_file);
    
    printf("Initializing Syscheck...\n");
    OS_SetName("repro_1813");
    
    /* SyscheckInit might assume some Config is loaded or defaults. 
       If it fails, we might need to populate Config global. 
       But let's try. */
    SyscheckInit();
    
    /* Setup Eventinfo */
    /* Format of syscheck: checksum filename */
    lf.log = strdup("csum /etc/testfile"); 
    lf.location = strdup(payload); /* The malicious agent name used for path construction */
    
    printf("Calling DecodeSyscheck with agent name: %s\n", lf.location);
    DecodeSyscheck(&lf);
    
    /* Check if file created */
    if (access(target_file, F_OK) == 0) {
        printf("VULNERABLE: File '%s' was created!\n", target_file);
        unlink(target_file);
        return 1; /* Vulnerable */
    } else {
        printf("SAFE: File '%s' was NOT created.\n", target_file);
        return 0; /* Safe */
    }
}
