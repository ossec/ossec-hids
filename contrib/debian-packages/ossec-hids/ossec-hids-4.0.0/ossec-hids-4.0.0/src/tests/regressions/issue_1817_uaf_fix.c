/*
 * Regression Test for Issue 1817: Heap Use-After-Free in OSSEC Alert Decoder
 *
 * Compilation Check:
 * This test requires linking against ossec-analysisd object files.
 *
 * Build Command (Server-side):
 * cd src
 * Build Command (Server-side):
 * cd src
 * make TARGET=server
 * cc -I./ -I./headers -o issue_1817_uaf_repro tests/regressions/issue_1817_uaf_repro.c \
 *   analysisd/cleanevent-live.o analysisd/eventinfo-live.o \
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
char *__stats_comment = "stats";
int __crt_hour = 0;
int __crt_wday = 0;
int one = 1;

EventNode *OS_GetLastEvent(void) { return NULL; }

/* We need to mock OSHash_Get or Config.g_rules_hash?
   OSSECAlert_Decoder_Exec calls OSHash_Get(Config.g_rules_hash, oa_id)
   So we need to initialize Config.g_rules_hash or mock OSHash_Get.
   Since OSHash_Get is in shared.a, we can't easily mock it if we link shared.a.
   We must setup Config.g_rules_hash.
*/

/* Declarations */
int OS_CleanMSG(char *msg, Eventinfo *lf);
void *OSSECAlert_Decoder_Exec(Eventinfo *lf);

int main(void) {
    /* 1. Setup Rule Hash Mock */
    Config.g_rules_hash = OSHash_Create();
    int rule_val = 1;
    OSHash_Add(Config.g_rules_hash, "500", &rule_val); // Mock rule ID 500

    /* 2. Prepare Eventinfo */
    Eventinfo lf;
    memset(&lf, 0, sizeof(Eventinfo));
    lf.decoder_info = calloc(1, sizeof(OSDecoderInfo));
    c_time = time(NULL);

    /* 3. Prepare Message */
    /* format: id:location:message */
    /* OSSEC Alert format:
       ** Alert 1234567890.1234: - syslog,errors,
       2020 Jan 15 12:00:00 (agent) 1.2.3.4->/var/log/syslog
       Rule: 500 (level 3) -> 'Some Alert'
       Src IP: 1.2.3.4
       User: root
       ossec: Alert Level: 3; Rule: 500; Location: (agent) 1.2.3.4->/var/log/syslog;
    */
    
    char msg[4096];
    // We construct a message that OS_CleanMSG will parse.
    // OS_CleanMSG expects "id:location:message"
    // And for it to extract program_name, it looks for "p_name: " or similar
    // BUT OSSECAlert decoder requires strict format "ossec: Alert Level:..."
    // Let's try to satisfy both.
    // OS_CleanMSG extracts program_name from the specific log formats like syslog.
    // The "message" part passed to OS_CleanMSG becomes lf->log.
    // We want lf->log to match OSSECAlert requirements AND have a program header.
    
    // We use a standard syslog format so OS_CleanMSG extracts program_name.
    // "Jan 15 12:00:00 hostname program: message"
    // "1:(agent) 1.2.3.4->syslog:Jan 15 12:00:00 hostname ossec-alert: ossec: Alert Level: 3; Rule: 500 (level 3) -> 'Alert'; Location: (agent) 1.2.3.4->syslog;"
    snprintf(msg, sizeof(msg), "1:(agent) 1.2.3.4->syslog:Jan 15 12:00:00 hostname ossec-alert: ossec: Alert Level: 3; Rule: 500 (level 3) -> 'Alert'; Location: (agent) 1.2.3.4->syslog;");

    printf("Input msg: %s\n", msg);

    /* 4. Call OS_CleanMSG */
    if (OS_CleanMSG(msg, &lf) < 0) {
        printf("OS_CleanMSG failed\n");
        return 1;
    }

    printf("After CleanMSG:\n");
    printf("  full_log ptr: %p\n", lf.full_log);
    printf("  program_name: '%s' (ptr: %p)\n", lf.program_name, lf.program_name);
    
    if (!lf.program_name) {
        printf("Failed to extract program_name. Test meaningless.\n");
        return 1;
    }

    char *old_full_log = lf.full_log;
    char *old_pname = lf.program_name;

    /* 5. Call OSSECAlert_Decoder_Exec */
    OSSECAlert_Decoder_Exec(&lf);

    printf("After OSSECAlert Decoder:\n");
    printf("  full_log ptr: %p\n", lf.full_log);
    printf("  program_name: %p\n", lf.program_name);

    if (lf.full_log == old_full_log) {
        printf("full_log was NOT freed/replaced. Decoder logic not triggered?\n");
        return 1;
    }

    /* 6. Check for UAF */
    /* program_name points to old buffer. full_log is new buffer. */
    if (lf.program_name == old_pname) {
        printf("VULNERABLE: lf->program_name still points to old address %p\n", lf.program_name);
        return 1; // Vulnerable
    } else {
        printf("SAFE: lf->program_name was updated (pointed to %p, different from old %p)\n", lf.program_name, old_pname);
        return 0; // Fixed
    }
}
