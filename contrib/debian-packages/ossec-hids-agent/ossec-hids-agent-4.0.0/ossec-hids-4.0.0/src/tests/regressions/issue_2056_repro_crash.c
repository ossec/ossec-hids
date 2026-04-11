#include "shared.h"
#include "analysisd/eventinfo.h"
#include "analysisd/config.h"

/* Mock global config */
/* _Config Config; -- defined in config-live.o */

/* Stubs for missing symbols */
void *NULL_Decoder = NULL;
int ReadConfig(int modules, const char *cfgfile, void *d1, void *d2) { return 0; }

/* External function */
void SyscheckInit();
int DecodeSyscheck(Eventinfo *lf);

int main()
{
    /* Initialize Syscheck DB (Allocate sdb.syscheck_dec) */
    SyscheckInit();

    Eventinfo lf;
    memset(&lf, 0, sizeof(Eventinfo));

    /* Initialize Mock Config */
    Config.syscheck_alert_new = 1; /* Crucial to trigger the vulnerable path */

    /* Malformed input: Fewer than 6 tokens in checksum part */
    /* Format: checksum filename */
    /* Checksum expected: c_sum:md5:sha1... based on ":" parsing */
    /* We provide a short checksum string */
    char *input_msg = "badchecksum:1234:short  /tmp/testfile"; 
    
    /* Setup Eventinfo */
    lf.log = strdup(input_msg);
    lf.location = "localhost";

    printf("Attempting to call DecodeSyscheck with malformed input (Regression check)...\n");
    fflush(stdout);
    DecodeSyscheck(&lf);
    printf("Survived Malformed Input!\n");
    fflush(stdout);

    /* Cleanup Test Case 1 resources */
    free(lf.log);
    if(lf.full_log) free(lf.full_log);
    /* Note: other fields leaked for simplicity, just zeroing struct for next test */
    memset(&lf, 0, sizeof(Eventinfo));

    /* Test Case 2: Full Checksum with SHA256 */
    /* Format: 1:2:3:4:MD5:SHA1:SHA256 */
    char *input_msg_full = "ignore:ignore:ignore:ignore:MYMD5:MYSHA1:MYSHA256  /tmp/testfile_sha256";
    lf.log = strdup(input_msg_full);
    lf.location = "localhost";

    printf("Attempting to call DecodeSyscheck with SHA256 input...\n");
    fflush(stdout);
    DecodeSyscheck(&lf);
    printf("Survived SHA256 Input!\n");
    fflush(stdout);

    return 0;
}
