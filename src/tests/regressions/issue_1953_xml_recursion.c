#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "os_xml.h"

int main(void) {
    const char *xml_file = "issue_1953_recursion.xml";
    FILE *fp;
    int i;
    OS_XML xml;

    /* Create a file with deep recursion */
    fp = fopen(xml_file, "w");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    /* Write 2000 levels of recursion, which exceeds the 1024 limit */
    for (i = 0; i < 2000; i++) {
        fprintf(fp, "<e>");
    }
    for (i = 0; i < 2000; i++) {
        fprintf(fp, "</e>");
    }
    fclose(fp);

    /* Try to parse it */
    if (OS_ReadXML(xml_file, &xml) < 0) {
        /* Check if error matches expected "Max recursion level reached" */
        if (strstr(xml.err, "Max recursion level reached")) {
            printf("PASS: Correctly detected recursion limit.\n");
            unlink(xml_file);
            return 0;
        } else {
            printf("FAIL: Failed with unexpected error: %s\n", xml.err);
            unlink(xml_file);
            return 1;
        }
    }

    printf("FAIL: Should have failed parsing but succeeded.\n");
    unlink(xml_file);
    return 1;
}
