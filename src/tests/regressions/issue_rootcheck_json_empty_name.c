/*
 * Regression for W_JSON_ParseRootcheck empty-name compliance tags
 * (ANT-2026-4ZSKX2AW / CWE-476).
 *
 * A rootcheck full_log containing "{: 1.1}" used to make strtok() skip the
 * leading colon, leave no value token, and call trim(NULL) -> strlen(NULL)
 * (SIGSEGV) while building the JSON alert. A well-formed "{CIS: 1.1}" must
 * still yield a "cis" array with "1.1".
 *
 * Build (from src/ after make TARGET=server):
 *   make -f tests/regressions/Makefile issue_rootcheck_json_empty_name
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "analysisd/eventinfo.h"
#include "analysisd/format/json_extended.h"
#include "cJSON.h"

static int failures = 0;

#define CHECK(cond, msg) do { \
        if (cond) { printf("  ok:   %s\n", msg); } \
        else { printf("  FAIL: %s\n", msg); failures++; } \
    } while (0)

static Eventinfo *new_lf(const char *full_log)
{
    Eventinfo *lf;

    os_calloc(1, sizeof(*lf), lf);
    os_strdup(full_log, lf->full_log);
    return lf;
}

static void free_lf(Eventinfo *lf)
{
    if (!lf) {
        return;
    }
    free(lf->full_log);
    free(lf);
}

/* Empty name: must not crash; must not invent a compliance key from the value. */
static void test_empty_name_tag(void)
{
    Eventinfo *lf;
    cJSON *rule;
    cJSON *cis;
    char *printed;

    printf("--- empty-name tag \"{: 1.1}\" ---\n");

    lf = new_lf("System Audit: {: 1.1} other text");
    rule = cJSON_CreateObject();
    W_JSON_ParseRootcheck(rule, lf, 0);

    printed = cJSON_PrintUnformatted(rule);
    CHECK(printed != NULL, "JSON rule object printed after empty-name tag");
    /* Pattern requires a name; empty-name tags must add nothing. */
    CHECK(cJSON_GetObjectItem(rule, "1.1") == NULL,
          "empty-name tag did not invent a \"1.1\" key");
    cis = cJSON_GetObjectItem(rule, "cis");
    CHECK(cis == NULL, "empty-name tag did not add a cis array");

    free(printed);
    cJSON_Delete(rule);
    free_lf(lf);
}

/* Control: well-formed CIS tag still becomes "cis":["1.1"]. */
static void test_cis_tag(void)
{
    Eventinfo *lf;
    cJSON *rule;
    cJSON *cis;
    cJSON *item;

    printf("--- well-formed tag \"{CIS: 1.1}\" ---\n");

    lf = new_lf("System Audit: {CIS: 1.1} other text");
    rule = cJSON_CreateObject();
    W_JSON_ParseRootcheck(rule, lf, 0);

    cis = cJSON_GetObjectItem(rule, "cis");
    CHECK(cis != NULL && cJSON_IsArray(cis), "CIS tag creates cis array");
    item = cJSON_GetArrayItem(cis, 0);
    CHECK(item != NULL && cJSON_IsString(item) &&
          strcmp(item->valuestring, "1.1") == 0,
          "CIS array contains \"1.1\"");

    cJSON_Delete(rule);
    free_lf(lf);
}

/* Empty name whose value looks like an allow-listed name still must not crash. */
static void test_empty_name_with_cis_value(void)
{
    Eventinfo *lf;
    cJSON *rule;

    printf("--- empty-name tag \"{: CIS}\" ---\n");

    lf = new_lf("System Audit: {: CIS}");
    rule = cJSON_CreateObject();
    W_JSON_ParseRootcheck(rule, lf, 0);

    CHECK(cJSON_GetObjectItem(rule, "cis") == NULL,
          "\"{: CIS}\" did not add a cis key from the value token");

    cJSON_Delete(rule);
    free_lf(lf);
}

/* Production alert path uses nested=1 (rule under the root object). */
static void test_nested_and_pci(void)
{
    Eventinfo *lf;
    cJSON *root;
    cJSON *rule;
    cJSON *pci;
    cJSON *item;

    printf("--- nested=1 with \"{PCI_DSS: 2.2.4}\" ---\n");

    lf = new_lf("System Audit: {PCI_DSS: 2.2.4} and {: 9.9}");
    root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "rule", rule = cJSON_CreateObject());
    W_JSON_ParseRootcheck(root, lf, 1);

    pci = cJSON_GetObjectItem(rule, "pci_dss");
    CHECK(pci != NULL && cJSON_IsArray(pci), "PCI_DSS tag creates pci_dss array");
    item = cJSON_GetArrayItem(pci, 0);
    CHECK(item != NULL && cJSON_IsString(item) &&
          strcmp(item->valuestring, "2.2.4") == 0,
          "PCI_DSS array contains \"2.2.4\"");
    CHECK(cJSON_GetObjectItem(rule, "9.9") == NULL,
          "nested empty-name tag did not invent a \"9.9\" key");

    cJSON_Delete(root);
    free_lf(lf);
}

/* Whitespace-only value must not crash trim() after the name split. */
static void test_blank_value(void)
{
    Eventinfo *lf;
    cJSON *rule;
    cJSON *cis;

    printf("--- blank value \"{CIS: }\" ---\n");

    lf = new_lf("System Audit: {CIS: }");
    rule = cJSON_CreateObject();
    W_JSON_ParseRootcheck(rule, lf, 0);

    cis = cJSON_GetObjectItem(rule, "cis");
    CHECK(cis != NULL && cJSON_IsArray(cis), "blank-value CIS still creates cis array");
    CHECK(cJSON_GetArraySize(cis) == 0 ||
          (cJSON_GetArrayItem(cis, 0) &&
           cJSON_GetArrayItem(cis, 0)->valuestring &&
           cJSON_GetArrayItem(cis, 0)->valuestring[0] == '\0'),
          "blank-value CIS does not invent a non-empty control id");

    cJSON_Delete(rule);
    free_lf(lf);
}

int main(void)
{
    printf("=== ANT-2026-4ZSKX2AW: W_JSON_ParseRootcheck empty-name tag ===\n");

    test_cis_tag();
    test_empty_name_tag();
    test_empty_name_with_cis_value();
    test_nested_and_pci();
    test_blank_value();

    if (failures) {
        printf("FAIL: %d check(s) failed\n", failures);
        return 1;
    }
    printf("PASS: empty-name rootcheck JSON tags handled without crash\n");
    return 0;
}
