/*
 * Regression: <field> rule crashes when the decoder has no field table
 *
 * ANT-2026-R3ZY7CWM / CWE-476
 *
 * OS_CheckIfRuleMatch() indexes lf->decoder_info->fields[] for a rule
 * with <field name="...">. That table is allocated only for a decoder
 * with <order>. A parent decoder or the placeholder decoder leaves it
 * NULL, and the read kills analysisd. A missing table is not a match.
 * A decoder that has the named field still matches.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_r3zy7cwm_field_null_decoder
 *
 * Run:
 *   ./issue_r3zy7cwm_field_null_decoder
 */

#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "analysisd.h"
#include "config.h"
#include "eventinfo.h"

RuleInfo *OS_CheckIfRuleMatch(Eventinfo *lf, RuleNode *curr_node);

/* Not reached: the rules under test set none of these options. */
int doDiff(RuleInfo *rule, const Eventinfo *lf)
{
    (void)rule;
    (void)lf;
    return 0;
}

int FTS(Eventinfo *lf)
{
    (void)lf;
    return 0;
}

int OS_DBSearch(ListRule *lrule, char *key)
{
    (void)lrule;
    (void)key;
    return 0;
}

_Config Config;

#define ORDER_SIZE 8

static int failures = 0;
static sigjmp_buf crash_jmp;
static volatile sig_atomic_t crashed;

static void expect(int cond, const char *msg)
{
    if (cond) {
        printf("  ok:   %s\n", msg);
    } else {
        printf("  FAIL: %s\n", msg);
        failures++;
    }
}

static void on_segv(int sig)
{
    (void)sig;
    crashed = 1;
    siglongjmp(crash_jmp, 1);
}

static RuleInfo *try_match(Eventinfo *lf, RuleNode *node)
{
    struct sigaction sa;
    struct sigaction old;
    RuleInfo *got = NULL;

    crashed = 0;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_segv;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &old);
    if (sigsetjmp(crash_jmp, 1) == 0) {
        got = OS_CheckIfRuleMatch(lf, node);
    }
    sigaction(SIGSEGV, &old, NULL);
    return got;
}

static OSRegex *compile_admin(void)
{
    OSRegex *reg = calloc(1, sizeof(*reg));

    if (reg == NULL || OSRegex_Compile("^admin$", reg, 0) == 0) {
        free(reg);
        return NULL;
    }
    return reg;
}

static void blank_rule(RuleInfo *rule, FieldInfo **fields)
{
    memset(rule, 0, sizeof(*rule));
    pthread_mutex_init(&rule->mutex, NULL);
    rule->sigid = 100101;
    rule->fields = fields;
}

static void blank_event(Eventinfo *lf, OSDecoderInfo *dec, char **values)
{
    memset(lf, 0, sizeof(*lf));
    memset(dec, 0, sizeof(*dec));
    dec->name = "myapp";
    dec->id = 50;
    lf->decoder_info = dec;
    lf->fields = values;
}

int main(void)
{
    FieldInfo **no_fields;
    FieldInfo **tenant_fields;
    FieldInfo tenant;
    OSRegex *admin;
    char *names[ORDER_SIZE];
    char *values[ORDER_SIZE];
    RuleInfo rule;
    RuleNode node;
    Eventinfo lf;
    OSDecoderInfo dec;
    RuleInfo *got;

    printf("issue_r3zy7cwm_field_null_decoder\n");

    Config.decoder_order_size = ORDER_SIZE;
    admin = compile_admin();
    expect(admin != NULL, "field regex compiled");
    if (admin == NULL) {
        printf("1 failure(s)\n");
        return 1;
    }

    no_fields = calloc(ORDER_SIZE, sizeof(*no_fields));
    tenant_fields = calloc(ORDER_SIZE, sizeof(*tenant_fields));
    expect(no_fields != NULL && tenant_fields != NULL, "field tables allocated");
    if (no_fields == NULL || tenant_fields == NULL) {
        printf("%d failure(s)\n", failures ? failures : 1);
        return 1;
    }

    memset(&tenant, 0, sizeof(tenant));
    tenant.name = "tenant";
    tenant.regex = admin;
    tenant_fields[0] = &tenant;

    memset(&node, 0, sizeof(node));
    node.ruleinfo = &rule;

    /* A rule with no <field> still matches a decoder that has no table. */
    blank_rule(&rule, no_fields);
    blank_event(&lf, &dec, NULL);
    got = try_match(&lf, &node);
    expect(!crashed && got == &rule,
           "rule without a field matches a decoder with no table");

    /* The named field is present and the value matches. */
    memset(names, 0, sizeof(names));
    memset(values, 0, sizeof(values));
    names[2] = "tenant";
    values[2] = "admin";
    blank_rule(&rule, tenant_fields);
    blank_event(&lf, &dec, values);
    dec.fields = names;
    got = try_match(&lf, &node);
    expect(!crashed && got == &rule, "named field matches");

    values[2] = "bob";
    got = try_match(&lf, &node);
    expect(!crashed && got == NULL, "wrong field value does not match");

    names[2] = "user";
    values[2] = "admin";
    got = try_match(&lf, &node);
    expect(!crashed && got == NULL, "missing field name does not match");

    /* Parent decoder and the placeholder decoder: fields stays NULL. */
    blank_rule(&rule, tenant_fields);
    blank_event(&lf, &dec, values);
    dec.fields = NULL;
    got = try_match(&lf, &node);
    expect(!crashed, "no field table does not crash");
    expect(!crashed && got == NULL,
           "field rule does not match a decoder with no field table");

    dec.name = NULL;
    got = try_match(&lf, &node);
    expect(!crashed, "placeholder decoder does not crash");
    expect(!crashed && got == NULL,
           "field rule does not match the placeholder decoder");

    OSRegex_FreePattern(admin);
    free(admin);
    free(no_fields);
    free(tenant_fields);
    pthread_mutex_destroy(&rule.mutex);

    if (failures) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
