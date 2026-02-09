/*
 * Regression Test for Issue 1748: analysisd Crash on sid_prev_matched List Overflow
 *
 * Bug Description:
 * When a rule with if_matched_sid triggers and the sid_prev_matched list reaches
 * its maximum size, OSList_AddData() automatically deletes the oldest node.
 * However, the Eventinfo structure for that deleted node still has sid_node_to_delete
 * pointing to the freed node. When Free_Eventinfo() is later called, it attempts to
 * delete the already-freed node, causing a double-free crash.
 *
 * Reproduction Steps:
 * 1. Create a rule with if_matched_sid
 * 2. Set the sid_prev_matched list to a small max size (e.g., 3)
 * 3. Trigger the rule multiple times (more than max size)
 * 4. OSList_AddData will auto-delete the oldest node
 * 5. Call Free_Eventinfo on the oldest event
 * 6. Crash occurs when trying to delete sid_node_to_delete
 *
 * Build Command:
 * cd src
 * make TARGET=server
 * cc -I./ -I./headers -o issue_1748_sid_list_crash \
 *   tests/regressions/issue_1748_sid_list_crash.c \
 *   analysisd/eventinfo-live.o shared.a -lm -lpthread
 *
 * Run with valgrind to detect double-free:
 * valgrind --leak-check=full ./issue_1748_sid_list_crash
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "shared.h"
#include "analysisd/eventinfo.h"
#include "analysisd/config.h"
#include "analysisd/rules.h"

/* Global mocks */
_Config Config;
time_t c_time;
OSDecoderInfo *NULL_Decoder = NULL;

/* Mock functions */
EventNode *OS_GetLastEvent(void) { return NULL; }

/* Callback function to clear sid_node_to_delete before auto-deletion
 * This is the FIX for issue #1748
 */
static void Mark_EventNodeDelete(void *data)
{
    Eventinfo *lf = (Eventinfo *)data;
    if (lf) {
        lf->sid_node_to_delete = NULL;
    }
}

int main(void) {
    printf("=== Issue 1748 Regression Test ===\n");
    printf("Testing double-free crash when sid_prev_matched list overflows\n\n");

    /* Initialize Config */
    memset(&Config, 0, sizeof(_Config));
    Config.decoder_order_size = 10;
    c_time = time(NULL);

    /* Create a mock rule with sid_prev_matched list */
    RuleInfo *test_rule = calloc(1, sizeof(RuleInfo));
    test_rule->sigid = 12345;
    test_rule->level = 5;
    test_rule->comment = "Test rule for issue 1748";
    
    /* Create and configure the sid_prev_matched list */
    test_rule->sid_prev_matched = OSList_Create();
    if (!test_rule->sid_prev_matched) {
        printf("ERROR: Failed to create OSList\n");
        return 1;
    }

    /* Set max size to 3 to trigger overflow quickly */
    const int MAX_SIZE = 3;
    if (!OSList_SetMaxSize(test_rule->sid_prev_matched, MAX_SIZE)) {
        printf("ERROR: Failed to set max size\n");
        return 1;
    }
    
    /* THE FIX: Set the callback to clear sid_node_to_delete before auto-deletion */
    if (!OSList_SetFreeDataPointer(test_rule->sid_prev_matched, Mark_EventNodeDelete)) {
        printf("ERROR: Failed to set free data pointer\n");
        return 1;
    }
    
    printf("Created sid_prev_matched list with max_size=%d\n", MAX_SIZE);
    printf("Registered Mark_EventNodeDelete callback (THE FIX)\n\n");

    /* Create multiple Eventinfo structures and add them to the list */
    #define NUM_EVENTS 5
    Eventinfo *events[NUM_EVENTS];
    
    for (int i = 0; i < NUM_EVENTS; i++) {
        events[i] = calloc(1, sizeof(Eventinfo));
        if (!events[i]) {
            printf("ERROR: Failed to allocate Eventinfo %d\n", i);
            return 1;
        }
        
        /* Allocate fields array */
        events[i]->fields = calloc(Config.decoder_order_size, sizeof(char*));
        
        /* Set up basic event info */
        events[i]->time = c_time + i;
        events[i]->generated_rule = test_rule;
        
        /* Simulate what analysisd.c does at lines 1008-1014 */
        printf("Event %d: Adding to sid_prev_matched list\n", i);
        if (!OSList_AddData(test_rule->sid_prev_matched, events[i])) {
            printf("ERROR: Failed to add event %d to list\n", i);
            return 1;
        }
        
        /* This is what analysisd.c does - save the node pointer */
        events[i]->sid_node_to_delete = test_rule->sid_prev_matched->last_node;
        
        printf("  Event %d: sid_node_to_delete = %p\n", i, events[i]->sid_node_to_delete);
        printf("  List size: %d\n", test_rule->sid_prev_matched->currently_size);
        
        /* When we exceed MAX_SIZE, OSList_AddData auto-deletes the oldest node */
        if (i >= MAX_SIZE) {
            printf("  WARNING: List at max size - oldest node was auto-deleted!\n");
        }
    }

    printf("\n=== Testing Free_Eventinfo on all events ===\n");
    
    /* Now try to free all events
     * Events 0 and 1 had their nodes auto-deleted by OSList_AddData
     * but their sid_node_to_delete pointers still point to freed memory
     * This should cause a crash or valgrind error
     */
    for (int i = 0; i < NUM_EVENTS; i++) {
        printf("Freeing event %d (sid_node_to_delete=%p)...\n", 
               i, events[i]->sid_node_to_delete);
        
        /* This is where the crash happens for events 0 and 1 */
        Free_Eventinfo(events[i]);
        
        printf("  Event %d freed successfully\n", i);
    }

    printf("\n=== Test Result ===\n");
    printf("If you see this message, the bug may be fixed OR not triggered.\n");
    printf("Run with valgrind to detect double-free:\n");
    printf("  valgrind --leak-check=full ./issue_1748_sid_list_crash\n");
    printf("\nExpected valgrind output if bug exists:\n");
    printf("  Invalid free() / delete / delete[] / realloc()\n");
    printf("  Address 0x... is ... bytes inside a block of size ... free'd\n");

    /* Cleanup */
    free(test_rule->sid_prev_matched);
    free(test_rule);

    return 0;
}
