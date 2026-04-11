/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 */

#include "shared.h"
#include "agentlessd.h"

const char *cfgfile;

/* Free the agentless configuration */
void FreeAgentlessConfig(agentlessd_config *config)
{
    int i = 0;

    if (config->entries) {
        while (config->entries[i]) {
            int j = 0;
            if (config->entries[i]->server) {
                while (config->entries[i]->server[j]) {
                    free(config->entries[i]->server[j]);
                    j++;
                }
                free(config->entries[i]->server);
            }

            free(config->entries[i]->type);
            free(config->entries[i]->command);
            
            /* options is often a static string "" or a strdup */
            /* In Read_CAgentless it is initialized to "" then strdup'ed */
            if (config->entries[i]->options && config->entries[i]->options[0] != '\0') {
                free((char *)config->entries[i]->options);
            }

            free(config->entries[i]);
            i++;
        }
        free(config->entries);
        config->entries = NULL;
    }
}
