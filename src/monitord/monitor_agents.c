/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "monitord.h"
#include "read-agents.h"

/* Queue location for an agent-disconnect event. agent is "<name>-<address>".
 * The queue message is "id:location:message" and analysisd ends the location
 * at the first ':' unless it is "(name) ip->...". An address, a CIDR, and
 * "any" contain no '-', so the last '-' is the split already used by
 * delete_agentinfo(). A name that is not in that form uses the plain
 * program location from before 4.1.0.
 */
void monitor_disconnect_location(const char *agent, const char *prog,
                                 char *out, size_t outsz)
{
    const char *agent_ip;

    if (outsz == 0) {
        return;
    }
    out[0] = '\0';
    if (!agent || !prog) {
        return;
    }

    agent_ip = strrchr(agent, '-');
    if (agent_ip && agent_ip > agent && agent_ip[1] != '\0') {
        snprintf(out, outsz, "(%.*s) %s->%s",
                 (int)(agent_ip - agent), agent, agent_ip + 1, prog);
    } else {
        snprintf(out, outsz, "%s", prog);
    }
}

void monitor_agents()
{
    char **cr_agents;
    char **av_agents;

    av_agents = get_agents_with_timeout(GA_ACTIVE, mond.notify_time);

    /* No agent saved */
    if (!mond.agents) {
        mond.agents = av_agents;
        return;
    }

    /* Check if any of the previously available agents are disconnected */
    cr_agents = mond.agents;
    while (*cr_agents) {
        int available = 0;
        char **tmp_av;

        tmp_av = av_agents;
        while (tmp_av && *tmp_av) {
            if (strcmp(*cr_agents, *tmp_av) == 0) {
                available = 1;
                break;
            }
            tmp_av++;
        }

        /* Agent disconnected */
        if (available == 0) {
            char str[OS_SIZE_1024 + 1];

            /* Send disconnected message */
            snprintf(str, OS_SIZE_1024 - 1, OS_AG_DISCON, *cr_agents);

            char refined_location[OS_SIZE_1024 + 1];
            monitor_disconnect_location(*cr_agents, ARGV0,
                                        refined_location, sizeof(refined_location));

            if (SendMSG(mond.a_queue, str, refined_location,
                        LOCALFILE_MQ) < 0) {
                merror(QUEUE_SEND, ARGV0);
            }
        }

        cr_agents++;
    }

    /* Remove old agent list and add current one */
    free_agents(mond.agents);
    mond.agents = av_agents;
    return;
}
