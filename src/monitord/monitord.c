/* @(#) $Id: ./src/monitord/monitord.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */



#include "shared.h"
#include "monitord.h"


/* Real monitord global */
void Monitord()
{
    time_t tm;
    struct tm *p;

    int today = 0;
    int thismonth = 0;
    int thisyear = 0;

    char str[OS_SIZE_1024 +1];

    /* Waiting a few seconds to settle */
    sleep(10);

    memset(str, '\0', OS_SIZE_1024 +1);


    /* Getting current time before starting */
    tm = time(NULL);
    p = localtime(&tm);

    today = p->tm_mday;
    thismonth = p->tm_mon;
    thisyear = p->tm_year+1900;



    /* Connecting to the message queue
     * Exit if it fails.
     */
    if((mond.a_queue = StartMQ(DEFAULTQUEUE,WRITE)) < 0)
    {
        ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQUEUE);
    }


    /* Sending startup message */
    snprintf(str, OS_SIZE_1024 -1, OS_AD_STARTED);
    if(SendMSG(mond.a_queue, str, ARGV0,
                       LOCALFILE_MQ) < 0)
    {
        merror(QUEUE_SEND, ARGV0);
    }


    /* Main monitor loop */
    while(1)
    {
        tm = time(NULL);
        p = localtime(&tm);


        /* Checking unavailable agents */
        if(mond.monitor_agents)
        {
            monitor_agents();
        }

        /* Day changed, deal with log files */
        if(today != p->tm_mday)
        {
            /* Generate reports */
            generate_reports(today, thismonth, thisyear, p);

            manage_files(today, thismonth, thisyear);

            today = p->tm_mday;
            thismonth = p->tm_mon;
            thisyear = p->tm_year+1900;
        }

        /* Sleep before checking again */
        sleep(120);
    }
}

/* EOF */
