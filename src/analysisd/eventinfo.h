/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _EVTINFO__H
#define _EVTINFO__H

#include <pthread.h>

#include "rules.h"
#include "decoders/decoder.h"

#include <time.h>

/* Event Information structure */
typedef struct _Eventinfo {
    /* Extracted from the event */
    char *log;
    char *full_log;
    char *location;
    char *hostname;
    char *program_name;

    /* Extracted from the decoders */
    char *srcip;
    char *srcgeoip;
    char *dstip;
    char *dstgeoip;
    char *srcport;
    char *dstport;
    char *protocol;
    char *action;
    char *srcuser;
    char *dstuser;
    char *id;
    char *status;
    char *command;
    char *url;
    char *data;
    char *systemname;
    char **fields;



    /* Pointer to the rule that generated it */
    RuleInfo *generated_rule;

    /* Async alert writer: snapshot of rule->last_events (owned by this event). */
    char **alert_last_events;
    /* Ticket-based alert id (0 = use ftell under writer lock). */
    long alert_id;

    /* Match-shard / process-thread index */
    int tid;

    /* Pointer to the decoder that matched */
    OSDecoderInfo *decoder_info;

    /* Sid node to delete */
    OSListNode *sid_node_to_delete;

    /* Extract when the event fires a rule */
    size_t size;
    size_t p_name_size;

    /* Memory management flags */
    unsigned int flags;
    #define EF_FREE_PNAME 0x001
    #define EF_FREE_HNAME 0x002
    /* log was separately allocated (not an alias into full_log). */
    #define EF_SEPARATE_LOG 0x004
    /* Async alert/archive/fw copy — skip sid/group list maintenance on free. */
    #define EF_ASYNC_COPY 0x008

    /* Other internal variables */
    int matched;

    time_t time;
    int day;
    int year;
    char hour[10];
    char mon[4];

    /* Enqueue timestamp for queue-wait sampling (CLOCK_MONOTONIC). */
    struct timespec queue_in_time;

    /* SYSCHECK Results variables */
    char *filename;
    int perm_before;
    int perm_after;
    char *md5_before;
    char *md5_after;
    char *sha1_before;
    char *sha1_after;
    char *sha256_before;
    char *sha256_after;
    char *size_before;
    char *size_after;
    char *owner_before;
    char *owner_after;
    char *gowner_before;
    char *gowner_after;
} Eventinfo;

/* Events List structure */
typedef struct _EventNode {
    Eventinfo *event;
    struct _EventNode *next;
    struct _EventNode *prev;
} EventNode;

/* Frequency / correlation ring (one per match shard). */
typedef struct _EventList {
    EventNode *first;
    EventNode *last;
    int memoryused;
    int memorymaxsize;
    pthread_mutex_t mutex;
} EventList;

#ifdef TESTRULE
extern int full_output;
extern int alert_only;
#endif

/* Types of events (from decoders) */
#define UNKNOWN         0   /* Unknown */
#define SYSLOG          1   /* syslog messages */
#define IDS             2   /* IDS alerts */
#define FIREWALL        3   /* Firewall events */
#define WEBLOG          7   /* Apache logs */
#define SQUID           8   /* Squid logs */
#define DECODER_WINDOWS 9   /* Windows logs */
#define HOST_INFO       10  /* Host information logs (from nmap or similar) */
#define OSSEC_RL        11  /* OSSEC rules */
#define OSSEC_ALERT     12  /* OSSEC alerts */

/* FTS allowed values */
#define FTS_NAME        001000
#define FTS_SRCUSER     002000
#define FTS_DSTUSER     004000
#define FTS_SRCIP       000100
#define FTS_DSTIP       000200
#define FTS_LOCATION    000400
#define FTS_ID          000010
#define FTS_DATA        000020
#define FTS_SYSTEMNAME  000040
#define FTS_DONE        010000

/** Functions for events **/

/* Search for matches in the last events */
Eventinfo *Search_LastEvents(Eventinfo *lf, RuleInfo *currently_rule);
Eventinfo *Search_LastSids(Eventinfo *my_lf, RuleInfo *currently_rule);
Eventinfo *Search_LastGroups(Eventinfo *my_lf, RuleInfo *currently_rule);

/* Frequency rule context log samples (heap-owned copies) */
void OS_SetRuleLastEvent(RuleInfo *rule, int idx, const char *log);
void OS_FreeRuleLastEvents(RuleInfo *rule);
/* Transfer rule->last_events ownership onto lf->alert_last_events.
 * Caller must already hold rule->mutex. */
void OS_MoveRuleLastEvents(RuleInfo *rule, Eventinfo *lf);

/* Zero the eventinfo structure */
void Zero_Eventinfo(Eventinfo *lf);

/* Free the eventinfo structure */
void Free_Eventinfo(Eventinfo *lf);

/* Add and event to the list of previous events */
void OS_AddEvent(Eventinfo *lf);
void OS_AddEvent_List(Eventinfo *lf, EventList *list);

/* Return the last event from the Event list */
EventNode *OS_GetLastEvent(void);
EventNode *OS_GetLastEvent_List(EventList *list);

/* Create the event list. Maxsize must be specified */
void OS_CreateEventList(int maxsize);
EventList *OS_EventList_Create(int maxsize);
void OS_EventList_Destroy(EventList *list);

/* Pointers to the event decoders */
void *SrcUser_FP(Eventinfo *lf, char *field, int order);
void *DstUser_FP(Eventinfo *lf, char *field, int order);
void *SrcIP_FP(Eventinfo *lf, char *field, int order);
void *DstIP_FP(Eventinfo *lf, char *field, int order);
void *SrcPort_FP(Eventinfo *lf, char *field, int order);
void *DstPort_FP(Eventinfo *lf, char *field, int order);
void *Protocol_FP(Eventinfo *lf, char *field, int order);
void *Action_FP(Eventinfo *lf, char *field, int order);
void *ID_FP(Eventinfo *lf, char *field, int order);
void *Url_FP(Eventinfo *lf, char *field, int order);
void *Data_FP(Eventinfo *lf, char *field, int order);
void *Status_FP(Eventinfo *lf, char *field, int order);
void *SystemName_FP(Eventinfo *lf, char *field, int order);
void *FileName_FP(Eventinfo *lf, char *field, int order);
void *DynamicField_FP(Eventinfo *lf, char *field, int order);
void *None_FP(Eventinfo *lf, char *field, int order);


#endif /* _EVTINFO__H */

