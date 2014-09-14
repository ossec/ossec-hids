/* @(#) $Id: ./src/headers/list_op.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Common list API */


#ifndef _OS_LIST
#define _OS_LIST

typedef struct _OSListNode
{
    struct _OSListNode *next;
    struct _OSListNode *prev;
    void *data;
}OSListNode;


typedef struct _OSList
{
    OSListNode *first_node;
    OSListNode *last_node;
    OSListNode *cur_node;

    int current_size;
    int max_size;

    void (*free_data_function)(void *data);
}OSList;


OSList *OSList_Create();

int OSList_SetMaxSize(OSList *list, int max_size);
int OSList_SetFreeDataPointer(OSList *list, void *free_data_function);

OSListNode *OSList_GetFirstNode(OSList *);
OSListNode *OSList_GetLastNode(OSList *);
OSListNode *OSList_GetPrevNode(OSList *);
OSListNode *OSList_GetNextNode(OSList *);
OSListNode *OSList_GetCurrentNode(OSList *list);

void OSList_DeleteCurrentNode(OSList *list);
void OSList_DeleteThisNode(OSList *list, OSListNode *thisnode);
void OSList_DeleteOldestNode(OSList *list);

int OSList_AddData(OSList *list, void *data);

#endif

/* EOF */
