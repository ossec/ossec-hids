/* @(#) $Id: ./src/analysisd/decoders/decoder.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */


#ifndef __DECODER_H

#define __DECODER_H


/* We need the eventinfo and os_regex in here */
#include "shared.h"
#include "os_regex/os_regex.h"

#define AFTER_PARENT    0x001   /* 1   */
#define AFTER_PREMATCH  0x002   /* 2   */
#define AFTER_PREVREGEX 0x004   /* 4   */
#define AFTER_ERROR     0x010



/* Decoder structure */
typedef struct
{
    u_int8_t  get_next;
    u_int8_t  type;
    u_int8_t  use_own_name;

    u_int16_t id;
    u_int16_t regex_offset;
    u_int16_t prematch_offset;

    int fts;
    int accumulate;
    char *parent;
    char *name;
    char *ftscomment;
    os_lua_t *lua; 
    int lua_function; 

    OSRegex *regex;
    OSRegex *prematch;
    OSMatch *program_name;

    void (*plugindecoder)(void *lf);
    void (**order)(void *lf, char *field);
}OSDecoderInfo;

/* List structure */
typedef struct _OSDecoderNode
{
    struct _OSDecoderNode *next;
    struct _OSDecoderNode *child;
    OSDecoderInfo *osdecoder;
}OSDecoderNode;


/*
 * decoder obj functions 
 */

OSDecoderInfo *decoder_new(char *name);
void decoder_destroy(OSDecoderInfo **self_p);
/*
int decoder_run_lua(OSDecoderInfo *self, Eventinfo *lf);
int decoder_set(OSDecoderInfo *self, const char *key, void *value);
*/


/* Functions to Create the list, Add a osdecoder to the
 * list and to get the first osdecoder.
 */
void OS_CreateOSDecoderList();
int OS_AddOSDecoder(OSDecoderInfo *pi);
OSDecoderNode *OS_GetFirstOSDecoder(char *pname);
int getDecoderfromlist(char *name);


#endif

/* EOF */
