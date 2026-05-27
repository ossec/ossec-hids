/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "headers/debug_op.h"
#include "decoder.h"
#include "config.h"
#include "error_messages/error_messages.h"

/* We have two internal lists. One with the program_name
 * and one without. This is going to improve greatly the
 * performance of our decoder matching.
 */
static OSDecoderNode *osdecodernode_forpname;
static OSDecoderNode *osdecodernode_nopname;
static OSDecoderNode *osdecodernode_forpname_staging;
static OSDecoderNode *osdecodernode_nopname_staging;
static int decoderlist_staging_active;

static OSDecoderNode **decoderlist_forpname_head(void)
{
    if (decoderlist_staging_active) {
        return (&osdecodernode_forpname_staging);
    }
    return (&osdecodernode_forpname);
}

static OSDecoderNode **decoderlist_nopname_head(void)
{
    if (decoderlist_staging_active) {
        return (&osdecodernode_nopname_staging);
    }
    return (&osdecodernode_nopname);
}

static OSDecoderNode *_OS_AddOSDecoder(OSDecoderNode *s_node, OSDecoderInfo *pi);

/* Create the Event List */
void OS_CreateOSDecoderList()
{
    *decoderlist_forpname_head() = NULL;
    *decoderlist_nopname_head() = NULL;

    return;
}

void OS_DecoderListStagingBegin(void)
{
    decoderlist_staging_active = 1;
    osdecodernode_forpname_staging = NULL;
    osdecodernode_nopname_staging = NULL;
}

void OS_DecoderListStagingCommit(void)
{
    OS_AbandonOSDecoderList();
    osdecodernode_forpname = osdecodernode_forpname_staging;
    osdecodernode_nopname = osdecodernode_nopname_staging;
    osdecodernode_forpname_staging = NULL;
    osdecodernode_nopname_staging = NULL;
    decoderlist_staging_active = 0;
}

void OS_DecoderListStagingAbort(void)
{
    if (osdecodernode_forpname_staging) {
        OS_FreeOSDecoderList(osdecodernode_forpname_staging);
        osdecodernode_forpname_staging = NULL;
    }
    if (osdecodernode_nopname_staging) {
        OS_FreeOSDecoderList(osdecodernode_nopname_staging);
        osdecodernode_nopname_staging = NULL;
    }
    decoderlist_staging_active = 0;
}

int OS_DecoderListStagingActive(void)
{
    return decoderlist_staging_active;
}

#define DECODER_LIST_FAIL(...) do {                                     \
        if (decoderlist_staging_active) {                               \
            merror(__VA_ARGS__);                                        \
            return (NULL);                                              \
        }                                                               \
        ErrorExit(__VA_ARGS__);                                         \
    } while (0)

/* Drop decoder lists without freeing nodes (used during SIGHUP reload). */
void OS_AbandonOSDecoderList(void)
{
    osdecodernode_forpname = NULL;
    osdecodernode_nopname = NULL;
}

/* Free all decoders and reset lists */
void OS_DestroyOSDecoderList()
{
    if (osdecodernode_forpname) {
        OS_FreeOSDecoderList(osdecodernode_forpname);
        osdecodernode_forpname = NULL;
    }
    if (osdecodernode_nopname) {
        OS_FreeOSDecoderList(osdecodernode_nopname);
        osdecodernode_nopname = NULL;
    }
}

/* Get first osdecoder */
OSDecoderNode *OS_GetFirstOSDecoder(const char *p_name)
{
    /* If program name is set, we return the forpname list */
    if (p_name) {
        return (*decoderlist_forpname_head());
    }

    return (*decoderlist_nopname_head());
}

/* Add an osdecoder to the list */
static OSDecoderNode *_OS_AddOSDecoder(OSDecoderNode *s_node, OSDecoderInfo *pi)
{
    OSDecoderNode *tmp_node = s_node;
    OSDecoderNode *new_node;
    int rm_f = 0;

    if (tmp_node) {
        new_node = (OSDecoderNode *)calloc(1, sizeof(OSDecoderNode));
        if (new_node == NULL) {
            merror(MEM_ERROR, ARGV0, errno, strerror(errno));
            return (NULL);
        }

        /* Going to the last node */
        do {
            /* Check for common names */
            if ((strcmp(tmp_node->osdecoder->name, pi->name) == 0) &&
                    (pi->parent != NULL)) {
                if ((tmp_node->osdecoder->prematch ||
                        tmp_node->osdecoder->regex ||
                        tmp_node->osdecoder->prematch_pcre2 ||
                        tmp_node->osdecoder->pcre2) && pi->regex_offset) {
                    rm_f = 1;
                }

                /* Multi-regexes patterns cannot have prematch */
                if (pi->prematch || pi->prematch_pcre2) {
                    merror(PDUP_INV, ARGV0, pi->name);
                    goto error;
                }

                /* Multi-regex patterns cannot have fts set */
                if (pi->fts) {
                    merror(PDUPFTS_INV, ARGV0, pi->name);
                    goto error;
                }

                if (tmp_node->osdecoder->regex && pi->regex) {
                    tmp_node->osdecoder->get_next = 1;
                } else if (tmp_node->osdecoder->pcre2 && pi->pcre2) {
                    tmp_node->osdecoder->get_next = 1;
                } else {
                    merror(DUP_INV, ARGV0, pi->name);
                    goto error;
                }
            }

        } while (tmp_node->next && (tmp_node = tmp_node->next));

        /* Must have a prematch set */
        if (!rm_f && (pi->regex_offset & AFTER_PREVREGEX)) {
            merror(INV_OFFSET, ARGV0, pi->name);
            goto error;
        }

        tmp_node->next = new_node;

        new_node->next = NULL;
        new_node->osdecoder = pi;
        new_node->child = NULL;
    }

    else {
        /* Must not have a previous regex set */
        if (pi->regex_offset & AFTER_PREVREGEX) {
            merror(INV_OFFSET, ARGV0, pi->name);
            return (NULL);
        }

        tmp_node = (OSDecoderNode *)calloc(1, sizeof(OSDecoderNode));

        if (tmp_node == NULL) {
            DECODER_LIST_FAIL(MEM_ERROR, ARGV0, errno, strerror(errno));
        }

        tmp_node->child = NULL;
        tmp_node->next = NULL;
        tmp_node->osdecoder = pi;

        s_node = tmp_node;
    }

    return (s_node);

error:
    if (new_node) {
        free(new_node);
    }
    return (NULL);
}

int OS_AddOSDecoder(OSDecoderInfo *pi)
{
    int added = 0;
    OSDecoderNode *osdecodernode;

    /* We can actually have two lists. One with program
     * name and the other without.
     */
    if (pi->program_name || pi->program_name_pcre2) {
        osdecodernode = *decoderlist_forpname_head();
    } else {
        osdecodernode = *decoderlist_nopname_head();
    }

    /* Search for parent on both lists */
    if (pi->parent) {
        OSDecoderNode *tmp_node = *decoderlist_forpname_head();

        /* List with p_name */
        while (tmp_node) {
            if (strcmp(tmp_node->osdecoder->name, pi->parent) == 0) {
                tmp_node->child = _OS_AddOSDecoder(tmp_node->child, pi);
                if (!tmp_node->child) {
                    merror(DEC_PLUGIN_ERR, ARGV0);
                    return (0);
                }
                added = 1;
            }
            tmp_node = tmp_node->next;
        }

        /* List without p name */
        tmp_node = *decoderlist_nopname_head();
        while (tmp_node) {
            if (strcmp(tmp_node->osdecoder->name, pi->parent) == 0) {
                tmp_node->child = _OS_AddOSDecoder(tmp_node->child, pi);
                if (!tmp_node->child) {
                    merror(DEC_PLUGIN_ERR, ARGV0);
                    return (0);
                }
                added = 1;
            }
            tmp_node = tmp_node->next;
        }

        /* OSDecoder was added correctly */
        if (added == 1) {
            return (1);
        }

        merror(PPLUGIN_INV, ARGV0, pi->parent);
        return (0);
    } else {
        osdecodernode = _OS_AddOSDecoder(osdecodernode, pi);
        if (!osdecodernode) {
            merror(DEC_PLUGIN_ERR, ARGV0);
            return (0);
        }

        /* Update global decoder pointers */
        if (pi->program_name || pi->program_name_pcre2) {
            *decoderlist_forpname_head() = osdecodernode;
        } else {
            *decoderlist_nopname_head() = osdecodernode;
        }
    }
    return (1);
}


/* Free a OSDecoderInfo structure and all its members */
void OS_FreeDecoderInfo(OSDecoderInfo *pi)
{
    int i;
    if (!pi) {
        return;
    }

    free(pi->parent);
    free(pi->name);
    free(pi->ftscomment);

    if (pi->fields) {
        for (i = 0; i < Config.decoder_order_size; i++) {
            free(pi->fields[i]);
        }
        free(pi->fields);
    }

    if (pi->order) {
        free(pi->order);
    }

    if (pi->regex) {
        OSRegex_FreePattern(pi->regex);
        free(pi->regex);
    }

    if (pi->prematch) {
        OSRegex_FreePattern(pi->prematch);
        free(pi->prematch);
    }

    if (pi->program_name) {
        OSMatch_FreePattern(pi->program_name);
        free(pi->program_name);
    }

    if (pi->pcre2) {
        OSPcre2_FreePattern(pi->pcre2);
        free(pi->pcre2);
    }

    if (pi->prematch_pcre2) {
        OSPcre2_FreePattern(pi->prematch_pcre2);
        free(pi->prematch_pcre2);
    }

    if (pi->program_name_pcre2) {
        OSPcre2_FreePattern(pi->program_name_pcre2);
        free(pi->program_name_pcre2);
    }

    free(pi);
}

/* Free a OSDecoderNode tree recursively */
void OS_FreeOSDecoderList(OSDecoderNode *node)
{
    if (!node) {
        return;
    }

    /* Free children first */
    if (node->child) {
        OS_FreeOSDecoderList(node->child);
    }

    /* Free siblings next */
    if (node->next) {
        OS_FreeOSDecoderList(node->next);
    }

    /* Free this decoderinfo */
    if (node->osdecoder) {
        OS_FreeDecoderInfo(node->osdecoder);
    }

    free(node);
}
