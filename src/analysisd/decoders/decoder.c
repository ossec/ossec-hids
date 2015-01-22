/* @(#) $Id: ./src/analysisd/decoders/decoder.c, 2011/09/08 dcid Exp $
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



#include "shared.h"
#include "os_regex/os_regex.h"
#include "os_xml/os_xml.h"


#include "eventinfo.h"
#include "decoder.h"

void decoder_destroy(OSDecoderInfo **self_p) 
{
    int i;
    if (*self_p) {
        OSDecoderInfo *self = *self_p; 
        if(self->parent) { free(self->parent); }
        if(self->name) { free(self->name);  }
        if(self->ftscomment) { free(self->ftscomment); }
        if(self->lua) { self->lua = NULL; }
        if(self->regex) { free(self->regex); }
        if(self->prematch) { free(self->prematch); }
        if(self->program_name) { free(self->program_name); }
        if(self->order) {
            for (i=0;self->order[i] != NULL; i++ ) {
                free(self->order[i]);
            }
        }
        self_p = NULL; 
    }
}
OSDecoderInfo *decoder_new(char *name)
{
    OSDecoderInfo *self = (OSDecoderInfo *)calloc(1,sizeof(OSDecoderInfo));
    check_mem(self);
    self->parent = NULL;
    self->id = 0;
    self->name = strdup(name);
    self->order = NULL;
    self->plugindecoder = NULL;
    self->fts = 0;
    self->lua = NULL; 
    self->accumulate = 0;
    self->type = SYSLOG;
    self->prematch = NULL;
    self->program_name = NULL;
    self->regex = NULL;
    self->use_own_name = 0;
    self->get_next = 0;
    self->regex_offset = 0;
    self->prematch_offset = 0;
    return self; 

error: 
    decoder_destroy(&self);
    return NULL;
}

int decoder_set_parent(OSDecoderInfo *self, const char *parent) {
    self->parent = strdup(parent);
    check_mem(self->parent); 
    return 0;
error:
    return 1;
}

int decoder_set_name(OSDecoderInfo *self, const char *name) 
{
    if (self->name) {
        return 2;
    }
    self->name = strdup(name);
    check_mem(self->name); 
    return 0;
error:
    return 1;
}

int decoder_set_ftscomment(OSDecoderInfo *self, const char *ftscomment) 
{
    if(self->ftscomment) {
        return 2;
    }
    self->ftscomment = strdup(ftscomment);
    check_mem(self->ftscomment); 
    return 0;
error:
    return 1;
}

int decoder_set_lua(OSDecoderInfo *self, os_lua_t *lua)
{
    if(self->lua) {
        return 2; 
    }
    self->lua = lua; 
    return 0; 
}

int decoder_set_lua_function(OSDecoderInfo *self, int f)
{
    if(self->lua_function) {
        return 2; 
    }
    self->lua_function = f; 
    return 0;
}

int decoder_set_regex(OSDecoderInfo *self, OSRegex *r )
{
    if(self->regex) {
        return 2; 
    }
    self->regex = r; 
    return 0; 
}

int decoder_set_regex_text(OSDecoderInfo *self, const char *pattern, int flags) 
{
    if(self->regex) {
        return 2; 
    }
    os_calloc(1, sizeof(OSRegex), self->regex);
    check_mem(self->regex); 
    if(!OSRegex_Compile(pattern, self->regex, flags))
    {
        merror(REGEX_COMPILE, ARGV0, pattern, self->regex->error);
        return(1);
    }
error:
    return 1; 
}


int decoder_run_lua(OSDecoderInfo *self, Eventinfo *lf) 
{
    d("starting run_lua");
    int t; 
    const char *key; 
    const char *value; 

    if(self->lua == NULL) {
        d("no lua");
        return 0; 
    }

    if (self->lua_function == 0) {
        d("no function"); 
        return 0; 
    }
    d("lua_function: %d", self->lua_function);
    lua_newtable(self->lua->L); 

    if(lf->log) {
        lua_pushstring(self->lua->L, "log");
        lua_pushstring(self->lua->L, lf->log); 
        lua_settable(self->lua->L, -3);
    }
    if(lf->full_log) {
        lua_pushstring(self->lua->L, "full_log");
        lua_pushstring(self->lua->L, lf->full_log); 
        lua_settable(self->lua->L, -3);
    }
    if(lf->location) {
        lua_pushstring(self->lua->L, "location");
        lua_pushstring(self->lua->L, lf->location); 
        lua_settable(self->lua->L, -3);
    }
    if(lf->hostname) {
        lua_pushstring(self->lua->L, "hostname");
        lua_pushstring(self->lua->L, lf->hostname); 
        lua_settable(self->lua->L, -3);
    }
    if(lf->program_name) {
        lua_pushstring(self->lua->L, "program_name");
        lua_pushstring(self->lua->L, lf->program_name); 
        lua_settable(self->lua->L, -3);
    }


    /* Run lua code */
    d("pcall");
    if(!(os_lua_pcall(self->lua, self->lua_function, 1, 1, 0))) {
        d("pcall done");
        goto error; 
    }

    /* output of lua code */ 
    t =  lua_type(self->lua->L, -1);
    switch(t) {
        case LUA_TTABLE: /* set values based on output Table */ 
            d("in table");
            lua_pushnil(self->lua->L); 
            while (lua_next(self->lua->L, -2)) {
                      // stack now contains: -1 => value; -2 => key; -3 => table
                      // copy the key so that lua_tostring does not modify the original
                      lua_pushvalue(self->lua->L, -2);
                      // stack now contains: -1 => key; -2 => value; -3 => key; -4 => table
                      key = lua_tostring(self->lua->L, -1);
                      value = lua_tostring(self->lua->L, -2);
                      if(strcasecmp(key,"dstip")==0) {
                          lf->dstip = strdup(value); 
                          #ifdef TESTRULE
                          if(!alert_only)print_out("       dstip: '%s'", lf->dstip);
                          #endif
                      } else if (strcasecmp(key,"dstuser")==0) {
                          lf->dstuser = strdup(value); 
                          #ifdef TESTRULE
                          if(!alert_only)print_out("       dstuser: '%s'", lf->dstuser);
                          #endif
                      } else if (strcasecmp(key,"dstport")==0) {
                          lf->dstport = strdup(value); 
                          #ifdef TESTRULE
                          if(!alert_only)print_out("       dstport: '%s'", lf->dstport);
                          #endif
                      } else if (strcasecmp(key,"srcip")==0) {
                          lf->srcip = strdup(value); 
                          #ifdef TESTRULE
                          if(!alert_only)print_out("       srcip: '%s'", lf->srcip);
                          #endif
                      } else if (strcasecmp(key,"srcuser")==0) {
                          lf->srcuser = strdup(value); 
                          #ifdef TESTRULE
                          if(!alert_only)print_out("       srcuser: '%s'", lf->srcuser);
                          #endif
                      } else if (strcasecmp(key,"srcport")==0) {
                          lf->srcport = strdup(value); 
                          #ifdef TESTRULE
                          if(!alert_only)print_out("       srcport: '%s'", lf->srcport);
                          #endif
                      } else if (strcasecmp(key,"protocol")==0) {
                          lf->protocol = strdup(value); 
                          #ifdef TESTRULE
                          if(!alert_only)print_out("       protocol: '%s'", lf->protocol);
                          #endif
                      } else if (strcasecmp(key,"action")==0) {
                          lf->action = strdup(value); 
                          #ifdef TESTRULE
                          if(!alert_only)print_out("       action: '%s'", lf->action);
                          #endif
                      } else if (strcasecmp(key,"status")==0) {
                          lf->status = strdup(value); 
                          #ifdef TESTRULE
                          if(!alert_only)print_out("       status: '%s'", lf->status);
                          #endif
                      } else if (strcasecmp(key,"url")==0) {
                          lf->url = strdup(value); 
                          #ifdef TESTRULE
                          if(!alert_only)print_out("       url: '%s'", lf->url);
                          #endif
                      } else if (strcasecmp(key,"data")==0) {
                          lf->data = strdup(value); 
                          #ifdef TESTRULE
                          if(!alert_only)print_out("       data: '%s'", lf->data);
                          #endif
                      } else if (strcasecmp(key,"data")==0) {
                          lf->data = strdup(value); 
                          #ifdef TESTRULE
                          if(!alert_only)print_out("       data: '%s'", lf->data);
                          #endif
                      }

                      d(" - %s => %s", key, value);
                      // pop value + copy of key, leaving original key
                      lua_pop(self->lua->L, 2);
                      // stack now contains: -1 => key; -2 => table

            }
            lua_pop(self->lua->L,1); 
            return 0; 
        case LUA_TNIL: /* dont do anything */ 
            lua_pop(self->lua->L,1);
            return 0;
            break;
        default:
            lua_pop(self->lua->L,1); 
            goto error; 
    }

error: 
    d("error");
    return 1; 
}


/* DecodeEvent.
 * Will use the osdecoders to decode the received event.
 */
void DecodeEvent(Eventinfo *lf)
{
    OSDecoderNode *node;
    OSDecoderNode *child_node;
    OSDecoderInfo *nnode;

    const char *llog = NULL;
    const char *pmatch = NULL;
    const char *cmatch = NULL;
    const char *regex_prev = NULL;


    node = OS_GetFirstOSDecoder(lf->program_name);


    /* Return if no node...
     * This shouldn't happen here anyways.
     */
    if(!node)
        return;


    #ifdef TESTRULE
    if(!alert_only)
    {
        print_out("\n**Phase 2: Completed decoding.");
    }
    #endif

    do
    {
        nnode = node->osdecoder;
        d("start do: nnode-name: %s", nnode->name);


        /* First checking program name */
        if(lf->program_name)
        {
            if(!OSMatch_Execute(lf->program_name, lf->p_name_size,
                        nnode->program_name))
            {
                continue;
            }
            pmatch = lf->log;
        }


        /* If prematch fails, go to the next osdecoder in the list */
        if(nnode->prematch)
        {
            if(!(pmatch = OSRegex_Execute(lf->log, nnode->prematch)))
            {
                continue;
            }

            /* Next character */
            if(*pmatch != '\0')
                pmatch++;
        }


        #ifdef TESTRULE
        if(!alert_only)print_out("       decoder: '%s'", nnode->name);
        #endif


        lf->decoder_info = nnode;


        child_node = node->child;


        /* If no child node is set, set the child node
         * as if it were the child (ugh)
         */
        if(!child_node)
        {
            child_node = node;
        }

        else
        {
            /* Check if we have any child osdecoder */
            while(child_node)
            {
                nnode = child_node->osdecoder;
                d("prematch: %s", nnode->name);


                /* If we have a pre match and it matches, keep
                 * going. If we don't have a prematch, stop
                 * and go for the regexes.
                 */
                if(nnode->prematch)
                {
                    const char *llog;

                    /* If we have an offset set, use it */
                    if(nnode->prematch_offset & AFTER_PARENT)
                    {
                        llog = pmatch;
                    }
                    else
                    {
                        llog = lf->log;
                    }

                    if((cmatch = OSRegex_Execute(llog, nnode->prematch)))
                    {
                        if(*cmatch != '\0')
                            cmatch++;

                        lf->decoder_info = nnode;

                        break;
                    }
                }
                else
                {
                    cmatch = pmatch;
                    break;
                }


                /* If we have multiple regex-only childs,
                 * do not attempt to go any further with them.
                 */
                if(child_node->osdecoder->get_next)
                {
                    do
                    {
                        child_node = child_node->next;
                    }while(child_node && child_node->osdecoder->get_next);

                    if(!child_node)
                        return;

                    child_node = child_node->next;
                    nnode = NULL;
                }
                else
                {
                    child_node = child_node->next;
                    nnode = NULL;
                }
            }
        }


        /* Nothing matched */
        if(!nnode)
            return;


        /* If we have a external decoder, execute it */
        if(nnode->plugindecoder)
        {
            nnode->plugindecoder(lf);
            return;
        }


        /* Getting the regex */
        while(child_node)
        {
            if(nnode->regex)
            {
                d("regex: %s", nnode->name);
                int i = 0;

                /* With regex we have multiple options
                 * regarding the offset:
                 * after the prematch,
                 * after the parent,
                 * after some previous regex,
                 * or any offset
                 */
                if(nnode->regex_offset)
                {
                    d("Regex offset");
                    if(nnode->regex_offset & AFTER_PARENT)
                    {
                        d("after_parent");
                        llog = pmatch;
                    }
                    else if(nnode->regex_offset & AFTER_PREMATCH)
                    {
                        d("AFTER_PREMATCH");
                        llog = cmatch;
                    }
                    else if(nnode->regex_offset & AFTER_PREVREGEX)
                    {
                        d("AFTER_PREVREGEX");
                        if(!regex_prev)
                            llog = cmatch;
                        else
                            llog = regex_prev;
                    }
                }
                else
                {
                    d("No Regex offset");
                    llog = lf->log;
                }

                /* If Regex does not match, return */
                if(!(regex_prev = OSRegex_Execute(llog, nnode->regex)))
                {
                    d("Regex does not match");
                    if(nnode->get_next)
                    {
                        child_node = child_node->next;
                        nnode = child_node->osdecoder;
                        continue;
                    }
                    d("return");
                    return;
                }
                d("it matched: %s",llog);


                /* Fixing next pointer */
                if(*regex_prev != '\0')
                    regex_prev++;

                while(nnode->regex->sub_strings[i])
                {
                    d(" order sub");
                    if(nnode->order[i])
                    {
                        nnode->order[i](lf, nnode->regex->sub_strings[i]);
                        nnode->regex->sub_strings[i] = NULL;
                        i++;
                        continue;
                    }

                    /* We do not free any memory used above */
                    os_free(nnode->regex->sub_strings[i]);
                    nnode->regex->sub_strings[i] = NULL;
                    i++;
                }


                if(nnode->lua) {
                    if(decoder_run_lua(nnode, lf) && nnode->get_next) {
                        child_node = child_node->next;
                        nnode = child_node->osdecoder;
                        continue;
                    } 
                }

                /* If we have a next regex, try getting it */
                if(nnode->get_next)
                {
                    child_node = child_node->next;
                    nnode = child_node->osdecoder;
                    continue;
                }

                d("Breaking out of regex");
                break;
            }


            /* If we don't have a regex, we may leave now */
            d("No regex return");
            return;
        }

        d("nnode->name: %s", nnode->name); 
        /* ok to return  */
        d("ok to return "); 
        return;
    }while((node=node->next) != NULL);

    #ifdef TESTRULE
    if(!alert_only)
    {
        print_out("       No decoder matched.");
    }
    #endif

}


/*** Event decoders ****/
void *DstUser_FP(Eventinfo *lf, char *field)
{
    #ifdef TESTRULE
    if(!alert_only)print_out("       dstuser: '%s'", field);
    #endif

    lf->dstuser = field;
    return(NULL);
}
void *SrcUser_FP(Eventinfo *lf, char *field)
{
    #ifdef TESTRULE
    if(!alert_only)print_out("       srcuser: '%s'", field);
    #endif

    lf->srcuser = field;
    return(NULL);
}
void *SrcIP_FP(Eventinfo *lf, char *field)
{
    #ifdef TESTRULE
    if(!alert_only)print_out("       srcip: '%s'", field);
    #endif

    lf->srcip = field;
    return(NULL);
}
void *DstIP_FP(Eventinfo *lf, char *field)
{
    #ifdef TESTRULE
    if(!alert_only)print_out("       dstip: '%s'", field);
    #endif

    lf->dstip = field;
    return(NULL);
}
void *SrcPort_FP(Eventinfo *lf, char *field)
{
    #ifdef TESTRULE
    if(!alert_only)print_out("       srcport: '%s'", field);
    #endif

    lf->srcport = field;
    return(NULL);
}
void *DstPort_FP(Eventinfo *lf, char *field)
{
    #ifdef TESTRULE
    if(!alert_only)print_out("       dstport: '%s'", field);
    #endif

    lf->dstport = field;
    return(NULL);
}
void *Protocol_FP(Eventinfo *lf, char *field)
{
    #ifdef TESTRULE
    if(!alert_only)print_out("       proto: '%s'", field);
    #endif

    lf->protocol = field;
    return(NULL);
}
void *Action_FP(Eventinfo *lf, char *field)
{
    #ifdef TESTRULE
    if(!alert_only)print_out("       action: '%s'", field);
    #endif

    lf->action = field;
    return(NULL);
}
void *ID_FP(Eventinfo *lf, char *field)
{
    #ifdef TESTRULE
    if(!alert_only)print_out("       id: '%s'", field);
    #endif

    lf->id = field;
    return(NULL);
}
void *Url_FP(Eventinfo *lf, char *field)
{
    #ifdef TESTRULE
    if(!alert_only)print_out("       url: '%s'", field);
    #endif

    lf->url = field;
    return(NULL);
}
void *Data_FP(Eventinfo *lf, char *field)
{
    #ifdef TESTRULE
    if(!alert_only)print_out("       extra_data: '%s'", field);
    #endif

    lf->data = field;
    return(NULL);
}
void *Status_FP(Eventinfo *lf, char *field)
{
    #ifdef TESTRULE
    if(!alert_only)print_out("       status: '%s'", field);
    #endif

    lf->status = field;
    return(NULL);
}
void *SystemName_FP(Eventinfo *lf, char *field)
{
    #ifdef TESTRULE
    if(!alert_only)print_out("       system_name: '%s'", field);
    #endif

    lf->systemname = field;
    return(NULL);
}
void *None_FP(__attribute__((unused)) Eventinfo *lf, char *field)
{
    free(field);
    return(NULL);
}


/* EOF */
