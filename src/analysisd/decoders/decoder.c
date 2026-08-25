/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "os_regex/os_regex.h"
#include "os_xml/os_xml.h"
#include "eventinfo.h"
#include "decoder.h"
#include "config.h"



/* Use the osdecoders to decode the received event */
static char **decoder_regex_substrings(OSRegex *regex)
{
    regex_matching *match = os_regex_get_thread_match();

    if (match) {
        return match->sub_strings;
    }

    return regex->sub_strings;
}

static char **decoder_pcre2_substrings(OSPcre2 *pcre2)
{
    regex_matching *match = os_regex_get_thread_match();

    if (match) {
        return match->sub_strings;
    }

    return pcre2->sub_strings;
}

void DecodeEvent(Eventinfo *lf, regex_matching *decoder_match)
{
    OSDecoderNode *node;
    OSDecoderNode *child_node;
    OSDecoderInfo *nnode;

    const char *llog = NULL;
    const char *pmatch = NULL;
    const char *cmatch = NULL;
    const char *regex_prev = NULL;
    char **capture_strings;

    os_regex_set_thread_match(decoder_match);

    node = OS_GetFirstOSDecoder(lf->program_name);

    if (!node) {
        goto out;
    }

#ifdef TESTRULE
    if (!alert_only) {
        print_out("\n**Phase 2: Completed decoding.");
    }
#endif

    do {
        nnode = node->osdecoder;

        /* First check program name */
        if (lf->program_name) {
            if (nnode->program_name) {
                if (!OSMatch_Execute(lf->program_name, lf->p_name_size,
                                     nnode->program_name)) {
                    continue;
                }
                pmatch = lf->log;
            } else if (nnode->program_name_pcre2) {
                if (!OSPcre2_Execute(lf->program_name, nnode->program_name_pcre2)) {
                    continue;
                }
                pmatch = lf->log;
            }
        }

        /* If prematch fails, go to the next osdecoder in the list */
        if (nnode->prematch) {
            if (!(pmatch = OSRegex_Execute(lf->log, nnode->prematch))) {
                continue;
            }
        }
        else if (nnode->prematch_pcre2) {
            if (!(pmatch = OSPcre2_Execute(lf->log, nnode->prematch_pcre2))) {
                continue;
            }
        }


        lf->decoder_info = nnode;
        child_node = node->child;

        /* If no child node is set, set the child node
         * as if it were the child (ugh)
         */
        if (!child_node) {
            child_node = node;
        }

        else {
            /* Check if we have any child osdecoder */
            while (child_node) {
                nnode = child_node->osdecoder;

                /* If we have a pre match and it matches, keep
                 * going. If we don't have a prematch, stop
                 * and go for the regexes.
                 */
                if (nnode->prematch) {
                    const char *llog2;

                    /* If we have an offset set, use it */
                    if (nnode->prematch_offset & AFTER_PARENT) {
                        llog2 = pmatch;
                    } else {
                        llog2 = lf->log;
                    }

                    if ((cmatch = OSRegex_Execute(llog2, nnode->prematch))) {
                        lf->decoder_info = nnode;

                        break;
                    }
                } else if (nnode->prematch_pcre2) {
                    const char *llog2;

                    /* If we have an offset set, use it */
                    if (nnode->prematch_offset & AFTER_PARENT) {
                        llog2 = pmatch;
                    } else {
                        llog2 = lf->log;
                    }

                    if ((cmatch = OSPcre2_Execute(llog2, nnode->prematch_pcre2))) {
                        lf->decoder_info = nnode;

                        break;
                    }
                } else {
                    cmatch = pmatch;
                    break;
                }

                /* If we have multiple regex-only childs,
                 * do not attempt to go any further with them.
                 */
                if (child_node->osdecoder->get_next) {
                    do {
                        child_node = child_node->next;
                    } while (child_node && child_node->osdecoder->get_next);

                    if (!child_node) {
                        goto out;
                    }

                    child_node = child_node->next;
                    nnode = NULL;
                } else {
                    child_node = child_node->next;
                    nnode = NULL;
                }
            }
        }

        /* Nothing matched */
        if (!nnode) {
            goto out;
        }

        /* If we have an external decoder, execute it */
        if (nnode->plugindecoder) {
            nnode->plugindecoder(lf);
            goto out;
        }

        /* Get the regex */
        while (child_node) {
            if (nnode->regex) {
                int i;

                /* With regex we have multiple options
                 * regarding the offset:
                 * after the prematch,
                 * after the parent,
                 * after some previous regex,
                 * or any offset
                 */
                if (nnode->regex_offset) {
                    if (nnode->regex_offset & AFTER_PARENT) {
                        llog = pmatch;
                    } else if (nnode->regex_offset & AFTER_PREMATCH) {
                        llog = cmatch;
                    } else if (nnode->regex_offset & AFTER_PREVREGEX) {
                        if (!regex_prev) {
                            llog = cmatch;
                        } else {
                            llog = regex_prev;
                        }
                    }
                } else {
                    llog = lf->log;
                }

                /* If Regex does not match, return */
                if (!(regex_prev = OSRegex_Execute(llog, nnode->regex))) {
                    if (nnode->get_next) {
                        child_node = child_node->next;
                        nnode = child_node->osdecoder;
                        continue;
                    }
                    goto out;
                }

                lf->decoder_info = nnode;

                capture_strings = decoder_regex_substrings(nnode->regex);
                for (i = 0; capture_strings && capture_strings[i]; i++) {
                    if (i >= Config.decoder_order_size) {
                        ErrorExit("%s: ERROR: Regex has too many groups.", ARGV0);
                    }

                    if (nnode->order[i])
                        nnode->order[i](lf, capture_strings[i], i);
                    else
                        /* We do not free any memory used above */
                        os_free(capture_strings[i]);

                    capture_strings[i] = NULL;
                }

                /* If we have a next regex, try getting it */
                if (nnode->get_next) {
                    child_node = child_node->next;
                    nnode = child_node->osdecoder;
                    continue;
                }

                break;
            }
            else if (nnode->pcre2) {
                int i;

                /* With regex we have multiple options
                 * regarding the offset:
                 * after the prematch,
                 * after the parent,
                 * after some previous regex,
                 * or any offset
                 */
                if (nnode->regex_offset) {
                    if (nnode->regex_offset & AFTER_PARENT) {
                        llog = pmatch;
                    } else if (nnode->regex_offset & AFTER_PREMATCH) {
                        llog = cmatch;
                    } else if (nnode->regex_offset & AFTER_PREVREGEX) {
                        if (!regex_prev) {
                            llog = cmatch;
                        } else {
                            llog = regex_prev;
                        }
                    }
                } else {
                    llog = lf->log;
                }

                /* If Regex does not match, return */
                if (!(regex_prev = OSPcre2_Execute(llog, nnode->pcre2))) {
                    if (nnode->get_next) {
                        child_node = child_node->next;
                        nnode = child_node->osdecoder;
                        continue;
                    }
                    goto out;
                }


                lf->decoder_info = nnode;

                capture_strings = decoder_pcre2_substrings(nnode->pcre2);
                for (i = 0; capture_strings && capture_strings[i]; i++) {
                    if (i >= Config.decoder_order_size) {
                        ErrorExit("%s: ERROR: Regex has too many groups.", ARGV0);
                    }

                    if (nnode->order[i])
                        nnode->order[i](lf, capture_strings[i], i);
                    else
                        /* We do not free any memory used above */
                        os_free(capture_strings[i]);

                    capture_strings[i] = NULL;
                }

                /* If we have a next regex, try getting it */
                if (nnode->get_next) {
                    child_node = child_node->next;
                    nnode = child_node->osdecoder;
                    continue;
                }

                break;
            }



            /* If we don't have a regex, we may leave now */
            goto out;
        }

        /* ok to return  */
        goto out;
    } while ((node = node->next) != NULL);

#ifdef TESTRULE
    if (!alert_only) {
        print_out("       No decoder matched.");
    }
#endif
    goto out;

out:
    os_regex_set_thread_match(NULL);
#ifdef LIBGEOIP_ENABLED
    /* Plugin decoders assign srcip/dstip directly and never hit SrcIP_FP /
     * DstIP_FP. Enrich here so rule matching and alert logs see GeoIP fields.
     * OS_GeoIP_Enrich() is a no-op when the FP path already filled them.
     */
    if (lf->srcip) {
        OS_GeoIP_Enrich(lf, 1);
    }
    if (lf->dstip) {
        OS_GeoIP_Enrich(lf, 0);
    }
#endif
#ifdef TESTRULE
    if (!alert_only && lf->decoder_info) {
        print_out("       decoder: '%s'", lf->decoder_info->name);
    }
#endif
    return;
}

/*** Event decoders ****/

void *DstUser_FP(Eventinfo *lf, char *field, __attribute__((unused)) int order)
{
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       dstuser: '%s'", field);
    }
#endif

    lf->dstuser = field;
    return (NULL);
}

void *SrcUser_FP(Eventinfo *lf, char *field, __attribute__((unused)) int order)
{
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       srcuser: '%s'", field);
    }
#endif

    lf->srcuser = field;
    return (NULL);
}

void *SrcIP_FP(Eventinfo *lf, char *field, __attribute__((unused)) int order)
{
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       srcip: '%s'", field);
    }
#endif

    lf->srcip = field;

#ifdef LIBGEOIP_ENABLED

    OS_GeoIP_Enrich(lf, 1);

    #ifdef TESTRULE
        if (!alert_only) {
            if (lf->srcgeoip)
                print_out("       srcgeoip: '%s'", lf->srcgeoip);
            if (lf->src_country)
                print_out("       src_country: '%s'", lf->src_country);
            if (lf->srcasn)
                print_out("       srcasn: '%s'", lf->srcasn);
            if (lf->srcas_org)
                print_out("       srcas_org: '%s'", lf->srcas_org);
        }
    #endif

#endif
    return (NULL);

}

void *DstIP_FP(Eventinfo *lf, char *field, __attribute__((unused)) int order)
{
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       dstip: '%s'", field);
    }
#endif

    lf->dstip = field;
#ifdef LIBGEOIP_ENABLED

    OS_GeoIP_Enrich(lf, 0);

    #ifdef TESTRULE
        if (!alert_only) {
            if (lf->dstgeoip)
                print_out("       dstgeoip: '%s'", lf->dstgeoip);
            if (lf->dst_country)
                print_out("       dst_country: '%s'", lf->dst_country);
            if (lf->dstasn)
                print_out("       dstasn: '%s'", lf->dstasn);
            if (lf->dstas_org)
                print_out("       dstas_org: '%s'", lf->dstas_org);
        }
    #endif

#endif
    return (NULL);

}

void *SrcPort_FP(Eventinfo *lf, char *field, __attribute__((unused)) int order)
{
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       srcport: '%s'", field);
    }
#endif

    lf->srcport = field;
    return (NULL);
}

void *DstPort_FP(Eventinfo *lf, char *field, __attribute__((unused)) int order)
{
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       dstport: '%s'", field);
    }
#endif

    lf->dstport = field;
    return (NULL);
}

void *Protocol_FP(Eventinfo *lf, char *field, __attribute__((unused)) int order)
{
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       proto: '%s'", field);
    }
#endif

    lf->protocol = field;
    return (NULL);
}

void *Action_FP(Eventinfo *lf, char *field, __attribute__((unused)) int order)
{
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       action: '%s'", field);
    }
#endif

    lf->action = field;
    return (NULL);
}

void *ID_FP(Eventinfo *lf, char *field, __attribute__((unused)) int order)
{
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       id: '%s'", field);
    }
#endif

    lf->id = field;
    return (NULL);
}

void *Url_FP(Eventinfo *lf, char *field, __attribute__((unused)) int order)
{
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       url: '%s'", field);
    }
#endif

    lf->url = field;
    return (NULL);
}

void *Data_FP(Eventinfo *lf, char *field, __attribute__((unused)) int order)
{
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       extra_data: '%s'", field);
    }
#endif

    lf->data = field;
    return (NULL);
}

void *Status_FP(Eventinfo *lf, char *field, __attribute__((unused)) int order)
{
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       status: '%s'", field);
    }
#endif

    lf->status = field;
    return (NULL);
}

void *SystemName_FP(Eventinfo *lf, char *field, __attribute__((unused)) int order)
{
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       system_name: '%s'", field);
    }
#endif

    lf->systemname = field;
    return (NULL);
}

void *FileName_FP(Eventinfo *lf, char *field, __attribute__((unused)) int order)
{
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       filename: '%s'", field);
    }
#endif

    lf->filename = field;
    return (NULL);
}


void *DynamicField_FP(Eventinfo *lf, char *field, int order)
{
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       %s: '%s'", lf->decoder_info->fields[order], field);
    }
#endif

    lf->fields[order] = field;

    return (NULL);
}

void *None_FP(__attribute__((unused)) Eventinfo *lf, char *field, __attribute__((unused)) int order)
{
    free(field);
    return (NULL);
}

