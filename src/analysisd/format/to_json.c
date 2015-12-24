/* Copyright (C) 2015 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "to_json.h"

#include "shared.h"
#include "rules.h"
#include "cJSON.h"


/* Convert Eventinfo to json */
char *Eventinfo_to_jsonstr(const Eventinfo *lf)
{
    cJSON *root;
    cJSON *rule;
    cJSON *file_diff;
    char *out;

    root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "rule", rule = cJSON_CreateObject());

    cJSON_AddNumberToObject(rule, "level", lf->generated_rule->level);

    if (lf->generated_rule->comment) {
        cJSON_AddStringToObject(rule, "comment", lf->generated_rule->comment);
    }
    if (lf->generated_rule->sigid) {
        cJSON_AddNumberToObject(rule, "sidid", lf->generated_rule->sigid);
    }
    if (lf->generated_rule->cve) {
        cJSON_AddStringToObject(rule, "cve", lf->generated_rule->cve);
    }
    if (lf->generated_rule->info) {
        cJSON_AddStringToObject(rule, "info", lf->generated_rule->info);
    }


    if (lf->action) {
        cJSON_AddStringToObject(root, "action", lf->action);
    }
    if (lf->srcip) {
        cJSON_AddStringToObject(root, "srcip", lf->srcip);
    }
    if (lf->srcport) {
        cJSON_AddStringToObject(root, "srcport", lf->srcport);
    }
    if (lf->srcuser) {
        cJSON_AddStringToObject(root, "srcuser", lf->srcuser);
    }
    if (lf->dstip) {
        cJSON_AddStringToObject(root, "dstip", lf->dstip);
    }
    if (lf->dstport) {
        cJSON_AddStringToObject(root, "dstport", lf->dstport);
    }
    if (lf->dstuser) {
        cJSON_AddStringToObject(root, "dstuser", lf->dstuser);
    }
    if (lf->location) {
        cJSON_AddStringToObject(root, "location", lf->location);
    }
    if (lf->full_log) {
        cJSON_AddStringToObject(root, "full_log", lf->full_log);
    }
    if (lf->filename) {
        cJSON_AddItemToObject(root, "file", file_diff = cJSON_CreateObject());

        cJSON_AddStringToObject(file_diff, "path", lf->filename);

        if (lf->md5_before && lf->md5_after && strcmp(lf->md5_before, lf->md5_after) != 0  ) {
            cJSON_AddStringToObject(file_diff, "md5_before", lf->md5_before);
            cJSON_AddStringToObject(file_diff, "md5_after", lf->md5_after);
        }
        if (lf->sha1_before && lf->sha1_after && !strcmp(lf->sha1_before, lf->sha1_after) != 0) {
            cJSON_AddStringToObject(file_diff, "sha1_before", lf->sha1_before);
            cJSON_AddStringToObject(file_diff, "sha1_after", lf->sha1_after);
        }
        if (lf->owner_before && lf->owner_after && !strcmp(lf->owner_before, lf->owner_after) != 0) {
            cJSON_AddStringToObject(file_diff, "owner_before", lf->owner_before);
            cJSON_AddStringToObject(file_diff, "owner_after", lf->owner_after);
        }
        if (lf->gowner_before && lf->gowner_after && !strcmp(lf->gowner_before, lf->gowner_after) != 0 ) {
            cJSON_AddStringToObject(file_diff, "gowner_before", lf->gowner_before);
            cJSON_AddStringToObject(file_diff, "gowner_after", lf->gowner_after);
        }
        if (lf->perm_before && lf->perm_after && lf->perm_before != lf->perm_after) {
            cJSON_AddNumberToObject(file_diff, "perm_before", lf->perm_before);
            cJSON_AddNumberToObject(file_diff, "perm_after", lf->perm_after);
        }
    }
    out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return out;
}

