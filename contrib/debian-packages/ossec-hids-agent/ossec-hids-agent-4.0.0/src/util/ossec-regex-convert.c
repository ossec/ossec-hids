/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "shared.h"

#undef ARGV0
#define ARGV0 "ossec-regex-convert"

typedef struct _OSConvertionMap {
    const char *old_element;
    const char *new_element;
    int map;
} OSConvertionMap;

/* Prototypes */
void helpmsg(void);
void list_tags(void);

/* Global variables */
const OSConvertionMap conv_map[] = {
    {.old_element = "regex", .new_element = "pcre2", .map = OS_CONVERT_REGEX},
    {.old_element = "match", .new_element = "match_pcre2", .map = OS_CONVERT_MATCH},
    {.old_element = "program_name", .new_element = "program_name_pcre2", .map = OS_CONVERT_MATCH},
    {.old_element = "prematch", .new_element = "prematch_pcre2", .map = OS_CONVERT_REGEX},
    {.old_element = "srcgeoip", .new_element = "srcgeoip_pcre2", .map = OS_CONVERT_MATCH},
    {.old_element = "dstgeoip", .new_element = "dstgeoip_pcre2", .map = OS_CONVERT_MATCH},
    {.old_element = "srcport", .new_element = "srcport_pcre2", .map = OS_CONVERT_MATCH},
    {.old_element = "dstport", .new_element = "dstport_pcre2", .map = OS_CONVERT_MATCH},
    {.old_element = "user", .new_element = "user_pcre2", .map = OS_CONVERT_MATCH},
    {.old_element = "url", .new_element = "url_pcre2", .map = OS_CONVERT_MATCH},
    {.old_element = "id", .new_element = "id_pcre2", .map = OS_CONVERT_MATCH},
    {.old_element = "status", .new_element = "status_pcre2", .map = OS_CONVERT_MATCH},
    {.old_element = "hostname", .new_element = "hostname_pcre2", .map = OS_CONVERT_MATCH},
    {.old_element = "extra_data", .new_element = "extra_data_pcre2", .map = OS_CONVERT_MATCH},
};
const struct option getopt_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"batch", no_argument, NULL, 'b'},
    {"regex", no_argument, NULL, 'r'},
    {"match", no_argument, NULL, 'm'},
    {"tags", no_argument, NULL, 't'},
    {NULL, 0, NULL, 0},
};

int main(int argc, char *const argv[])
{
    char *converted_pattern = NULL;
    const OSConvertionMap *m = NULL;
    int batch_mode = 0;
    int regex_to_pcre2 = 1;
    int match_to_pcre2 = 1;
    int opt;
    int i;
    const char *pattern = NULL;
    const char *type = NULL;
    size_t idx;

    OS_SetName(ARGV0);

    while ((opt = getopt_long(argc, argv, "hbrmt", getopt_options, NULL)) != EOF) {
        switch (opt) {
            case 'h':
                helpmsg();
                return (EXIT_SUCCESS);
            case 'b':
                batch_mode = 1;
                break;
            case 'r':
                regex_to_pcre2 = 1;
                match_to_pcre2 = 0;
                break;
            case 'm':
                regex_to_pcre2 = 0;
                match_to_pcre2 = 1;
                break;
            case 't':
                list_tags();
                return (EXIT_SUCCESS);
            default:
                helpmsg();
                return (EXIT_FAILURE);
        }
    }
    argc -= optind;
    argv += optind;

    /* User arguments */
    if (argc < 1) {
        helpmsg();
        return (EXIT_FAILURE);
    }

    if (batch_mode) {
        for (i = 0; i < argc; i += 2) {
            type = argv[i];
            pattern = argv[i + 1];
            m = NULL;
            for (idx = 0; idx < sizeof(conv_map) / sizeof(OSConvertionMap); idx++) {
                m = &conv_map[idx];
                if (strcmp(m->old_element, type) == 0) {
                    break;
                }
            }
            if (!m) {
                fprintf(stderr, "Invalid type \"%s\"\n", type);
                goto fail;
            }
            if (OSRegex_Convert(pattern, &converted_pattern, m->map)) {
                printf("%s %s\n", m->new_element, converted_pattern);
                free(converted_pattern);
            } else {
                goto fail;
            }
        }
    } else {
        for (i = 0; i < argc; i++) {
            pattern = argv[i];
            if (i > 0) {
                printf("\n");
            }
            printf("pattern = %s\n", pattern);
            if (regex_to_pcre2) {
                OSRegex_Convert(pattern, &converted_pattern, OS_CONVERT_REGEX);
                printf("regex   = %s\n", converted_pattern);
                if (converted_pattern) {
                    free(converted_pattern);
                }
            }
            if (match_to_pcre2) {
                OSRegex_Convert(pattern, &converted_pattern, OS_CONVERT_MATCH);
                printf("match   = %s\n", converted_pattern);
                if (converted_pattern) {
                    free(converted_pattern);
                }
            }
        }
    }

    return (EXIT_SUCCESS);

fail:
    if (converted_pattern) {
        free(converted_pattern);
    }

    return (EXIT_FAILURE);
}

void list_tags(void)
{
    size_t idx;

    for (idx = 0; idx < sizeof(conv_map) / sizeof(OSConvertionMap); idx++) {
        printf("%s\n", conv_map[idx].old_element);
    }
}

void helpmsg(void)
{
    printf("\n"
           "OSSEC HIDS %s: ossec-regex-convert -h\n"
           "OSSEC HIDS %s: ossec-regex-convert -t\n"
           "OSSEC HIDS %s: ossec-regex-convert [-mr] PATTERN [PATTERN...]\n"
           "OSSEC HIDS %s: ossec-regex-convert -b TAG PATTERN [TAG PATTERN...]\n"
           "    -h, --help  : displays this message and exits.\n"
           "    -b, --batch : runs in batch mode.\n"
           "    -r, --regex : only convert patterns from OSRegex to PCRE2 (default is both).\n"
           "    -m, --match : only convert patterns from OSMatch to PCRE2 (default is both).\n"
           "    -t, --tags  : list XML tags that can be converted.\n"
           "    PATTERN     : pattern to convert.\n"
           "    TAG         : a valid XML tag (list available with -t,--tags).\n",
           ARGV0, ARGV0, ARGV0, ARGV0);
}
