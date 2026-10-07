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
#include <string.h>

#include "shared.h"

#undef ARGV0
#define ARGV0 "ossec-regex"

/*
 * Flags analysisd passes to OSPcre2_Compile for <pcre2> and <match_pcre2>.
 * OS_Pcre2() also sets PCRE2_UTF and PCRE2_NO_UTF_CHECK; that result is
 * printed separately so the two calls can be compared.
 */
#define OSSEC_REGEX_PCRE2_FLAGS PCRE2_CASELESS

/* Prototypes */
static void helpmsg(int status) __attribute__((noreturn));
static void chomp_line(char *msg);
static void print_pcre2_compile_error(const char *pattern);
static int run_ossec(const char *pattern);
static int run_pcre2(const char *pattern);


static void helpmsg(int status)
{
    printf("\n"
           "OSSEC HIDS %s: ossec-regex [-hp] [--] <pattern>\n"
           "  Reads lines from stdin and prints matches.\n"
           "  -h, --help   Show this help.\n"
           "  -p, --pcre2  Match <pattern> as PCRE2, with the same flags as a\n"
           "               <pcre2> rule (caseless, no OSSEC syntax translation).\n"
           "  Without -p, <pattern> is OSSEC regex and match syntax.\n"
           "\n",
           ARGV0);
    exit(status);
}

static void chomp_line(char *msg)
{
    size_t len = strlen(msg);

    if (len > 0 && msg[len - 1] == '\n') {
        msg[len - 1] = '\0';
    }
}

static void print_pcre2_compile_error(const char *pattern)
{
    int error = 0;
    PCRE2_SIZE erroroffset = 0;
    PCRE2_UCHAR errbuf[256];
    pcre2_code *re;

    re = pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED,
                       OSSEC_REGEX_PCRE2_FLAGS, &error, &erroroffset, NULL);
    if (re != NULL) {
        pcre2_code_free(re);
        printf("pattern does not compile with OSPcre2_Compile\n");
        return;
    }

    pcre2_get_error_message(error, errbuf, sizeof(errbuf));
    printf("pattern does not compile with OSPcre2_Compile: %s at offset %zu\n",
           (char *)errbuf, (size_t)erroroffset);
}

static int run_ossec(const char *pattern)
{
    char msg[OS_MAXSTR + 1];
    OSRegex regex;
    OSMatch matcher;

    memset(msg, '\0', OS_MAXSTR + 1);

    if (!OSRegex_Compile(pattern, &regex, 0)) {
        printf("pattern does not compile with OSRegex_Compile\n");
        return (-1);
    }
    if (!OSMatch_Compile(pattern, &matcher, 0)) {
        printf("pattern does not compile with OSMatch_Compile\n");
        OSRegex_FreePattern(&regex);
        return (-1);
    }

    while ((fgets(msg, OS_MAXSTR, stdin)) != NULL) {
        chomp_line(msg);

        /* Make sure we ignore blank lines */
        if (strlen(msg) < 2) {
            continue;
        }

        if (OSRegex_Execute(msg, &regex)) {
            printf("+OSRegex_Execute: %s\n", msg);
        }

        if (OS_Regex(pattern, msg)) {
            printf("+OS_Regex       : %s\n", msg);
        }

        if (OSMatch_Execute(msg, strlen(msg), &matcher)) {
            printf("+OSMatch_Compile: %s\n", msg);
        }

        if (OS_Match2(pattern, msg)) {
            printf("+OS_Match2      : %s\n", msg);
        }
    }

    OSRegex_FreePattern(&regex);
    OSMatch_FreePattern(&matcher);
    return (0);
}

static int run_pcre2(const char *pattern)
{
    char msg[OS_MAXSTR + 1];
    OSPcre2 regex;
    int i;

    memset(msg, '\0', OS_MAXSTR + 1);

    if (!OSPcre2_Compile(pattern, &regex, OSSEC_REGEX_PCRE2_FLAGS)) {
        print_pcre2_compile_error(pattern);
        return (-1);
    }

    while ((fgets(msg, OS_MAXSTR, stdin)) != NULL) {
        chomp_line(msg);

        /* Make sure we ignore blank lines */
        if (strlen(msg) < 2) {
            continue;
        }

        if (OSPcre2_Execute(msg, &regex)) {
            printf("+OSPcre2_Execute: %s\n", msg);
            if (regex.sub_strings) {
                for (i = 0; regex.sub_strings[i]; i++) {
                    printf(" -Substring: %s\n", regex.sub_strings[i]);
                }
            }
            OSPcre2_FreeSubStrings(&regex);
        }

        if (OS_Pcre2(pattern, msg)) {
            printf("+OS_Pcre2       : %s\n", msg);
        }
    }

    OSPcre2_FreePattern(&regex);
    return (0);
}

int main(int argc, char **argv)
{
    int opt;
    int pcre2_mode = 0;
    const char *pattern;
    static const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"pcre2", no_argument, NULL, 'p'},
        {NULL, 0, NULL, 0},
    };

    OS_SetName(ARGV0);

    while ((opt = getopt_long(argc, argv, "hp", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                helpmsg(0);
            case 'p':
                pcre2_mode = 1;
                break;
            default:
                helpmsg(1);
        }
    }

    if (argc - optind != 1) {
        helpmsg(1);
    }

    pattern = argv[optind];
    if (pcre2_mode) {
        return run_pcre2(pattern);
    }
    return run_ossec(pattern);
}
