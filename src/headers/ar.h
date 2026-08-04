/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Active Response shared headers */

#ifndef __AR_H
#define __AR_H

/* Recipient agents */
#define ALL_AGENTS      0000001
#define REMOTE_AGENT    0000002
#define SPECIFIC_AGENT  0000004
#define AS_ONLY         0000010

/* We now also support non Active Response messages in here */
#define NO_AR_MSG       0000020

#define ALL_AGENTS_C     'A'
#define REMOTE_AGENT_C   'R'
#define SPECIFIC_AGENT_C 'S'
#define NONE_C           'N'
#define NO_AR_C          '!'

/* AR Queues to use */
#define REMOTE_AR       00001
#define LOCAL_AR        00002

/* Expected values */
#define FILENAME    0000010
#define SRCIP       0000004
#define DSTIP       0000002
#define USERNAME    0000001

/**
 * Parse an active-response <expect> string into a bitmask of
 * USERNAME / SRCIP / FILENAME. Tokens may be separated by commas and/or
 * whitespace. Accepts "user" and "username" as aliases. Unknown tokens are
 * ignored. Empty / NULL → 0.
 */
int ar_parse_expect(const char *expect_str);

/**
 * Prefer dstuser, then srcuser; treat empty and "-" as absent.
 * Returns a pointer into one of the inputs, or NULL.
 */
const char *ar_pick_username(const char *dstuser, const char *srcuser);

#endif /* __AR_H */

