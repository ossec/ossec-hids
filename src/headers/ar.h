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

/**
 * Active-response arguments are split on spaces and later expanded by
 * shell scripts. Accept letters, digits, and the characters used by IP
 * addresses, hostnames, and account names. Reject a leading "-" so the
 * value cannot be read as a command option. Returns 1 if safe, else 0.
 */
int ar_safe_argument(const char *value);

/**
 * Build the remoted active-response header that precedes the command.
 * Layout: "<source> <FFF> " where FFF are ALL/REMOTE/SPECIFIC flags.
 *
 * For agent events (location starts with '('), only the manager-written
 * "(name) ip" prefix up to "->" is used as <source>. Text after "->" is
 * agent- or log-controlled and must not precede the flags (ANT-2026-PMMTS4QR).
 * For manager-local events, <source> is the constant "[]".
 *
 * Returns 0 on success, -1 if an agent location has no "->" separator.
 * On success, *out_hdr is a newly allocated string the caller must free.
 */
int OS_AR_FormatRemoteHdr(const char *location, char f_all, char f_remote,
                          char f_specific, char **out_hdr);

#endif /* __AR_H */

