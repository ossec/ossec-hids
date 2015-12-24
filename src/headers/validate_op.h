/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef __VALIDATE_H
#define __VALIDATE_H

/* IP structure */
typedef struct _os_ip {
    char *ip;
    struct sockaddr_storage ss;
    unsigned int prefixlength;
}os_ip;

/* Run-time definitions */
int getDefine_Int(const char *high_name, const char *low_name, int min, int max) __attribute__((nonnull));

/* Check if IP_address is present at that_ip
 * Returns 1 on success or 0 on failure
 */
int OS_IPFound(const char *ip_address, const os_ip *that_ip) __attribute__((nonnull));

/* Check if IP_address is present in the list_of_ips
 * Returns 1 on success or 0 on failure.
 * The list MUST be NULL terminated
 */
int OS_IPFoundList(const char *ip_address, os_ip **list_of_ips) __attribute__((nonnull));

/* Validate if an IP address is in the right format
 * Returns 0 if doesn't match or 1 if it does (or 2 if it has a CIDR)
 * WARNING: On success this function may modify the value of IP_address
 */
int OS_IsValidIP(const char *ip_address, os_ip *final_ip);

/** int sacmp(struct sockaddr *sa1, struct sockaddr *sa2, int prefixlength)
 * Compares two sockaddrs up to prefixlength.
 * Returns 0 if doesn't match or 1 if they do.
 */
int sacmp(struct sockaddr *sa1, struct sockaddr *sa2, int prefixlength);

/** Time range validations **/

/* Validate if a time is in an acceptable format for OSSEC
 * Returns 0 if doesn't match or a valid string for OSSEC usage in success.
 * WARNING: On success this function may modify the value of date
 *
 * Acceptable formats:
 *      hh:mm - hh:mm (24 hour format)
 *      !hh:mm -hh:mm (24 hour format)
 *      hh - hh (24 hour format)
 *      hh:mm am - hh:mm pm (12 hour format)
 *      hh am - hh pm (12 hour format)
 */
char *OS_IsValidTime(const char *time_str);

/* Same as above, but only accepts a unique time, not a range */
char *OS_IsValidUniqueTime(const char *time_str) __attribute__((nonnull));

/* Must be a valid string, called after OS_IsValidTime
 * Returns 1 on success or 0 on failure
 */
int OS_IsonTime(const char *time_str, const char *ossec_time) __attribute__((nonnull));

/* Same as above, but checks if time is the same or has passed a specified one */
int OS_IsAfterTime(const char *time_str, const char *ossec_time) __attribute__((nonnull));

/** Day validations **/

/* Check if the specified week day is in the range */
int OS_IsonDay(int week_day, const char *ossec_day) __attribute__((nonnull));

/* Validate if a day is in an acceptable format for OSSEC
 * Returns 0 if doesn't match or a valid string for ossec usage in success
 * WARNING: On success this function may modify the value of date
 *
 * Acceptable formats:
 *      weekdays, weekends, monday, tuesday, thursday,..
 *      monday,tuesday
 *      mon,tue wed
 */
char *OS_IsValidDay(const char *day_str);

/* Macros */

/* Check if the IP is a single host, not a network with a netmask */
#define isSingleHost(x) ((x->ss.ss_family == AF_INET) ? (x->prefixlength == 32) : (x->prefixlength == 128))

#endif

