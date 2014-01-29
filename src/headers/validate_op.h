/* @(#) $Id: ./src/headers/validate_op.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Part of the OSSEC HIDS
 * Available at http://www.ossec.net
 */


#ifndef __VALIDATE_H

#define __VALIDATE_H

/* IP structure */
typedef struct _os_ip
{
    char *ip;
    unsigned int ip_address;
    unsigned int netmask;
}os_ip;


/* Getting the netmask based on the integer value. */
int getNetmask(unsigned int mask, char *strmask, int size);


/* Run time definitions. */
int getDefine_Int(char *high_name, char *low_name, int min, int max);



/** int OS_IPFound(char *ip_address, os_ip *that_ip)
 * Checks if ip_address is present at that_ip.
 * Returns 1 on success or 0 on failure.
 */
int OS_IPFound(char *ip_address, os_ip *that_ip);



/** int OS_IPFoundList(char *ip_address, char **list_of_ips)
 * Checks if ip_address is present on the "list_of_ips".
 * Returns 1 on success or 0 on failure.
 * The list MUST be NULL terminated
 */
int OS_IPFoundList(char *ip_address, os_ip **list_of_ips);



/** int OS_IsValidIP(char *ip)
 * Validates if an ip address is in the right
 * format.
 * Returns 0 if doesn't match or 1 if it does (or 2 if it has a cidr).
 * ** On success this function may modify the value of ip_address
 */
int OS_IsValidIP(char *ip_address, os_ip *final_ip);


/** Time range validations **/

/** char *OS_IsValidTime(char *time_str)
 * Validates if a time is in an acceptable format
 * for ossec.
 * Returns 0 if doesn't match or a valid string for
 * ossec usage in success.
 * ** On success this function may modify the value of date
 * Acceptable formats:
 * hh:mm - hh:mm (24 hour format)
 * !hh:mm -hh:mm (24 hour format)
 * hh - hh (24 hour format)
 * hh:mm am - hh:mm pm (12 hour format)
 * hh am - hh pm (12 hour format)
 */
char *OS_IsValidTime(char *time_str);

/* Same as above, but only accepts a unique time, not a range. */
char *OS_IsValidUniqueTime(char *time_str);



/** int OS_IsonTime(char *time_str, char *ossec_time)
 * Must be a valid string, called after OS_IsValidTime.
 * Returns 1 on success or 0 on failure.
 */
int OS_IsonTime(char *time_str, char *ossec_time);

/* Same as above, but checks if time is the same or has passed a specified one. */
int OS_IsAfterTime(char *time_str, char *ossec_time);



/** Day validations **/


/** int OS_IsonDay(int week_day, char *ossec_day)
 * Checks if the specified week day is in the
 * range.
 */
int OS_IsonDay(int week_day, char *ossec_day);


/** char *OS_IsValidDay(char *day_str)
 * Validates if an day is in an acceptable format
 * for ossec.
 * Returns 0 if doesn't match or a valid string for
 * ossec usage in success.
 * ** On success this function may modify the value of date
 * Acceptable formats:
 * weekdays, weekends, monday, tuesday, thursday,..
 * monday,tuesday
 * mon,tue wed
 */
char *OS_IsValidDay(char *day_str);


/* Macros */

/* Checks if the ip is a single host, not a network with a netmask */
#define isSingleHost(x) (x->netmask == 0xFFFFFFFF)

#endif

/* EOF */
