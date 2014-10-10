/* @(#) $Id: ./src/headers/debug_op.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* Part of the OSSEC HIDS
 * Available at http://www.ossec.net
 */

/* Functions to generate debug/verbose/err reports.
 * Right now, we have two debug levels: 1,2,
 * a verbose mode and a error (merror) function.
 * To see these messages, use the "-d","-v" options
 * (or "-d" twice to see debug2). The merror is printed
 * by default when an important error occur.
 * */

#ifndef __DEBUG_H

#define __DEBUG_H

#ifndef __GNUC__
#define __attribute__(x)
#endif

#include <errno.h> 

#ifdef DEV_DEBUG 
#define d(M, ...) fprintf(stderr, "DEBUG %s:%d: " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define d(M, ...) // fprintf(stderr, "DEBUG %s:%d: " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#endif

#define RED    "\e[31m"
#define GREEN  "\e[32m"
#define YELLOW "\e[33m"
#define WHITE  "\e[1m"
#define COLOR_X "\e[m"

#define clean_errno() (errno == 0 ? "None" : strerror(errno))
 
#define log_err(M, ...) fprintf(stderr, RED "[ERROR]" COLOR_X " (%s:%d:%s: errno: %s) " M "\n", __FILE__, __LINE__, __func__, clean_errno(), ##__VA_ARGS__) 
 
#define log_warn(M, ...) fprintf(stderr, YELLOW "[WARN]" COLOR_X " (%s:%d:%s: errno: %s) " M "\n", __FILE__, __LINE__, __func__, clean_errno(), ##__VA_ARGS__) 
 
#define log_info(M, ...) fprintf(stderr, WHITE "[INFO]" COLOR_X " (%s:%d:%s) " M "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__) 
 
#define check(A, M, ...) if(!(A)) { log_err(M, ##__VA_ARGS__); errno=0; goto error; } 
 
#define sentinel(M, ...)  { log_err(M, ##__VA_ARGS__); errno=0; goto error; } 
 
#define check_mem(A) check((A), "Out of memory.")
 
#define check_debug(A, M, ...) if(!(A)) { d(M, ##__VA_ARGS__); errno=0; goto error; } 

void debug1(const char *msg,...) __attribute__((format(printf, 1, 2))) __attribute__((nonnull));

void debug2(const char *msg,...) __attribute__((format(printf, 1, 2))) __attribute__((nonnull));

void merror(const char *msg,...) __attribute__((format(printf, 1, 2))) __attribute__((nonnull));

void verbose(const char *msg,...) __attribute__((format(printf, 1, 2))) __attribute__((nonnull));

void print_out(const char *msg,...) __attribute__((format(printf, 1, 2))) __attribute__((nonnull));

void log2file(const char * msg,... ) __attribute__((format(printf, 1, 2))) __attribute__((nonnull));

void ErrorExit(const char *msg,...) __attribute__((format(printf, 1, 2))) __attribute__((nonnull)) __attribute__ ((noreturn));


/* Use these three functions to set when you
 * enter in debug, chroot or daemon mode
 */
void nowDebug(void);

void nowChroot(void);

void nowDaemon(void);

int isChroot(void);

/* Debug analysisd */
#ifdef DEBUGAD
    #define DEBUG_MSG(x,y,z) verbose(x,y,z)
#else
    #define DEBUG_MSG(x,y,z)
#endif /* end debug analysisd */

#endif
