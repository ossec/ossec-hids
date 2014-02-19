/* @(#) $Id: ./src/os_crypto/sha1/sha1_op.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <stdio.h>
#include <string.h>
#include "sha1_op.h"

/* Openssl sha1
 * Only use if open ssl is not available.
#ifndef USE_OPENSSL
#include "sha.h"
#include "sha_locl.h"
#else
#include <openssl/sha.h>
#endif
*/

#include "sha_locl.h"
#include "../shared/prefilter.h"


int OS_SHA1_Stream(FILE *fp, char * output)
{
    SHA_CTX c;
    unsigned char buf[2048 +2];
    unsigned char md[SHA_DIGEST_LENGTH];
    int n;

    memset(output,0, 65);
    buf[2049] = '\0';

    SHA1_Init(&c);
    while((n = fread(buf, 1, 2048, fp)) > 0)
    {
        buf[n] = '\0';
        SHA1_Update(&c,buf,(unsigned long)n);
    }

    SHA1_Final(&(md[0]),&c);

    for (n=0; n<SHA_DIGEST_LENGTH; n++)
    {
        snprintf(output, 3, "%02x", md[n]);
        output+=2;
    }

    return(0);
}

int OS_SHA1_File_Prefilter(char * fname, char *prefilter_cmd, char * output)
{
    FILE *fp;
 
    fp = prefilter(fname, prefilter_cmd);
    if(!fp)
        return(-1);

    OS_SHA1_Stream(fp, output);

    /* Closing it */
    prefilter_close(fp, prefilter_cmd);

    return(0);
}

int OS_SHA1_File(char * fname, char * output)
{
    FILE *fp;
 
    fp = fopen(fname, "r");
    if(!fp)
        return(-1);

    OS_SHA1_Stream(fp, output);

    /* Closing it */
    fclose(fp);

    return(0);
}


/* EOF */
