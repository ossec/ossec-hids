/* $OpenBSD: includes.h,v 1.54 2006/07/22 20:48:23 stevesk Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * This file includes most of the needed system headers.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ifndef OPENBSD

#ifndef INCLUDES_H
#define INCLUDES_H

//#include "config.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* activate extra prototypes for glibc */
#endif

#include <sys/types.h>
#include <sys/socket.h> /* For CMSG_* */

#ifdef HAVE_LIMITS_H
# include <limits.h> /* For PATH_MAX */
#endif
#ifdef HAVE_BSTRING_H
# include <bstring.h>
#endif

#ifdef HAVE_ENDIAN_H
# include <endian.h>
#endif
#ifdef HAVE_MAILLOCK_H
# include <maillock.h> /* For _PATH_MAILDIR */
#endif
#ifdef HAVE_PATHS_H
# include <paths.h>
#endif

#ifdef HAVE_RPC_TYPES_H
# include <rpc/types.h> /* For INADDR_LOOPBACK */
#endif
#ifdef USE_PAM
#if defined(HAVE_SECURITY_PAM_APPL_H)
# include <security/pam_appl.h>
#elif defined (HAVE_PAM_PAM_APPL_H)
# include <pam/pam_appl.h>
#endif
#endif
#include <errno.h>

/* chl */
#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif
/* end of chl*/

#include <openssl/opensslv.h> /* For OPENSSL_VERSION_NUMBER */

//#include "defines.h"

//#include "openbsd-compat.h"

//#include "entropy.h"

#endif /* INCLUDES_H */
#endif //OPENBSD

