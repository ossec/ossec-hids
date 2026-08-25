/* Copyright (C) 2026 Atomicorp LLC
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Connect / send / reconnect helpers for syslog_output (UDP, TCP, TLS).
 */

#include "shared.h"
#include "csyslogd.h"
#include "csyslog_tls.h"
#include "os_net/os_net.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>

#ifndef CSYSLOG_SNDTIMEO_SEC
#define CSYSLOG_SNDTIMEO_SEC 10
#endif

#ifndef CSYSLOG_CONNECT_TIMEOUT_SEC
#define CSYSLOG_CONNECT_TIMEOUT_SEC CSYSLOG_SNDTIMEO_SEC
#endif

static void csyslog_set_tcp_opts(int sock)
{
    int on = 1;
    struct timeval tv;

    if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) < 0) {
        merror("%s: WARN: Unable to set SO_KEEPALIVE on syslog_output socket: %s",
               ARGV0, strerror(errno));
    }

    tv.tv_sec = CSYSLOG_SNDTIMEO_SEC;
    tv.tv_usec = 0;
    /* Bound both directions: TLS handshake reads and TCP/TLS writes. */
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        merror("%s: WARN: Unable to set SO_SNDTIMEO on syslog_output socket: %s",
               ARGV0, strerror(errno));
    }
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        merror("%s: WARN: Unable to set SO_RCVTIMEO on syslog_output socket: %s",
               ARGV0, strerror(errno));
    }
}

/* Non-blocking TCP connect with a hard deadline so a blackholed SIEM does
 * not stall the single-threaded csyslogd loop during SYN retries.
 */
static int csyslog_connect_tcp(const char *port, const char *server)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *rp;
    int sock = -1;
    int s;
    int flags;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    s = getaddrinfo(server, port, &hints, &result);
    if (s != 0) {
        hints.ai_family = AF_INET;
        s = getaddrinfo(server, port, &hints, &result);
    }
    if (s != 0 || !result) {
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        int rv;
        struct pollfd pfd;
        int soerr = 0;
        socklen_t soerr_len = sizeof(soerr);

        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) {
            continue;
        }

        flags = fcntl(sock, F_GETFL, 0);
        if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
            close(sock);
            sock = -1;
            continue;
        }

        rv = connect(sock, rp->ai_addr, rp->ai_addrlen);
        if (rv != 0) {
            if (errno != EINPROGRESS) {
                close(sock);
                sock = -1;
                continue;
            }

            pfd.fd = sock;
            pfd.events = POLLOUT;
            pfd.revents = 0;
            rv = poll(&pfd, 1, CSYSLOG_CONNECT_TIMEOUT_SEC * 1000);
            if (rv <= 0) {
                close(sock);
                sock = -1;
                continue;
            }
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &soerr, &soerr_len) < 0 ||
                    soerr != 0) {
                close(sock);
                sock = -1;
                continue;
            }
        }

        /* Back to blocking for SSL_connect / send with SO_*TIMEO. */
        flags = fcntl(sock, F_GETFL, 0);
        if (flags >= 0) {
            fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
        }
        break;
    }

    freeaddrinfo(result);

    if (sock < 0) {
        return -1;
    }

    csyslog_set_tcp_opts(sock);
    return sock;
}

/* TCP can return short writes; loop until complete or error. */
static int csyslog_send_tcp(int sock, const char *buf, size_t len)
{
    size_t off = 0;

    while (off < len) {
        ssize_t n = send(sock, buf + off, len - off, 0);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        off += (size_t)n;
    }

    return 0;
}

void csyslog_close(SyslogConfig *cfg)
{
    if (!cfg) {
        return;
    }

#ifdef LIBOPENSSL_ENABLED
    if (cfg->ssl) {
        SSL *ssl = (SSL *)cfg->ssl;
        csyslog_tls_close(&ssl);
        cfg->ssl = NULL;
    }
    /* Keep ssl_ctx across reconnects; freed only on shutdown if ever needed. */
#endif

    if (cfg->socket >= 0) {
        OS_CloseSocket(cfg->socket);
        cfg->socket = -1;
    }
}

int csyslog_connect(SyslogConfig *cfg)
{
    int sock;

    if (!cfg || !cfg->server || !cfg->port) {
        return -1;
    }

    csyslog_close(cfg);

    if (cfg->protocol == CSYSLOG_TCP) {
        /* Load CA / build SSL_CTX before connect (and before chroot) so a
         * failed first connect still leaves a usable ctx for post-chroot
         * reconnects. */
        if (cfg->tls) {
#ifdef LIBOPENSSL_ENABLED
            if (!cfg->ssl_ctx) {
                cfg->ssl_ctx = csyslog_tls_ctx_create((int)cfg->tls_verify,
                                                     cfg->tls_ca);
                if (!cfg->ssl_ctx) {
                    return -1;
                }
            }
#else
            merror("%s: ERROR: syslog_output tls requested but OpenSSL is not enabled.",
                   ARGV0);
            return -1;
#endif
        }

        sock = csyslog_connect_tcp(cfg->port, cfg->server);
        if (sock < 0) {
            return -1;
        }
        cfg->socket = sock;

        if (cfg->tls) {
#ifdef LIBOPENSSL_ENABLED
            SSL *ssl = csyslog_tls_connect((SSL_CTX *)cfg->ssl_ctx, sock,
                                           cfg->server, (int)cfg->tls_verify);
            if (!ssl) {
                csyslog_close(cfg);
                return -1;
            }
            cfg->ssl = ssl;
#endif
        }
    } else {
        sock = OS_ConnectUDP(cfg->port, cfg->server);
        if (sock < 0) {
            return -1;
        }
        cfg->socket = sock;
    }

    return 0;
}

/* Send one framed alert. TCP/TLS append a trailing newline (RFC 6587).
 * Embedded CR/LF in the payload are flattened so one alert stays one frame.
 * On failure, reconnect once and retry. Returns 0 on success, -1 on failure.
 */
int csyslog_send(SyslogConfig *cfg, const char *msg, size_t len)
{
    char framed[OS_CSYSLOG_MAX + 2];
    const char *out;
    size_t out_len;
    int attempt;

    if (!cfg || !msg) {
        return -1;
    }

    if (cfg->protocol == CSYSLOG_TCP) {
        size_t i;

        if (len >= OS_CSYSLOG_MAX) {
            merror("%s: WARN: syslog_output TCP message truncated from %zu to %d bytes.",
                   ARGV0, len, OS_CSYSLOG_MAX - 1);
            len = OS_CSYSLOG_MAX - 1;
        }
        memcpy(framed, msg, len);
        for (i = 0; i < len; i++) {
            if (framed[i] == '\n' || framed[i] == '\r') {
                framed[i] = ' ';
            }
        }
        framed[len] = '\n';
        framed[len + 1] = '\0';
        out = framed;
        out_len = len + 1;
    } else {
        out = msg;
        out_len = len;
    }

    for (attempt = 0; attempt < 2; attempt++) {
        if (cfg->socket < 0) {
            if (csyslog_connect(cfg) < 0) {
                merror("%s: ERROR: Unable to connect syslog_output to '%s:%s'.",
                       ARGV0, cfg->server, cfg->port);
                continue;
            }
        }

        if (cfg->protocol == CSYSLOG_UDP) {
            if (OS_SendUDPbySize(cfg->socket, (int)out_len, out) == 0) {
                return 0;
            }
        } else if (cfg->tls) {
#ifdef LIBOPENSSL_ENABLED
            if (cfg->ssl &&
                    csyslog_tls_write((SSL *)cfg->ssl, out, out_len) == 0) {
                return 0;
            }
#else
            merror("%s: ERROR: syslog_output tls send without OpenSSL.", ARGV0);
#endif
        } else {
            if (csyslog_send_tcp(cfg->socket, out, out_len) == 0) {
                return 0;
            }
        }

        merror("%s: WARN: syslog_output send to '%s:%s' failed; reconnecting.",
               ARGV0, cfg->server, cfg->port);
        csyslog_close(cfg);
    }

    return -1;
}
