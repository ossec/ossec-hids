/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_net/os_net.h"
#include "remoted.h"

#include <errno.h>
#include <netinet/tcp.h>

#define SYSLOG_TCP_READ_TIMEOUT_DEFAULT 30
/* Keepalive probes sent to a client that stayed quiet for one read timeout */
#define SYSLOG_TCP_KEEPALIVE_INTERVAL 10
#define SYSLOG_TCP_KEEPALIVE_PROBES 3

typedef struct syslog_client_arg {
    remoted_listener *listener;
    int client_socket;
    char srcip[IPSIZE + 1];
} syslog_client_arg;

static void syslog_set_client_timeout(int sock, int sec)
{
    struct timeval tv;

    tv.tv_sec = sec;
    tv.tv_usec = 0;
    (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

/* Probe a quiet client so one that vanished without FIN/RST releases its
 * worker: recv() then fails with ECONNRESET or ETIMEDOUT. */
static void syslog_set_client_keepalive(int sock, int idle_sec)
{
    int on = 1;

    (void)setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
    {
        int interval = SYSLOG_TCP_KEEPALIVE_INTERVAL;
        int probes = SYSLOG_TCP_KEEPALIVE_PROBES;

#if defined(TCP_KEEPIDLE)
        (void)setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &idle_sec, sizeof(idle_sec));
#elif defined(__APPLE__) && defined(TCP_KEEPALIVE)
        /* macOS: seconds idle before the first keepalive probe. Do not use
         * TCP_KEEPALIVE on other platforms (e.g. older Solaris: milliseconds). */
        (void)setsockopt(sock, IPPROTO_TCP, TCP_KEEPALIVE, &idle_sec, sizeof(idle_sec));
#else
        (void)idle_sec;
#endif
#if defined(TCP_KEEPINTVL)
        (void)setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
#else
        (void)interval;
#endif
#if defined(TCP_KEEPCNT)
        (void)setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &probes, sizeof(probes));
#else
        (void)probes;
#endif
    }
}

/* Returns the byte count, 0 when the peer closed the connection, or -1 with
 * errno set (EAGAIN on read timeout). */
static int syslog_recv_buffer(int sock, char *buffer, int sizet)
{
    int retsize;

    if ((retsize = recv(sock, buffer, sizet - 1, 0)) > 0) {
        buffer[retsize] = '\0';
    }
    return (retsize);
}

/* Checks if an IP is not allowed */
static int OS_IPNotAllowed(char *srcip)
{
    if (logr.denyips != NULL) {
        if (OS_IPFoundList(srcip, logr.denyips)) {
            return (1);
        }
    }
    if (logr.allowips != NULL) {
        if (OS_IPFoundList(srcip, logr.allowips)) {
            return (0);
        }
    }

    /* If the IP is not allowed, it will be denied */
    return (1);
}

static void syslog_client_drop_pending(void *arg)
{
    syslog_client_arg *client = (syslog_client_arg *)arg;

    if (!client) {
        return;
    }

    if (client->client_socket >= 0) {
        close(client->client_socket);
    }
    free(client);
}

/* Handle each client connection in a worker thread */
static void *syslog_client_worker(void *arg)
{
    syslog_client_arg *client = (syslog_client_arg *)arg;
    remoted_listener *listener = client->listener;
    int client_socket = client->client_socket;
    char srcip[IPSIZE + 1];
    int sb_size = OS_MAXSTR;
    int r_sz = 0;

    char buffer[OS_MAXSTR + 2];
    char storage_buffer[OS_MAXSTR + 2];
    char tmp_buffer[OS_MAXSTR + 2];

    char *buffer_pt = NULL;

    strncpy(srcip, client->srcip, IPSIZE);
    srcip[IPSIZE] = '\0';
    free(client);

    os_block_worker_signals();

    memset(buffer, '\0', OS_MAXSTR + 2);
    memset(storage_buffer, '\0', OS_MAXSTR + 2);
    memset(tmp_buffer, '\0', OS_MAXSTR + 2);

    while (1) {
        if (remoted_shutting_down) {
            close(client_socket);
            return NULL;
        }

        if ((r_sz = syslog_recv_buffer(client_socket, buffer, OS_MAXSTR - 2)) <= 0) {
            if (remoted_shutting_down) {
                close(client_socket);
                return NULL;
            }
            /* Read timeout (ETIMEDOUT is not one: the keepalive probes went
             * unanswered). A quiet client keeps its worker while nobody is
             * waiting for one; claim at most one idle drop per queued client
             * so a shared timeout wave cannot herd-close every forwarder. */
            {
                int drop = 0;

                if (r_sz < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    drop = thread_pool_should_drop_idle(listener->syslog_tcp_pool);
                }
                if (!syslog_tcp_should_close_on_recv(r_sz, errno, drop)) {
                    continue;
                }
                if (drop) {
                    merror("%s: WARN: Syslog TCP worker pool exhausted, closing idle connection from %s",
                           ARGV0, srcip);
                }
            }
            close(client_socket);
            return NULL;
        }

        buffer_pt = strchr(buffer, '\n');
        if (!buffer_pt) {
            if ((sb_size - r_sz) <= 2) {
                merror("%s: Full buffer receiving from: '%s'", ARGV0, srcip);
                sb_size = OS_MAXSTR;
                storage_buffer[0] = '\0';
                continue;
            }

            strncat(storage_buffer, buffer, sb_size);
            sb_size -= r_sz;
            continue;
        }

        if (*(buffer_pt + 1) != '\0') {
            *buffer_pt = '\0';
            buffer_pt++;
            strncpy(tmp_buffer, buffer_pt, OS_MAXSTR);
        }

        if ((sb_size - r_sz) <= 2) {
            merror("%s: Full buffer receiving from: '%s'.", ARGV0, srcip);
            sb_size = OS_MAXSTR;
            storage_buffer[0] = '\0';
            tmp_buffer[0] = '\0';
            continue;
        }

        strncat(storage_buffer, buffer, sb_size);

        buffer_pt = strchr(storage_buffer, '\r');
        if (buffer_pt) {
            *buffer_pt = '\0';
        }

        if (storage_buffer[0] == '<') {
            buffer_pt = strchr(storage_buffer + 1, '>');
            if (buffer_pt) {
                buffer_pt++;
            } else {
                buffer_pt = storage_buffer;
            }
        } else {
            buffer_pt = storage_buffer;
        }

        if (remoted_send_syslog_msg(listener, buffer_pt, srcip) < 0) {
            close(client_socket);
            return NULL;
        }

        if (tmp_buffer[0] != '\0') {
            strncpy(storage_buffer, tmp_buffer, OS_MAXSTR);
            sb_size = OS_MAXSTR - (strlen(storage_buffer) + 1);
            tmp_buffer[0] = '\0';
        } else {
            storage_buffer[0] = '\0';
            sb_size = OS_MAXSTR;
        }
    }
}

/* Handle syslog TCP connections */
void HandleSyslogTCP()
{
    char srcip[IPSIZE + 1];
    fd_set fdsave, fdwork;
    int fdmax;
    int sock;

    memset(srcip, '\0', IPSIZE + 1);

    fdsave = remoted_self->netinfo->fdset;
    fdmax  = remoted_self->netinfo->fdmax;

    if ((remoted_self->m_queue = StartMQ(DEFAULTQUEUE, WRITE)) < 0) {
        ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQUEUE);
    }

    int tcp_read_timeout;

    {
        int worker_pool = getDefine_Int("remoted", "syslog_tcp_worker_pool", 1, 64);
        int max_tasks = getDefine_Int("remoted", "syslog_tcp_max_tasks", 1, 1024);

        remoted_self->syslog_tcp_pool =
            thread_pool_create_limited(worker_pool, max_tasks);
        if (!remoted_self->syslog_tcp_pool) {
            ErrorExit(THREAD_ERROR, ARGV0);
        }
        thread_pool_set_drop_fn(remoted_self->syslog_tcp_pool,
                                syslog_client_drop_pending);
    }

    tcp_read_timeout = getDefine_Int("remoted", "syslog_tcp_read_timeout", 1, 3600);
    if (tcp_read_timeout <= 0) {
        tcp_read_timeout = SYSLOG_TCP_READ_TIMEOUT_DEFAULT;
    }
    if (tcp_read_timeout > REMOTED_SHUTDOWN_POOL_TIMEOUT) {
        tcp_read_timeout = REMOTED_SHUTDOWN_POOL_TIMEOUT;
    }

    while (1) {
        if (remoted_shutting_down) {
            return;
        }

        fdwork = fdsave;
        if (select (fdmax, &fdwork, NULL, NULL, NULL) < 0) {
            if (remoted_shutting_down) {
                return;
            }
            if (errno == EINTR) {
                continue;
            }
            if (errno == EBADF) {
                return;
            }
            merror("%s: ERROR: syslogtcp select() failed: %s", ARGV0, strerror(errno));
            sleep(1);
            continue;
        }

        for (sock = 0; sock <= fdmax; sock++) {
            if (FD_ISSET (sock, &fdwork)) {
                syslog_client_arg *client;
                int client_socket = OS_AcceptTCP(sock, srcip, IPSIZE);

                if (client_socket < 0) {
                    merror("%s: WARN: Accepting tcp connection from client failed.", ARGV0);
                    continue;
                }

                if (OS_IPNotAllowed(srcip)) {
                    if (remoted_log_reject()) {
                        merror(DENYIP_WARN, ARGV0, srcip);
                    }
                    close(client_socket);
                    continue;
                }

                syslog_set_client_timeout(client_socket, tcp_read_timeout);
                syslog_set_client_keepalive(client_socket, tcp_read_timeout);

                os_calloc(1, sizeof(syslog_client_arg), client);
                client->listener = remoted_self;
                client->client_socket = client_socket;
                strncpy(client->srcip, srcip, IPSIZE);
                client->srcip[IPSIZE] = '\0';

                if (thread_pool_try_submit(remoted_self->syslog_tcp_pool,
                                       syslog_client_worker, client) != 0) {
                    free(client);
                    close(client_socket);
                    merror("%s: WARN: Syslog TCP worker pool full, dropping connection from %s",
                           ARGV0, srcip);
                    continue;
                }
            }
        }
    }
}
