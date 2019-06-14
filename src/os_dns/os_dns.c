/* Copyright (C) 2019 Daniel Parriott <ddpbsd@gmail.com>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <stdint.h>
#include <imsg.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>

/* Requires libevent */
#include <event.h>

#include "headers/privsep_op.h"
#include "headers/debug_op.h"
#include "os_net/os_net.h"
#include "os_dns.h"

#ifdef CLIENT
#include "client-agent/agentd.h"
#include "config/client-config.h"
#endif //CLIENT

char *dname = NULL;

void osdns_accept(int fd, short ev, void *arg) {

    /* sssssssh */
    if (fd) { }

    /* We have a request from ossec-maild */
    struct os_dns_request dnsr;
    ssize_t n, datalen;
    struct imsg imsg;
    struct imsgbuf *ibuf = (struct imsgbuf *)arg;

#ifdef CLIENT
    extern agent *agt;
    unsigned int attempts = 2;
#endif //CLIENT


    if (ev & EV_READ) {
        if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN) {
            ErrorExit("%s [dns]: ERROR: imsg_read() failed: %s", dname, strerror(errno));
        }
        if (n == 0) {
            debug2("%s [dns]: DEBUG: n == 0", dname);
            return;
        }
    } else {
        merror("Not EV_READ");
        return;
    }

    for (;;) {
        if ((n = imsg_get(ibuf, &imsg)) == -1) {
            merror("%s [dns]: ERROR: imsg_get() failed: %s", dname, strerror(errno));
            return;
        }
        if (n == 0) {
            debug2("%s [dns]: DEBUG: imsg_get() n == 0", dname);
            return; /* No more messages */
        }


        datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

        switch(imsg.hdr.type) {
            /*
             * OS_Sendmail() sends a DNS_REQ for the smtp_server
             * osdns() sends back a socket to the connection to the smtp_server
             */
            case DNS_REQ:
                if (datalen != sizeof(&dnsr)) {
                    merror("%s [dns]: ERROR: DNS_REQ wrong length (%lu)", dname, datalen);
                    struct os_dns_error os_dns_err;
                    //os_dns_err.msg = "wrong len";
                    imsg_compose(ibuf, DNS_FAIL, 0, 0, -1, &os_dns_err, sizeof(&os_dns_err));
                    if ((n = msgbuf_write(&ibuf->w) == -1) && errno != EAGAIN) {
                        merror("%s [dns]: ERROR: msgbuf_write() failed (DNS_FAIL size): %s", dname, strerror(errno));
                        return;
                    }
                    if (n == 0) {
                        debug2("%s [dns]: DEBUG: DNS_FAIL size n == 0", dname);
                        return;
                    }
                    if (n == EAGAIN) {
                        debug2("%s [dns]: DEBUG EAGAIN size", dname);
                        return; //XXX
                    }
                }
                memcpy(&dnsr, imsg.data, sizeof(dnsr));
                int idata = 42; /* XXX Not sure why this is actually needed */
                struct addrinfo hints, *result, *rp = NULL;
                memset(&hints, 0, sizeof(hints));
                hints.ai_family = AF_UNSPEC;
                hints.ai_socktype = SOCK_STREAM;

                /* socket */
                int sock;
                sock = getaddrinfo(dnsr.hostname, "smtp", &hints, &result);
                if (sock != 0) {
                    merror("%s [dns]: ERROR: getaddrinfo() error: %s\n", dname, gai_strerror(sock));

                    struct os_dns_error os_dns_err;
                    os_dns_err.code = sock;
                    //os_dns_err.msg = gai_strerror(sock);

                    imsg_compose(ibuf, DNS_FAIL, 0, 0, -1, &os_dns_err, sizeof(&os_dns_err));
                    if ((n = msgbuf_write(&ibuf->w) == -1) && errno != EAGAIN) {
                        merror("%s [dns]: ERROR: msgbuf_write() failed (DNS_FAIL): %s", dname, strerror(errno));
                    }
                    if (n == 0) {
                        debug2("%s [dns]: DEBUG: DNS_FAIL n == 0", dname);
                        return;
                    }
                    if (n == EAGAIN) {
                        debug2("%s [dns]: DEBUG: EAGAIN 1", dname);
                        return; //XXX
                    }
                }

                sock = -1;
                for(rp = result; rp; rp = rp->ai_next) {
                    sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                    if (sock == -1) {
                        merror("%s [dns]: ERROR: socket() error", dname);
                    } else {
                        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == -1) {
                            merror("%s [dns]: ERROR: connect() failed.", dname);
                        } else {
                            if ((imsg_compose(ibuf, DNS_RESP, 0, 0, sock, &idata, sizeof(idata))) == -1) {
                                merror("%s [dns]: ERROR: DNS_RESP imsg_compose() failed: %s", dname, strerror(errno));
                                freeaddrinfo(result);
                                return;
                            } else {
                                if ((n = msgbuf_write(&ibuf->w) == -1) && errno != EAGAIN) {
                                    merror("%s [dns]: ERROR: DNS_RESP msgbuf_write() failed: %s", dname, strerror(errno));
                                    freeaddrinfo(result);
                                    return;
                                }
                                if (n == 0) {
                                    debug2("%s [dns]: DEBUG: DNS_RESP n == 0", dname);
                                }
                                freeaddrinfo(result);
                                return;
                            }
                        }
                    }
                }

                struct os_dns_error os_dns_err;
                os_dns_err.code = -1;
                //os_dns_err.msg = "Cannot connect to smtp server";

                imsg_compose(ibuf, DNS_FAIL, 0, 0, -1, &os_dns_err, sizeof(&os_dns_err));
                if ((n = msgbuf_write(&ibuf->w) == -1) && errno != EAGAIN) {
                    merror("%s [dns]: ERROR: msgbuf_write() failed (DNS_FAIL): %s", dname, strerror(errno));
                    return;
                }
                if (n == 0) {
                    debug2("%s [dns]: DEBUG: DNS_FAIL n == 0", dname);
                }
                if (n == EAGAIN) {
                    debug2("%s [dns]: DEBUG: EAGAIN 1", dname);
                }
                break;
#ifdef CLIENT
            case AGENT_REQ:
                /*
                 * agentd needs to find the IP of the ossec server
                 * This should give agentd a socket to use for the traffic
                 */
                memcpy(&agt, imsg.data, sizeof(agt));

                int rc = 0;
                while (agt->rip[rc] != NULL) {
                    agt->sock = OS_ConnectUDP(agt->port, agt->rip[rc]);
                    if (agt->sock < 0) {
                        agt->sock = -1;
                        merror(CONNS_ERROR, dname, agt->rip[rc]);
                        attempts += 10;
                        sleep(attempts);
                        if (rc > 0) {
                            merror("Could not connect to any server.");
                            struct os_dns_error os_dns_err;
                            os_dns_err.code = -1;
                            imsg_compose(ibuf, DNS_FAIL, 0, 0, -1, &os_dns_err, sizeof(&os_dns_err));
                            if ((n = msgbuf_write(&ibuf->w) == -1) && errno != EAGAIN) {
                                    merror("%s [dns]: ERROR: msgbuf_write() failed (AGENT_REQ)", dname);
                                    return;
                            }
                            if (n == 0) {
                                debug2("%s [dns]: DEBUG: AGENT_REQ size n == 0", dname);
                                return;
                            }
                                    
                        } else {
                            rc++;
                        }
                    } else {
                        /* Success */
                        /* Send the socket back to agentd */
                        if ((imsg_compose(ibuf, DNS_RESP, 0, 0, agt->sock, &idata, sizeof(idata))) == -1) {
                            merror("%s [dns]: ERROR: DNS_RESP imsg_compose() failed: %s", dname, strerror(errno));
                            freeaddrinfo(result);
                            return;
                        } else {
                            if ((n = msgbuf_write(&ibuf->w) == -1) && errno != EAGAIN) {
                                merror("%s [dns]: ERROR: DNS_RESP msgbuf_write() failed: %s", dname, strerror(errno));
                                freeaddrinfo(result);
                                return;
                            }
                            if (n == 0) {
                                debug1("%s [dns]: DEBUG: n == 0", dname);
                                return;
                            }
                            freeaddrinfo(result);
                            return;
                        }

                    }
                }
                break;
#endif //CLIENT
            default:
                merror("%s [dns]: ERROR: Unknown imsg type", dname);
                if ((imsg_compose(ibuf, DNS_FAIL, 0, 0, -1, &idata, sizeof(idata))) == -1) {
                    merror("%s [dns]: ERROR: DNS_FAIL imsg_compose() failed: %s", dname, strerror(errno));
                    return;
                } else {
                    if ((n = msgbuf_write(&ibuf->w) == -1) && errno != EAGAIN) {
                        merror("%s [dns]: ERROR: DNS_FAIL msgbuf_write failed: %s", dname, strerror(errno));
                        return;
                    }
                    if (n == 0) {
                        debug2("%s [dns]: DEBUG: DNS_FAIL n == 0", dname);
                        return;
                    }
                }
                return;
        }
    }


    return;
}

/* osdns() is simple, it received the ibuf and
 * sets up the event loop for the parent to query.
 * osdns_accept() will pass a socket back to the 
 * parent with the connection established.
 *
 * Focusing on TCP right now.
 */
int osdns(struct imsgbuf *ibuf, char *os_name) {

    dname = os_name;

#if __OpenBSD__
    setproctitle("[dns]");
#endif

    debug1("%s [dns]: INFO: Starting osdns", os_name);

    /* setuid() ossecm */
    /* This is static ossecm for now, I'll figure out the trick later */
#ifdef CLIENT
    char *login = USER;
#else
    char *login = MAILUSER;
#endif //CLIENT
    struct passwd *pw;


    pw = getpwnam(login);


    if (Privsep_SetGroup(pw->pw_gid) < 0) {
        ErrorExit("%s [dns]: ERROR: Cannot setgid.", os_name);
    }
    if (Privsep_SetUser(pw->pw_uid) < 0) {
        ErrorExit("%s [dns]: ERROR: Cannot setuid.", os_name);
    }

    if (CreatePID(dname, getpid()) < 0) {
        ErrorExit(PID_ERROR, dname);
    }

    /* Setup libevent */
    struct event_base *eb;
    eb = event_init();
    if (!eb) {
        ErrorExit("%s [dns]: event_init() failed.", os_name);
    }

    debug1("%s [dns]: INFO: Starting libevent.", os_name);
    struct event ev_accept;
    event_set(&ev_accept, ibuf->fd, EV_READ|EV_PERSIST, osdns_accept, ibuf);
    event_add(&ev_accept, NULL);
    event_dispatch();



    return(0);
}

