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



void osdns_accept(int fd, short ev, void *arg) {

    /* sssssssh */
    if (fd) { }
    if (ev) { }
    merror("ossec-maild [dns]: INFO: osdns_accept()");

    /* temporary things */
    char *protocol = "tcp";


    /* We have a request from ossec-maild */
    struct os_dns_request dnsr;
    ssize_t n, datalen;
    struct imsg imsg;
    struct imsgbuf *ibuf = (struct imsgbuf *)arg;

    merror("ossec-maild [dns]: DEBUG: Starting imsg stuff.");

    if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN) {
        ErrorExit("ossec-maild [dns]: ERROR: imsg_read() failed: %s", strerror(errno));
        return;
    }
    if (n == 0) {
        merror("ossec-maild [dns]: DEBUG: n == 0");
    }
    merror("ossec-maild [dns]: DEBUG: imsg_read() succeeded.");

    if ((n = imsg_get(ibuf, &imsg)) == -1) {
        merror("ossec-maild [dns]: ERROR: imsg_get() failed: %s", strerror(errno));
        return;
    }
    if (n == 0) {
        merror("ossec-maild [dns]: DEBUG: imsg_get() n == 0");
    }

    merror("ossec-maild [dns]: DEBUG: imsg_get() successful");

    datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
    merror("ossec-maild [dns]: DEBUG datalen: %zd (hdr.len: %d/%lu)", datalen, imsg.hdr.len, IMSG_HEADER_SIZE); 

    switch(imsg.hdr.type) {
        case DNS_REQ:
            merror("ossec-maild [dns]: DEBUG: It's the memcpy, isn't it?");
            memcpy(&dnsr, imsg.data, sizeof(dnsr));
            //memcpy(&hostname, imsg.data, datalen);
            //memcpy(&hostname, imsg.data, datalen);
            //hostname = imsg.data;
            //hostname = strndup(imsg.data, 255);
            //strlcpy(hostname, (char *)imsg.data, 255);
            merror("ossec-maild [dns]: DEBUG: hostname: XXX%sXXX (%lu)", dnsr.hostname, sizeof(dnsr.hostname));
            //strlcpy(&hostname, "ix.example.com", 15);
            //merror("ossec-maild [dns]: DEBUG: hostname: XXX%sXXX (%lu)", &hostname, sizeof(hostname));
            int idata = 42;
            struct addrinfo hints, *result, *rp = NULL;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            if (strncmp(protocol, "tcp", 3) == 0) {
                hints.ai_socktype = SOCK_STREAM;
            } else if (strncmp(protocol, "udp", 3) == 0) {
                hints.ai_socktype = SOCK_DGRAM;
            }

            merror("ossec-maild [dns]: DEBUG: Starting socket work.");
            /* socket */
            int sock;
            sock = getaddrinfo(dnsr.hostname, "smtp", &hints, &result);
            if (sock != 0) {
                merror("ossec-maild [dns]: ERROR: getaddrinfo() error: %s\n", gai_strerror(sock));
                imsg_compose(ibuf, DNS_FAIL, 0, 0, -1, &idata, sizeof(idata));
                if ((n = msgbuf_write(&ibuf->w) == -1) && errno != EAGAIN) {
                    merror("ossec-maild [dns]: ERROR: msgbuf_write() failed (DNS_FAIL): %s", strerror(errno));
                }
                if (n == 0) {
                    merror("ossec-maild [dns]: DEBUG: DNS_FAIL n == 0");
                }
                if (n == EAGAIN) {
                    merror("ossec-maild [dns]: DEBUG: EAGAIN 1");
                }
                merror("ossec-maild [dns]: DEBUG: Got past the imsg stuff");
                //return;
            }

            merror("ossec-maild [dns]: DEBUG: getaddrinfo() seems to have succeeded.");

            sock = -1;
            for(rp = result; rp; rp = rp->ai_next) {
                sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                if (sock == -1) {
                    merror("ossec-maild [dns]: ERROR: socket() error");
                } else {
                    merror("ossec-maild [dns]: DEBUG: Connecting...");
                    if (connect(sock, rp->ai_addr, rp->ai_addrlen) == -1) {
                        merror("ossec-maild [dns]: ERROR: connect() failed.");
                        //XXX return error to caller
                    } else {
                        merror("ossec-maild [dns]: DEBUG: Did I totally forget to tell OS_Sendmail() that we have a socket?");
                        if ((imsg_compose(ibuf, DNS_RESP, 0, 0, sock, &idata, sizeof(idata))) == -1) {
                            merror("ossec-maild [dns]: ERROR: DNS_RESP imsg_compose() failed: %s", strerror(errno));
                            freeaddrinfo(result);
                            return;
                        } else {
                            if ((n = msgbuf_write(&ibuf->w) == -1) && errno != EAGAIN) {
                                merror("ossec-maild [dns]: ERROR: DNS_RESP msgbuf_write() failed: %s", strerror(errno));
                                freeaddrinfo(result);
                                return;
                            }
                            if (n == 0) {
                                merror("ossec-maild [dns]: DEBUG: DNS_RESP n == 0");
                            }
                            freeaddrinfo(result);
                            return;
                        }
                    }
                }
            }
            break;
        default:
            merror("ossec-maild [dns]: ERROR: Unknown imsg type");
            if ((imsg_compose(ibuf, DNS_FAIL, 0, 0, -1, &idata, sizeof(idata))) == -1) {
                merror("ossec-maild [dns]: ERROR: DNS_FAIL imsg_compose() failed: %s", strerror(errno));
                return;
            } else {
                if ((n = msgbuf_write(&ibuf->w) == -1) && errno != EAGAIN) {
                    merror("ossec-maild [dns]: ERROR: DNS_FAIL msgbuf_write failed: %s", strerror(errno));
                    return;
                }
                if (n == 0) {
                    merror("ossec-maild [dns]: DEBUG: DNS_FAIL n == 0");
                    return;
                }
            }
            return;
    }



    merror("ossec-maild [dns]: DEBUG: how did I get here?");
    return;
}

/* osdns() is simple, it received the ibuf and
 * sets up the event loop for the parent to query.
 * osdns_accept() will pass a socket back to the 
 * parent with the connection established.
 *
 * Focusing on TCP right now.
 */
int osdns(struct imsgbuf *ibuf) {


#if __OpenBSD__
    setproctitle("[dns]");
#endif

    merror("ossec-maild [dns]: INFO: Starting osdns");

    /* setuid() ossecm */
    /* This is static ossecm for now, I'll figure out the trick later */
    char *login = "ossecm";
    struct passwd *pw;


    pw = getpwnam(login);


    if (Privsep_SetGroup(pw->pw_gid) < 0) {
        ErrorExit("ossec-maild [dns]: ERROR: Cannot setgid.");
    }
    if (Privsep_SetUser(pw->pw_uid) < 0) {
        ErrorExit("ossec-maild [dns]: ERROR: Cannot setuid.");
    }

    /* Setup libevent */
    struct event_base *eb;
    eb = event_init();
    if (!eb) {
        ErrorExit("ossec-maild [dns]: event_init() failed.");
    }

    merror("ossec-maild [dns]: INFO: Starting libevent.");
    struct event ev_accept;
    event_set(&ev_accept, ibuf->fd, EV_READ|EV_PERSIST, osdns_accept, ibuf);
    event_add(&ev_accept, NULL);
    event_dispatch();



    return(0);
}






