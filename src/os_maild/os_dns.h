#include <imsg.h>
#include <config/mail-config.h>

int maild_osdns(struct imsgbuf *ibuf, char *os_name, MailConfig mail);
void osdns_accept(int fd, short ev, void *arg);

/* Two types of messages */
enum imsg_type {
    DNS_REQ,
    DNS_RESP,
    DNS_FAIL,
    AGENT_REQ
};

struct os_dns_request {
    char *hostname;
    size_t hname_len;
    char *caller;
    char *protocol;
    char *port;
};

struct os_dns_error {
    int code;
    const char *msg;
};

