

int osdns(struct imsgbuf *ibuf);
void osdns_accept(int fd, short ev, void *arg);

/* Two types of messages */
enum imsg_type {
    DNS_REQ,
    DNS_RESP,
    DNS_FAIL
};

struct os_dns_request {
    char *hostname;
    size_t hname_len;
    char *caller;
};

struct os_dns_error {
    int code;
    char *msg;
};

