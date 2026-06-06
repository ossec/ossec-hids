/* Copyright (C) 2010 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "auth.h"
#include "auth_conn.h"

static pthread_mutex_t auth_keys_mutex;
static int auth_keys_mutex_ready = 0;

void auth_keys_init(void)
{
    if (!auth_keys_mutex_ready) {
        os_mutex_init(&auth_keys_mutex, NULL);
        auth_keys_mutex_ready = 1;
    }
}

void auth_keys_lock(void)
{
    os_mutex_lock(&auth_keys_mutex);
}

void auth_keys_unlock(void)
{
    os_mutex_unlock(&auth_keys_mutex);
}

static int ssl_error(const SSL *ssl, int ret)
{
    if (ret <= 0) {
        switch (SSL_get_error(ssl, ret)) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                usleep(100 * 1000);
                return (0);
            default:
                merror("%s: ERROR: SSL Error (%d)", ARGV0, ret);
                ERR_print_errors_fp(stderr);
                return (1);
        }
    }

    return (0);
}

static void auth_close_connection(SSL *ssl, int sock)
{
    if (ssl) {
        SSL_free(ssl);
    }
    if (sock >= 0) {
        close(sock);
    }
}

void *auth_connection_worker(void *arg)
{
    auth_conn_arg *conn = (auth_conn_arg *)arg;
    int client_sock = conn->client_sock;
    int use_ip_address = conn->use_ip_address;
    char *authpass = conn->authpass;
    SSL_CTX *ctx = conn->ctx;
    char srcip[IPSIZE + 1];
    char buf[4096 + 1];
    SSL *ssl = NULL;
    int ret;
    char *agentname = NULL;
    int parseok;

    os_block_worker_signals();

    strncpy(srcip, conn->srcip, IPSIZE);
    srcip[IPSIZE] = '\0';
    free(conn);

    ssl = SSL_new(ctx);
    if (!ssl) {
        auth_close_connection(NULL, client_sock);
        return NULL;
    }
    SSL_set_fd(ssl, client_sock);

    do {
        ret = SSL_accept(ssl);

        if (ssl_error(ssl, ret)) {
            auth_close_connection(ssl, client_sock);
            return NULL;
        }

    } while (ret <= 0);

    verbose("%s: INFO: New connection from %s", ARGV0, srcip);
    buf[0] = '\0';

    do {
        ret = SSL_read(ssl, buf, sizeof(buf));

        if (ssl_error(ssl, ret)) {
            auth_close_connection(ssl, client_sock);
            return NULL;
        }

    } while (ret <= 0);

    parseok = 0;
    {
        char *tmpstr = buf;

        if (authpass) {
            if (strncmp(tmpstr, "OSSEC PASS: ", 12) == 0) {
                tmpstr = tmpstr + 12;

                if (strlen(tmpstr) > strlen(authpass) && strncmp(tmpstr, authpass, strlen(authpass)) == 0) {
                    tmpstr += strlen(authpass);

                    if (*tmpstr == ' ') {
                        tmpstr++;
                        parseok = 1;
                    }
                }
            }
            if (parseok == 0) {
                merror("%s: ERROR: Invalid password provided by %s. Closing connection.", ARGV0, srcip);
                auth_close_connection(ssl, client_sock);
                return NULL;
            }
        }

        parseok = 0;
        if (strncmp(tmpstr, "OSSEC A:'", 9) == 0) {
            agentname = tmpstr + 9;
            tmpstr += 9;
            while (*tmpstr != '\0') {
                if (*tmpstr == '\'') {
                    *tmpstr = '\0';
                    verbose("%s: INFO: Received request for a new agent (%s) from: %s", ARGV0, agentname, srcip);
                    parseok = 1;
                    break;
                }
                tmpstr++;
            }
        }
        if (parseok == 0) {
            merror("%s: ERROR: Invalid request for new agent from: %s", ARGV0, srcip);
        } else {
            int acount = 2;
            char fname[2048 + 1];
            char response[2048 + 1];
            char *finalkey = NULL;
            response[2048] = '\0';
            fname[2048] = '\0';
            if (!OS_IsValidName(agentname)) {
                merror("%s: ERROR: Invalid agent name: %s from %s", ARGV0, agentname, srcip);
                snprintf(response, 2048, "ERROR: Invalid agent name: %s\n\n", agentname);
                SSL_write(ssl, response, strlen(response));
                snprintf(response, 2048, "ERROR: Unable to add agent.\n\n");
                SSL_write(ssl, response, strlen(response));
                sleep(1);
            } else {
                auth_keys_lock();

                strncpy(fname, agentname, 2048);
                while (NameExist(fname)) {
                    snprintf(fname, 2048, "%s%d", agentname, acount);
                    acount++;
                    if (acount > 256) {
                        auth_keys_unlock();
                        merror("%s: ERROR: Invalid agent name %s (duplicated)", ARGV0, agentname);
                        snprintf(response, 2048, "ERROR: Invalid agent name: %s\n\n", agentname);
                        SSL_write(ssl, response, strlen(response));
                        snprintf(response, 2048, "ERROR: Unable to add agent.\n\n");
                        SSL_write(ssl, response, strlen(response));
                        sleep(1);
                        goto done;
                    }
                }
                agentname = fname;

                {
                    char *check_ip_address = IPExist(srcip);
                    if (check_ip_address) {
                        auth_keys_unlock();
                        merror("%s: ERROR: Invalid IP address %s (duplicated)", ARGV0, check_ip_address);
                        snprintf(response, 2048, "ERROR: Invalid IP address: %s\n\n", check_ip_address);
                        SSL_write(ssl, response, strlen(response));
                        snprintf(response, 2048, "ERROR: Unable to add agent.\n\n");
                        SSL_write(ssl, response, strlen(response));
                        sleep(1);
                    } else {
                        if (use_ip_address) {
                            finalkey = OS_AddNewAgent(agentname, srcip, NULL);
                        } else {
                            finalkey = OS_AddNewAgent(agentname, NULL, NULL);
                        }

                        auth_keys_unlock();

                        if (!finalkey) {
                            merror("%s: ERROR: Unable to add agent: %s (internal error)", ARGV0, agentname);
                            snprintf(response, 2048, "ERROR: Internal manager error adding agent: %s\n\n", agentname);
                            SSL_write(ssl, response, strlen(response));
                            snprintf(response, 2048, "ERROR: Unable to add agent.\n\n");
                            SSL_write(ssl, response, strlen(response));
                            sleep(1);
                        } else {
                            snprintf(response, 2048, "OSSEC K:'%s'\n\n", finalkey);
                            verbose("%s: INFO: Agent key generated for %s (requested by %s)", ARGV0, agentname, srcip);
                            ret = SSL_write(ssl, response, strlen(response));
                            if (ret < 0) {
                                merror("%s: ERROR: SSL write error (%d)", ARGV0, ret);
                                merror("%s: ERROR: Agen key not saved for %s", ARGV0, agentname);
                                ERR_print_errors_fp(stderr);
                            } else {
                                verbose("%s: INFO: Agent key created for %s (requested by %s)", ARGV0, agentname, srcip);
                            }
                        }
                    }
                }
            }
        }
    }

done:
    auth_close_connection(ssl, client_sock);
    return NULL;
}
