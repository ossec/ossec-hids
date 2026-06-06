/* Copyright (C) 2010 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 */

#include "auth.h"
#include "auth_conn.h"
#include "os_crypto/md5/md5_op.h"

/* Prototypes */
static void help_authd(int status) __attribute((noreturn));
static void auth_shutdown(SSL_CTX *ctx, int sock) __attribute__((noreturn));
static void authd_HandleSIG(int sig);

static volatile sig_atomic_t authd_shutting_down = 0;
#define AUTHD_SHUTDOWN_POOL_TIMEOUT 60


/* Print help statement */
static void help_authd(int status)
{
    print_header();
    print_out("  %s: -[Vhdti] [-g group] [-D dir] [-p port] [-c ciphers] [-v path] [-x path] [-k path]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground.");
    print_out("    -i          Use client's source IP address");
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -D <dir>    Directory to chroot into (default: %s)", DEFAULTDIR);
    print_out("    -p <port>   Manager port (default: %s)", DEFAULT_PORT);
    print_out("    -n          Disable shared password authentication (not recommended).\n");
    print_out("    -c          SSL cipher list (default: %s)", DEFAULT_CIPHERS);
    print_out("    -v <path>   Full path to CA certificate used to verify clients");
    print_out("    -x <path>   Full path to server certificate");
    print_out("    -k <path>   Full path to server key");
    print_out(" ");
    exit(status);
}

/* Generates a random and temporary shared pass to be used by the agents. */
char *__generatetmppass()
{
    int rand1;
    int rand2;
    char *rand3;
    char *rand4;
    os_md5 md1;
    os_md5 md3;
    os_md5 md4;
    char *fstring = NULL;
    char str1[STR_SIZE +1];
    char *muname = NULL;

    #ifndef WIN32
        #ifdef __OpenBSD__
        srandomdev();
        #else
        srandom(time(0) + getpid() + getppid());
        #endif
    #else
        srandom(time(0) + getpid());
    #endif

    rand1 = random();
    rand2 = random();

    rand3 = GetRandomNoise();
    rand4 = GetRandomNoise();

    OS_MD5_Str(rand3, md3);
    OS_MD5_Str(rand4, md4);

    muname = getuname();

    snprintf(str1, STR_SIZE, "%d%d%s%d%s%s",(int)time(0), rand1, muname, rand2, md3, md4);
    OS_MD5_Str(str1, md1);
    fstring = strdup(md1);
    free(rand3);
    free(rand4);
    if(muname) {
        free(muname);
    }
    return(fstring);
}

static void auth_shutdown(SSL_CTX *ctx, int sock)
{
    SSL_CTX_free(ctx);
    close(sock);
    exit(0);
}

static void authd_HandleSIG(int sig)
{
    if (!authd_shutting_down) {
        authd_shutting_down = 1;
        merror("%s: Shutdown requested (signal %d); stopping new enrollments.",
               ARGV0, sig);
        return;
    }

    merror(SIGNAL_RECV, ARGV0, sig, strsignal(sig));
    DeletePID(ARGV0);
    exit(1);
}

/* Exit handler */
static void cleanup();



int main(int argc, char **argv)
{
    FILE *fp;
    char *authpass = NULL;
    thread_pool *auth_pool = NULL;
    int c = 0, test_config = 0, use_ip_address = 0;
    int use_pass = 1;
    int run_foreground = 0;
    gid_t uid;
    gid_t gid;
    int client_sock = 0, sock = 0, portnum;
    int debug_level = 0;
    char *port = DEFAULT_PORT;
    char *ciphers = DEFAULT_CIPHERS;
    const char *dir  = DEFAULTDIR;
    const char *user = USER;
    const char *group = GROUPGLOBAL;
    const char *server_cert = NULL;
    const char *server_key = NULL;
    const char *ca_cert = NULL;
    char buf[4096 + 1];
    SSL_CTX *ctx;
    char srcip[IPSIZE + 1];
    struct sockaddr_storage _nc;
    socklen_t _ncl;
    fd_set fdsave, fdwork;		/* select() work areas */
    int fdmax;				/* max socket number + 1 */
    OSNetInfo *netinfo;			/* bound network sockets */
    /* Initialize some variables */
    memset(srcip, '\0', IPSIZE + 1);
    bio_err = 0;

    OS_PassEmptyKeyfile();

    /* Set the name */
    OS_SetName(ARGV0);

    while ((c = getopt(argc, argv, "Vdhtfiu:g:D:m:p:c:v:x:k:n")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_authd(0);
                break;
            case 'd':
                debug_level = 1;
                nowDebug();
                break;
            case 'i':
                use_ip_address = 1;
                break;
            case 'u':
                if (!optarg) {
                    ErrorExit("%s: -u needs an argument", ARGV0);
                }
                user = optarg;
                break;
            case 'g':
                if (!optarg) {
                    ErrorExit("%s: -g needs an argument", ARGV0);
                }
                group = optarg;
                break;
            case 'D':
                if (!optarg) {
                    ErrorExit("%s: -D needs an argument", ARGV0);
                }
                dir = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'n':
                use_pass = 0;
                break;
            case 'p':
                if (!optarg) {
                    ErrorExit("%s: -%c needs an argument", ARGV0, c);
                }
                portnum = atoi(optarg);
                if (portnum <= 0 || portnum >= 65536) {
                    ErrorExit("%s: Invalid port: %s", ARGV0, optarg);
                }
                port = optarg;
                break;
            case 'c':
                if (!optarg) {
                    ErrorExit("%s: -%c needs an argument", ARGV0, c);
                }
                ciphers = optarg;
                break;
            case 'v':
                if (!optarg) {
                    ErrorExit("%s: -%c needs an argument", ARGV0, c);
                }
                ca_cert = optarg;
                break;
            case 'x':
                if (!optarg) {
                    ErrorExit("%s: -%c needs an argument", ARGV0, c);
                }
                server_cert = optarg;
                break;
            case 'k':
                if (!optarg) {
                    ErrorExit("%s: -%c needs an argument", ARGV0, c);
                }
                server_key = optarg;
                break;
            default:
                help_authd(1);
                break;
        }
    }

    if (chdir(dir) == -1) {
        ErrorExit(CHDIR_ERROR, ARGV0, dir, errno, strerror(errno));
    }

    if (debug_level == 0) {
        debug_level = getDefine_Int("authd", "debug", 0, 2);
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }

    /* Exit here if test config is set */
    if (test_config) {
        exit(0);
    }


    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        ErrorExit(USER_ERROR, ARGV0, user, group);
    }


    if (!run_foreground) {
        nowDaemon();
        goDaemon();
    }
    


    /* Signal manipulation */
    StartSIG2(ARGV0, authd_HandleSIG);

    /* Create PID files */
    if (CreatePID(ARGV0, getpid()) < 0) {
  	    ErrorExit(PID_ERROR, ARGV0);
    }

    atexit(cleanup);

    verbose(STARTUP_MSG, ARGV0, (int)getpid());


    /* load keys */
    fp = fopen(KEYSFILE_PATH, "a");
    if (!fp) {
        merror("%s: ERROR: Unable to open %s (key file)", ARGV0, KEYSFILE_PATH);
        exit(1);
    }
    fclose(fp);

    /* Set ownership to ossec user and group */
    if (chown(KEYSFILE_PATH, uid, gid) < 0) {
        merror("%s: ERROR: Unable to set ownership of %s to %d:%d (%s)", ARGV0, KEYSFILE_PATH, uid, gid, strerror(errno));
        exit(1);
    }

    /* Set permissions to read/write for owner, read for group */
    if (chmod(KEYSFILE_PATH, 0640) < 0) {
        merror("%s: ERROR: Unable to set permissions of %s to 0640 (%s)", ARGV0, KEYSFILE_PATH, strerror(errno));
        exit(1);
    }
    
    if (use_pass) {

        /* Checking if there is a custom password file */
        fp = fopen(AUTHDPASS_PATH, "r");
        buf[0] = '\0';
        if (fp) {
            buf[4096] = '\0';
            char *ret = fgets(buf, 4095, fp);

            if (ret && strlen(buf) > 2) {
                /* Remove newline */
                buf[strlen(buf) - 1] = '\0';
                authpass = strdup(buf);
            }

            fclose(fp);
        }

        if (buf[0] != '\0')
            verbose("Accepting connections. Using password specified on file: %s",AUTHDPASS_PATH);
        else {
            /* Getting temporary pass. */
            authpass = __generatetmppass();
            verbose("Accepting connections. Random password chosen for agent authentication: %s", authpass);
        }
    } else {
        verbose("Accepting connections. No password required (not recommended)");
    }


    /* Setup random */
    srandom_init();

    /* Start SSL */
    /* Getting SSL cert. */
    ctx = os_ssl_keys(1, dir, ciphers, server_cert, server_key, ca_cert);
    if (!ctx) {
        merror("%s: ERROR: SSL error. Exiting.", ARGV0);
        exit(1);
    }

    /* Connect via TCP */
    netinfo = OS_Bindporttcp(port, NULL);
    if (netinfo->status < 0) {
        merror("%s: Unable to bind to port %s", ARGV0, port);
        exit(1);
    }

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        ErrorExit(SETGID_ERROR, ARGV0, group, errno, strerror(errno));
    }

    /* Chroot to the specified directory */
    if (Privsep_Chroot(dir) < 0) {
        ErrorExit(CHROOT_ERROR, ARGV0, dir, errno, strerror(errno));
    }

    if (Privsep_SetUser(uid) < 0) {
        ErrorExit(SETUID_ERROR, ARGV0, user, errno, strerror(errno));
    }


    /* Log that we are now in the chrooted environment */
    nowChroot();

    /* Change working directory to / within the chroot */
    if (chdir("/") < 0) {
        ErrorExit(CHDIR_ERROR, ARGV0, "/", errno, strerror(errno));
    }


    /* initialize select() save area */
    fdsave = netinfo->fdset;
    fdmax  = netinfo->fdmax;            /* value preset to max fd + 1 */

    {
        int worker_pool = getDefine_Int("authd", "worker_pool", 1, 128);
        int max_connections = getDefine_Int("authd", "max_connections", 1, 512);

        auth_pool = thread_pool_create_limited(worker_pool, max_connections);
        if (!auth_pool) {
            merror("%s: ERROR: Unable to create auth worker thread pool.", ARGV0);
            exit(1);
        }
    }

    auth_keys_init();

    debug1("%s: DEBUG: Going into listening mode.", ARGV0);

    while (!authd_shutting_down) {
        struct timeval tv;

        memset(&_nc, 0, sizeof(_nc));
        _ncl = sizeof(_nc);

        fdwork = fdsave;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        if (select (fdmax, &fdwork, NULL, NULL, &tv) < 0) {
            if (errno == EINTR) {
                continue;
            }
            ErrorExit("ERROR: Call to os_auth select() failed, errno %d - %s",
                      errno, strerror (errno));
        }

        if (authd_shutting_down) {
            break;
        }

        /* read through socket list for active socket */
        for (sock = 0; sock <= fdmax; sock++) {
            if (FD_ISSET (sock, &fdwork)) {
                if ((client_sock = accept(sock, (struct sockaddr *) &_nc, &_ncl)) > 0) {
                    auth_conn_arg *conn;

                    satop((struct sockaddr *) &_nc, srcip, IPSIZE);
                    os_calloc(1, sizeof(auth_conn_arg), conn);
                    conn->client_sock = client_sock;
                    strncpy(conn->srcip, srcip, IPSIZE);
                    conn->srcip[IPSIZE] = '\0';
                    conn->use_ip_address = use_ip_address;
                    conn->authpass = authpass;
                    conn->ctx = ctx;

                    if (thread_pool_try_submit(auth_pool, auth_connection_worker, conn) != 0) {
                        free(conn);
                        close(client_sock);
                        merror("%s: ERROR: Unable to queue auth connection from %s", ARGV0, srcip);
                    }
                }
            } /* if active socket */
        } /* for() loop on available sockets */

    } /* while listening */

    {
        time_t start = time(NULL);

        verbose("%s: Waiting for auth worker threads to finish.", ARGV0);
        while (thread_pool_active(auth_pool) > 0) {
            if ((time(NULL) - start) >= AUTHD_SHUTDOWN_POOL_TIMEOUT) {
                merror("%s: Shutdown timeout (%d s) with auth workers still active.",
                       ARGV0, AUTHD_SHUTDOWN_POOL_TIMEOUT);
                break;
            }
            sleep(1);
        }
        thread_pool_destroy(auth_pool);
    }

    /* Shut down the socket */
    auth_shutdown(ctx, sock);

    return (0);
}

/* Exit handler */
static void cleanup() {
	DeletePID(ARGV0);
}
