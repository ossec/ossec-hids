/* @(#) $Id: ./src/os_net/os_net.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* OS_net Library.
 * APIs for many network operations.
 */

#ifndef __OS_NET_H

#define __OS_NET_H

#include <stdint.h> /* uint16_t */

/* OS_Bindport*
 * Bind a specific port (protocol and a ip).
 * If the IP is not set, it is going to use ADDR_ANY
 * Return the socket.
 */
int OS_Bindporttcp(uint16_t _port, const char *_ip, int ipv6);
int OS_Bindportudp(uint16_t _port, const char *_ip, int ipv6);

/* OS_BindUnixDomain
 * Bind to a specific file, using the "mode" permissions in
 * a Unix Domain socket.
 */
int OS_BindUnixDomain(const char * path, mode_t mode, int max_msg_size);
int OS_ConnectUnixDomain(const char * path, int max_msg_size);
int OS_getsocketsize(int ossock);


/* OS_Connect
 * Connect to a TCP/UDP socket
 */
int OS_ConnectTCP(uint16_t _port, const char *_ip, int ipv6);
int OS_ConnectUDP(uint16_t _port, const char *_ip, int ipv6);

/* OS_RecvUDP
 * Receive a UDP packet. Return NULL if failed
 */
char *OS_RecvUDP(int socket, int sizet);
int OS_RecvConnUDP(int socket, char *buffer, int buffer_size);


/* OS_RecvUnix
 * Receive a message via a Unix socket
 */
int OS_RecvUnix(int socket, int sizet, char *ret);


/* OS_RecvTCP
 * Receive a TCP packet
 */
int OS_AcceptTCP(int socket, char *srcip, size_t addrsize);
char *OS_RecvTCP(int socket, int sizet);
int OS_RecvTCPBuffer(int socket, char *buffer, int sizet);


/* OS_SendTCP
 * Send a TCP/UDP/UnixSocket packet (in a open socket)
 */
int OS_SendTCP(int socket, const char *msg);
int OS_SendTCPbySize(int socket, int size, const char *msg);

int OS_SendUnix(int socket, const char * msg, int size);

int OS_SendUDP(int socket, char *msg);
int OS_SendUDPbySize(int socket, int size, const char *msg);


/* OS_GetHost
 * Calls gethostbyname
 */
char *OS_GetHost(const char *host, unsigned int attempts);

/**
 * Close a network socket.
 * @param socket the socket to close
 * @return 0 on success, else -1 or SOCKET_ERROR
 */
int OS_CloseSocket(int socket);

#endif

/* EOF */
