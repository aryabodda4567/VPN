#ifndef DHCP_CLIENT_H
#define DHCP_CLIENT_H

#include <netinet/in.h>

// Returns 0 on success, -1 on failure.
// Populates assigned_ip_str with the dynamic IP.
int request_vpn_ip(int udp_fd, struct sockaddr_in *server_addr, char *assigned_ip_str);

#endif
