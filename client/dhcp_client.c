#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "dhcp_client.h"
#include "consts.h"

int request_vpn_ip(int udp_fd, struct sockaddr_in *server_addr, char *assigned_ip_str) {
    unsigned char req[1] = {0x01}; // MAGIC BYTE: IP_REQUEST
    socklen_t len = sizeof(*server_addr);
    unsigned char resp[2];

    printf("[*] Sending IP request to VPN server...\n");
    if (sendto(udp_fd, req, 1, 0, (struct sockaddr *)server_addr, len) < 0) {
        perror("sendto failed");
        return -1;
    }

    // Set a 5-second timeout so the client doesn't hang forever if the server is down
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(udp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    printf("[*] Waiting for DHCP response...\n");
    int n = recvfrom(udp_fd, resp, sizeof(resp), 0, NULL, NULL);

    if (n < 0) {
        printf("[-] Handshake timeout or server unreachable.\n");
        return -1;
    }

    if (resp[0] == 0x02) { // MAGIC BYTE: IP_ASSIGN
        // Build the string (e.g., "10.8.0" + "." + "5")
        snprintf(assigned_ip_str, 16, "%s.%d", TUN_SUBNET_PREFIX, resp[1]);
        printf("[+] Handshake successful! Assigned IP: %s\n", assigned_ip_str);

        // Remove the timeout so our main tunnel loop doesn't break
        tv.tv_sec = 0;
        setsockopt(udp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        return 0;
    }

    printf("[-] Received unknown response from server.\n");
    return -1;
}
