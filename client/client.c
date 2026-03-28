#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <signal.h>

#include "consts.h"
#include "dhcp_client.h"

// DNS Cleanup Function
void cleanup_and_exit(int sig) {
    printf("\nCaught signal %d (Ctrl+C). Restoring original /etc/resolv.conf...\n", sig);
    system("mv /etc/resolv.conf.bak /etc/resolv.conf");
    printf("Cleanup complete. Exiting.\n");
    exit(0);
}

void secure_dns() {
    printf("Securing DNS: Redirecting to VPN Server (10.8.0.1)...\n");
    system("cp /etc/resolv.conf /etc/resolv.conf.bak");
    FILE *f = fopen("/etc/resolv.conf", "w");
    if (f == NULL) {
        perror("Failed to open resolv.conf");
        system("mv /etc/resolv.conf.bak /etc/resolv.conf");
        return;
    }
    fprintf(f, "nameserver 10.8.0.1\n");
    fclose(f);
}

int tun_alloc(char *dev) {
    struct ifreq ifr;
    int fd, err;
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("Cannot open /dev/net/tun"); exit(1);
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (*dev) strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        perror("ioctl(TUNSETIFF) failed"); close(fd); exit(1);
    }
    printf("Created interface: %s\n", ifr.ifr_name);
    return fd;
}

// UPDATED: Now takes the dynamic IP as an argument
void setup_routing(char *assigned_ip) {
    char cmd[256];
    printf("Configuring network routing for %s...\n", assigned_ip);

    snprintf(cmd, sizeof(cmd), "ip link set dev tun0 up mtu %d", MTU); system(cmd);

    // Inject dynamic IP here
    snprintf(cmd, sizeof(cmd), "ip addr add %s/24 dev tun0", assigned_ip); system(cmd);

    snprintf(cmd, sizeof(cmd), "ip route add %s via %s dev %s", SERVER_IP, LOCAL_GATEWAY, PHYSICAL_IF); system(cmd);
    snprintf(cmd, sizeof(cmd), "ip route add 0.0.0.0/1 dev tun0"); system(cmd);
    snprintf(cmd, sizeof(cmd), "ip route add 128.0.0.0/1 dev tun0"); system(cmd);
    printf("Routing configured successfully.\n");
}

int setup_udp_socket(struct sockaddr_in *server_addr) {
    int sock;
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("UDP socket creation failed"); exit(1);
    }
    memset(server_addr, 0, sizeof(*server_addr));
    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr->sin_addr);
    return sock;
}

// UPDATED: Now handles the 0x00 Magic Byte
void run_tunnel(int tun_fd, int udp_fd, struct sockaddr_in *server_addr) {
    char buffer[MTU + 100]; // Extra space for Magic Byte
    int nread;
    socklen_t addr_len = sizeof(*server_addr);
    fd_set readfds;
    int max_fd = (tun_fd > udp_fd) ? tun_fd : udp_fd;

    printf("VPN Client running. Capturing traffic...\n");

    while (1) {
        FD_ZERO(&readfds); FD_SET(tun_fd, &readfds); FD_SET(udp_fd, &readfds);
        if (select(max_fd + 1, &readfds, NULL, NULL, NULL) < 0) {
            perror("select() failed"); break;
        }

        // DIRECTION 1: Outbound (Local App -> TUN -> UDP -> Server)
        if (FD_ISSET(tun_fd, &readfds)) {
            // Read raw IP packet leaving room for magic byte at buffer[0]
            nread = read(tun_fd, buffer + 1, sizeof(buffer) - 1);
            if (nread > 0) {
                buffer[0] = 0x00; // MAGIC BYTE: DATA
                sendto(udp_fd, buffer, nread + 1, 0, (struct sockaddr *)server_addr, addr_len);
            }
        }

        // DIRECTION 2: Inbound (Server -> UDP -> TUN -> Local App)
        if (FD_ISSET(udp_fd, &readfds)) {
            nread = recvfrom(udp_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)server_addr, &addr_len);
            if (nread > 1 && buffer[0] == 0x00) {
                // Strip the magic byte and write the raw IP packet to TUN
                write(tun_fd, buffer + 1, nread - 1);
            }
        }
    }
}

int main() {
    char tun_name[IFNAMSIZ] = "tun0";
    struct sockaddr_in server_addr;
    char assigned_ip[16];

    signal(SIGINT, cleanup_and_exit);

    // 1. Prepare UDP socket FIRST (so we can handshake)
    int udp_fd = setup_udp_socket(&server_addr);

    // 2. THE HANDSHAKE (Ask server for an IP)
    if (request_vpn_ip(udp_fd, &server_addr, assigned_ip) < 0) {
        printf("Failed to get IP from server. Exiting.\n");
        close(udp_fd);
        return 1;
    }

    // 3. Allocate TUN interface
    int tun_fd = tun_alloc(tun_name);

    // 4. Configure network/routing using the dynamically assigned IP
    setup_routing(assigned_ip);

    // 5. Secure DNS
    secure_dns();

    // 6. Run the infinite forwarding loop
    run_tunnel(tun_fd, udp_fd, &server_addr);

    return 0;
}
