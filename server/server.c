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
#include <netinet/ip.h> // For struct iphdr
#include <time.h>       // For time() and select timeout

#include "dhcp.h"       // custom DHCP logic

#define MTU 1400
#define LISTEN_PORT 5555
#define TUN_IP "10.8.0.1"
#define CLIENT_SUBNET "10.8.0.0/24"
#define PHYSICAL_IF "eth0"
#define SECRET_KEY "iugfsivbhibiicbSDcbSjcbSEUIfhweuhffnfoNIORroNUERIERBIhVARHVSRnruiviverivb"

/*
 * XOR Cipher: Modifies the buffer in-place
 * Because XOR is symmetric (A ^ B = C, and C ^ B = A)
 */
void encrypt_decrypt(char *buffer, int length) {
    int key_len = strlen(SECRET_KEY);

    for (int i = 0; i < length; i++) {
        buffer[i] = buffer[i] ^ SECRET_KEY[i % key_len];
    }
}

// Global Array to holds clients (Index 2 to 254)
ClientMap clients[256] = {0};

 
// GARBAGE COLLECTOR
void sweep_stale_clients() {
    time_t current_time = time(NULL);
    int stale_timeout = 600; // 10 minutes (600 seconds)

    for (int i = 2; i < 255; i++) {
        if (clients[i].active == 1) {
            if ((current_time - clients[i].last_active) > stale_timeout) {
                printf("[GARBAGE COLLECTOR] Client 10.8.0.%d timed out. Reclaiming IP.\n", i);
                clients[i].active = 0; // Free the slot
            }
        }
    }
}

//NETWORK SETUP FUNCTIONS (Unchanged)
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
    printf(" Created interface: %s\n", ifr.ifr_name);
    return fd;
}

void setup_kernel_nat() {
    char cmd[512];
    printf(" Configuring kernel routing, IP forwarding, and NAT...\n");
    snprintf(cmd, sizeof(cmd), "ip link set dev tun0 up mtu %d", MTU); system(cmd);
    snprintf(cmd, sizeof(cmd), "ip addr add %s/24 dev tun0", TUN_IP); system(cmd);
    system("sysctl -w net.ipv4.ip_forward=1");
    snprintf(cmd, sizeof(cmd), "iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE", CLIENT_SUBNET, PHYSICAL_IF); system(cmd);
    snprintf(cmd, sizeof(cmd), "iptables -A FORWARD -i tun0 -o %s -j ACCEPT", PHYSICAL_IF); system(cmd);
    snprintf(cmd, sizeof(cmd), "iptables -A FORWARD -i %s -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT", PHYSICAL_IF); system(cmd);
    snprintf(cmd, sizeof(cmd), "iptables -t nat -A PREROUTING -i tun0 -p udp --dport 53 -j DNAT --to-destination 8.8.8.8"); system(cmd);
    snprintf(cmd, sizeof(cmd), "iptables -t nat -A PREROUTING -i tun0 -p tcp --dport 53 -j DNAT --to-destination 8.8.8.8"); system(cmd);
    printf(" Kernel NAT and forwarding configured successfully.\n");
}

int setup_udp_server() {
    int sock;
    struct sockaddr_in server_addr;
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("UDP socket creation failed"); exit(1);
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(LISTEN_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("UDP bind failed"); exit(1);
    }
    printf(" Listening for UDP VPN traffic on port %d...\n", LISTEN_PORT);
    return sock;
}

// THE MAIN SERVER LOOP (Multi-Client Upgraded & Encrypted)
void run_server_tunnel(int tun_fd, int udp_fd) {
    char buffer[MTU + 100]; // Extra space for Magic Byte header
    int nread;

    struct sockaddr_in sender_addr;
    socklen_t sender_addr_len = sizeof(sender_addr);

    fd_set readfds;
    int max_fd = (tun_fd > udp_fd) ? tun_fd : udp_fd;

    time_t last_sweep_time = time(NULL);

    printf("\n VPN Server is online and waiting for ENCRYPTED clients...\n");

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(tun_fd, &readfds);
        FD_SET(udp_fd, &readfds);

        struct timeval timeout;
        timeout.tv_sec = 60;
        timeout.tv_usec = 0;

        int activity = select(max_fd + 1, &readfds, NULL, NULL, &timeout);

        if (activity < 0) {
            perror("select() failed"); break;
        }

        // --- GARBAGE COLLECTOR TRIGGER ---
        time_t now = time(NULL);
        if (now - last_sweep_time >= 60) {
            sweep_stale_clients();
            last_sweep_time = now;
        }

        // --- DIRECTION 1: INBOUND FROM UDP (Client to Server) ---
        if (activity > 0 && FD_ISSET(udp_fd, &readfds)) {
            nread = recvfrom(udp_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender_addr, &sender_addr_len);
            if (nread > 0) {

                // 1. DECRYPT THE PAYLOAD  
                encrypt_decrypt(buffer, nread);

                // 2. Read the Magic Byte
                unsigned char magic_byte = buffer[0];

                if (magic_byte == 0x01) {
                    // HANDSHAKE: IP REQUEST
                    int assigned_idx = allocate_ip(clients, &sender_addr);
                    if (assigned_idx != -1) {
                        unsigned char reply[2] = {0x02, (unsigned char)assigned_idx};

                        // ENCRYPT THE HANDSHAKE REPLY 
                        encrypt_decrypt((char *)reply, 2);

                        sendto(udp_fd, reply, 2, 0, (struct sockaddr *)&sender_addr, sender_addr_len);
                    }
                }
                else if (magic_byte == 0x00 && nread > 1) {
                    // DATA: STANDARD VPN TRAFFIC
                    struct iphdr *ip_header = (struct iphdr *)(buffer + 1);
                    if (ip_header->version == 4) {
                        uint8_t index = ntohl(ip_header->saddr) & 0xFF;

                        // Update tracking
                        clients[index].active = 1;
                        clients[index].public_addr = sender_addr;
                        clients[index].last_active = now;

                        // Write raw, decrypted IP packet to TUN
                        write(tun_fd, buffer + 1, nread - 1);
                    }
                }
            }
        }

        // --- DIRECTION 2: INBOUND FROM TUN (Internet to Server to Client) ---
        if (activity > 0 && FD_ISSET(tun_fd, &readfds)) {
            nread = read(tun_fd, buffer + 1, sizeof(buffer) - 1);
            if (nread > 0) {
                struct iphdr *ip_header = (struct iphdr *)(buffer + 1);

                if (ip_header->version == 4) {
                    uint8_t index = ntohl(ip_header->daddr) & 0xFF;

                    if (clients[index].active == 1) {
                        // 1. Attach the DATA magic byte
                        buffer[0] = 0x00;

                        // 2. ENCRYPT THE WHOLE PAYLOAD (Magic Byte + IP Packet)
                        encrypt_decrypt(buffer, nread + 1);

                        // 3. Send it to the client
                        sendto(udp_fd, buffer, nread + 1, 0, (struct sockaddr *)&clients[index].public_addr, sizeof(struct sockaddr_in));
                    }
                }
            }
        }
    }
}

int main() {
    char tun_name[IFNAMSIZ] = "tun0";
    int tun_fd = tun_alloc(tun_name);
    setup_kernel_nat();
    int udp_fd = setup_udp_server();

    run_server_tunnel(tun_fd, udp_fd);

    close(tun_fd);
    close(udp_fd);
    return 0;
}
