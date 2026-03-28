#ifndef DHCP_H
#define DHCP_H

#include <netinet/in.h>
#include <time.h>

// The structure representing a single client slot
typedef struct {
    int active;                      // 1 if in use, 0 if free
    struct sockaddr_in public_addr;  // The client's real-world IP and Port
    time_t last_active;              // Timestamp for the garbage collector
} ClientMap;

// Function prototype
int allocate_ip(ClientMap *clients, struct sockaddr_in *client_addr);

#endif
