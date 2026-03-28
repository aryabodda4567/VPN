#include "dhcp.h"
#include <stdio.h>

/*
 * Finds a free IP slot, registers the client, and returns the assigned index.
 * Returns -1 if the server is full.
 */
int allocate_ip(ClientMap *clients, struct sockaddr_in *client_addr) {
    time_t current_time = time(NULL);

    // Start at 2 (10.8.0.2) and stop at 254 (10.8.0.254)
    for (int i = 2; i < 255; i++) {
        if (clients[i].active == 0) {
            // Found a free slot! Claim it.
            clients[i].active = 1;
            clients[i].public_addr = *client_addr;
            clients[i].last_active = current_time;

            printf("[DHCP] Allocated 10.8.0.%d to new client.\n", i);
            return i; // Return the assigned index
        }
    }

    // If the loop finishes without returning, the server is completely full.
    printf("[DHCP] ERROR: IP pool exhausted. Cannot allocate new client.\n");
    return -1;
}
