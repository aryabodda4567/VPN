#ifndef CONSTS_H
#define CONSTS_H

#define MTU 1400
#define SERVER_IP "192.168.44.135"   // Your Server's IP
#define SERVER_PORT 5555             // Your Server's Port
#define LOCAL_GATEWAY "192.168.44.2" // Your Client's Physical Router IP
#define PHYSICAL_IF "eth0"           // Your Client's Physical Interface

// We define the prefix so the DHCP client can append the assigned number
#define TUN_SUBNET_PREFIX "10.8.0"

#endif
