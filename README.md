# 🛡️ Custom Layer 3 VPN in C
A lightweight, multi-client Layer 3 Virtual Private Network (VPN) built entirely from scratch in C. This project demonstrates core networking concepts, including virtual network interfaces (TUN), dynamic IP allocation, Linux kernel routing, NAT traversal, and symmetric stream encryption.

## ✨ Features
Multi-Client Architecture: Supports up to 253 concurrent clients dynamically using a custom built-in DHCP-style handshake.

Layer 3 Tunneling: Routes raw IPv4 packets using the Linux /dev/net/tun interface.

Symmetric Encryption: Secures all UDP transport traffic and handshake negotiations using a fast XOR cipher.

Roaming Support: Dynamically updates client mappings (IP/Port) to handle seamless network transitions (e.g., switching from Wi-Fi to Cellular).

Automatic Routing & DNS: The client automatically configures the OS routing table to prevent routing loops and temporarily hijacks DNS to prevent leaks.

Dead Peer Detection: Built-in server garbage collector reclaims inactive Virtual IPs after a timeout period.

## 🏗️ How It Works (Architecture)
This VPN relies on a dedicated, encrypted UDP control and data channel. The heavy lifting of routing and stateful tracking is delegated to the Linux Kernel.

### 1. The Handshake (Dynamic IP Allocation)
The Client establishes an encrypted UDP connection with the Server.

The Client sends a [0x01] Magic Byte request asking for a Virtual IP.

The Server scans its internal IP pool, finds an available 10.8.0.x address, maps it to the client's public IP/Port, and replies with a [0x02] Magic Byte and the assigned index.

### 2. The Client-Side Flow (Outbound)
The Client uses system() calls to create the tun0 interface with the assigned IP.

It modifies the OS routing table to redirect all internet traffic into tun0—except the VPN's own UDP traffic, which is routed through the physical gateway to prevent a routing loop.

The C program reads naked IP packets from tun0, attaches a [0x00] Data byte, encrypts the payload via XOR, and fires it to the server over the physical eth0 interface via UDP.

### 3. The Server-Side Flow (NAT & Return)
The Server receives the encrypted UDP packet, decrypts it, and verifies the mapping.

It unwraps the raw IP packet and writes it to its own tun0 interface.

The Server's Linux Kernel takes over. Using iptables MASQUERADE (NAT), it swaps the client's 10.8.0.x source IP with the server's public IP and forwards it to the open internet.

When the internet replies, the Kernel's connection tracker (conntrack) reverse-NATs the packet back to the 10.8.0.x destination and pushes it out of tun0.

The Server's C program reads the reply, looks up the specific client's real-world IP/Port in its state array, encrypts the payload, and sends the UDP packet back to the client.

### 4. The Client-Side Flow (Inbound)
The Client receives the encrypted UDP packet on its physical eth0 interface.

It decrypts the payload, strips the Magic Byte, and writes the raw IP packet back into its tun0 interface.

The OS delivers the packet to the local application (e.g., the web browser).

## 🚀 Getting Started

### Prerequisites
Two Linux machines (e.g., VMs, VPS, or physical hardware).

gcc compiler installed.

root (sudo) privileges on both machines (required for creating TUN interfaces and modifying routing tables).

## 🛠️ Compilation

### On the Server:

```bash
# Compile the main server and the DHCP logic
gcc server.c dhcp.c -o server
```

### On the Client:

```bash
# Compile the main client and the DHCP request logic
gcc client.c dhcp_client.c -o client
```
Note: Before compiling the client, ensure you edit consts.h and update SERVER_IP to match your server's actual public or local network IP address.

## 🏃‍♂️ Usage

**1. Start the Server:**

```bash
sudo ./server
```

The server will automatically configure iptables NAT rules and enable IPv4 forwarding.

**2. Start the Client:**

```bash
sudo ./client
```

The client will perform the handshake, receive its IP, configure its routing table, backup your DNS, and begin tunneling.

**3. Stop the Client:**

Press Ctrl+C. The client includes a signal handler that will safely restore your original /etc/resolv.conf DNS settings before exiting.

## ⚠️ Disclaimer

Educational Purposes Only. The XOR cipher implemented in this project is used to demonstrate the mechanics of symmetric stream encryption. It is not cryptographically secure against modern attacks. Do not use this VPN to transmit sensitive data over untrusted networks. For production-grade security, the XOR function should be replaced with a robust library like libsodium (ChaCha20-Poly1305).
