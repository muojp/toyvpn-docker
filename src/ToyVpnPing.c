/*
 * ToyVpnPing.c
 * A simple client to ping through ToyVpnServer for performance testing.
 *
 * Usage: ./ToyVpnPing <server_ip> <server_port> <secret> <local_virtual_ip> <remote_virtual_ip>
 * Example: ./ToyVpnPing 127.0.0.1 8000 test 10.0.0.2 10.0.0.1
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>

#define PACKET_SIZE 4096
#define PAYLOAD_SIZE 64

static volatile int keep_running = 1;

void handle_sigint(int sig) {
    keep_running = 0;
}

// Checksum calculation function
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main(int argc, char *argv[]) {
    if (argc != 6) {
        printf("Usage: %s <server_ip> <server_port> <secret> <local_virtual_ip> <remote_virtual_ip>\n", argv[0]);
        return 1;
    }

    char *server_ip = argv[1];
    int server_port = atoi(argv[2]);
    char *secret = argv[3];
    char *local_vip = argv[4];
    char *remote_vip = argv[5];

    int sock;
    struct sockaddr_in server_addr;

    // Create UDP socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(server_ip, NULL, &hints, &res) != 0) {
        perror("getaddrinfo");
        return 1;
    }
    server_addr.sin_addr = ((struct sockaddr_in *)(res->ai_addr))->sin_addr;
    freeaddrinfo(res);

    // --- Handshake ---
    // Protocol: 0x00 + secret string
    char handshake[1024];
    handshake[0] = 0;
    // Copy secret starting at index 1
    strncpy(handshake + 1, secret, sizeof(handshake) - 2);
    int handshake_len = 1 + strlen(secret) + 1; // +1 for null terminator to be safe

    printf("Connecting to %s:%d with secret '%s'...\n", server_ip, server_port, secret);
    if (sendto(sock, handshake, handshake_len, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("sendto handshake");
        return 1;
    }

    // Wait for server parameters to confirm connection
    // The server sends parameters (packet starting with 0) 3 times.
    printf("Waiting for server response...\n");
    fd_set readfds;
    struct timeval tv_handshake;
    tv_handshake.tv_sec = 2;
    tv_handshake.tv_usec = 0;
    
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);
    
    int ret = select(sock + 1, &readfds, NULL, NULL, &tv_handshake);
    if (ret > 0) {
        char param_buf[1024];
        ssize_t n = recvfrom(sock, param_buf, sizeof(param_buf), 0, NULL, NULL);
        if (n > 0 && param_buf[0] == 0) {
            // Ensure null termination for printing
            param_buf[n < 1023 ? n : 1023] = 0;
            printf("Connection established. Server parameters: %s\n", param_buf + 1);
        } else {
            fprintf(stderr, "Error: Received unexpected packet during handshake\n");
            return 1;
        }
    } else if (ret == 0) {
        fprintf(stderr, "Error: Timeout waiting for handshake response from server\n");
        return 1;
    } else {
        perror("select");
        return 1;
    }

    // Set receive timeout for ping loop
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    int seq = 0;
    char buffer[PACKET_SIZE];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    printf("Starting ping to virtual IP %s...\n", remote_vip);
    
    // Register signal handler
    signal(SIGINT, handle_sigint);

    // --- Ping Loop ---
    while (keep_running) {
        char packet[PACKET_SIZE];
        struct ip *ip_header = (struct ip *)packet;
        struct icmp *icmp_header = (struct icmp *)(packet + sizeof(struct ip));

        // 1. Build IP Header (We are creating a raw IP packet to be encapsulated in UDP)
        ip_header->ip_hl = 5;
        ip_header->ip_v = 4;
        ip_header->ip_tos = 0;
        ip_header->ip_len = htons(sizeof(struct ip) + sizeof(struct icmp) + PAYLOAD_SIZE);
        ip_header->ip_id = htons(seq + 1000);
        ip_header->ip_off = htons(0); // or 0
        ip_header->ip_ttl = 64;
        ip_header->ip_p = IPPROTO_ICMP;
        ip_header->ip_sum = 0;
        inet_pton(AF_INET, local_vip, &ip_header->ip_src);
        inet_pton(AF_INET, remote_vip, &ip_header->ip_dst);

        // Calculate IP Checksum
        ip_header->ip_sum = checksum(ip_header, sizeof(struct ip));

        // 2. Build ICMP Header
        icmp_header->icmp_type = ICMP_ECHO;
        icmp_header->icmp_code = 0;
        icmp_header->icmp_id = htons(0x1234);
        icmp_header->icmp_seq = htons(seq);
        memset(packet + sizeof(struct ip) + sizeof(struct icmp), 'A', PAYLOAD_SIZE); // Payload
        icmp_header->icmp_cksum = 0;
        // Calculate ICMP Checksum (Header + Data)
        icmp_header->icmp_cksum = checksum(icmp_header, sizeof(struct icmp) + PAYLOAD_SIZE);

        // 3. Send Packet
        struct timeval start, end;
        gettimeofday(&start, NULL);
        
        int total_len = sizeof(struct ip) + sizeof(struct icmp) + PAYLOAD_SIZE;
        ssize_t sent = sendto(sock, packet, total_len, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
        if (sent < 0) {
            perror("sendto");
        }

        // 4. Receive Loop (Wait for reply)
        int received = 0;
        while (1) {
            ssize_t recvd = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&from_addr, &from_len);
            gettimeofday(&end, NULL);
            
            if (recvd < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    if (keep_running) printf("Request timeout for seq %d\n", seq);
                } else if (keep_running) {
                    perror("recvfrom");
                }
                break;
            }

            // ToyVpn Control Messages start with 0
            if (buffer[0] == 0) {
                continue; // Ignore control messages
            }

            // Parse IP Packet
            struct ip *recv_ip = (struct ip *)buffer;
            
            // Check if it is ICMP
            if (recv_ip->ip_p == IPPROTO_ICMP) {
                int ip_hdr_len = recv_ip->ip_hl * 4;
                if (recvd < ip_hdr_len + sizeof(struct icmp)) continue; // Too short

                struct icmp *recv_icmp = (struct icmp *)(buffer + ip_hdr_len);
                
                // Check if it is our Echo Reply
                if (recv_icmp->icmp_type == ICMP_ECHOREPLY && 
                    recv_icmp->icmp_id == htons(0x1234) && 
                    recv_icmp->icmp_seq == htons(seq)) {
                    
                    double rtt = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;
                    printf("%zd bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n", 
                           recvd, remote_vip, seq, recv_ip->ip_ttl, rtt);
                    received = 1;
                    break;
                }
            }
        }

        seq++;
        if (keep_running) sleep(1);
    }

    // Send disconnect signal to server
    printf("\nDisconnecting from server...\n");
    char disconnect[2] = {0, (char)0xFF};
    sendto(sock, disconnect, 2, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));

    close(sock);
    return 0;
}
