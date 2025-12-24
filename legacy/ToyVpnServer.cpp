/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>

#include <map>
#include <string>
#include <vector>

#ifdef __linux__

#include <net/if.h>
#include <linux/if_tun.h>

static int get_interface(char *name)
{
    int interface = open("/dev/net/tun", O_RDWR | O_NONBLOCK);

    ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

    if (ioctl(interface, TUNSETIFF, &ifr)) {
        perror("Cannot get TUN interface");
        exit(1);
    }

    return interface;
}

#else

#error Sorry, you have to implement this part by yourself.

#endif

static int create_socket(char *port)
{
    int tunnel = socket(AF_INET6, SOCK_DGRAM, 0);
    int flag = 1;
    setsockopt(tunnel, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    flag = 0;
    setsockopt(tunnel, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag));

    sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(atoi(port));

    while (bind(tunnel, (sockaddr *)&addr, sizeof(addr))) {
        if (errno != EADDRINUSE) {
            return -1;
        }
        usleep(100000);
    }

    return tunnel;
}

static void build_parameters(char *parameters, int size, int argc, char **argv)
{
    int offset = 0;
    for (int i = 4; i < argc; ++i) {
        char *parameter = argv[i];
        int length = strlen(parameter);
        char delimiter = ',';

        if (length == 2 && parameter[0] == '-') {
            ++parameter;
            --length;
            delimiter = ' ';
        }

        if (offset + length >= size) {
            puts("Parameters are too large");
            exit(1);
        }

        parameters[offset] = delimiter;
        memcpy(&parameters[offset + 1], parameter, length);
        offset += 1 + length;
    }

    memset(&parameters[offset], ' ', size - offset);
    parameters[0] = 0;
}

// Build parameters with client-specific IP address
static void build_client_parameters(char *parameters, int size, uint32_t client_ip, int argc, char **argv)
{
    int offset = 0;

    // Convert client IP to string (network byte order to host byte order)
    struct in_addr addr;
    addr.s_addr = client_ip;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

    printf("DEBUG: Generating parameters with IP: %s\n", ip_str);

    for (int i = 4; i < argc; ++i) {
        char *original_param = argv[i];
        char *parameter = original_param;
        int length = strlen(parameter);
        char delimiter = ',';

        if (length == 2 && parameter[0] == '-') {
            ++parameter;
            --length;
            delimiter = ' ';
        }

        printf("DEBUG: Processing parameter: %s\n", parameter);

        // Check if this is the address parameter flag '-a' or direct 'a,'
        if (length == 1 && parameter[0] == 'a') {
            // This is '-a' flag format, next two args are IP and prefix
            if (i + 2 < argc) {
                char new_param[128];
                snprintf(new_param, sizeof(new_param), "a,%s,32", ip_str);
                int new_length = strlen(new_param);

                printf("DEBUG: Replacing -a flag address with: %s\n", new_param);

                if (offset + new_length >= size) {
                    puts("Parameters are too large");
                    exit(1);
                }

                parameters[offset] = delimiter;
                memcpy(&parameters[offset + 1], new_param, new_length);
                offset += 1 + new_length;

                // Skip next two arguments (IP and prefix)
                i += 2;
                continue;
            }
        } else if (length >= 2 && parameter[0] == 'a' && parameter[1] == ',') {
            // Direct 'a,IP,prefix' format
            char new_param[128];
            snprintf(new_param, sizeof(new_param), "a,%s,32", ip_str);
            int new_length = strlen(new_param);

            printf("DEBUG: Replacing address parameter with: %s\n", new_param);

            if (offset + new_length >= size) {
                puts("Parameters are too large");
                exit(1);
            }

            parameters[offset] = delimiter;
            memcpy(&parameters[offset + 1], new_param, new_length);
            offset += 1 + new_length;
            continue;
        }

        // Normal parameter - copy as is
        if (offset + length >= size) {
            puts("Parameters are too large");
            exit(1);
        }

        parameters[offset] = delimiter;
        memcpy(&parameters[offset + 1], parameter, length);
        offset += 1 + length;
    }

    memset(&parameters[offset], ' ', size - offset);
    parameters[0] = 0;

    printf("DEBUG: Final parameters: %s\n", parameters + 1);
}

//-----------------------------------------------------------------------------

struct Session {
    sockaddr_storage addr;
    socklen_t addrlen;
    uint32_t virtual_ip;
    time_t last_active;
};

int main(int argc, char **argv)
{
    if (argc < 5) {
        printf("Usage: %s <tunN> <port> <secret> options...\n", argv[0]);
        exit(1);
    }

    int interface = get_interface(argv[1]);
    int tunnel = create_socket(argv[2]);
    if (tunnel < 0) {
        perror("Cannot create socket");
        exit(1);
    }

    char *secret = argv[3];
    std::map<std::string, Session> sessions;
    std::map<uint32_t, std::string> routing_table;

    // IP allocation state - start from 172.31.0.2, increment for each client
    // Parse base IP from parameters to determine starting point
    uint32_t next_available_ip = 0;
    for (int i = 4; i < argc; ++i) {
        if (strncmp(argv[i], "a,", 2) == 0) {
            // Found address parameter like "a,172.31.0.2,32"
            char ip_str[32];
            const char *comma = strchr(argv[i] + 2, ',');
            if (comma) {
                size_t len = comma - (argv[i] + 2);
                if (len < sizeof(ip_str)) {
                    memcpy(ip_str, argv[i] + 2, len);
                    ip_str[len] = '\0';
                    struct in_addr addr;
                    if (inet_pton(AF_INET, ip_str, &addr) == 1) {
                        next_available_ip = addr.s_addr;
                        printf("Starting IP allocation from: %s\n", ip_str);
                    }
                }
            }
            break;
        }
    }

    if (next_available_ip == 0) {
        // Default to 172.31.0.2 if not specified
        struct in_addr addr;
        inet_pton(AF_INET, "172.31.0.2", &addr);
        next_available_ip = addr.s_addr;
        printf("Using default starting IP: 172.31.0.2\n");
    }

    // Put the tunnel into non-blocking mode.
    fcntl(tunnel, F_SETFL, O_NONBLOCK);

    struct pollfd fds[2];
    fds[0].fd = interface;
    fds[0].events = POLLIN;
    fds[1].fd = tunnel;
    fds[1].events = POLLIN;

    char packet[32767];
    time_t last_prune = time(NULL);

    while (true) {
        int ret = poll(fds, 2, 1000);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }

        time_t now = time(NULL);

        // Read from TUN interface (Packets going TO clients)
        if (fds[0].revents & POLLIN) {
            int length = read(interface, packet, sizeof(packet));
            if (length > 0) {
                struct iphdr *ip = (struct iphdr *)packet;
                if (ip->version == 4) {
                    uint32_t dest_ip = ip->daddr;
                    char dest_ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &dest_ip, dest_ip_str, sizeof(dest_ip_str));

                    if (routing_table.count(dest_ip)) {
                        Session &s = sessions[routing_table[dest_ip]];

                        char src_ip_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &ip->saddr, src_ip_str, sizeof(src_ip_str));

                        printf("[TUN->Client] Routing packet: %s -> %s (%d bytes)\n",
                               src_ip_str, dest_ip_str, length);

                        sendto(tunnel, packet, length, MSG_NOSIGNAL, (sockaddr *)&s.addr, s.addrlen);
                        s.last_active = now;
                    } else {
                        printf("[TUN->Client] No route found for destination: %s (dropped)\n", dest_ip_str);
                    }
                }
            }
        }

        // Read from Socket (Packets coming FROM clients)
        if (fds[1].revents & POLLIN) {
            sockaddr_storage client_addr;
            memset(&client_addr, 0, sizeof(client_addr));
            socklen_t addrlen = sizeof(client_addr);
            int length = recvfrom(tunnel, packet, sizeof(packet), 0, (sockaddr *)&client_addr, &addrlen);

            if (length > 0) {
                // Use only the relevant part of the address for the key
                std::string addr_key((char *)&client_addr, addrlen);
                
                if (packet[0] == 0) {
                    // Control message
                    if (length > 1 && (unsigned char)packet[1] == 0xFF) {
                        // Disconnect
                        if (sessions.count(addr_key)) {
                            char ip_str[INET6_ADDRSTRLEN];
                            void *src_addr;
                            if (client_addr.ss_family == AF_INET) {
                                src_addr = &((struct sockaddr_in *)&client_addr)->sin_addr;
                            } else {
                                src_addr = &((struct sockaddr_in6 *)&client_addr)->sin6_addr;
                            }
                            inet_ntop(client_addr.ss_family, src_addr, ip_str, sizeof(ip_str));
                            printf("Client disconnected: %s\n", ip_str);
                            
                            routing_table.erase(sessions[addr_key].virtual_ip);
                            sessions.erase(addr_key);
                        }
                    } else if (strcmp(secret, &packet[1]) == 0) {
                        // Handshake
                        bool is_new_session = (sessions.find(addr_key) == sessions.end());
                        Session &s = sessions[addr_key];
                        s.addr = client_addr;
                        s.addrlen = addrlen;
                        s.last_active = now;

                        char ip_str[INET6_ADDRSTRLEN];
                        void *src_addr;
                        int port;
                        if (client_addr.ss_family == AF_INET) {
                            src_addr = &((struct sockaddr_in *)&client_addr)->sin_addr;
                            port = ntohs(((struct sockaddr_in *)&client_addr)->sin_port);
                        } else {
                            src_addr = &((struct sockaddr_in6 *)&client_addr)->sin6_addr;
                            port = ntohs(((struct sockaddr_in6 *)&client_addr)->sin6_port);
                        }
                        inet_ntop(client_addr.ss_family, src_addr, ip_str, sizeof(ip_str));

                        // Allocate a new virtual IP if this is a new session
                        if (is_new_session || s.virtual_ip == 0) {
                            // Find next available IP (skip already allocated ones)
                            uint32_t candidate_ip = next_available_ip;
                            while (routing_table.count(candidate_ip) > 0) {
                                // Increment IP address in network byte order
                                uint32_t host_order = ntohl(candidate_ip);
                                host_order++;
                                candidate_ip = htonl(host_order);
                            }

                            // Clean up old routing entry if IP changed
                            if (s.virtual_ip != 0 && s.virtual_ip != candidate_ip) {
                                routing_table.erase(s.virtual_ip);
                            }

                            s.virtual_ip = candidate_ip;
                            routing_table[candidate_ip] = addr_key;

                            // Update next_available_ip for next client
                            uint32_t host_order = ntohl(candidate_ip);
                            host_order++;
                            next_available_ip = htonl(host_order);

                            char virtual_ip_str[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &s.virtual_ip, virtual_ip_str, sizeof(virtual_ip_str));
                            printf("New client handshake from %s:%d - Assigned virtual IP: %s\n",
                                   ip_str, port, virtual_ip_str);
                        } else {
                            char virtual_ip_str[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &s.virtual_ip, virtual_ip_str, sizeof(virtual_ip_str));
                            printf("Reconnecting client from %s:%d - Keeping virtual IP: %s\n",
                                   ip_str, port, virtual_ip_str);
                        }

                        // Build and send client-specific parameters
                        char client_parameters[1024];
                        build_client_parameters(client_parameters, sizeof(client_parameters),
                                              s.virtual_ip, argc, argv);

                        for (int i = 0; i < 3; ++i) {
                            sendto(tunnel, client_parameters, sizeof(client_parameters),
                                   MSG_NOSIGNAL, (sockaddr *)&client_addr, addrlen);
                        }
                    }
                } else {
                    // Data packet
                    if (sessions.count(addr_key)) {
                        Session &s = sessions[addr_key];
                        s.last_active = now;

                        struct iphdr *ip = (struct iphdr *)packet;
                        if (ip->version == 4) {
                            char src_ip_str[INET_ADDRSTRLEN];
                            char dst_ip_str[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &ip->saddr, src_ip_str, sizeof(src_ip_str));
                            inet_ntop(AF_INET, &ip->daddr, dst_ip_str, sizeof(dst_ip_str));

                            // Verify the source IP matches assigned virtual IP
                            if (s.virtual_ip != 0 && s.virtual_ip != ip->saddr) {
                                char expected_ip_str[INET_ADDRSTRLEN];
                                inet_ntop(AF_INET, &s.virtual_ip, expected_ip_str, sizeof(expected_ip_str));
                                printf("[Client->TUN] WARNING: Source IP mismatch! Expected %s, got %s (dropped)\n",
                                       expected_ip_str, src_ip_str);
                            } else {
                                // Learn/Update routing if not yet set
                                if (s.virtual_ip != ip->saddr) {
                                    if (s.virtual_ip != 0) routing_table.erase(s.virtual_ip);
                                    s.virtual_ip = ip->saddr;
                                    routing_table[s.virtual_ip] = addr_key;

                                    printf("Routing learned: Virtual IP %s -> Client Session\n", src_ip_str);
                                }

                                printf("[Client->TUN] Forwarding packet: %s -> %s (%d bytes)\n",
                                       src_ip_str, dst_ip_str, length);

                                if (write(interface, packet, length) < 0) {
                                    perror("write to tun");
                                }
                            }
                        }
                    } else {
                        printf("[Client->TUN] Packet from unknown session (dropped)\n");
                    }
                }
            }
        }

        // Prune inactive sessions every 10 seconds
        if (now - last_prune > 10) {
            for (auto it = sessions.begin(); it != sessions.end(); ) {
                if (now - it->second.last_active > 60) {
                    printf("Pruning inactive session: %s\n", it->first.c_str());
                    routing_table.erase(it->second.virtual_ip);
                    it = sessions.erase(it);
                } else {
                    ++it;
                }
            }
            last_prune = now;
        }
    }

    return 0;
}