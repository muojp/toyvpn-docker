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

    char parameters[1024];
    build_parameters(parameters, sizeof(parameters), argc, argv);

    int interface = get_interface(argv[1]);
    int tunnel = create_socket(argv[2]);
    if (tunnel < 0) {
        perror("Cannot create socket");
        exit(1);
    }

    char *secret = argv[3];
    std::map<std::string, Session> sessions;
    std::map<uint32_t, std::string> routing_table;

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
                    if (routing_table.count(dest_ip)) {
                        Session &s = sessions[routing_table[dest_ip]];
                        sendto(tunnel, packet, length, MSG_NOSIGNAL, (sockaddr *)&s.addr, s.addrlen);
                        s.last_active = now;
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
                        Session &s = sessions[addr_key];
                        s.addr = client_addr;
                        s.addrlen = addrlen;
                        s.last_active = now;
                        
                        char ip_str[INET6_ADDRSTRLEN];
                        void *src_addr;
                        if (client_addr.ss_family == AF_INET) {
                            src_addr = &((struct sockaddr_in *)&client_addr)->sin_addr;
                        } else {
                            src_addr = &((struct sockaddr_in6 *)&client_addr)->sin6_addr;
                        }
                        inet_ntop(client_addr.ss_family, src_addr, ip_str, sizeof(ip_str));
                        printf("New client handshake from %s\n", ip_str);

                        for (int i = 0; i < 3; ++i) {
                            sendto(tunnel, parameters, sizeof(parameters), MSG_NOSIGNAL, (sockaddr *)&client_addr, addrlen);
                        }
                    }
                } else {
                    // Data packet
                    if (sessions.count(addr_key)) {
                        Session &s = sessions[addr_key];
                        s.last_active = now;
                        
                        struct iphdr *ip = (struct iphdr *)packet;
                        if (ip->version == 4) {
                            // Learn/Update routing
                            if (s.virtual_ip != ip->saddr) {
                                if (s.virtual_ip != 0) routing_table.erase(s.virtual_ip);
                                s.virtual_ip = ip->saddr;
                                routing_table[s.virtual_ip] = addr_key;
                                
                                char vip_str[INET_ADDRSTRLEN];
                                inet_ntop(AF_INET, &ip->saddr, vip_str, sizeof(vip_str));
                                printf("Routing updated: Virtual IP %s -> Client Session\n", vip_str);
                            }
                            if (write(interface, packet, length) < 0) {
                                perror("write to tun");
                            }
                        }
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