/*
 * Educational Packet Sniffer - For network understanding and educational purposes only
 * This tool is designed for learning network protocols and packet analysis
 * Use only on networks you own or have explicit permission to monitor
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <time.h>
#include <errno.h>
#include <signal.h>

#define BUFFER_SIZE 65536
#define CLIENT_PORT 8888
#define MAX_CLIENTS 5

struct packet_stats {
    unsigned long total_packets;
    unsigned long tcp_packets;
    unsigned long udp_packets;
    unsigned long icmp_packets;
    unsigned long other_packets;
    unsigned long bytes_captured;
};

struct packet_info {
    char timestamp[32];
    char src_mac[18];
    char dst_mac[18];
    char src_ip[16];
    char dst_ip[16];
    int src_port;
    int dst_port;
    char protocol[16];
    int packet_size;
    int ttl;
    char flags[32];
    unsigned char *data;
    int data_len;
};

int raw_socket;
int server_socket;
int running = 1;
int client_fds[MAX_CLIENTS];
struct packet_stats stats = {0};

void signal_handler(int sig) {
    (void)sig;
    running = 0;
    printf("\nPackets captured: %lu\n", stats.total_packets);
    printf("Total bytes: %lu\n", stats.bytes_captured);
    if (raw_socket) close(raw_socket);
    if (server_socket) close(server_socket);
    exit(0);
}

void get_timestamp(char *buffer) {
    struct timeval tv;
    struct tm *timeinfo;
    gettimeofday(&tv, NULL);
    timeinfo = localtime(&tv.tv_sec);
    snprintf(buffer, 32, "%02d:%02d:%02d.%03ld",
        timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, tv.tv_usec/1000);
}

void format_mac_address(unsigned char *mac, char *buffer) {
    snprintf(buffer, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void get_tcp_flags(struct tcphdr *tcp, char *buffer) {
    buffer[0] = '\0';
    if (tcp->syn) strcat(buffer, "SYN ");
    if (tcp->ack) strcat(buffer, "ACK ");
    if (tcp->fin) strcat(buffer, "FIN ");
    if (tcp->rst) strcat(buffer, "RST ");
    if (tcp->psh) strcat(buffer, "PSH ");
    if (tcp->urg) strcat(buffer, "URG ");
    if (strlen(buffer) > 0) buffer[strlen(buffer)-1] = '\0';
}

void parse_packet(unsigned char *buffer, int size, struct packet_info *info) {
    struct ethhdr *eth = (struct ethhdr*)buffer;
    struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));

    info->packet_size = size;
    get_timestamp(info->timestamp);

    format_mac_address(eth->h_source, info->src_mac);
    format_mac_address(eth->h_dest, info->dst_mac);

    if (ntohs(eth->h_proto) == ETH_P_IP) {
        strcpy(info->src_ip, inet_ntoa(*(struct in_addr*)&ip->saddr));
        strcpy(info->dst_ip, inet_ntoa(*(struct in_addr*)&ip->daddr));
        info->ttl = ip->ttl;

        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + (ip->ihl * 4));
            strcpy(info->protocol, "TCP");
            info->src_port = ntohs(tcp->source);
            info->dst_port = ntohs(tcp->dest);
            get_tcp_flags(tcp, info->flags);
            stats.tcp_packets++;

            int header_size = sizeof(struct ethhdr) + (ip->ihl * 4) + (tcp->doff * 4);
            info->data = buffer + header_size;
            info->data_len = size - header_size;
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr*)(buffer + sizeof(struct ethhdr) + (ip->ihl * 4));
            strcpy(info->protocol, "UDP");
            info->src_port = ntohs(udp->source);
            info->dst_port = ntohs(udp->dest);
            strcpy(info->flags, "");
            stats.udp_packets++;

            int header_size = sizeof(struct ethhdr) + (ip->ihl * 4) + sizeof(struct udphdr);
            info->data = buffer + header_size;
            info->data_len = size - header_size;
        } else if (ip->protocol == IPPROTO_ICMP) {
            struct icmphdr *icmp = (struct icmphdr*)(buffer + sizeof(struct ethhdr) + (ip->ihl * 4));
            strcpy(info->protocol, "ICMP");
            info->src_port = icmp->type;
            info->dst_port = icmp->code;
            snprintf(info->flags, 32, "Type:%d Code:%d", icmp->type, icmp->code);
            stats.icmp_packets++;

            int header_size = sizeof(struct ethhdr) + (ip->ihl * 4) + sizeof(struct icmphdr);
            info->data = buffer + header_size;
            info->data_len = size - header_size;
        } else {
            snprintf(info->protocol, 16, "IP(%d)", ip->protocol);
            info->src_port = 0;
            info->dst_port = 0;
            strcpy(info->flags, "");
            stats.other_packets++;

            int header_size = sizeof(struct ethhdr) + (ip->ihl * 4);
            info->data = buffer + header_size;
            info->data_len = size - header_size;
        }
    } else {
        strcpy(info->protocol, "NON-IP");
        strcpy(info->src_ip, "");
        strcpy(info->dst_ip, "");
        info->src_port = 0;
        info->dst_port = 0;
        info->ttl = 0;
        strcpy(info->flags, "");
        stats.other_packets++;

        info->data = buffer + sizeof(struct ethhdr);
        info->data_len = size - sizeof(struct ethhdr);
    }

    stats.total_packets++;
    stats.bytes_captured += size;
}

char* format_hex_dump(unsigned char *data, int len, int max_bytes) {
    static char hex_buffer[2048];
    char *ptr = hex_buffer;
    int bytes_to_show = (len > max_bytes) ? max_bytes : len;

    for (int i = 0; i < bytes_to_show; i++) {
        if (i > 0 && i % 16 == 0) {
            ptr += sprintf(ptr, "\n                    ");
        } else if (i > 0 && i % 8 == 0) {
            ptr += sprintf(ptr, "  ");
        } else if (i > 0) {
            ptr += sprintf(ptr, " ");
        }
        ptr += sprintf(ptr, "%02x", data[i]);
    }

    if (len > max_bytes) {
        ptr += sprintf(ptr, "... (%d more bytes)", len - max_bytes);
    }

    return hex_buffer;
}

int setup_server() {
    int sock, opt = 1;
    struct sockaddr_in server_addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Server socket creation failed");
        return -1;
    }

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(CLIENT_PORT);

    if (bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sock);
        return -1;
    }

    if (listen(sock, MAX_CLIENTS) < 0) {
        perror("Listen failed");
        close(sock);
        return -1;
    }

    printf("Packet sniffer listening on port %d\n", CLIENT_PORT);
    return sock;
}

void send_to_clients(struct packet_info *info) {
    char message[4096];
    char port_info[64];

    if (strcmp(info->protocol, "TCP") == 0 || strcmp(info->protocol, "UDP") == 0) {
        snprintf(port_info, 64, ":%d -> %s:%d", info->src_port, info->dst_ip, info->dst_port);
    } else if (strcmp(info->protocol, "ICMP") == 0) {
        snprintf(port_info, 64, " -> %s", info->dst_ip);
    } else {
        snprintf(port_info, 64, " -> %s", info->dst_ip);
    }

    int header_len = snprintf(message, sizeof(message),
        "PACKET|%s|%s|%s|%s%s|%s|%d|TTL:%d|%s\n",
        info->timestamp, info->src_mac, info->dst_mac,
        info->src_ip, port_info, info->protocol,
        info->packet_size, info->ttl, info->flags);

    if (info->data_len > 0) {
        char *hex = format_hex_dump(info->data, info->data_len, 64);
        snprintf(message + header_len, sizeof(message) - header_len,
            "HEXDATA|%s\n", hex);
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (client_fds[i] > 0) {
            if (send(client_fds[i], message, strlen(message), MSG_NOSIGNAL) < 0) {
                close(client_fds[i]);
                client_fds[i] = 0;
            }
        }
    }
}

void send_stats_to_clients() {
    char stats_msg[512];
    snprintf(stats_msg, sizeof(stats_msg),
        "STATS|Total:%lu|TCP:%lu|UDP:%lu|ICMP:%lu|Other:%lu|Bytes:%lu\n",
        stats.total_packets, stats.tcp_packets, stats.udp_packets,
        stats.icmp_packets, stats.other_packets, stats.bytes_captured);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (client_fds[i] > 0) {
            send(client_fds[i], stats_msg, strlen(stats_msg), MSG_NOSIGNAL);
        }
    }
}

int main() {
    unsigned char buffer[BUFFER_SIZE];
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    struct packet_info packet;
    time_t last_stats = time(NULL);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_fds[i] = 0;
    }

    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_socket < 0) {
        perror("Raw socket creation failed. Run as root");
        return 1;
    }

    server_socket = setup_server();
    if (server_socket < 0) {
        close(raw_socket);
        return 1;
    }

    printf("Packet sniffer started. Press Ctrl+C to stop.\n");

    while (running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(server_socket, &read_fds);
        FD_SET(raw_socket, &read_fds);

        int max_fd = (server_socket > raw_socket) ? server_socket : raw_socket;

        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);

        if (activity < 0 && errno != EINTR) {
            perror("Select error");
            break;
        }

        if (FD_ISSET(server_socket, &read_fds)) {
            int new_client = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
            if (new_client >= 0) {
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (client_fds[i] == 0) {
                        client_fds[i] = new_client;
                        printf("Client connected: %s\n", inet_ntoa(client_addr.sin_addr));
                        break;
                    }
                }
            }
        }

        if (FD_ISSET(raw_socket, &read_fds)) {
            int packet_size = recv(raw_socket, buffer, BUFFER_SIZE, 0);
            if (packet_size > 0) {
                parse_packet(buffer, packet_size, &packet);

                printf("%s [%s] %s -> %s (%s) %d bytes\n",
                    packet.timestamp, packet.protocol, packet.src_ip,
                    packet.dst_ip, packet.flags, packet.packet_size);

                send_to_clients(&packet);
            }
        }

        if (time(NULL) - last_stats >= 5) {
            send_stats_to_clients();
            last_stats = time(NULL);
        }
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (client_fds[i] > 0) close(client_fds[i]);
    }
    close(server_socket);
    close(raw_socket);
    return 0;
}