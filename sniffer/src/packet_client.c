/*
 * Educational Packet Sniffer Client - For network understanding and educational purposes only
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#define BUFFER_SIZE 8192
#define DEFAULT_PORT 8888

int client_socket;
int running = 1;
int show_hex = 1;
int show_stats = 1;

void signal_handler(int sig) {
    (void)sig;
    running = 0;
    if (client_socket) close(client_socket);
    printf("\nClient disconnected\n");
    exit(0);
}

void print_packet_line(char* packet_data) {
    char timestamp[32], src_mac[18], dst_mac[18], src_dst[64], protocol[16], flags[32];
    int packet_size, ttl;

    if (sscanf(packet_data, "PACKET|%31[^|]|%17[^|]|%17[^|]|%63[^|]|%15[^|]|%d|TTL:%d|%31[^\n]",
               timestamp, src_mac, dst_mac, src_dst, protocol, &packet_size, &ttl, flags) >= 7) {

        printf("[%s] %s %s -> %s %s (%d bytes, TTL:%d) %s\n",
               timestamp, protocol, src_mac, dst_mac, src_dst, packet_size, ttl, flags);
    }
}

void print_hex_line(char* hex_data) {
    if (show_hex && strncmp(hex_data, "HEXDATA|", 8) == 0) {
        char *hex_content = hex_data + 8;
        printf("    HEX: %s\n", hex_content);
    }
}

void print_stats_line(char* stats_data) {
    unsigned long total, tcp, udp, icmp, other, bytes;

    if (sscanf(stats_data, "STATS|Total:%lu|TCP:%lu|UDP:%lu|ICMP:%lu|Other:%lu|Bytes:%lu",
               &total, &tcp, &udp, &icmp, &other, &bytes) == 6) {

        printf("STATS: Total: %lu | TCP: %lu | UDP: %lu | ICMP: %lu | Other: %lu | Bytes: %lu\n",
               total, tcp, udp, icmp, other, bytes);
        printf("----------------------------------------------------------------------\n");
    }
}

int connect_to_server(const char* server_ip, int port) {
    int sock;
    struct sockaddr_in server_addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid server IP address");
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection to server failed");
        close(sock);
        return -1;
    }

    return sock;
}

int main(int argc, char *argv[]) {
    char buffer[BUFFER_SIZE];
    int bytes_received;

    if (argc != 2) {
        printf("Usage: %s <server_ip>\n", argv[0]);
        printf("Example: %s 192.168.1.100\n", argv[0]);
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    client_socket = connect_to_server(argv[1], DEFAULT_PORT);
    if (client_socket < 0) {
        return 1;
    }

    printf("Connected to packet sniffer server at %s:%d\n", argv[1], DEFAULT_PORT);
    printf("Receiving packet data...\n");
    printf("----------------------------------------------------------------------\n");

    while (running) {
        bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);

        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';

            char *line = strtok(buffer, "\n");
            while (line != NULL) {
                if (strncmp(line, "PACKET|", 7) == 0) {
                    print_packet_line(line);
                } else if (strncmp(line, "HEXDATA|", 8) == 0) {
                    print_hex_line(line);
                } else if (strncmp(line, "STATS|", 6) == 0 && show_stats) {
                    print_stats_line(line);
                }
                line = strtok(NULL, "\n");
            }
            fflush(stdout);
        } else if (bytes_received == 0) {
            printf("Server disconnected\n");
            break;
        } else {
            perror("Receive failed");
            break;
        }
    }

    close(client_socket);
    return 0;
}