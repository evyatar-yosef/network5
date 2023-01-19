#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_BUF_LEN 100

int main(int argc, char *argv[]) {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    char buffer[MAX_BUF_LEN];
    socklen_t addrlen;
    int opt = 1;
    int recv_bytes, sent_bytes;

    if (argc < 3) {
        printf("Usage: %s <ip address> <port number>\n", argv[0]);
        exit(1);
    }

    // Create socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    // Set socket options
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        exit(1);
    }

    // Set server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(atoi(argv[2]));

    // Bind socket to address
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        exit(1);
    }

    srand(time(NULL));
    while (1) {
        addrlen = sizeof(client_addr);
        memset(buffer, 0, MAX_BUF_LEN);

        // Receive data from client
        recv_bytes = recvfrom(sockfd, buffer, MAX_BUF_LEN, 0, (struct sockaddr *)&client_addr, &addrlen);
        if (recv_bytes < 0) {
            perror("recvfrom");
            exit(1);
        }
        printf("Received %d bytes from %s:%d\n", recv_bytes, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        // Send data back to client with 50% probability
        if (((float)rand() / (float)RAND_MAX) > 0.5) {
            sent_bytes = sendto(sockfd, buffer, recv_bytes, 0, (struct sockaddr *)&client_addr, addrlen);
            if (sent_bytes < 0) {
                perror("sendto");
                exit(1);
            }
        }
    }
}    
