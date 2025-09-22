#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <cstring>
#include <iostream>
#include <string>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <vector>
#include <regex>
#include <netinet/udp.h>
#include <netinet/ip.h>

void check_if_digit(std::string str) {
    for (char c : str) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            std::cerr << "non-numeric character in port\n";
            exit(0);
        }
    }
}

void check_in_range(int str) {
    if (str < 1 || str > 65535) {
        std::cerr << "port is out of range\n";
        exit(0);
    }
}

int main(int argc, char *argv[]) {
    /*
    *   Puzzle solver that takes in as arguments the IP address of the machine,
    *   and 4 ports to...
    */
    int port1 = 0;
    int port2 = 0;
    int port3 = 0;
    int port4 = 0;

    if (argc != 6) {
        std::cerr << "Command needs to be ./puzzlesolver [IP] [PORT 1] [PORT 2] [PORT 3] [PORT 4]\n";
        exit(0);
    }

    // IP ADDRESS is argument nr 1
    const char* ip_string = argv[1];

    // PORTS are arguments nr 2, 3, 4, 5
    std::string port1_str = argv[2];
    std::string port2_str = argv[3];
    std::string port3_str = argv[4];
    std::string port4_str = argv[5];

    // make sure all ports are just digits
    check_if_digit(port1_str);
    check_if_digit(port2_str);
    check_if_digit(port3_str);
    check_if_digit(port4_str);

    // turn ports into int
    int port1_parsed = std::stoi(port1_str);
    int port2_parsed = std::stoi(port2_str);
    int port3_parsed = std::stoi(port3_str);
    int port4_parsed = std::stoi(port4_str);

    // make sure they are in range (1 - 65535)
    check_in_range(port1_parsed);
    check_in_range(port2_parsed);
    check_in_range(port3_parsed);
    check_in_range(port4_parsed);

    // ports have been validated
    port1 = port1_parsed;
    port2 = port2_parsed;
    port3 = port3_parsed;
    port4 = port4_parsed;

    // Create socket
    int sock;
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(0);
    }

    // Set timeout for receiving responses to 1 second
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0; // 1 second
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt failed");
        close(sock);
        exit(0);
    }

    // 
    std::vector<int> ports = {port1, port2, port3, port4};
    std::vector<int> secret_ports;
    std::string secret_phrase;
    int final_port = 0;
    bool raw_socket_used = false;

    std::string default_message = "tester";

    for (int port : ports) {
        std::string response;
    }

    close(sock);
    return 0;
}