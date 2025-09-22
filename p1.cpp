// Thetta shit var ekki ad virka, svo eg setti thad i thetta skjal

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
#include <random>
#include <cctype>
#include <cstdlib>

// ========== Constants ==========
std::string usernames = "georg23,arnagud21";

// ========== Port Validation Helpers ==========
void check_if_digit(std::string str) {
    for (char c : str) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            std::cerr << "non-numeric character in port\n";
            exit(1);
        }
    }
}

void check_in_range(int str) {
    if (str < 1 || str > 65535) {
        std::cerr << "port is out of range\n";
        exit(1);
    }
}

// ========== UDP helpers ==========
static bool send_all_udp(int sock, const sockaddr_in &dst, const void *data, size_t len) {
    ssize_t n = sendto(sock, data, len, 0, (const sockaddr*)&dst, sizeof(dst));
    return n == (ssize_t)len;
}
static std::string recv_text(int sock, int ms_timeout) {
    timeval tv{ ms_timeout/1000, (ms_timeout%1000)*1000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char buf[2048];
    sockaddr_in from{};
    socklen_t fl = sizeof(from);

    ssize_t n = recvfrom(sock, buf, sizeof(buf) - 1, 0,
                         (struct sockaddr*)&from, &fl);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return {}; // timeout
        perror("recvfrom");
        return {};
    }
    buf[n] = 0;
    return std::string(buf);
}

    
// ========== Port Classification ==========
bool is_secret(const std::string& s){
    return s.find("Greetings from S.E.C.R.E.T.") != std::string::npos;
}
bool is_evil(const std::string& s){
    return s.find("I am an evil port") != std::string::npos;
}
bool is_checksum(const std::string& s){
    return s.find("Send me a 4-byte message containing the signature");
}
bool is_exps(const std::string& s){
    return s.find("E.X.P.S.T.N") != std::string::npos;
}

// ========== Secret Port Helper ==========
bool handle_secret(int sock, const char* ip, int port, uint32_t &out_groupID, uint32_t &out_signature, int &secret_port1) {

    // Destination
    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &dst.sin_addr) != 1) {
        std::cerr << "bad ip address: " << ip << "\n";
        return false;
    }

    // 1. Generate a secret number.
    std::random_device rd;
    uint32_t secret_number = rd();

    // 2. Construct the message (S, secret number and RU usernames) and send to the port.
    std::string msg;
    msg.push_back('S');
    uint32_t net_secret = htonl(secret_number);
    msg.append(reinterpret_cast<char*>(&net_secret), 4); 
    msg += usernames; 

    ssize_t sent = sendto(sock, msg.data(), msg.size(), 0, (struct sockaddr*)&dst, sizeof(dst));
    if (sent != (ssize_t)msg.size()) {
        std::cerr << "SECRET init send short: " << sent << "/" << msg.size() << "\n";
        perror("sendto");
        return false;
    }
    std::cout << "Sent S message (" << msg.size() << " bytes). Usernames: \"" << usernames << "\"\n";

    // gamalt
    // if (!send_all_udp(sock, dst, msg.data(), msg.size())) { 
    //     perror("SECRET send fail");
    //     return false;
    // }

    // 3. Receive your 5-byte reply: (group ID + 4-byte challenge).
    char buf[512];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    int recieved_reply = recvfrom(sock, buf, sizeof(buf), 0, (sockaddr*)&from, &fromlen);
    if (recieved_reply != 5) { perror("SECRET recv (5 bytes)"); return false; }

    uint8_t groupID = buf[0];
    uint32_t challenge;
    std::memcpy(&challenge, buf + 1, 4);
    challenge = ntohl(challenge);

    // 4. Compute challenge XOR secret number.
    uint32_t signature = challenge ^ secret_number;

    // 5. Reply with your group number + the signature.
    char reply[5];
    reply[0] = groupID;
    uint32_t net_sig = htonl(signature);
    std::memcpy(reply + 1, &net_sig, 4);
    
    if (!send_all_udp(sock, dst, reply, sizeof(reply))) {
        perror("SECRET send reply fail");
        return false;
    }
    
    // 6. If correct, you will receive a secret port number 1 (for port
    // knocking). Remember your group ID and signature (do not
    // hard-code them).
    int n = recvfrom(sock, buf, sizeof(buf) - 1, 0, (sockaddr*)&from, &fromlen);
    if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        std::cerr << "SECRET recv timeout waiting for 5 bytes\n";
    } else {
        perror("SECRET recv error");
    }
    return false;
    }
    if (n != 5) {
        std::cerr << "SECRET recv wrong length: got " << n << ", expected 5\n";
        return false;
    }
    buf[n] = 0;

    std::cout << "[secret port] reply: " << buf << "\n";
    secret_port1 = std::atoi(buf);

    out_groupID = groupID;
    out_signature = signature;
    return true;
}

// ========== Evil Port Helper ==========

// ========== Checksum Port Helper ==========

// ========== EXPSTN Port Helper ==========

// ========== Port Knocking Helper ==========

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
        return 1;
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
        return 1;
    }

    // Set timeout for receiving responses to 1 second
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0; // 1 second
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt failed");
        close(sock);
        return 1;
    }

    // 
    std::vector<int> ports = {port1, port2, port3, port4};
    std::vector<int> secret_ports;
    std::string secret_phrase;
    int final_port = 0;
    bool raw_socket_used = false;

    std::string default_message = "tester";

    for (int port : ports) {
    // --- build destination ---
    struct sockaddr_in dst;
    std::memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(port);
    if (inet_pton(AF_INET, ip_string, &dst.sin_addr) != 1) {
        std::cerr << "bad ip address: " << ip_string << "\n";
        continue;
    }

    // --- send a ≥6 byte probe ---
    const char* probe = "tester"; // exactly 6 bytes
    ssize_t sent = sendto(sock, probe, std::strlen(probe), 0,
                          (const struct sockaddr*)&dst, sizeof(dst));
    if (sent < 0) {
        perror("sendto");
        continue;
    }

    // --- receive banner (1s timeout already set on socket) ---
    char buf[2048];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    ssize_t n = recvfrom(sock, buf, sizeof(buf)-1, 0,
                         (struct sockaddr*)&from, &fromlen);

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            std::cout << "[port " << port << "] timeout waiting for banner\n";
        } else {
            perror("recvfrom");
        }
        continue;
    }

    buf[n] = '\0';
    std::string banner(buf);

    std::cout << "[port " << port << "] banner: " << banner << "\n";

    static uint32_t groupID = 0;
    static uint32_t signature = 0;  
    static int secret_port1 = 0;

    if (is_secret(banner)) {
        std::cout << "========================== S.E.C.R.E.T PORT ON " << port << " ==========================\n";
        if (!handle_secret(sock, ip_string, port, groupID, signature, secret_port1)) {
            std::cerr << "S.E.C.R.E.T. flow failed on port " << port << "\n";
        } else {
            std::cout << "GroupID = " << groupID
                      << " Signature = " << signature
                      << " SecretPort1 = " << secret_port1 << "\n";

        secret_ports.push_back(secret_port1);   
        }
        continue;

    } else if (is_evil(banner)) {
        std::cout << "========================== E.V.I.L PORT ON " << port << " ==========================\n";
        // TODO: implement evil port handling
        continue;

    } else if (is_checksum(banner)) {
        std::cout << "========================== C.H.E.C.K.S.U.M PORT ON " << port << " ==========================\n";
        // TODO: implement checksum port handling
        continue;
    } else if (is_exps(banner)) {
        std::cout << "========================== E.X.P.S.T.N PORT ON " << port << " ==========================\n";
        // TODO: implement exps port handling
        continue;
    } else {
        std::cout << "[port " << port << "] unknown service\n";
        continue;
    }
    }
    close(sock);
    return 0;
}