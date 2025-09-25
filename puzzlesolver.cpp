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
#include <netinet/in.h>
#include <random>
#include <cctype>
#include <cstdlib>
#include <set>
#include <netinet/ip.h>
#include <netinet/udp.h>

// ========== Global variables ==========
const std::string usernames = "georg23,arnagud21";
const int SECRET = 0;
const int EVIL = 1;
const int CHECKSUM = 2;
const int EXPSTN = 3;

// ========== Port Validation Helpers ==========
void check_if_digit(const std::string &str) {
    for (char c : str) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            std::cerr << "non-numeric character in port\n";
            exit(1);
        }
    }
}

void check_in_range(int val) {
    if (val < 1 || val > 65535) {
        std::cerr << "port is out of range\n";
        exit(1);
    }
}

// ========== Port Classification ==========
int check_port_type(const std::string &sock) {
    if (sock.find("Greetings from S.E.C.R.E.T.") != std::string::npos) {
        return SECRET;
    } else if (sock.find("Send me a 4-byte message containing the signature") != std::string::npos) {
        return CHECKSUM;
    } else if (sock.find("I am an evil port") != std::string::npos) {
        return EVIL;
    } else if (sock.find("E.X.P.S.T.N") != std::string::npos) {
        return EXPSTN;
    } else {
        return -1;
    }
}

// ========== Secret Port Helper ==========
bool handle_secret(const char* ip, int port, uint32_t &out_groupID, uint32_t &out_signature, int &secret_port1) {

    // create a fresh socket for the S.E.C.R.E.T flow
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return false;
    }

    // bind to port so replies go to our socket
    sockaddr_in bind_addr;
    std::memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = 0;
    if (bind(sock, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("bind");
        close(sock);
        return false;
    }

    timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt");
        close(sock);
        return false;
    }

    // Destination
    struct sockaddr_in dst;
    std::memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &dst.sin_addr) != 1) {
        std::cerr << "bad ip address: " << ip << "\n";
        close(sock);
        return false;
    }

    // 1) Very secret number
    uint32_t secret_number = 0x12345678;

    // 2) send 'S' message: 'S' + 4 bytes (net-order secret) + usernames
    std::string msg;
    msg.push_back('S');
    uint32_t net_secret = htonl(secret_number);
    msg.append(reinterpret_cast<char*>(&net_secret), 4);
    msg += usernames;

    ssize_t sent = sendto(sock, msg.data(), msg.size(), 0, (const sockaddr*)&dst, sizeof(dst));
    if (sent < 0) {
        perror("SECRET initial sendto");
        close(sock);
        return false;
    }
    std::cout << "Sent S message (" << sent << " bytes). Usernames: \"" << usernames << "\"\n";

    // 3) wait for 5-byte challenge 
    char buf[1024];
    sockaddr_in from;
    socklen_t fl = sizeof(from);
    ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, (sockaddr*)&from, &fl);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            std::cerr << "[DEBUG] timeout waiting to receive 5-byte challenge\n";
        } else {
            perror("recvfrom challenge");
        }
        close(sock);
        return false;
    }
    if (n != 5) {
        std::cerr << "[DEBUG] expected 5 bytes for challenge, got " << n << " bytes\n";
        close(sock);
        return false;
    }

    uint8_t groupID = static_cast<uint8_t>(buf[0]);
    uint32_t challenge;
    std::memcpy(&challenge, buf+1, 4);
    challenge = ntohl(challenge);
    std::cout << "[INFO] Received groupID=" << (int)groupID << " challenge=" << challenge << "\n";

    // 4) compute signature
    uint32_t signature = challenge ^ secret_number;
    uint32_t net_sig = htonl(signature);

    // 5) reply with groupID + signature
    char reply[5];
    reply[0] = groupID;
    std::memcpy(reply+1, &net_sig, 4);
    sent = sendto(sock, reply, sizeof(reply), 0, (const sockaddr*)&dst, sizeof(dst));
    if (sent != (ssize_t)sizeof(reply)) {
        perror("SECRET send reply fail");
        close(sock);
        return false;
    }
    
    // 6) wait for final secret port reply
    socklen_t fl2 = sizeof(from);
    ssize_t m = recvfrom(sock, buf, sizeof(buf)-1, 0, (sockaddr*)&from, &fl2);
    if (m < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            std::cerr << "[DEBUG] timeout waiting for secret-port reply\n";
        } else {
            perror("recv from secret port");
        }
        close(sock);
        return false;
    }
    if (m > 0) {
        buf[m] = '\0';
        std::string reply_str(buf, m);
        std::smatch sm;
        bool parsed_ok = false;
        long parsed_val = 0;
        try {
            // 1) targeted regex: look for "port[: -]*<digits>"
            std::regex port_re(R"(port[:\sock-]*([0-9]{1,5}))", std::regex_constants::icase);
            if (std::regex_search(reply_str, sm, port_re) && sm.size() >= 2) {
                parsed_val = std::stol(sm[1].str());
                parsed_ok = true;
            } else {
                // 2) fallback: find all digit runs and take the last one
                std::regex all_digits(R"((\d{1,5}))");
                std::sregex_iterator it(reply_str.begin(), reply_str.end(), all_digits);
                std::sregex_iterator end;
                for (; it != end; ++it) {
                    parsed_val = std::stol((*it)[1].str()); // last match wins
                    parsed_ok = true;
                }
            }
        } catch (const std::exception &e) {
            std::cerr << "[WARN] exception parsing port from reply: " << e.what() << "\n";
            parsed_ok = false;
        }
        if (parsed_ok) {
            if (parsed_val >= 1 && parsed_val <= 65535) {
                secret_port1 = static_cast<int>(parsed_val);
            } else {
                std::cerr << "[WARN] parsed port out of range: " << parsed_val << "\n";
                close(sock);
                return false;
            }
        } else {
            std::cerr << "[WARN] no numeric substring found in reply\n";
            close(sock);
            return false;
        }
    } else {
        std::cerr << "[WARN] did not receive any bytes for secret port reply\n";
        close(sock);
        return false;
    }

    out_groupID = groupID;
    out_signature = signature;
    std::cout << "[SUCCESS] secret_port1 = " << secret_port1 << "\n";
    close(sock);
    return true;
}

// Helper function to get local IP address
std::string getLocalIPAddress(const char* target_ip) {
    int temp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (temp_sock < 0) return "127.0.0.1";
    
    struct sockaddr_in temp_addr;
    temp_addr.sin_family = AF_INET;
    temp_addr.sin_port = htons(80);
    inet_pton(AF_INET, target_ip, &temp_addr.sin_addr);
    
    if (connect(temp_sock, (struct sockaddr*)&temp_addr, sizeof(temp_addr)) == 0) {
        socklen_t len = sizeof(temp_addr);
        getsockname(temp_sock, (struct sockaddr*)&temp_addr, &len);
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &temp_addr.sin_addr, ip_str, INET_ADDRSTRLEN);
        close(temp_sock);
        return std::string(ip_str);
    }
    
    close(temp_sock);
    return "127.0.0.1";
}

bool handle_evil(const char* ip, int port, uint32_t signature, uint8_t groupID, int &secret_port2) {
    // Create a raw socket (IPPROTO_RAW allows us to construct raw IP packets)
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock == -1) {
        std::cerr << "Failed to create raw socket" << std::endl;
        return false;
    }

    // Enable IP_HDRINCL so we can build our own IP header
    int one = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL");
        close(raw_sock);
        return false;
    }

    // Create receiving UDP socket
    int recv_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (recv_sock == -1) {
        perror("Failed to create UDP socket");
        close(raw_sock);
        return false;
    }

    // Set timeout for receiving socket
    timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    if (setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt timeout");
        close(raw_sock);
        close(recv_sock);
        return false;
    }

    // Get local IP address
    std::string local_ip = getLocalIPAddress(ip);

    // Bind the receiving socket to port 58585
    struct sockaddr_in recv_addr;
    memset(&recv_addr, 0, sizeof(recv_addr));
    recv_addr.sin_family = AF_INET;
    inet_pton(AF_INET, local_ip.c_str(), &recv_addr.sin_addr);
    recv_addr.sin_port = htons(58585);

    if (bind(recv_sock, (const sockaddr*)&recv_addr, sizeof(recv_addr)) < 0) {
        perror("Failed to bind receive socket");
        close(raw_sock);
        close(recv_sock);
        return false;
    }

    // Set up destination address
    struct sockaddr_in server_address;
    std::memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &server_address.sin_addr) != 1) {
        std::cerr << "bad ip address: " << ip << "\n";
        close(raw_sock);
        close(recv_sock);
        return false;
    }

    // Create the UDP packet
    char udp_packet[4096];
    memset(udp_packet, 0, sizeof(udp_packet));

    struct ip *ip_header = (struct ip *)udp_packet;
    struct udphdr *udp_header = (struct udphdr *)(udp_packet + sizeof(struct ip));
    char *message_buffer = (char *)(udp_packet + sizeof(struct ip) + sizeof(struct udphdr));

    uint32_t evil_signature = htonl(signature); // Convert to network byte order

    // Set IP header
    ip_header->ip_v = 4; // IPv4
    ip_header->ip_hl = 5; // Header length (5 * 4 = 20 bytes)
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + sizeof(evil_signature));
    ip_header->ip_id = htons(1377); // ID
    ip_header->ip_off = htons(0x8000); // Set the evil bit
    ip_header->ip_ttl = 255;
    ip_header->ip_p = IPPROTO_UDP; // Protocol
    inet_pton(AF_INET, local_ip.c_str(), &ip_header->ip_src); // Local IP
    inet_pton(AF_INET, ip, &ip_header->ip_dst); // Destination IP
    ip_header->ip_sum = 0;  // Set to 0 for checksum calculation

    // Set UDP header
    udp_header->uh_sport = htons(58585); // Source port
    udp_header->uh_dport = htons(port); // Destination port
    udp_header->uh_ulen = htons(sizeof(struct udphdr) + sizeof(evil_signature)); // UDP length
    udp_header->uh_sum = 0;  // Set to 0 for checksum calculation

    // Copy the evil signature into the message buffer
    memcpy(message_buffer, &evil_signature, sizeof(evil_signature));

    // Total packet length
    int length = sizeof(struct ip) + sizeof(struct udphdr) + sizeof(evil_signature);

    // Send the raw packet
    if (sendto(raw_sock, udp_packet, length, 0, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        perror("sendto error");
        std::cerr << "Error sending raw UDP packet" << std::endl;
        close(raw_sock);
        close(recv_sock);
        return false;
    } else {
        std::cout << "Sent evil UDP packet with evil bit set to port " << port << "." << std::endl;
        
        // Attempt to receive the response with a timeout
        char buffer[4096];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);

        ssize_t recv_len = recvfrom(recv_sock, buffer, sizeof(buffer)-1, 0, (struct sockaddr*)&from, &from_len);

        if (recv_len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                std::cerr << "[EVIL] Timeout waiting for response from the server" << std::endl;
            } else {
                perror("[EVIL] recvfrom error");
            }
            close(raw_sock);
            close(recv_sock);
            return false;
        } else {
            buffer[recv_len] = '\0'; // Null-terminate the received message
            std::cout << "[EVIL] Received response (" << recv_len << " bytes): " << buffer << std::endl;

            // Extract the 4-character port from the end of the response
            if (recv_len >= 4) {
                char port_str[5]; // 4 characters for the port number + 1 for the null terminator
                memcpy(port_str, buffer + recv_len - 4, 4); // Extract the 4 characters
                port_str[4] = '\0'; // Null-terminate the string

                try {
                    secret_port2 = std::stoi(port_str);
                    std::cout << "[EVIL] Extracted secret port: " << secret_port2 << std::endl;
                } catch (const std::exception& e) {
                    std::cerr << "[EVIL] Warning: Could not parse secret port from: " << port_str << std::endl;
                }
            }
        }
    }

    close(raw_sock);
    close(recv_sock);
    return true;
}

// Pseudo-header for UDP checksum calculation
struct pseudo_header {
    uint32_t src_addr;
    uint32_t dest_addr;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t udp_length;
};

// Function to calculate the checksum for the UDP header
uint16_t calculate_checksum(unsigned short *udpheader, u_short len){
    long checksum = 0;
    u_short odd_byte;
    short checksum_short;

    while(len > 1) {
        checksum += *udpheader++;
        len -= 2;
    }
    if(len == 1) {
        odd_byte = 0;
        *((u_char*) &odd_byte) = *(u_char*)udpheader;
        checksum += odd_byte;
    }

    checksum = (checksum >> 16) + (checksum & 0xffff);
    checksum = checksum + (checksum >> 16);
    checksum_short = (short)~checksum;

    return checksum_short;
}

bool handle_checksum(const char* ip, int port, uint32_t signature, uint8_t groupID, std::string &out_secret_phrase) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("checksum socket");
        return false;
    }

    // Timeout
    timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt");
        close(sock);
        return false;
    }

    // Destination address
    struct sockaddr_in dst;
    std::memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &dst.sin_addr) != 1) {
        std::cerr << "bad ip address for checksum: " << ip << "\n";
        close(sock);
        return false;
    }

    // Step 1: Send initial probe to get the target checksum
    uint32_t net_sig = htonl(signature);
    ssize_t sent = sendto(sock, &net_sig, sizeof(net_sig), 0, (sockaddr*)&dst, sizeof(dst));
    if (sent != sizeof(net_sig)) {
        perror("[CHECKSUM] initial sendto");
        close(sock);
        return false;
    }
    std::cout << "[CHECKSUM] Sent initial signature (" << sent << " bytes)\n";

    // Receive response
    char buf[2048];
    sockaddr_in from;
    socklen_t fl = sizeof(from);
    ssize_t r = recvfrom(sock, buf, sizeof(buf)-1, 0, (sockaddr*)&from, &fl);
    if (r < 0) {
        perror("[CHECKSUM] recvfrom");
        close(sock);
        return false;
    }
    buf[r] = '\0';
    std::cout << "[CHECKSUM] Initial reply: " << buf << "\n";

    // Parse target checksum and source IP from reply
    uint16_t target_checksum = 0;
    std::string source_ip_str;
    std::string reply(buf);
    std::smatch sm;

    // Parsing checksum from text
    std::regex checksum_re(R"(checksum\s+of\s+0x([0-9a-fA-F]{1,4}))", std::regex_constants::icase);
    if (std::regex_search(reply, sm, checksum_re) && sm.size() >= 2) {
        try {
            target_checksum = static_cast<uint16_t>(std::stoul(sm[1].str(), nullptr, 16));
            std::cout << "[CHECKSUM] Parsed checksum from text: 0x" << std::hex << target_checksum << std::dec << "\n";
        } catch (const std::exception& e) {
            std::cerr << "[CHECKSUM] Failed to parse checksum from text: " << e.what() << "\n";
        }
    }

    // Parsing source IP from text
    std::regex ip_re(R"(source address being\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}))");
    if (std::regex_search(reply, sm, ip_re) && sm.size() >= 2) {
        source_ip_str = sm[1].str();
        std::cout << "[CHECKSUM] Parsed source IP from text: " << source_ip_str << "\n";
    }

    if (target_checksum == 0 || source_ip_str.empty()) {
        std::cerr << "[CHECKSUM] Failed to extract required information\n";
        close(sock);
        return false;
    }

    // Build encapsulated IPv4 packet (IP header + UDP header + 2-byte data)
    const int data_len = 2; // 2-byte data field for adjustment
    const int udp_header_len = sizeof(struct udphdr);
    const int ip_header_len = sizeof(struct ip);
    const int total_len = ip_header_len + udp_header_len + data_len;

    char udp_packet[4096];
    memset(udp_packet, 0, sizeof(udp_packet));
    
    struct ip* iph = (struct ip*)udp_packet;
    struct udphdr* udph = (struct udphdr*)(udp_packet + ip_header_len);
    char* message_buffer = udp_packet + ip_header_len + udp_header_len;

    // Set IP header (matching working code structure)
    struct in_addr src_addr;
    inet_aton(source_ip_str.c_str(), &src_addr);
    iph->ip_src = src_addr;
    iph->ip_dst = dst.sin_addr;  // Use the destination from our socket
    iph->ip_ttl = 255;
    iph->ip_len = htons(total_len);
    iph->ip_hl = 5;
    iph->ip_p = IPPROTO_UDP;
    iph->ip_tos = 0;
    iph->ip_off = 0;
    iph->ip_id = htons(1377);
    iph->ip_v = 4;

    // Calculate and set IP header checksum
    iph->ip_sum = 0;
    iph->ip_sum = calculate_checksum((unsigned short*)iph, ip_header_len);

    // Set UDP header
    udph->uh_sport = htons(58585);
    udph->uh_dport = htons(port);
    udph->uh_ulen = htons(udp_header_len + data_len);
    udph->uh_sum = htons(target_checksum);  // Set to target checksum

    // Create pseudo header for checksum calculation
    pseudo_header psh;

    psh.src_addr = src_addr.s_addr;
    psh.dest_addr = dst.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(udp_header_len + data_len);

    // Calculate what data value will make the checksum valid
    int psize = sizeof(struct pseudo_header) + udp_header_len + data_len;
    char* pseudo_data = (char*)malloc(psize);
    memcpy(pseudo_data, &psh, sizeof(struct pseudo_header));
    memcpy(pseudo_data + sizeof(struct pseudo_header), udph, udp_header_len);
    memcpy(pseudo_data + sizeof(struct pseudo_header) + udp_header_len, message_buffer, data_len);

    // Calculate the adjustment value needed
    unsigned short adjustment = calculate_checksum((unsigned short*)pseudo_data, psize);
    memcpy(message_buffer, &adjustment, 2);

    free(pseudo_data);

    std::cout << "[CHECKSUM] Target checksum: 0x" << std::hex << target_checksum << std::dec << "\n";
    std::cout << "[CHECKSUM] Adjustment value: 0x" << std::hex << adjustment << std::dec << "\n";

    // Debug: Print packet contents
    std::cout << "[CHECKSUM] UDP packet (first 40 bytes): ";
    for (size_t i = 0; i < std::min((size_t)40, (size_t)total_len); ++i) {
        printf("%02x ", (unsigned char)udp_packet[i]);
    }
    printf("\n");

    // Send the encapsulated packet
    sent = sendto(sock, udp_packet, total_len, 0, (sockaddr*)&dst, sizeof(dst));
    if (sent != total_len) {
        if (sent < 0) perror("[CHECKSUM] sendto");
        else std::cerr << "[CHECKSUM] short send " << sent << " bytes\n";
        close(sock);
        return false;
    }
    std::cout << "[CHECKSUM] Sent " << sent << " bytes\n";

    // Receive response
    r = recvfrom(sock, buf, sizeof(buf)-1, 0, (sockaddr*)&from, &fl);
    if (r < 0) {
        perror("[CHECKSUM] recvfrom");
        close(sock);
        return false;
    }
    buf[r] = '\0';
    std::cout << "[CHECKSUM] Final reply: " << buf << "\n";

    // Parse secret phrase from reply
    char* phrase = strchr(buf, '\n');
    if (phrase) {
        phrase++; // Move past the newline
        if (phrase[0] == '"') {
            phrase++; // Move past the opening quote
            char* end_quote = strchr(phrase, '"');
            if (end_quote) {
                *end_quote = '\0'; // Temporarily terminate at the closing quote
                out_secret_phrase = phrase;
            } else {
                out_secret_phrase = phrase;
            }
        } else {
            out_secret_phrase = phrase;
        }
    } else {
        out_secret_phrase = buf;
    }   

    close(sock);
    return true;
}

bool handle_exps(const char* ip, int port, uint32_t signature, std::string secret_phrase, const std::vector<int>& secret_ports) {
    if (secret_ports.empty()) {
        std::cerr << "[EXPS] No secret ports provided\n";
        return false;
    }
    
    // send secret ports list + knocks, format: [4 bytes signature][phrase]
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("checksum socket");
        return false;
    }

    // Timeout
    timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt");
        close(sock);
        return false;
    }

    // Destination address
    struct sockaddr_in dst;
    std::memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &dst.sin_addr) != 1) {
        std::cerr << "bad ip address for checksum: " << ip << "\n";
        close(sock);
        return false;
    }
    
    // Build list of secret ports
    std::string port_list;
    for (size_t i = 0; i < secret_ports.size(); ++i) {
        std::cout << "secret ports: " << secret_ports[i] << "\n";
        if (i) port_list.push_back(',');
        port_list += std::to_string(secret_ports[i]);
    }
    // add newline at end of list
    port_list.push_back('\n');

    // Send list of secret ports
    ssize_t sent = sendto(sock, port_list.data(), port_list.size(), 0, (sockaddr*)&dst, sizeof(dst));
    if (sent != (ssize_t)port_list.size()) {
        perror("[EXPS] sendto");
        close(sock);
        return false;
    }
    std::cout << "[EXPS] Sent port list: " << port_list << "\n";

    // Receive reply
    char buf[4096];
    sockaddr_in from{};
    socklen_t fl = sizeof(from);
    ssize_t r = recvfrom(sock, buf, sizeof(buf)-1, 0, (sockaddr*)&from, &fl);
    if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            std::cerr << "[EXPS] timeout waiting for instructions\n";
        else
            perror("[EXPS] recvfrom");
        close(sock);
        return false;
    }
    buf[r] = '\0';
    std::string reply(buf, r);
    std::cout << "[EXPS] Received reply (" << r << " bytes):\n" << reply << "\n";


    // Parse knock order: pull all numbers from reply, in order, including repeats
    std::vector<int> knock_order;
    size_t pos = 0;
    while (pos < reply.size()) {
        // Skip non-digit characters
        while (pos < reply.size() && !isdigit(reply[pos])) ++pos;
        if (pos >= reply.size()) break;
        // Parse number
        int val = 0;
        while (pos < reply.size() && isdigit(reply[pos])) {
            val = val * 10 + (reply[pos] - '0');
            ++pos;
        }
        knock_order.push_back(val);
    }

    // Knock each port in sequence
    if (knock_order.empty()) {
        std::cerr << "[EXPS] No knocking sequence found in reply\n";
        close(sock);
        return false;
    }

    for (int knock_port : knock_order) {
        std::cout << "[EXPS] Knocking on port " << knock_port << "\n";

        // Build the payload: 4 bytes signature (network order) + secret phrase
        uint32_t net_sig = htonl(signature);
        std::string payload;
        payload.resize(4);
        memcpy(&payload[0], &net_sig, 4);
        payload += secret_phrase;

        // Setup the server address
        struct sockaddr_in knock_addr;
        knock_addr.sin_family = AF_INET;
        knock_addr.sin_port = htons(knock_port);
        if (inet_pton(AF_INET, ip, &knock_addr.sin_addr) != 1) {
            std::cerr << "bad ip address for knocking: " << ip << "\n";
            continue;
        }

        // Send the knock (only send the actual payload size)
        ssize_t sent = sendto(sock, payload.data(), payload.size(), 0,
                              (sockaddr*)&knock_addr, sizeof(knock_addr));
        if (sent < 0) {
            perror("[EXPS] sendto knock");
        } else {
            std::cout << "[EXPS] Sent " << sent << " bytes to port " << knock_port << "\n";
        }

        // Wait a short time before the next knock
        usleep(120000); // 120 ms

        // Receive the message back from the server
        char buf[4096];
        sockaddr_in from{};
        socklen_t fl = sizeof(from);
        ssize_t r = recvfrom(sock, buf, sizeof(buf)-1, 0, (sockaddr*)&from, &fl);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                std::cerr << "[EXPS] timeout waiting for instructions\n";
            else
                perror("[EXPS] recvfrom");
            close(sock);
            return false;
        } else {
            buf[r] = '\0';
            std::string reply(buf, r);
            std::cout << "[EXPS] Received reply (" << r << " bytes):\n" << reply << "\n";
        }
    }
    return true;
}

int main(int argc, char *argv[]) {
    if (argc != 6) {
        std::cerr << "Command needs to be ./puzzlesolver [IP] [PORT 1] [PORT 2] [PORT 3] [PORT 4]\n";
        return 1;
    }
    
    const char* ip_string = argv[1];
    
    // Loop to validate ports
    std::vector<int> input_ports;
    for (int i = 2; i <= 5; ++i) {
        std::string port_str = argv[i];
        check_if_digit(port_str);
        int port = std::stoi(port_str);
        check_in_range(port);
        input_ports.push_back(port);
    }

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

    // Map: type -> actual port. Initialize to -1 (unknown)
    int port_of[4] = {-1, -1, -1, -1};

    // ---- SCAN & CLASSIFY ----
    for (int port : input_ports) {
        sockaddr_in dst{}; 
        dst.sin_family = AF_INET; 
        dst.sin_port = htons(port);
        if (inet_pton(AF_INET, ip_string, &dst.sin_addr) != 1) {
            std::cerr << "bad ip address: " << ip_string << "\n";
            continue;
        }

        // send a small probe (≥6 bytes)
        const char* probe = "tester";
        ssize_t sent = sendto(sock, probe, std::strlen(probe), 0,
                              (sockaddr*)&dst, sizeof(dst));
        if (sent < 0) { perror("sendto"); continue; }

        // read banner
        char buf[2048];
        sockaddr_in from{}; socklen_t fl = sizeof(from);
        ssize_t n = recvfrom(sock, buf, sizeof(buf)-1, 0, (sockaddr*)&from, &fl);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                std::cout << "[port " << port << "] timeout waiting for banner\n";
            else
                perror("recvfrom");
            continue;
        }
        buf[n] = '\0';
        std::string banner(buf);
        std::cout << "[port " << port << "] banner: " << banner << "\n";

        int t = check_port_type(banner);
        if (t == -1) {
            std::cout << "Classified: UNKNOWN\n";
            continue;
        }

        if (port_of[t] == -1) {
            port_of[t] = port;
        } else if (port_of[t] != port) {
            std::cout << "[warn] Duplicate " 
                      << (t==SECRET?"SECRET":t==CHECKSUM?"CHECKSUM":t==EVIL?"EVIL":"EXPSTN")
                      << " found on " << port << " (already recorded " << port_of[t] << ")\n";
        }

        std::cout << "Classified: "
                  << (t==SECRET?"SECRET":t==CHECKSUM?"CHECKSUM":t==EVIL?"EVIL":"EXPSTN")
                  << " on port " << port << "\n";
    }
    close(sock);

    // ---- RUN HANDLERS ONCE, IN ORDER ----
    uint32_t groupID = 0;
    uint32_t signature = 0;
    std::vector<int> secret_ports;
    int secret_port1 = 0;
    int secret_port2 = 0;
    std::string secret_phrase;

    // 1) SECRET
    if (port_of[SECRET] != -1) {
        std::cout << "========================== S.E.C.R.E.T PORT ON " << port_of[SECRET] << " ==========================\n";
        if (!handle_secret(ip_string, port_of[SECRET], groupID, signature, secret_port1)) {
            std::cerr << "S.E.C.R.E.T. flow failed\n";
        } else {
            std::cout << "GroupID = " << groupID
                        << " Signature = " << signature
                        << " SecretPort1 = " << secret_port1 << "\n";
            if (secret_port1 > 0) secret_ports.push_back(secret_port1);
        }
    } else {
        std::cerr << "[error] No S.E.C.R.E.T. port discovered. Skipping the rest will likely fail.\n";
    }

    // 2) EVIL
    if (port_of[EVIL] != -1) {
        std::cout << "========================== E.V.I.L PORT ON " << port_of[EVIL] << " ==========================\n";
        if (!handle_evil(ip_string, port_of[EVIL], signature, static_cast<uint8_t>(groupID), secret_port2)) {
            std::cerr << "E.V.I.L. flow failed\n";
        } else {
            std::cout << "[EVIL] signature sent to port " << port_of[EVIL] << "\n";
            if (secret_port2 > 0) secret_ports.push_back(secret_port2);
        }
    } else {
        std::cout << "[info] No E.V.I.L. port found.\n";
    }

    // 3) CHECKSUM
    if (port_of[CHECKSUM] != -1) {
        std::cout << "========================== C.H.E.C.K.S.U.M PORT ON " << port_of[CHECKSUM] << " ==========================\n";
        if (!handle_checksum(ip_string, port_of[CHECKSUM], signature, static_cast<uint8_t>(groupID), secret_phrase)) {
            std::cerr << "CHECKSUM failed\n";
        }
    } else {
        std::cout << "[info] No CHECKSUM port found.\n";
    }

    // 4) EXPSTN
    if (port_of[EXPSTN] != -1) {
        std::cout << "========================== E.X.P.S.T.N PORT ON " << port_of[EXPSTN] << " ==========================\n";  
        if (!handle_exps(ip_string, port_of[EXPSTN], signature, secret_phrase, secret_ports)) {
            std::cerr << "E.X.P.S.T.N. failed\n";
        } 
    } else {
        std::cout << "[info] No E.X.P.S.T.N. port found.\n";
    }

    return 0;
}