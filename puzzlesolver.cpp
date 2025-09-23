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
int check_port_type(const std::string &s) {
    if (s.find("Greetings from S.E.C.R.E.T.") != std::string::npos) {
        return SECRET;
    } else if (s.find("Send me a 4-byte message containing the signature") != std::string::npos) {
        return CHECKSUM;
    } else if (s.find("I am an evil port") != std::string::npos) {
        return EVIL;
    } else if (s.find("E.X.P.S.T.N") != std::string::npos) {
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
    tv.tv_sec = 5;
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

    // 1) Generate secret number
    std::random_device rd;
    // uint32_t secret_number = rd();

    // For debugging, use a fixed secret number
    uint32_t secret_number = 0x12345678; // or any fixed value

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
    std::cout << "[DEBUG] S message bytes:";
    for (size_t i=0;i<msg.size();++i) printf(" %02x", (unsigned char)msg[i]);
    printf("\n");
    

    // 3) wait for 5-byte challenge (up to a few attempts)
    char buf[1024];
    sockaddr_in from;
    ssize_t n = -1;
    bool got_challenge = false;
    for (int attempt=0; attempt<3 && !got_challenge; ++attempt) {
        socklen_t fl = sizeof(from);
        n = recvfrom(sock, buf, sizeof(buf), 0, (sockaddr*)&from, &fl);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                std::cerr << "[DEBUG] attempt " << attempt+1 << " to receive 5-byte challenge timed out\n";
            } else {
                perror("recvfrom challenge");
                close(sock);
                return false;
            }
        }
        if (n == 5) {
            got_challenge = true;
            break;
        } else {
            std::cerr << "[DEBUG] expected 5 bytes for challenge, got " << n << " bytes\n";
        }
    }

    if (!got_challenge) {
        std::cerr << "SECRET failed: did not receive 5-byte challenge from S.E.C.R.E.T.\n";
        close(sock);
        return false;
    }

    uint8_t groupID = static_cast<uint8_t>(buf[0]);
    uint32_t challenge32;
    std::memcpy(&challenge32, buf+1, 4);
    challenge32 = ntohl(challenge32);
    std::cout << "[INFO] Received groupID=" << (int)groupID << " challenge=" << challenge32 << "\n";

    // 4) compute signature
    uint32_t signature = challenge32 ^ secret_number;
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
    std::cout << "[INFO] Sent signature reply (5 bytes). signature=" << signature << "\n";
    std::cout << "[DEBUG] signature bytes:";
    for (int i=0;i<5;++i) printf(" %02x", (unsigned char)reply[i]);
    printf("\n");

    // 6) wait for final secret port reply
    bool got_secret_port = false;
    ssize_t m = -1;
    for (int attempt=0; attempt<4 && !got_secret_port; ++attempt) {
        socklen_t fl = sizeof(from);
        m = recvfrom(sock, buf, sizeof(buf)-1, 0, (sockaddr*)&from, &fl);
        if (m < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                std::cerr << "[DEBUG] attempt " << attempt+1 << " waiting for secret-port reply timed out\n";
            } else {
                perror("recv from secret port");
            }
            continue;
        }
        if (m > 0) {
            buf[m] = '\0';
            std::string reply_str(buf, m);
            std::smatch sm;
            bool parsed_ok = false;
            long parsed_val = 0;

            try {
                // 1) targeted regex: look for "port[: -]*<digits>"
                std::regex port_re(R"(port[:\s-]*([0-9]{1,5}))", std::regex_constants::icase);
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
                    got_secret_port = true;
                    break;
                } else {
                    std::cerr << "[WARN] parsed port out of range: " << parsed_val << "\n";
                }
            } else {
                std::cerr << "[WARN] no numeric substring found in reply\n";
            }
        }
    }

    if (!got_secret_port) {
        std::cerr << "SECRET recv timeout waiting for secret port (or couldn't parse it)\n";
        close(sock);
        return false;
    }

    out_groupID = groupID;
    out_signature = signature;
    std::cout << "[SUCCESS] secret_port1 = " << secret_port1 << "\n";
    close(sock);
    return true;
}

bool handle_evil(const char* ip, int port, uint32_t signature, uint8_t groupID) {
    // create a fresh socket for the E.V.I.L flow
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return false;
    }

    // also create raw socket to send from
    int raw_sock = socket(AF_INET, SOCK_RAW, 0);
    if (raw_sock < 0) {
        perror("raw socket");
        close(sock);
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


    // Trying 2 byte orders: network order first, fallback to host order.
    // uint32_t orders[2] = { htonl(signature), signature };
    // bool sent_ok = false;
    // bool got_reply = false;
    // char rbuf[1024];
    // sockaddr_in from; socklen_t fl = sizeof(from);

    // for (int attempt = 0; attempt < 2 && !got_reply; ++attempt) {
    //     uint32_t out = orders[attempt];
    //     ssize_t n = sendto(s, &out, sizeof(out), 0, (const sockaddr*)&dst, sizeof(dst));
    //     if (n != (ssize_t)sizeof(out)) {
    //         perror("sendto evil signature");
    //     } else {
    //         sent_ok = true;
    //         std::cout << "[EVIL] Sent 4-byte signature (order " << (attempt==0 ? "network" : "host") << ")\n";
    //         // wait for reply
    //         ssize_t r = recvfrom(s, rbuf, sizeof(rbuf)-1, 0, (sockaddr*)&from, &fl);
    //         if (r < 0) {
    //             if (errno == EAGAIN || errno == EWOULDBLOCK) {
    //                 std::cerr << "[EVIL] no reply (timeout) for this byte order, trying next\n";
    //                 continue;
    //             } else {
    //                 perror("recvfrom evil");
    //                 break;
    //             }
    //         } else {
    //             // got a reply
    //             rbuf[r] = '\0';
    //             char frombuf[INET_ADDRSTRLEN];
    //             inet_ntop(AF_INET, &from.sin_addr, frombuf, sizeof(frombuf));
    //             std::cout << "[EVIL] reply from " << frombuf << ":" << ntohs(from.sin_port)
    //                       << " (" << r << " bytes): '" << rbuf << "'\n";
    //             got_reply = true;
    //             break;
    //         }
    //     }
    // }

    // if (!sent_ok) {
    //     std::cerr << "[EVIL] failed to send signature\n";
    // }

    close(sock);
    close(raw_sock);
    return true;
}

bool handle_checksum(const char* ip, int port, uint32_t signature) {
    // send 4-byte signature (network order), parse reply as needed
    // return true/false
    std::cout << "[STUB] handle_checksum on port " << port << " with signature=" << signature << "\n";
    return true;
}

bool handle_exps(const char* ip, int port, uint32_t signature, const std::vector<int>& secret_ports) {
    // send secret ports list + knocks, format: [4 bytes signature][phrase]
    std::cout << "[STUB] handle_exps on port " << port << " (signature=" << signature << ")\n";
    return true;
}

int main(int argc, char *argv[]) {
    int port1 = 0;
    int port2 = 0;
    int port3 = 0;
    int port4 = 0;

    if (argc != 6) {
        std::cerr << "Command needs to be ./puzzlesolver [IP] [PORT 1] [PORT 2] [PORT 3] [PORT 4]\n";
        return 1;
    }

    const char* ip_string = argv[1];
    std::string port1_str = argv[2];
    std::string port2_str = argv[3];
    std::string port3_str = argv[4];
    std::string port4_str = argv[5];

    check_if_digit(port1_str);
    check_if_digit(port2_str);
    check_if_digit(port3_str);
    check_if_digit(port4_str);

    int port1_parsed = std::stoi(port1_str);
    int port2_parsed = std::stoi(port2_str);
    int port3_parsed = std::stoi(port3_str);
    int port4_parsed = std::stoi(port4_str);

    check_in_range(port1_parsed);
    check_in_range(port2_parsed);
    check_in_range(port3_parsed);
    check_in_range(port4_parsed);

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

    std::vector<int> input_ports = {port1, port2, port3, port4};

    // Map: type -> actual port. Initialize to -1 (unknown)
    int port_of[4] = {-1, -1, -1, -1};

    // ---- SCAN & CLASSIFY ONLY (no handlers here) ----
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
    static uint32_t groupID = 0;
    static uint32_t signature = 0;
    std::vector<int> secret_ports;
    static int secret_port1 = 0;

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
        if (!handle_evil(ip_string, port_of[EVIL], signature, static_cast<uint8_t>(groupID))) {
            std::cerr << "E.V.I.L. flow failed\n";
        } else {
            std::cout << "[EVIL] signature sent to port " << port_of[EVIL] << "\n";
        }
    } else {
        std::cout << "[info] No E.V.I.L. port found.\n";
    }

    // 3) CHECKSUM
    if (port_of[CHECKSUM] != -1) {
        std::cout << "========================== C.H.E.C.K.S.U.M PORT ON " << port_of[CHECKSUM] << " ==========================\n";
        if (!handle_checksum(ip_string, port_of[CHECKSUM], signature)) {
            std::cerr << "CHECKSUM failed\n";
        }
    } else {
        std::cout << "[info] No CHECKSUM port found.\n";
    }

    // 4) EXPSTN
    if (port_of[EXPSTN] != -1) {
        std::cout << "========================== E.X.P.S.T.N PORT ON " << port_of[EXPSTN] << " ==========================\n";
        if (!handle_exps(ip_string, port_of[EXPSTN], signature, secret_ports)) {
            std::cerr << "E.X.P.S.T.N. failed\n";
        } 
    } else {
        std::cout << "[info] No E.X.P.S.T.N. port found.\n";
    }

    return 0;
}
