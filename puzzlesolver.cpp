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
const std::string usernames = "georg23,arnagud21";

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

// ========== UDP helpers ==========
static bool send_all_udp(int sock, const sockaddr_in &dst, const void *data, size_t len) {
    ssize_t n = sendto(sock, data, len, 0, (const sockaddr*)&dst, sizeof(dst));
    return n == (ssize_t)len;
}

static std::string recv_text(int sock, int ms_timeout) {
    timeval tv{ ms_timeout/1000, static_cast<suseconds_t>((ms_timeout%1000)*1000) };
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
    // BUG FIX: must compare to npos
    return s.find("Send me a 4-byte message containing the signature") != std::string::npos;
}
bool is_exps(const std::string& s){
    return s.find("E.X.P.S.T.N") != std::string::npos;
}

// ========== Secret Port Helper ==========
bool handle_secret(const char* ip, int port, uint32_t &out_groupID, uint32_t &out_signature, int &secret_port1) {

    // create a fresh socket for the S.E.C.R.E.T flow
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
        return false;
    }

    // bind to ephemeral port so replies go to our socket
    sockaddr_in bind_addr;
    std::memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = 0; // ephemeral
    if (bind(s, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("bind");
        close(s);
        return false;
    }

    // show local binding
    sockaddr_in local;
    socklen_t local_len = sizeof(local);
    if (getsockname(s, (struct sockaddr*)&local, &local_len) == 0) {
        char addrbuf[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &local.sin_addr, addrbuf, sizeof(addrbuf));
        std::cout << "[DEBUG] SECRET socket bound locally to " << addrbuf << ":" << ntohs(local.sin_port) << "\n";
    }

    // set a longer timeout for reliability
    timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt");
        close(s);
        return false;
    }

    // Destination
    struct sockaddr_in dst;
    std::memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &dst.sin_addr) != 1) {
        std::cerr << "bad ip address: " << ip << "\n";
        close(s);
        return false;
    }

    // 1) Generate secret number
    std::random_device rd;
    uint32_t secret_number = rd();

    // 2) send 'S' message: 'S' + 4 bytes (net-order secret) + usernames
    std::string msg;
    msg.push_back('S');
    uint32_t net_secret = htonl(secret_number);
    msg.append(reinterpret_cast<char*>(&net_secret), 4);
    msg += usernames;

    ssize_t sent = sendto(s, msg.data(), msg.size(), 0, (const sockaddr*)&dst, sizeof(dst));
    if (sent < 0) {
        perror("SECRET initial sendto");
        close(s);
        return false;
    }
    std::cout << "Sent S message (" << sent << " bytes). Usernames: \"" << usernames << "\"\n";
    std::cout << "[DEBUG] S message bytes:";
    for (size_t i=0;i<msg.size();++i) printf(" %02x", (unsigned char)msg[i]);
    printf("\n");

    // helper recv lambda
    auto recv_and_report = [&](char *buf, size_t bufsz, ssize_t &out_len, sockaddr_in &from) -> bool {
        socklen_t fl = sizeof(from);
        out_len = recvfrom(s, buf, bufsz, 0, (sockaddr*)&from, &fl);
        if (out_len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                std::cerr << "[DEBUG] recvfrom: timeout (errno " << errno << ")\n";
            } else {
                perror("recvfrom");
            }
            return false;
        }
        char frombuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &from.sin_addr, frombuf, sizeof(frombuf));
        std::cout << "[DEBUG] recvfrom: got " << out_len << " bytes from " << frombuf << ":" << ntohs(from.sin_port) << "\n";
        std::cout << "[DEBUG] data:";
        for (ssize_t i=0;i<out_len;++i) printf(" %02x", (unsigned char)buf[i]);
        printf("\n");
        return true;
    };

    // 3) wait for 5-byte challenge (up to a few attempts)
    char buf[1024];
    sockaddr_in from;
    ssize_t n = -1;
    bool got_challenge = false;
    for (int attempt=0; attempt<3 && !got_challenge; ++attempt) {
        if (!recv_and_report(buf, sizeof(buf), n, from)) {
            std::cerr << "[DEBUG] attempt " << attempt+1 << " to receive 5-byte challenge failed\n";
            continue;
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
        close(s);
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
    sent = sendto(s, reply, sizeof(reply), 0, (const sockaddr*)&dst, sizeof(dst));
    if (sent != (ssize_t)sizeof(reply)) {
        perror("SECRET send reply fail");
        close(s);
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
        if (!recv_and_report(buf, sizeof(buf)-1, m, from)) {
            std::cerr << "[DEBUG] attempt " << attempt+1 << " waiting for secret-port reply failed\n";
            continue;
        }
        if (m > 0) {
            buf[m] = '\0';
            std::cout << "[secret port] raw reply (ASCII if printable): '" << buf << "'\n";
            secret_port1 = std::atoi(buf);
            if (secret_port1 > 0) {
                got_secret_port = true;
                break;
            } else {
                std::cerr << "[WARN] atoi parsed port as " << secret_port1 << " -- maybe reply is binary. Check hex dump above.\n";
            }
        }
    }

    if (!got_secret_port) {
        std::cerr << "SECRET recv timeout waiting for secret port (or couldn't parse it)\n";
        close(s);
        return false;
    }

    out_groupID = groupID;
    out_signature = signature;
    std::cout << "[SUCCESS] secret_port1 = " << secret_port1 << "\n";
    close(s);
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

    std::vector<int> ports = {port1, port2, port3, port4};
    std::vector<int> secret_ports;
    std::string secret_phrase;
    int final_port = 0;
    bool raw_socket_used = false;

    std::string default_message = "tester";

    for (int port : ports) {
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
            if (!handle_secret(ip_string, port, groupID, signature, secret_port1)) {
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
            // TODO: implement evil port handling (requires raw socket + root)
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
