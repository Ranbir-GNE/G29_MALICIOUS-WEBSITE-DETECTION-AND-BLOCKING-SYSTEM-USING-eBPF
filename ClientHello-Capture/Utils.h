#ifndef UTILS_H
#define UTILS_H
#include <string>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

//function definitions
void print_bytes(const u_char *data, size_t length);
std::string bytes_to_string(const u_char *data, size_t length);
std::string parse_client_hello(const u_char *tls_data, size_t length);
uint32_t ipToInt(const std::string& ip) ;
bool is_utf8(const std::string& str);
uint64_t computeIndex(const std::string& srcIP, const std::string& tgtIP, uint16_t port);
void insertBytesInfo(const std::string& src_ip, int port, const std::string& dst_ip, bool fwd_connection, int bytes);
void deleteConnectionInfo(const std::string& src_ip, int port, const std::string& dst_ip);
void displayHostnameInfo(std::string src_ip,int src_port,std::string  dst_ip,int dst_port,std::string  server_name);
void storeConnectionInfo(const std::string& src_ip, int port, const std::string& dst_ip, __time_t time);
void insertHostname(const std::string& src_ip, const std::string& dst_ip, int port, const std::string& hostname);

class Packet {
    public:
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    u_short src_port;
    u_short dst_port;
    bool fwd_connection;
    bool bwd_connection;

    Packet(struct ip ip_header, struct tcphdr tcp_header);
};



struct ConnectionInfo {
    std::string sourceIP;
    std::string hostname;
    uint64_t bytesDownloaded;
    uint64_t bytesUploaded;
};
#endif // UTILS_H
