#include "Utils.h"
#include <iostream>
#include <iomanip>
#include <cctype>
#include <cstdint>
#include <unordered_map>
#include <map>
#include "DatabaseManager.h"

std::unordered_map<uint64_t, ConnectionInfo> connectionMap;
std::map<uint64_t, bool> connection_state;
DatabaseManager db_manager("tcp://127.0.0.1:3306", "root", "1", "test");

bool is_utf8(const std::string& str) {
    size_t i = 0;
    size_t length = str.length();
    
    while (i < length) {
        unsigned char byte = str[i];
        
        // Single-byte (ASCII)
        if ((byte & 0x80) == 0x00) {
            ++i;
        }
        // Two-byte sequence
        else if ((byte & 0xE0) == 0xC0) {
            if (i + 1 >= length || (str[i + 1] & 0xC0) != 0x80) return false;
            i += 2;
        }
        // Three-byte sequence
        else if ((byte & 0xF0) == 0xE0) {
            if (i + 2 >= length ||
                (str[i + 1] & 0xC0) != 0x80 ||
                (str[i + 2] & 0xC0) != 0x80) return false;
            i += 3;
        }
        // Four-byte sequence
        else if ((byte & 0xF8) == 0xF0) {
            if (i + 3 >= length ||
                (str[i + 1] & 0xC0) != 0x80 ||
                (str[i + 2] & 0xC0) != 0x80 ||
                (str[i + 3] & 0xC0) != 0x80) return false;
            i += 4;
        }
        else {
            // Invalid byte
            return false;
        }
    }
    
    return true;
}

void print_bytes(const u_char *data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        if (i > 0 && i % 16 == 0) {
            std::cout << std::endl;
        }
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]) << ' ';
    }
    std::cout << std::dec << std::endl;
}

std::string bytes_to_string(const u_char *data, size_t length) {
    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        if (std::isprint(data[i])) {
            result += static_cast<char>(data[i]);
        } else {
            result += '.';
        }
    }
    return result;
}

std::string parse_client_hello(const u_char *tls_data, size_t length) {
    size_t offset = 0;

    if (length < 5) {
        std::cout << "Not enough data for TLS Record Header" << std::endl;
        return "None";
    }

    u_char content_type = tls_data[offset];
    offset += 1;

    if (length < 7) {
        std::cout << "Not enough data for TLS Version" << std::endl;
        return "None";
    }
    u_short version = ntohs(*(u_short*)(tls_data + offset));
    offset += 2;

    if (length < offset + 2) {
        std::cout << "Not enough data for Length" << std::endl;
        return "None";
    }
    u_short length_value = ntohs(*(u_short*)(tls_data + offset));
    offset += 2;

    if (length < offset + 4) {
        std::cout << "Not enough data for Handshake Header" << std::endl;
        return "None";
    }
    u_char handshake_type = tls_data[offset];
    offset += 1;

    u_int32_t handshake_length = ntohl(*(u_int32_t*)(tls_data + offset));
    offset += 3;

    if (length < offset + 2) {
        return "None";
    }
    u_short handshake_version = ntohs(*(u_short*)(tls_data + offset));
    offset += 2;

    if (length < offset + 32) {
        std::cout << "Not enough data for Random" << std::endl;
        return "None";
    }
    offset += 32;

    if (length < offset + 1) {
        std::cout << "Not enough data for Session ID Length" << std::endl;
        return "None";
    }
    u_char session_id_length = tls_data[offset];
    offset += 1 + session_id_length;

    if (length < offset + 2) {
        std::cout << "Not enough data for Cipher Suites Length" << std::endl;
        return "None";
    }
    u_short cipher_suites_length = ntohs(*(u_short*)(tls_data + offset));
    offset += 2;
    offset += cipher_suites_length;

    if (length < offset + 1) {
        std::cout << "Not enough data for Compression Methods Length" << std::endl;
        return "None";
    }
    u_char compression_methods_length = tls_data[offset];
    offset += 1;
    offset += compression_methods_length;

    if (length < offset + 2) {
        std::cout << "Not enough data for Extensions Length" << std::endl;
        return "None";
    }
    u_short extensions_length = ntohs(*(u_short*)(tls_data + offset));
    offset += 2;

    size_t end_offset = offset + extensions_length;
    while (offset < end_offset) {
        if (length < offset + 4) {
            std::cout << "Not enough data for Extension" << std::endl;
            return "None";
        }
        u_short extension_type = ntohs(*(u_short*)(tls_data + offset));
        u_short extension_length = ntohs(*(u_short*)(tls_data + offset + 2));

        if (extension_type == 0x00) {
            size_t sni_offset = offset + 4;

            while (sni_offset < (offset + 4 + extension_length)) {
                if (sni_offset + 2 > (offset + 4 + extension_length)) {
                    std::cout << "Not enough data for SNI" << std::endl;
                    return "None";
                }
                u_short server_name_list_length = ntohs(*(u_short*)(tls_data + sni_offset));
                sni_offset += 2;

                while (server_name_list_length > 0) {
                    if (sni_offset + 3 > (offset + 4 + extension_length)) {
                        std::cout << "Not enough data for Server Name" << std::endl;
                        return "None";
                    }
                    u_char server_name_type = tls_data[sni_offset];
                    u_short server_name_length = ntohs(*(u_short*)(tls_data + sni_offset + 1));
                    sni_offset += 3;

                    if (sni_offset + server_name_length > (offset + 4 + extension_length)) {
                        std::cout << "Server Name Length exceeds remaining data" << std::endl;
                        return "None";
                    }
                    std::string server_name(reinterpret_cast<const char*>(tls_data + sni_offset), server_name_length);
		    std::cout << "Server Name  is: " << server_name << std::endl;
                    return is_utf8(server_name)?server_name:"None";
                    sni_offset += server_name_length;

                    server_name_list_length -= (server_name_length + 3);
                }
            }
        }

        offset += 4 + extension_length;
    }
    return "None";
}

Packet::Packet(struct ip ip_header, struct tcphdr tcp_header) {
    inet_ntop(AF_INET, &(ip_header.ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header.ip_dst), dst_ip, INET_ADDRSTRLEN);
    src_port = ntohs(tcp_header.th_sport);
    dst_port = ntohs(tcp_header.th_dport);
    fwd_connection = (dst_port == 443);
    bwd_connection = (src_port == 443); 
}

uint32_t ipToInt(const std::string& ip) {
    struct in_addr addr;
    inet_pton(AF_INET, ip.c_str(), &addr);
    return ntohl(addr.s_addr); // Convert from network to host byte order
}

uint64_t computeIndex(const std::string& srcIP, const std::string& tgtIP, uint16_t port) {
    uint32_t srcInt = ipToInt(srcIP);
    uint32_t tgtInt = ipToInt(tgtIP);
    return srcInt ^ tgtInt ^ port;
}

void insertBytesInfo(const std::string& src_ip, int port, const std::string& dst_ip, bool fwd_connection, int bytes) {
    uint64_t index = computeIndex(src_ip, dst_ip, static_cast<uint16_t>(port));
    auto it = connectionMap.find(index);
    
    if (it != connectionMap.end()) {
        // Update existing entry
        if (fwd_connection) {
            it->second.bytesUploaded += bytes;
            // std::cout<< "-" << bytes << "[" << port << "] " << src_ip << " | " << dst_ip << "[" << it->second.hostname << "]" << std::endl;
        } else {
            it->second.bytesDownloaded += bytes;
            // std::cout<< "+" << bytes << "[" << port << "] " << src_ip << " | " << dst_ip << "[" << it->second.hostname << "]" <<std::endl;
        }
    } else {
        // Create new entry with hostname as an empty string
        ConnectionInfo info = {src_ip, "", 0, 0};
        if (fwd_connection) {
            info.bytesUploaded = bytes;
        } else {
            info.bytesDownloaded = bytes;
        }
        connectionMap[index] = info;
    }
}

void deleteConnectionInfo(const std::string& src_ip, int port, const std::string& dst_ip) {
    uint64_t index = computeIndex(src_ip, dst_ip, static_cast<uint16_t>(port));
    connectionMap.erase(index);
}

void displayHostnameInfo(std::string src_ip,int src_port,std::string  dst_ip,int dst_port,std::string  server_name) {
    std::cout << src_ip << ":" << src_port << " -> " << dst_ip << ":" << dst_port << " [" << server_name << "]" << std::endl;
}

void storeConnectionInfo(const std::string& src_ip, int port, const std::string& dst_ip, __time_t time) {
    uint64_t index = computeIndex(src_ip, dst_ip, static_cast<uint16_t>(port));
    auto it = connectionMap.find(index);
    std::string hostname; // this exists to remove www. from the original hostname.
    std::stringstream query;
    if (it != connectionMap.end()) {
        // Entry found
        const ConnectionInfo& info = it->second;
        hostname = info.hostname;
        if (hostname.rfind("www.", 0) == 0) {
            hostname.erase(0, 4); // removing www. from the start
        }
        std::cout << " (X) <<[" << info.sourceIP << ":" << port << " -> " << info.hostname << " | Rx: " << info.bytesDownloaded << " Tx: " << info.bytesUploaded << " ]>>" << std::endl;
        if(info.hostname == " " || info.hostname == "None") {
            std::cout<<"Hostname is NULL" << std::endl;
        } else {
        query << "INSERT INTO bytes_usage (source_ip, hostname, downloaded, uploaded, date) VALUES ('"
            << info.sourceIP << "', '"
            << info.hostname << "', "
            << info.bytesDownloaded << ", "
            << info.bytesUploaded << ","
            << "FROM_UNIXTIME(" << time << ", '%Y-%m-\%d')) "
            << "ON DUPLICATE KEY UPDATE "
            << "downloaded = bytes_usage.downloaded + VALUES(downloaded), "
            << "uploaded = bytes_usage.uploaded + VALUES(uploaded);";
            std::cout << "Storing in db\n";

              db_manager.executeQuery(query.str());
        }
    } else {
        // Entry not found
        std::cout << "No connection information found for the given details." << std::endl;
    }
}

void insertHostname(const std::string& src_ip, const std::string& dst_ip, int port, const std::string& hostname) {
    uint64_t index = computeIndex(src_ip, dst_ip, static_cast<uint16_t>(port));
    auto it = connectionMap.find(index);
    
    if (it != connectionMap.end()) {
        // Update existing entry with hostname
        it->second.hostname = hostname;
        std::cout<<"Inserting hostname " <<hostname << " where Tx: " << it->second.bytesUploaded << " and RX: " << it->second.bytesDownloaded << std::endl;
    } else {
        // Handle the case where the connection is not found
        // You might want to print a message, throw an exception, or use a default behavior
        std::cerr << "Connection not found for IPs: " << src_ip << " and " << dst_ip << " with port: " << port << std::endl;
    }
}
