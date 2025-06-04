#include "PacketProcessor.h"
#include "Utils.h"
#include <iostream>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 1

void process_packet(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header = (struct ip*)(packet + 14);
    struct tcphdr *tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ip_hl * 4));
    Packet  p(*ip_header, *tcp_header);

    if (p.fwd_connection || p.bwd_connection) {
        const u_char *tls_data = packet + 14 + (ip_header->ip_hl * 4) + (tcp_header->th_off * 4);
        uint16_t tcp_flags = tcp_header->th_flags;
        
        if (tcp_flags & TH_FIN || tcp_flags & TH_RST) {
            // std::cout << (p.fwd_connection?"Forward":"Backward") << " connection ended for: " << p.src_ip << ":" << p.src_port << "->" << p.dst_ip << ":" << p.dst_port << std::endl;
            if(p.fwd_connection) {
                storeConnectionInfo(p.src_ip, p.src_port, p.dst_ip, pkthdr->ts.tv_sec);
                deleteConnectionInfo(p.src_ip, p.src_port, p.dst_ip);
            } else {
                storeConnectionInfo(p.dst_ip, p.dst_port, p.src_ip, pkthdr->ts.tv_sec);
                deleteConnectionInfo(p.dst_ip, p.dst_port, p.src_ip);
            }
        }

        p.fwd_connection
        ?insertBytesInfo(p.src_ip, p.src_port, p.dst_ip, true, pkthdr->len)
        :insertBytesInfo(p.dst_ip, p.dst_port, p.src_ip, false, pkthdr->len);

        size_t tls_offset = 14 + (ip_header->ip_hl * 4) + (tcp_header->th_off * 4);
        size_t tls_data_length = pkthdr->caplen - tls_offset;
        if (tls_data_length >= 5) {
            if (pkthdr->caplen >= (14 + (ip_header->ip_hl * 4) + (tcp_header->th_off * 4) + 5)) {
                u_char content_type = tls_data[0];
                if (content_type == 0x16) {
                    u_char handshake_type = tls_data[5];
                    if (handshake_type == TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
                        std::string server_name = parse_client_hello(tls_data, tls_data_length);
                        if(server_name=="None") {
                            if(p.dst_port==443)
                                server_name = p.dst_ip;
                            if(p.src_port==443)
                                server_name = p.src_ip;
                        }
                        displayHostnameInfo(p.src_ip, p.src_port, p.dst_ip, p.dst_port, server_name);
                        insertHostname(p.src_ip, p.dst_ip, p.src_port, server_name);
                    }
                }
            }
        }
    }
}
