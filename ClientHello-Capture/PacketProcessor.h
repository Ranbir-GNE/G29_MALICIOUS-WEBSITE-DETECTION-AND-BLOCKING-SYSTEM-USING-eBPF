#ifndef PACKET_PROCESSOR_H
#define PACKET_PROCESSOR_H

#include <pcap.h>

void process_packet(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);

#endif // PACKET_PROCESSOR_H
