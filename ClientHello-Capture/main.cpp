#include <pcap.h>
#include <iostream>
#include "PacketProcessor.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>" << std::endl;
        return 1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return 2;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "tcp port 443", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Could not parse filter" << std::endl;
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Could not install filter" << std::endl;
        return 2;
    }

    pcap_loop(handle, 0, process_packet, nullptr);

    pcap_close(handle);
    return 0;
}
