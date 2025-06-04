// Netify Agent
// Copyright (C) 2015-2024 eGloo Incorporated
// <http://www.egloo.ca>
//
// This program is free software: you can redistribute it
// and/or modify it under the terms of the GNU General
// Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE.  See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public
// License along with this program.  If not, see
// <http://www.gnu.org/licenses/>.

#pragma once

#include <pcap/pcap.h>

#include "nd-capture.hpp"

class ndCapturePcap : public ndCaptureThread
{
public:
    ndCapturePcap(int16_t cpu, nd_iface_ptr &iface,
      const ndDetectionThreads &threads_dpi,
      ndDNSHintCache *dhc = NULL, uint8_t private_addr = 0);
    virtual ~ndCapturePcap();

    virtual void *Entry(void);

    // XXX: Ensure thread is locked before calling!
    virtual void GetCaptureStats(ndPacketStats &stats);

protected:
    pcap_t *pcap;
    int pcap_fd;
    struct bpf_program pcap_filter;
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    int pcap_snaplen;
    struct pcap_pkthdr *pkt_header;
    const uint8_t *pkt_data;
    struct pcap_stat pcs_last;

    pcap_t *OpenCapture(void);
};
