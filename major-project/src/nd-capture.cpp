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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstddef>
#include <mutex>

#if defined(__FreeBSD__)
// XXX: Needed for u_char.  Must be included before
// net/ethernet.h below
#include <sys/types.h>
#endif

#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <resolv.h>

#if defined(HAVE_PCAP_DLT_H)
#include <pcap/dlt.h>
#elif defined(_ND_PCAP_DLT_IN_BPF_H)
#include <pcap/bpf.h>
#else
#include "pcap-compat/dlt.h"
#endif

#ifdef HAVE_PCAP_SLL_H
#include <pcap/sll.h>
#else
#include "pcap-compat/sll.h"
#endif

#ifdef HAVE_PCAP_VLAN_H
#include <pcap/vlan.h>
#else
#include "pcap-compat/vlan.h"
#endif

#if HAVE_NET_PPP_DEFS_H
#include <net/ppp_defs.h>
#elif HAVE_LINUX_PPP_DEFS_H
#include <linux/ppp_defs.h>
#else
#error Unable to find a usable ppp_defs include
#endif

#define __FAVOR_BSD
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#undef __FAVOR_BSD

#if defined(__linux__)
#define _ND_ADDROFF(ptr, typeof, member) &ptr->member
#elif defined(__FreeBSD__)
// XXX: FreeBSD network structures such as 'struct ip' are
// packed.  Eliminate unaligned address warnings.
#define _ND_ADDROFF(ptr, typeof, member) \
    ((size_t)ptr + offsetof(typeof, member))
#endif

#if ! defined(ETHERTYPE_MPLS_UC)
#if defined(ETHERTYPE_MPLS)
#define ETHERTYPE_MPLS_UC ETHERTYPE_MPLS
#elif defined(ETH_P_MPLS_UC)
#define ETHERTYPE_MPLS_UC ETH_P_MPLS_UC
#else
#error Unable to find suitable define for ETHERTYPE_MPLS_UC
#endif
#endif

#if ! defined(ETHERTYPE_MPLS_MC)
#if defined(ETHERTYPE_MPLS_MCAST)
#define ETHERTYPE_MPLS_MC ETHERTYPE_MPLS_MCAST
#elif defined(ETH_P_MPLS_MC)
#define ETHERTYPE_MPLS_MC ETH_P_MPLS_MC
#else
#error Unable to find suitable define for ETHERTYPE_MPLS_MC
#endif
#endif

#if ! defined(ETHERTYPE_PPPOE)
#if defined(ETH_P_PPP_SES)
#define ETHERTYPE_PPPOE ETH_P_PPP_SES
#else
#error Unable to find suitable define for ETHERTYPE_PPPOE
#endif
#endif

#if ! defined(ETHERTYPE_PPPOEDISC)
#if defined(ETH_P_PPP_DISC)
#define ETHERTYPE_PPPOEDISC ETH_P_PPP_DISC
#else
#error Unable to find suitable define for ETHERTYPE_PPPOEDISC
#endif
#endif

#define _ND_PPP_PROTOCOL(p) \
    ((((uint8_t *)(p))[0] << 8) + ((uint8_t *)(p))[1])

#define _ND_GTP_U_PORT 2152
#define _ND_GTP_G_PDU  0xff

#include "nd-capture.hpp"
#include "nd-config.hpp"
#include "nd-detection.hpp"

using namespace std;

// Enable to log discarded packets
// #define _ND_LOG_PKT_DISCARD 1

// Enable to log discarded TCP packets
// #define _ND_LOG_PKT_DISCARD_TCP 1

// Enable to log discarded flows
// #define _ND_LOG_FLOW_DISCARD 1

#define _ND_LOG_DISCARD(tag, reason) \
    nd_dprintf("%s: discard: %s\n", tag, reason);

#define _ND_LOG_DISCARD_ETHER(tag, reason, eth_hdr) \
    if (eth_hdr == nullptr) { \
        _ND_LOG_DISCARD(tag, reason) \
    } \
    else { \
        nd_dprintf( \
          "%s: discard: %s: src: " \
          "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx, " \
          "dst: " \
          "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n", \
          tag, reason, eth_hdr->ether_shost[0], \
          eth_hdr->ether_shost[1], eth_hdr->ether_shost[2], \
          eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], \
          eth_hdr->ether_shost[5], eth_hdr->ether_dhost[0], \
          eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2], \
          eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], \
          eth_hdr->ether_dhost[5]); \
    }

// Enable to log TCP flags
// #define _ND_LOG_PKT_TCP_FLAGS 1

// Enable to log replay packet delay intervals
// #define _ND_LOG_PKT_DELAY_TIME 1

// Enable DNS response debug logging
// #define _ND_LOG_DNS_RESPONSE 1

// Enable DNS hint cache debug logging
// #define _ND_LOG_DHC 1

// Enable flow hash cache debug logging
// #define _ND_LOG_FHC 1

// Enable GTP tunnel dissection
#define _ND_DISSECT_GTP 1

struct __attribute__((packed)) nd_mpls_header_t {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint32_t ttl:8, s:1, exp:3, label:20;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    uint32_t label:20, exp:3, s:1, ttl:8;
#else
#error Endianess not defined (__BYTE_ORDER__).
#endif
};
#ifdef _ND_DISSECT_GTP
struct __attribute__((packed)) nd_gtpv1_header_t {
    struct {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        uint8_t npdu_num:1;
        uint8_t seq_num:1;
        uint8_t ext_hdr:1;
        uint8_t reserved:1;
        uint8_t proto_type:1;
        uint8_t version:3;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        uint8_t version:3;
        uint8_t proto_type:1;
        uint8_t reserved:1;
        uint8_t ext_hdr:1;
        uint8_t seq_num:1;
        uint8_t npdu_num:1;
#else
#error Endianess not defined (__BYTE_ORDER__).
#endif
    } flags;

    uint8_t type;
    uint16_t length;
    uint32_t teid;
};

struct __attribute__((packed)) nd_gtpv2_header_t {
    struct {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        uint8_t reserved:3;
        uint8_t teid:1;
        uint8_t piggyback:1;
        uint8_t version:3;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        uint8_t version:3;
        uint8_t piggyback:1;
        uint8_t teid:1;
        uint8_t reserved:3;
#else
#error Endianess not defined (__BYTE_ORDER__).
#endif
    } flags;

    uint8_t type;
    uint16_t length;
    uint32_t teid;
};
#endif  // _ND_DISSECT_GTP

struct __attribute__((packed)) nd_dns_header_t {
    uint16_t tr_id;
    uint16_t flags;
    uint16_t num_queries;
    uint16_t num_answers;
    uint16_t authority_rrs;
    uint16_t additional_rrs;
};

ndCaptureThread::ndCaptureThread(ndFlags<ndCaptureType> cs_type,
  int16_t cpu, nd_iface_ptr &iface,
  const ndDetectionThreads &threads_dpi,
  ndDNSHintCache *dhc, uint8_t private_addr)
  : ndThread(iface->ifname, (long)cpu, /* IPC? */ false),
    cs_type(cs_type), iface(iface), flow(iface), dhc(dhc),
    threads_dpi(threads_dpi),
    dpi_thread_id(rand() % threads_dpi.size()) {

    if (ndGC_REPLAY_DELAY &&
      ndCT_TYPE(iface->capture_type.flags) != ndCaptureType::PCAP_OFFLINE)
    {
        nd_printf(
          "%s: WARNING: replay delay enabled for online "
          "capture!",
          tag.c_str());
        nd_dprintf("%s: disabling replay delay.\n", tag.c_str());

        ndGC_SetFlag(ndGlobalFlags::REPLAY_DELAY, false);
    }

    private_addrs.first.ss_family = AF_INET;
    nd_private_ipaddr(private_addr, private_addrs.first);

    private_addrs.second.ss_family = AF_INET6;
    nd_private_ipaddr(private_addr, private_addrs.second);
}

const ndPacket *
ndCaptureThread::ProcessPacket(const ndPacket *packet) {
    nd_flow_ptr nf;
    ndDebugLogStream dls(ndDebugLogStream::Type::FLOW);
    const struct ether_header *hdr_eth = nullptr;
    const struct sll_header *hdr_sll = nullptr;
    const struct ip *hdr_ip = nullptr;
    const struct ip6_hdr *hdr_ip6 = nullptr;
    const struct tcphdr *hdr_tcp = nullptr;
    const struct udphdr *hdr_udp = nullptr;
#ifdef _ND_DISSECT_GTP
    const struct nd_gtpv1_header_t *hdr_gtpv1 = nullptr;
    const struct nd_gtpv2_header_t *hdr_gtpv2 = nullptr;
#endif
    const uint8_t *l3 = nullptr, *l4 = nullptr, *pkt = nullptr;
    uint16_t l2_len, l3_len, l4_len = 0, pkt_len = 0;
    uint16_t type = 0;
    uint16_t ppp_proto;
    uint16_t frag_off = 0;
    uint8_t vlan_packet = 0;
    int addr_cmp = 0;

    uint64_t ts_pkt = ((uint64_t)packet->tv_sec) * ND_DETECTION_TICKS +
      packet->tv_usec / (1000000 / ND_DETECTION_TICKS);

    if (ndCT_TYPE(iface->capture_type.flags) == ndCaptureType::PCAP_OFFLINE)
    {
        if (ts_pkt_first == 0) ts_pkt_first = ts_pkt;

        ts_pkt = (ts_pkt - ts_pkt_first) + (tv_epoch * 1000);

        if (ts_pkt_last > ts_pkt) ts_pkt = ts_pkt_last;

        if (ndGC_REPLAY_DELAY) {
            if (ts_pkt_last) {
                useconds_t delay =
                  useconds_t(ts_pkt - ts_pkt_last) * 1000;
#ifdef _ND_LOG_PKT_DELAY_TIME
                nd_dprintf("%s: pkt delay: %lu\n",
                  tag.c_str(), delay);
#endif
                if (delay) {
                    pthread_mutex_unlock(&lock);
                    usleep(delay);
                    pthread_mutex_lock(&lock);
                }
            }
        }
        else if (ts_pkt_last > ts_pkt) ts_pkt = ts_pkt_last;
    }

    ts_pkt_last = ts_pkt;

    stats.pkt.raw++;
    if (packet->length > stats.pkt.maxlen)
        stats.pkt.maxlen = packet->length;

    switch (dl_type) {
    case DLT_NULL:
        if (packet->caplen < sizeof(uint32_t)) {
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            _ND_LOG_DISCARD(tag.c_str(), "truncated packet");
#endif
            return packet;
        }

        switch (ntohl(*((uint32_t *)packet->data))) {
        case 2: type = ETHERTYPE_IP; break;
        case 24:
        case 28:
        case 30: type = ETHERTYPE_IPV6; break;
        default:
#ifdef _ND_LOG_PKT_DISCARD
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
            _ND_LOG_DISCARD(tag.c_str(),
              "unsupported BSD loopback encapsulation "
              "type");
#endif
            return packet;
        }

        l2_len = 4;
        break;

    case DLT_EN10MB:
        if (packet->caplen < sizeof(struct ether_header)) {
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            _ND_LOG_DISCARD(tag.c_str(), "truncated packet");
#endif
            return packet;
        }

        hdr_eth = reinterpret_cast<const struct ether_header *>(
          packet->data);
        type = ntohs(hdr_eth->ether_type);
        l2_len = sizeof(struct ether_header);
        stats.pkt.eth++;

        // STP?
        if ((hdr_eth->ether_shost[0] == 0x01 &&
              hdr_eth->ether_shost[1] == 0x80 &&
              hdr_eth->ether_shost[2] == 0xC2) ||
          (hdr_eth->ether_dhost[0] == 0x01 &&
            hdr_eth->ether_dhost[1] == 0x80 &&
            hdr_eth->ether_dhost[2] == 0xC2))
        {
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            _ND_LOG_DISCARD_ETHER(tag.c_str(),
              "bridge group address", hdr_eth);
#endif
            return packet;
        }

        break;

    case DLT_LINUX_SLL:
        if (packet->caplen < sizeof(struct sll_header)) {
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            _ND_LOG_DISCARD_ETHER(tag.c_str(),
              "truncated packet", hdr_eth);
#endif
            return packet;
        }

        hdr_sll = reinterpret_cast<const struct sll_header *>(
          packet->data);
        type = hdr_sll->sll_protocol;
        l2_len = SLL_HDR_LEN;
        break;

    case DLT_RAW:
    case DLT_IPV4:
    case DLT_IPV6:
        l2_len = 0;
        // type will be set to ETHERTYPE_IP/V6 below...
        break;

    default:
        stats.pkt.discard++;
        stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
        _ND_LOG_DISCARD_ETHER(tag.c_str(),
          "unsupported datalink type", hdr_eth);
#endif
        return packet;
    }

    if (l2_len > packet->caplen) {
        stats.pkt.discard++;
        stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
        _ND_LOG_DISCARD_ETHER(tag.c_str(),
          "layer-2 length is beyond capture length", hdr_eth);
#endif
    }

    flow.vlan_id = 0;

    while (true) {
        if (type == ETHERTYPE_VLAN) {
            if (l2_len + 4 > packet->caplen) {
                stats.pkt.discard++;
                stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
                _ND_LOG_DISCARD_ETHER(tag.c_str(),
                  "layer-2 + VLAN length is beyond capture "
                  "length",
                  hdr_eth);
#endif
            }

            // TODO: Replace with struct vlan_tag from
            // <pcap/vlan.h> See:
            // https://en.wikipedia.org/wiki/IEEE_802.1Q
            vlan_packet = 1;
            flow.vlan_id = ((packet->data[l2_len] << 8) +
                             packet->data[l2_len + 1]) &
              0xFFF;
            type = (packet->data[l2_len + 2] << 8) +
              packet->data[l2_len + 3];
            l2_len += VLAN_TAG_LEN;
        }
        else if (type == ETHERTYPE_MPLS_UC || type == ETHERTYPE_MPLS_MC)
        {
            stats.pkt.mpls++;
            uint32_t u32 = (uint32_t)ntohl(
              *((uint32_t *)&packet->data[l2_len]));
            const struct nd_mpls_header_t *mpls =
              reinterpret_cast<const struct nd_mpls_header_t *>(&u32);
            type = ETHERTYPE_IP;
            l2_len += 4;

            if (l2_len > packet->caplen) {
                stats.pkt.discard++;
                stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
                _ND_LOG_DISCARD_ETHER(tag.c_str(),
                  "layer-2 + MPLS length is beyond capture "
                  "length",
                  hdr_eth);
#endif
            }

            while (! mpls->s) {
                l2_len += 4;

                if (l2_len > packet->caplen) {
                    stats.pkt.discard++;
                    stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
                    _ND_LOG_DISCARD_ETHER(tag.c_str(),
                      "%s: discard: layer-2 + MPLS length "
                      "is beyond capture length",
                      hdr_eth);
#endif
                }
                u32 = (uint32_t)ntohl(
                  *((uint32_t *)&packet->data[l2_len]));
                mpls = reinterpret_cast<const struct nd_mpls_header_t *>(
                  &u32);
            }
        }
        else if (type == ETHERTYPE_PPPOE) {
            stats.pkt.pppoe++;
            type = ETHERTYPE_IP;

            if (l2_len + 6 > packet->caplen) {
                stats.pkt.discard++;
                stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
                _ND_LOG_DISCARD_ETHER(tag.c_str(),
                  "layer-2 + PPP length is beyond capture "
                  "length",
                  hdr_eth);
#endif
            }

            ppp_proto = (uint16_t)(_ND_PPP_PROTOCOL(
              packet->data + l2_len + 6));
            if (ppp_proto != PPP_IP && ppp_proto != PPP_IPV6)
            {
                stats.pkt.discard++;
                stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
                _ND_LOG_DISCARD_ETHER(tag.c_str(),
                  "unsupported PPP protocol", hdr_eth);
#endif
                return packet;
            }

            l2_len += 8;

            if (l2_len > packet->caplen) {
                stats.pkt.discard++;
                stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
                _ND_LOG_DISCARD_ETHER(tag.c_str(),
                  "layer-2 + PPP length is beyond capture "
                  "length",
                  hdr_eth);
#endif
            }
        }
        else if (type == ETHERTYPE_PPPOEDISC) {
            stats.pkt.pppoe++;
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            _ND_LOG_DISCARD_ETHER(tag.c_str(),
              "PPPoE discovery protocol", hdr_eth);
#endif
            return packet;
        }
        else break;
    }

    stats.pkt.vlan += vlan_packet;

    flow.tunnel_type = ndFlow::TunnelType::NONE;

nd_process_ip:
    if (l2_len + sizeof(struct ip) > packet->caplen) {
        stats.pkt.discard++;
        stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
        _ND_LOG_DISCARD_ETHER(tag.c_str(),
          "layer-2 + IP length is beyond capture length", hdr_eth);
#endif
    }

    hdr_ip = reinterpret_cast<const struct ip *>(
      &packet->data[l2_len]);

    flow.ip_version = hdr_ip->ip_v;

    if (flow.ip_version == 4) {
        if (type == 0) type = ETHERTYPE_IP;

        l3_len = ((uint16_t)hdr_ip->ip_hl * 4);
        l4_len = ntohs(hdr_ip->ip_len) - l3_len;
        flow.ip_protocol = hdr_ip->ip_p;
        l3 = reinterpret_cast<const uint8_t *>(hdr_ip);

        if (packet->caplen >= l2_len)
            frag_off = ntohs(hdr_ip->ip_off);

        if ((unsigned)(packet->caplen - l2_len) < sizeof(struct ip))
        {
            // XXX: header too small
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            _ND_LOG_DISCARD_ETHER(tag.c_str(),
              "IP header too small", hdr_eth);
#endif
            return packet;
        }

        if ((frag_off & 0x3FFF) != 0) {
            // XXX: fragmented packets are not supported
            stats.pkt.frags++;
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            _ND_LOG_DISCARD_ETHER(tag.c_str(),
              "fragmented IP, offset: 0x3fff\n", hdr_eth);
#endif
            return packet;
        }

        if ((frag_off & 0x1FFF) != 0) {
            // XXX: fragmented packets are not supported
            stats.pkt.frags++;
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            _ND_LOG_DISCARD_ETHER(tag.c_str(),
              "fragmented IP, offset: 0x1fff\n", hdr_eth);
#endif
            return packet;
        }

        if (l3_len > (packet->caplen - l2_len)) {
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            nd_dprintf(
              "%s: discard: l3_len[%hu] > "
              "(packet->caplen[%hu] - l2_len[%hu])(%hu)\n",
              tag.c_str(), l3_len, packet->caplen, l2_len,
              packet->caplen - l2_len);
#endif
            return packet;
        }

        addr_cmp = memcmp(
          (const uint8_t *)_ND_ADDROFF(hdr_ip, struct ip, ip_src),
          (const uint8_t *)_ND_ADDROFF(hdr_ip, struct ip, ip_dst),
          sizeof(struct in_addr));

        if (addr_cmp < 0) {
            ndAddr::Create(flow.lower_addr,
              (const struct in_addr *)_ND_ADDROFF(hdr_ip,
                struct ip, ip_src));
            ndAddr::Create(flow.upper_addr,
              (const struct in_addr *)_ND_ADDROFF(hdr_ip,
                struct ip, ip_dst));
            if (dl_type == DLT_EN10MB) {
                ndAddr::Create(flow.lower_mac,
                  (const uint8_t *)hdr_eth->ether_shost,
                  ETH_ALEN);
                ndAddr::Create(flow.upper_mac,
                  (const uint8_t *)hdr_eth->ether_dhost,
                  ETH_ALEN);
            }
        }
        else {
            ndAddr::Create(flow.lower_addr,
              (const struct in_addr *)_ND_ADDROFF(hdr_ip,
                struct ip, ip_dst));
            ndAddr::Create(flow.upper_addr,
              (const struct in_addr *)_ND_ADDROFF(hdr_ip,
                struct ip, ip_src));
            if (dl_type == DLT_EN10MB) {
                ndAddr::Create(flow.lower_mac,
                  (const uint8_t *)hdr_eth->ether_dhost,
                  ETH_ALEN);
                ndAddr::Create(flow.upper_mac,
                  (const uint8_t *)hdr_eth->ether_shost,
                  ETH_ALEN);
            }
        }

        l4 = reinterpret_cast<const uint8_t *>(l3 + l3_len);
    }
    else if (flow.ip_version == 6) {
        if (type == 0) type = ETHERTYPE_IPV6;

        hdr_ip6 = reinterpret_cast<const struct ip6_hdr *>(
          &packet->data[l2_len]);

        l3 = reinterpret_cast<const uint8_t *>(hdr_ip6);
        l3_len = sizeof(struct ip6_hdr);
        l4 = reinterpret_cast<const uint8_t *>(l3 + l3_len);
        l4_len = ntohs(hdr_ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);
        flow.ip_protocol = hdr_ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;

        if (ndpi_handle_ipv6_extension_headers(l3_len, &l4,
              &l4_len, &flow.ip_protocol))
        {
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            _ND_LOG_DISCARD_ETHER(tag.c_str(),
              "error walking IPv6 extensions", hdr_eth);
#endif
            return packet;
        }

        int i = 0;
        if (memcmp(&hdr_ip6->ip6_src, &hdr_ip6->ip6_dst,
              sizeof(struct in6_addr)))
        {
            do {
                addr_cmp = memcmp(&hdr_ip6->ip6_src.s6_addr32[i],
                  &hdr_ip6->ip6_dst.s6_addr32[i],
                  sizeof(uint32_t));
                i++;
            }
            while (addr_cmp == 0);
        }

        if (addr_cmp < 0) {
            ndAddr::Create(flow.lower_addr,
              (const struct in6_addr *)_ND_ADDROFF(hdr_ip6,
                struct ip6_hdr, ip6_src));
            ndAddr::Create(flow.upper_addr,
              (const struct in6_addr *)_ND_ADDROFF(hdr_ip6,
                struct ip6_hdr, ip6_dst));
            if (dl_type == DLT_EN10MB) {
                ndAddr::Create(flow.lower_mac,
                  hdr_eth->ether_shost, ETH_ALEN);
                ndAddr::Create(flow.upper_mac,
                  hdr_eth->ether_dhost, ETH_ALEN);
            }
        }
        else {
            ndAddr::Create(flow.lower_addr,
              (const struct in6_addr *)_ND_ADDROFF(hdr_ip6,
                struct ip6_hdr, ip6_dst));
            ndAddr::Create(flow.upper_addr,
              (const struct in6_addr *)_ND_ADDROFF(hdr_ip6,
                struct ip6_hdr, ip6_src));
            if (dl_type == DLT_EN10MB) {
                ndAddr::Create(flow.lower_mac,
                  hdr_eth->ether_dhost, ETH_ALEN);
                ndAddr::Create(flow.upper_mac,
                  hdr_eth->ether_shost, ETH_ALEN);
            }
        }
    }
    else {
        // XXX: Warning: unsupported IP protocol version (IPv4/6
        // only)
        stats.pkt.discard++;
        stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
        _ND_LOG_DISCARD_ETHER(tag.c_str(),
          "invalid IP protocol version", hdr_eth);
#endif
        return packet;
    }

    if (l2_len + l3_len + l4_len > packet->caplen) {
        stats.pkt.discard++;
        stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
        _ND_LOG_DISCARD_ETHER(tag.c_str(),
          "layer-2 + layer-3 + layer-4 length is beyond "
          "capture length",
          hdr_eth);
#endif
        return packet;
    }

#if _ND_DISSECT_GTP
    if (l4_len > 8 && flow.ip_protocol == IPPROTO_UDP) {
        hdr_udp = reinterpret_cast<const struct udphdr *>(l4);

        if (ntohs(hdr_udp->uh_sport) == _ND_GTP_U_PORT ||
          ntohs(hdr_udp->uh_dport) == _ND_GTP_U_PORT)
        {
            hdr_gtpv1 = reinterpret_cast< const struct nd_gtpv1_header_t *>(
              l4 + sizeof(struct udphdr));

            if (hdr_gtpv1->flags.version == 1) {
                if (flow.tunnel_type == ndFlow::TunnelType::NONE)
                {
                    flow.tunnel_type = ndFlow::TunnelType::GTP;

                    flow.gtp.version = hdr_gtpv1->flags.version;
                    flow.gtp.ip_version = flow.ip_version;
                    flow.gtp.lower_addr = flow.lower_addr;
                    flow.gtp.upper_addr = flow.upper_addr;
                }

                if (hdr_gtpv1->type == _ND_GTP_G_PDU) {
                    l2_len = (l4 - packet->data) +
                      sizeof(struct udphdr) + 8;

                    if (hdr_gtpv1->flags.ext_hdr)
                        l2_len += 1;
                    if (hdr_gtpv1->flags.seq_num)
                        l2_len += 4;
                    if (hdr_gtpv1->flags.npdu_num)
                        l2_len += 1;

                    goto nd_process_ip;
                }
#if 0
                else {
                    nd_dprintf("%s: unsupported GTPv1 message type: 0x%hhx (%hhu)\n",
                        tag.c_str(), hdr_gtpv1->type, hdr_gtpv1->type);
                }
#endif
            }
            else if (hdr_gtpv1->flags.version == 2) {
                // TODO: GTPv2...
                hdr_gtpv2 = reinterpret_cast< const struct nd_gtpv2_header_t *>(
                  l4 + sizeof(struct udphdr));
                nd_dprintf(
                  "%s: unimplemented GTP version (TODO): "
                  "%u\n",
                  tag.c_str(), hdr_gtpv1->flags.version);
            }
            else {
                nd_dprintf(
                  "%s: unsupported GTP version: %u\n",
                  tag.c_str(), hdr_gtpv1->flags.version);
            }
        }
    }
#endif
    switch (flow.ip_protocol) {
    case IPPROTO_TCP:
        stats.pkt.tcp++;

        if (l4_len < 20) {
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            _ND_LOG_DISCARD_ETHER(tag.c_str(),
              "layer-4 length is too small for TCP header", hdr_eth);
#endif
            return packet;
        }
        else {
            hdr_tcp = reinterpret_cast<const struct tcphdr *>(l4);
#ifdef _ND_LOG_PKT_TCP_FLAGS
            nd_dprintf("%s: TCP flags: %c%c%c%c%c%c\n",
              tag.c_str(), (hdr_tcp->th_flags & TH_FIN) ? 'f' : '-',
              (hdr_tcp->th_flags & TH_SYN) ? 's' : '-',
              (hdr_tcp->th_flags & TH_RST) ? 'r' : '-',
              (hdr_tcp->th_flags & TH_PUSH) ? 'p' : '-',
              (hdr_tcp->th_flags & TH_ACK) ? 'a' : '-',
              (hdr_tcp->th_flags & TH_URG) ? 'u' : '-');
#endif
            uint16_t hdr_size = hdr_tcp->th_off * 4;

            if (hdr_size < 20 || hdr_size > l4_len) {
                stats.pkt.discard++;
                stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
                _ND_LOG_DISCARD_ETHER(tag.c_str(),
                  "unexpected TCP payload length", hdr_eth);
#endif
                return packet;
            }

            if (addr_cmp < 0) {
                flow.lower_addr.SetPort(hdr_tcp->th_sport);
                flow.upper_addr.SetPort(hdr_tcp->th_dport);
            }
            else if (addr_cmp > 0) {
                flow.lower_addr.SetPort(hdr_tcp->th_dport);
                flow.upper_addr.SetPort(hdr_tcp->th_sport);
            }
            else {
                if (hdr_tcp->th_sport < hdr_tcp->th_dport) {
                    flow.lower_addr.SetPort(hdr_tcp->th_sport);
                    flow.upper_addr.SetPort(hdr_tcp->th_dport);
                }
                else {
                    flow.lower_addr.SetPort(hdr_tcp->th_dport);
                    flow.upper_addr.SetPort(hdr_tcp->th_sport);
                }
            }

            pkt = reinterpret_cast<const uint8_t *>(
              l4 + (hdr_tcp->th_off * 4));
            pkt_len = l4_len - hdr_size;
        }

        break;

    case IPPROTO_UDP:
        stats.pkt.udp++;

        if (l4_len < 8) {
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            _ND_LOG_DISCARD_ETHER(tag.c_str(),
              "layer-4 length is too small for UDP header", hdr_eth);
#endif
            return packet;
        }

        hdr_udp = reinterpret_cast<const struct udphdr *>(l4);

        if (addr_cmp < 0) {
            flow.lower_addr.SetPort(hdr_udp->uh_sport);
            flow.upper_addr.SetPort(hdr_udp->uh_dport);
        }
        else if (addr_cmp > 0) {
            flow.lower_addr.SetPort(hdr_udp->uh_dport);
            flow.upper_addr.SetPort(hdr_udp->uh_sport);
        }
        else {
            if (hdr_udp->uh_sport < hdr_udp->uh_dport) {
                flow.lower_addr.SetPort(hdr_udp->uh_sport);
                flow.upper_addr.SetPort(hdr_udp->uh_dport);
            }
            else {
                flow.lower_addr.SetPort(hdr_udp->uh_dport);
                flow.upper_addr.SetPort(hdr_udp->uh_sport);
            }
        }

        if (ntohs(hdr_udp->uh_ulen) != l4_len) {
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            _ND_LOG_DISCARD_ETHER(tag.c_str(),
              "unexpected UDP data length", hdr_eth);
#endif
            return packet;
        }

        pkt = reinterpret_cast<const uint8_t *>(
          l4 + sizeof(struct udphdr));
        pkt_len = ntohs(hdr_udp->uh_ulen) - sizeof(struct udphdr);

        break;

    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6: stats.pkt.icmp++; break;

    case IPPROTO_IGMP: stats.pkt.igmp++; break;

    default:
        // Non-TCP/UDP protocols, ex: ICMP...
        // nd_dprintf("%s: non TCP/UDP protocol: %d\n",
        // tag.c_str(), flow.ip_protocol);
        break;
    }

    flow.Hash(tag);
    flow_digest.assign(flow.digest_lower.begin(),
      flow.digest_lower.end());

    nf = ndi.flow_buckets->Lookup(flow_digest, true);

    if (nf) {
        // Flow exists in map.
        if (nf->direction != addr_cmp) {
#if _ND_DISSECT_GTP
            if (hdr_gtpv1 != nullptr && hdr_gtpv1->flags.version == 1)
            {
                if (nf->tunnel_type == ndFlow::TunnelType::GTP)
                {
                    switch (nf->origin) {
                    case ndFlow::Origin::LOWER:
                        if (nf->gtp.upper_teid == 0)
                            nf->gtp.upper_teid = hdr_gtpv1->teid;
                        else if (hdr_gtpv1->teid != nf->gtp.upper_teid)
                            nf->gtp.upper_teid = hdr_gtpv1->teid;
                        break;
                    case ndFlow::Origin::UPPER:
                        if (nf->gtp.lower_teid == 0)
                            nf->gtp.lower_teid = hdr_gtpv1->teid;
                        else if (hdr_gtpv1->teid != nf->gtp.lower_teid)
                            nf->gtp.lower_teid = hdr_gtpv1->teid;
                        break;
                    default: break;
                    }
                }
            }
            else if (hdr_gtpv2 != nullptr &&
              hdr_gtpv2->flags.version == 2)
            {
                // TODO: Implemented GTPv2.
            }
#endif
        }

        ndi.flow_buckets->Release(flow_digest);
    }
    else {
        if (ndGC.max_flows > 0 &&
          ndi.status.flows.load() + 1 > ndGC.max_flows)
        {
#ifdef _ND_LOG_FLOW_DISCARD
            _ND_LOG_DISCARD(tag.c_str(),
              "maximum flows exceeded");
#endif
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
            stats.flow.dropped++;

            ndi.flow_buckets->Release(flow_digest);
            return packet;
        }

        // A new TCP flow must only have SYN+ACK bits set
        if (ndGC_SYN_SCAN_PROTECTION && flow.ip_protocol == IPPROTO_TCP &&
          hdr_tcp->th_flags != (TH_SYN | TH_ACK))
        {
#ifdef _ND_LOG_PKT_DISCARD_TCP
            _ND_LOG_DISCARD(tag.c_str(),
              "new TCP flow without SYN/ACK");
#endif
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
            stats.flow.dropped++;

            ndi.flow_buckets->Release(flow_digest);
            return packet;
        }

        nf = make_shared<ndFlow>(flow);

        nf->direction = addr_cmp;

        if (! ndi.flow_buckets->InsertUnlocked(flow_digest, nf))
        {
            ndi.flow_buckets->Release(flow_digest);
            // Flow exists in map!  Impossible!
            throw ndException("%s: flow exists in map",
              tag.c_str());
        }

        ndi.status.flows++;

        // New flow inserted, initialize...
        nf->ts_first_seen = ts_pkt;

        // Set initial flow origin:
        // XXX: A 50-50 guess based on which side we saw first.
        if (addr_cmp < 0)
            nf->origin = ndFlow::Origin::LOWER;
        else nf->origin = ndFlow::Origin::UPPER;

        // Refine according to the lowest port address
        // XXX: The lowest port is likely the destination.
        switch (nf->ip_protocol) {
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
        case IPPROTO_UDP:
        case IPPROTO_UDPLITE:
            if (nf->lower_addr.GetPort() < nf->upper_addr.GetPort())
                nf->origin = ndFlow::Origin::UPPER;
            else if (nf->lower_addr.GetPort() >
              nf->upper_addr.GetPort())
                nf->origin = ndFlow::Origin::LOWER;
            break;
        }

        // Try to refine flow origin for TCP flows using SYN/ACK
        // flags
        if (nf->ip_protocol == IPPROTO_TCP) {
            if ((hdr_tcp->th_flags & TH_SYN)) {
                if (! (hdr_tcp->th_flags & TH_ACK)) {
                    if (addr_cmp < 0)
                        nf->origin = ndFlow::Origin::LOWER;
                    else nf->origin = ndFlow::Origin::UPPER;
                }
                else {
                    if (addr_cmp < 0)
                        nf->origin = ndFlow::Origin::UPPER;
                    else nf->origin = ndFlow::Origin::LOWER;
                }
            }
        }

        if (nf->tunnel_type == ndFlow::TunnelType::GTP) {
            switch (nf->origin) {
            case ndFlow::Origin::LOWER:
                nf->gtp.lower_teid = hdr_gtpv1->teid;
                break;
            case ndFlow::Origin::UPPER:
                nf->gtp.upper_teid = hdr_gtpv1->teid;
                break;
            default: break;
            }
        }

        ndi.flow_buckets->Release(flow_digest);

        ndi.plugins.BroadcastProcessorEvent(
          ndPluginProcessor::Event::FLOW_NEW, nf);
    }

    stats.pkt.wire_bytes += packet->length + 24;

    stats.pkt.ip++;
    stats.pkt.ip_bytes += packet->length;

    if (nf->ip_version == 4) {
        stats.pkt.ip4++;
        stats.pkt.ip4_bytes += packet->length;
    }
    else {
        stats.pkt.ip6++;
        stats.pkt.ip6_bytes += packet->length;
    }

    nf->stats.total_packets++;
    nf->stats.total_bytes += packet->length;

    if (addr_cmp < 0) {
        nf->stats.lower_packets++;
        nf->stats.lower_bytes += packet->length;
#ifdef _ND_ENABLE_EXTENDED_STATS
        nf->stats.UpdateRate(true, ts_pkt, packet->length);
#endif
    }
    else {
        nf->stats.upper_packets++;
        nf->stats.upper_bytes += packet->length;
#ifdef _ND_ENABLE_EXTENDED_STATS
        nf->stats.UpdateRate(false, ts_pkt, packet->length);
#endif
    }

    nf->ts_last_seen = ts_pkt;

    if (nf->ip_protocol == IPPROTO_TCP) {
        if (hdr_tcp->th_seq <= nf->tcp.last_seq) {
            nf->tcp.last_seq = hdr_tcp->th_seq;
#ifdef _ND_ENABLE_EXTENDED_STATS
            nf->stats.tcp_seq_errors++;
            // TODO: tcp_retrans detection
#endif
            stats.pkt.tcp_seq_errors++;
        }

        if ((hdr_tcp->th_flags & TH_FIN) &&
          (hdr_tcp->th_flags & TH_ACK))
            nf->tcp.fin_ack++;
        if (hdr_tcp->th_flags & TH_RST) {
#ifdef _ND_ENABLE_EXTENDED_STATS
            nf->stats.tcp_resets++;
#endif
            stats.pkt.tcp_resets++;
        }
    }

    if (dhc != nullptr && pkt != nullptr &&
      pkt_len > sizeof(struct nd_dns_header_t) &&
      packet->caplen == packet->length)
    {
        ndProto::Id proto = ndProto::Id::UNKNOWN;

        if (nf->GetMasterProtocol() == ndProto::Id::DNS)
            proto = nf->detected_protocol;
        else {
            uint16_t lport = nf->lower_addr.GetPort(),
                     uport = nf->upper_addr.GetPort();

            // DNS, MDNS, or LLMNR?
            if (lport == 53 || uport == 53)
                proto = ndProto::Id::DNS;
            else if (lport == 5353 || uport == 5353)
                proto = ndProto::Id::MDNS;
            else if (lport == 5355 || uport == 5355)
                proto = ndProto::Id::LLMNR;
        }

        if (proto != ndProto::Id::UNKNOWN)
            ProcessDNSPacket(nf, pkt, pkt_len, proto);
    }

    if (nf->flags.detection_complete.load() == false &&
      nf->flags.expired.load() == false &&
      nf->stats.detection_packets.load() < ndGC.max_detection_pkts &&
      nf->dpi_queued < ndGC.max_detection_pkts)
    {
        nf->dpi_queued++;

        if (nf->dpi_thread_id < 0) {
            nf->dpi_thread_id = dpi_thread_id;
            if (++dpi_thread_id == (int16_t)threads_dpi.size())
                dpi_thread_id = 0;
        }

        auto idpi = threads_dpi.find(nf->dpi_thread_id);

        if (idpi != threads_dpi.end()) {
            idpi->second->QueuePacket(nf, packet,
              (nf->ip_version == 4) ? (uint8_t *)hdr_ip : (uint8_t *)hdr_ip6,
              packet->caplen - l2_len);

            // Hand over packet ownership to the DPI queue
            packet = nullptr;
        }
        else {
            throw ndException(
              "%s: detection thread ID not found (%hd)",
              tag.c_str(), nf->dpi_thread_id);
        }
    }
    // dls << "PACKET RECEIVED LETS GOOOOOOOOOOOOOOooo" <<
    // " Local Bytes: " << nf->stats.lower_bytes.load() << ", "
    // "Other Bytes: " << nf->stats.upper_bytes.load() << ", "
    // "Host Server Name: " << (nf->HasMDNSDomainName() ? nf->mdns.domain_name : "N/A") << ", "
    // "Local IP: " << nf->lower_addr.GetString() << ", "
    // "Other IP: " << nf->upper_addr.GetString() << ", "
    // "Total Packets: " << nf->stats.total_packets.load() << ", "
    // "Total Bytes: " << nf->stats.total_bytes.load() << "\n";
    return packet;
}

bool ndCaptureThread::ProcessDNSPacket(nd_flow_ptr &flow,
  const uint8_t *pkt,
  uint16_t pkt_len,
  ndProto::Id proto) {
    ns_rr rr;
    ns_msg ns_h;
    const char *host = nullptr;
    int rc = ns_initparse(pkt, pkt_len, &ns_h);

    if (rc < 0) {
        // XXX: (Most) TCP DNS packets have a two byte header
        pkt += 2;
        pkt_len -= 2;
    }

    rc = ns_initparse(pkt, pkt_len, &ns_h);

    if (rc < 0) {
#ifdef _ND_LOG_DHC
        nd_dprintf(
          "%s: dns initparse error: %s, length: %hu\n",
          tag.c_str(), strerror(errno), pkt_len);
#endif
        return false;
    }

    if (ns_msg_getflag(ns_h, ns_f_rcode) != ns_r_noerror) {
#ifdef _ND_LOG_DHC
        nd_dprintf("%s: dns response code: %hu\n",
          tag.c_str(), ns_msg_getflag(ns_h, ns_f_rcode));
#endif
        return false;
    }

#ifdef _ND_LOG_DHC
    nd_dprintf(
      "%s: type: %d, dns queries: %hu, answers: %hu\n",
      tag.c_str(), ns_msg_getflag(ns_h, ns_f_qr),
      ns_msg_count(ns_h, ns_s_qd), ns_msg_count(ns_h, ns_s_an));
#endif

    for (uint16_t i = 0; i < ns_msg_count(ns_h, ns_s_qd); i++)
    {
        if (ns_parserr(&ns_h, ns_s_qd, i, &rr)) {
#ifdef _ND_LOG_DHC
            nd_dprintf(
              "%s: dns error parsing QD RR %hu of %hu.\n",
              tag.c_str(), i + 1, ns_msg_count(ns_h, ns_s_qd));
#endif
            continue;
        }

        if (ns_rr_type(rr) != ns_t_a && ns_rr_type(rr) != ns_t_aaaa)
        {
#ifdef _ND_LOG_DHC
            nd_dprintf("%s: Skipping QD RR type: %d\n",
              tag.c_str(), ns_rr_type(rr));
#endif
            continue;
        }

#ifdef _ND_LOG_DHC
        nd_dprintf("%s: QD RR type: %d, name: %s\n",
          tag.c_str(), ns_rr_type(rr), ns_rr_name(rr));
#endif
        host = ns_rr_name(rr);
        break;
    }

    // Is query?
    if (host != nullptr && ns_msg_getflag(ns_h, ns_f_qr) == 0)
    {
#ifdef _ND_LOG_DHC
        nd_dprintf("%s: DNS query, returning...\n", tag.c_str());
#endif
        return true;
    }

    // If this isn't a response, return.
    if (ns_msg_getflag(ns_h, ns_f_qr) != 1) {
#ifdef _ND_LOG_DHC
        nd_dprintf("%s: NOT a DNS response, returning...\n",
          tag.c_str());
#endif
        return false;
    }

    // Process responses records...
    for (uint16_t i = 0; i < ns_msg_count(ns_h, ns_s_an); i++)
    {
        if (ns_parserr(&ns_h, ns_s_an, i, &rr)) {
#ifdef _ND_LOG_DHC
            nd_dprintf(
              "%s: dns error parsing AN RR %hu of %hu.\n",
              tag.c_str(), i + 1, ns_msg_count(ns_h, ns_s_an));
#endif
            continue;
        }
#ifdef _ND_LOG_DHC
        nd_dprintf("%s: AN RR type: %d\n", tag.c_str(),
          ns_rr_type(rr));
#endif
        if (ns_rr_type(rr) == ns_t_ptr) {
            if (proto != ndProto::Id::MDNS) {
#ifdef _ND_LOG_DHC
                nd_dprintf(
                  "%s: Ignoring PTR, not mDNS...\n", tag.c_str());
#endif
                continue;
            }

            lock_guard<recursive_mutex> lg(flow->lock);

            if (flow->HasMDNSDomainName() != false) {
#ifdef _ND_LOG_DHC
                nd_dprintf(
                  "%s: mDNS domain name already set...\n",
                  tag.c_str());
#endif
                continue;
            }

            const uint8_t *p = (const uint8_t *)ns_rr_rdata(rr);

            flow->mdns.domain_name.clear();

            while (*p != 0 && p < (const uint8_t *)(pkt + pkt_len))
            {
                if ((*p & 0xc0) == 0xc0) {
                    uint16_t offset = (*(p + 1)) +
                      ((*p & 0x3f) << 8);
                    p = (const uint8_t *)(pkt + offset);
                }

                uint8_t len = *p;
                p++;
                if (! flow->mdns.domain_name.empty())
                    flow->mdns.domain_name += '.';

                for (uint8_t j = 0; j < len &&
                     p < (const uint8_t *)(pkt + pkt_len);
                     p++, j++)
                {
                    flow->mdns.domain_name +=
                      static_cast<const char>(*p);
                }
            }

            if (! flow->mdns.domain_name.empty()) {
                nd_set_hostname(flow->mdns.domain_name, false);
            }
#ifdef _ND_LOG_DHC
            if (flow->HasMDNSDomainName() == false)
                continue;
            nd_dprintf(
              "%s: parsing mDNS PTR RR: ttl: %d, data len: "
              "%d: "
              "%s\n",
              tag.c_str(), ns_rr_ttl(rr), ns_rr_rdlen(rr),
              flow->mdns.domain_name.c_str());
#endif
            continue;
        }

        if (ns_rr_type(rr) != ns_t_a && ns_rr_type(rr) != ns_t_aaaa)
            continue;

        if (proto != ndProto::Id::DNS || host == nullptr)
            continue;

        // Add responses to DHC...
        ndAddr addr((ns_rr_type(rr) == ns_t_a) ?
            ndAddr((const struct in_addr *)ns_rr_rdata(rr)) :
            ndAddr((const struct in6_addr *)ns_rr_rdata(rr)));

        dhc->Insert(addr, host);

#ifdef _ND_LOG_DHC
        nd_dprintf(
          "%s: dns RR %s address: %s, ttl: %u, rlen: %hu: "
          "%s\n",
          tag.c_str(), host,
          (ns_rr_type(rr) == ns_t_a) ? "A" : "AAAA", ns_rr_ttl(rr),
          ns_rr_rdlen(rr), addr.GetString().c_str());
#endif  // _ND_LOG_DHC
    }

    return false;
}
