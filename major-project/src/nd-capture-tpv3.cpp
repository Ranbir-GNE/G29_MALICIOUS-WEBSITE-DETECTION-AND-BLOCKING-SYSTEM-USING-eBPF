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

#include <net/if.h>
#include <pcap/pcap.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>

#if defined(HAVE_PCAP_DLT_H)
#include <pcap/dlt.h>
#elif defined(_ND_PCAP_DLT_IN_BPF_H)
#include <pcap/bpf.h>
#else
#include "pcap-compat/dlt.h"
#endif

#ifdef HAVE_PCAP_VLAN_H
#include <pcap/vlan.h>
#else
#include "pcap-compat/vlan.h"
#endif

#include "nd-capture-tpv3.hpp"
#include "nd-config.hpp"
#include "nd-detection.hpp"
#include "nd-except.hpp"
#include "nd-flags.hpp"
#include "nd-util.hpp"

using namespace std;

#define _ND_VLAN_OFFSET (2 * ETH_ALEN)

class ndPacketRing;
class ndPacketRingBlock
{
public:
    ndPacketRingBlock(void *entry);

    inline uint32_t GetStatus(void) {
        return hdr.bdh->hdr.bh1.block_status;
    }

    inline void SetStatus(uint32_t status = TP_STATUS_KERNEL) {
        hdr.bdh->hdr.bh1.block_status = status;
    }

    inline void Release(void) {
        hdr.bdh->hdr.bh1.block_status = TP_STATUS_KERNEL;
    }

    size_t ProcessPackets(ndPacketRing *ring,
      vector<ndPacket *> &pkt_queue);

protected:
    friend class ndPacket;
    friend class ndPacketRing;

    union {
        uint8_t *raw;
        struct tpacket_block_desc *bdh;
    } hdr;
};

typedef vector<ndPacketRingBlock *> ndPacketRingBlocks;

class ndPacketRing
{
public:
    ndPacketRing(const string &ifname,
      const nd_config_tpv3 &config,
      ndPacketStats *stats);

    virtual ~ndPacketRing();

    inline int GetDescriptor(void) { return sd; }

    void SetFilter(const string &expr);
    bool ApplyFilter(const uint8_t *pkt, size_t snaplen,
      size_t length) const;

    ndPacketRingBlock *Next(void);

    ndPacket *CopyPacket(const void *entry,
      ndFlags<ndPacket::StatusFlags> &status);

    bool GetStats(void);

protected:
    friend class ndPacket;
    friend class ndPacketRingBlock;

    string ifname;
    int sd;
    void *buffer;
    ndPacketRingBlocks blocks;
    ndPacketRingBlocks::iterator it_block;

    size_t tp_hdr_len;
    size_t tp_reserved;
    size_t tp_frame_size;
    size_t tp_ring_size;

    struct tpacket_req3 tp_req;

    struct bpf_program filter;

    ndPacketStats *stats;
};

ndPacketRingBlock::ndPacketRingBlock(void *entry) {
    hdr.raw = static_cast<uint8_t *>(entry);
    hdr.bdh = static_cast<struct tpacket_block_desc *>(entry);
}

size_t ndPacketRingBlock::ProcessPackets(ndPacketRing *ring,
  vector<ndPacket *> &pkt_queue) {
    struct tpacket3_hdr *entry;
    entry = (struct tpacket3_hdr *)(hdr.raw +
      hdr.bdh->hdr.bh1.offset_to_first_pkt);

    size_t packets = (size_t)hdr.bdh->hdr.bh1.num_pkts;

    for (size_t i = 0; i < packets; i++) {
        ndFlags<ndPacket::StatusFlags> status;
        ndPacket *pkt = ring->CopyPacket(entry, status);

        if (ndFlagBoolean(status, ndPacket::StatusFlags::FILTERED))
            ring->stats->pkt.capture_filtered++;

        if (! ndFlagBoolean(status, ndPacket::StatusFlags::OK))
        {
            ring->stats->pkt.discard++;
            ring->stats->pkt.discard_bytes += entry->tp_snaplen;
        }

        if (pkt != nullptr) pkt_queue.push_back(pkt);

        entry = (struct tpacket3_hdr *)((uint8_t *)entry +
          entry->tp_next_offset);
    }

    return packets;
}

ndPacketRing::ndPacketRing(const string &ifname,
  const nd_config_tpv3 &config,
  ndPacketStats *stats)
  : ifname(ifname), sd(-1), buffer(nullptr), tp_hdr_len(0),
    tp_reserved(0), tp_frame_size(0), tp_ring_size(0),
    tp_req{ 0 }, filter{ 0 }, stats(stats) {
    unsigned so_uintval;

    struct ifreq ifr;
    if (nd_ifreq(ifname.c_str(), SIOCGIFINDEX, &ifr) < 0) {
        throw ndException("%s: %s", ifname.c_str(),
          "nd_ifreq");
    }

    sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sd < 0) {
        throw ndExceptionSystemError(ifname.c_str(),
          "socket");
    }

    nd_dprintf("%s: AF_PACKET socket created: %d\n",
      ifname.c_str(), sd);

    so_uintval = TPACKET_V3;
    socklen_t so_vallen = sizeof(so_uintval);
    if (getsockopt(sd, SOL_PACKET, PACKET_HDRLEN,
          (void *)&so_uintval, &so_vallen) < 0)
    {
        throw ndExceptionSystemError(ifname.c_str(),
          "getsockopt(TPACKET_V3)");
    }

    tp_hdr_len = (size_t)so_uintval;
    nd_dprintf("%s: TPACKET_V3 header length: %ld\n",
      ifname.c_str(), tp_hdr_len);

    so_uintval = TPACKET_V3;
    if (setsockopt(sd, SOL_PACKET, PACKET_VERSION,
          (const void *)&so_uintval, sizeof(so_uintval)) < 0)
    {
        throw ndExceptionSystemError(ifname.c_str(),
          "setsockopt(TPACKET_V3)");
    }

    struct sockaddr_ll sa_ll_bind;
    memset(&sa_ll_bind, 0, sizeof(struct sockaddr_ll));
    sa_ll_bind.sll_family = AF_PACKET;
    sa_ll_bind.sll_protocol = htons(ETH_P_ALL);
    sa_ll_bind.sll_ifindex = ifr.ifr_ifindex;

    if (bind(sd, (const struct sockaddr *)&sa_ll_bind,
          sizeof(struct sockaddr_ll)) < 0)
    {
        throw ndExceptionSystemError(ifname.c_str(),
          "bind(TPACKET_V3)");
    }

    nd_dprintf("%s: AF_PACKET socket bound to: %s [%d]\n",
      ifname.c_str(), ifname.c_str(), ifr.ifr_ifindex);

    struct packet_mreq pmreq;
    memset(&pmreq, 0, sizeof(struct packet_mreq));
    pmreq.mr_ifindex = ifr.ifr_ifindex;

    const vector<short> pmreq_types = { PACKET_MR_PROMISC,
        PACKET_MR_ALLMULTI };

    for (unsigned i = 0; i < pmreq_types.size(); i++) {
        pmreq.mr_type = pmreq_types[i];

        if (setsockopt(sd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
              (const void *)&pmreq, sizeof(struct packet_mreq)) < 0)
        {
            throw ndExceptionSystemError(ifname.c_str(),
              "setsockopt(PACKET_ADD_MEMBERSHIP)");
        }
    }
#ifdef PACKET_FANOUT
    if (config.fanout_mode != ndTPv3FanoutMode::DISABLED) {
        switch (config.fanout_mode) {
        case ndTPv3FanoutMode::HASH:
#ifdef PACKET_FANOUT_HASH
            so_uintval = PACKET_FANOUT_HASH;
#else
            nd_dprintf(
              "%s: PACKET_FANOUT_HASH not supported.\n",
              ifname.c_str());
#endif
            break;
        case ndTPv3FanoutMode::LOAD_BALANCED:
#ifdef PACKET_FANOUT_LB
            so_uintval = PACKET_FANOUT_LB;
#else
            nd_dprintf(
              "%s: PACKET_FANOUT_LB not supported.\n",
              ifname.c_str());
#endif
            break;
        case ndTPv3FanoutMode::CPU:
#ifdef PACKET_FANOUT_CPU
            so_uintval = PACKET_FANOUT_CPU;
#else
            nd_dprintf(
              "%s: PACKET_FANOUT_CPU not supported.\n",
              ifname.c_str());
#endif
            break;
        case ndTPv3FanoutMode::ROLLOVER:
#ifdef PACKET_FANOUT_ROLLOVER
            so_uintval = PACKET_FANOUT_ROLLOVER;
#else
            nd_dprintf(
              "%s: PACKET_FANOUT_ROLLOVER not supported.\n",
              ifname.c_str());
#endif
            break;
        case ndTPv3FanoutMode::QUEUE_MAP:
#ifdef PACKET_FANOUT_QM
            so_uintval = PACKET_FANOUT_QM;
#else
            nd_dprintf(
              "%s: PACKET_FANOUT_QM not supported.\n",
              ifname.c_str());
#endif
            break;
        default:
            throw ndException("%s: invalid fanout mode: %d",
              ifname.c_str(), config.fanout_mode);
        }
#ifdef PACKET_FANOUT_FLAG_DEFRAG
        if (ndFlagBoolean(config.fanout_flags, ndTPv3FanoutFlags::DEFRAG))
            so_uintval |= PACKET_FANOUT_FLAG_DEFRAG;
#else
        nd_dprintf(
          "%s: PACKET_FANOUT_FLAG_DEFRAG not supported.\n",
          ifname.c_str());
#endif
#ifdef PACKET_FANOUT_FLAG_ROLLOVER
        if (ndFlagBoolean(config.fanout_flags,
              ndTPv3FanoutFlags::ROLLOVER))
            so_uintval |= PACKET_FANOUT_FLAG_ROLLOVER;
#else
        nd_dprintf(
          "%s: PACKET_FANOUT_FLAG_ROLLOVER not "
          "supported.\n",
          ifname.c_str());
#endif
        so_uintval <<= 16;
        so_uintval |= (uint16_t)ifr.ifr_ifindex;

        nd_dprintf("%s: fanout mode and flags: 0x%08x\n",
          ifname.c_str(), so_uintval);

        if (setsockopt(sd, SOL_PACKET, PACKET_FANOUT,
              (const void *)&so_uintval, sizeof(so_uintval)) < 0)
        {
            throw ndExceptionSystemError(ifname.c_str(),
              "setsockopt(PACKET_FANOUT)");
        }
    }
#else
#warning "PACKET_FANOUT not supported."
#endif
    so_uintval = sizeof(struct vlan_tag);
    if (setsockopt(sd, SOL_PACKET, PACKET_RESERVE,
          (const void *)&so_uintval, sizeof(so_uintval)) < 0)
    {
        throw ndExceptionSystemError(ifname.c_str(),
          "setsockopt(PACKET_RESERVE)");
    }

    so_uintval = 0;
    so_vallen = sizeof(so_uintval);
    if (getsockopt(sd, SOL_PACKET, PACKET_RESERVE,
          (void *)&so_uintval, &so_vallen) < 0)
    {
        throw ndExceptionSystemError(ifname.c_str(),
          "getsockopt(PACKET_RESERVE)");
    }

    tp_reserved = (size_t)so_uintval;
    if (tp_reserved != sizeof(struct vlan_tag)) {
        throw ndException(
          "%s: unexpected reserved VLAN TAG size (%lu != "
          "%u)",
          ifname.c_str(), tp_reserved, sizeof(struct vlan_tag));
    }

    tp_req.tp_block_size = config.rb_block_size;
    tp_req.tp_frame_size = config.rb_frame_size;
    tp_req.tp_block_nr = config.rb_blocks;
    tp_req.tp_frame_nr = (tp_req.tp_block_size * tp_req.tp_block_nr) /
      tp_req.tp_frame_size;
    tp_req.tp_retire_blk_tov = ndGC.capture_read_timeout;
    // tp_req.tp_feature_req_word = // TODO: Features?

    nd_dprintf("%s: block size: %u\n", ifname.c_str(),
      tp_req.tp_block_size);
    nd_dprintf("%s: frame size: %u\n", ifname.c_str(),
      tp_req.tp_frame_size);
    nd_dprintf("%s: blocks: %u\n", ifname.c_str(), tp_req.tp_block_nr);
    nd_dprintf("%s: frames: %u\n", ifname.c_str(), tp_req.tp_frame_nr);

    if (setsockopt(sd, SOL_PACKET, PACKET_RX_RING,
          (const void *)&tp_req, sizeof(struct tpacket_req3)) < 0)
    {
        throw ndException(
          "%s: setsockopt(PACKET_RX_RING): %s",
          ifname.c_str(), strerror(errno));
    }

    buffer = mmap(0, tp_req.tp_block_size * tp_req.tp_block_nr,
      PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, sd, 0);
    if (buffer == MAP_FAILED) {
        throw ndException("%s: mmap(%u): %s", ifname.c_str(),
          tp_req.tp_block_size * tp_req.tp_block_nr,
          strerror(errno));
    }

    for (unsigned b = 0; b < tp_req.tp_block_nr; b++) {
        ndPacketRingBlock *entry = new ndPacketRingBlock(
          (void *)(((size_t)buffer) + (b * tp_req.tp_block_size)));
        blocks.push_back(entry);
    }

    it_block = blocks.begin();

    nd_dprintf("%s: created %lu packet ring blocks.\n",
      ifname.c_str(), blocks.size());
}

ndPacketRing::~ndPacketRing() {
    if (buffer) munmap(buffer, tp_ring_size);
    if (sd != -1) close(sd);
    for (auto &i : blocks) delete i;
}

void ndPacketRing::SetFilter(const string &expr) {
#ifdef HAVE_PCAP_OPEN_DEAD
    pcap_t *pcap = pcap_open_dead(DLT_EN10MB, ndGC.max_capture_length);
    if (pcap == nullptr) {
        throw ndException(__PRETTY_FUNCTION__,
          "error creating PCAP context");
    }
    if (pcap_compile(pcap, &filter, expr.c_str(), 1,
          PCAP_NETMASK_UNKNOWN) == -1)
    {
#else
    if (pcap_compile_nopcap(ndGC.max_capture_length, DLT_EN10MB,
          &filter, expr.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1)
    {
#endif
        throw ndException(__PRETTY_FUNCTION__,
          "error compiling BPF filter");
    }

#ifdef HAVE_PCAP_OPEN_DEAD
    pcap_close(pcap);
#endif
}

bool ndPacketRing::ApplyFilter(const uint8_t *pkt,
  size_t length, size_t snaplen) const {
    return (filter.bf_insns &&
      bpf_filter(filter.bf_insns, pkt, length, snaplen) == 0);
}

bool ndPacketRing::GetStats(void) {
    struct tpacket_stats_v3 tp_stats;
    socklen_t so_vallen = sizeof(struct tpacket_stats_v3);

    memset(&tp_stats, 0, so_vallen);

    if (getsockopt(sd, SOL_PACKET, PACKET_STATISTICS,
          &tp_stats, &so_vallen) < 0)
    {
        nd_dprintf(
          "%s: error getting packet statistics: %s\n",
          ifname.c_str(), strerror(errno));
        return false;
    }

    stats->pkt.capture_dropped = tp_stats.tp_drops;

    if (tp_stats.tp_freeze_q_cnt > 0) {
        nd_dprintf("%s: queue freeze count: %u\n",
          ifname.c_str(), tp_stats.tp_freeze_q_cnt);
    }

    return true;
}

ndPacketRingBlock *ndPacketRing::Next(void) {
    ndPacketRingBlock *block = nullptr;

    if ((*it_block)->hdr.bdh->hdr.bh1.block_status & TP_STATUS_USER)
    {
        block = (*it_block);

        if (++it_block == blocks.end())
            it_block = blocks.begin();
    }

    return block;
}

ndPacket *ndPacketRing::CopyPacket(const void *entry,
  ndFlags<ndPacket::StatusFlags> &status) {
    const struct tpacket3_hdr *hdr = (const struct tpacket3_hdr *)entry;

    unsigned int tp_len, tp_mac, tp_snaplen;
    tp_len = hdr->tp_len;
    tp_mac = hdr->tp_mac;
    tp_snaplen = hdr->tp_snaplen;

    struct timeval tv = { hdr->tp_sec, hdr->tp_nsec / 1000 };

    status = ndPacket::StatusFlags::INIT;

    if (tp_len != tp_snaplen)
        nd_dprintf("tp_len: %u, tp_snaplen: %u\n", tp_len, tp_snaplen);

#if 0
    if (tp_mac + tp_snaplen > tp_req.tp_frame_size) {
        nd_dprintf("%s: Corrupted kernel ring frame: MAC offset: %u + snaplen: %u > frame_size: %u\n",
            ifname.c_str(), tp_mac, tp_snaplen,
            tp_req.tp_frame_size
        );

        status = ndPacket::StatusFlags::CORRUPTED;
        return nullptr;
    }
#endif
    uint8_t *data = (uint8_t *)entry + tp_mac;

    if ((hdr->hv1.tp_vlan_tci ||
          (hdr->tp_status & TP_STATUS_VLAN_VALID)) &&
      tp_snaplen >= (unsigned int)_ND_VLAN_OFFSET)
    {
        struct nd_vlan_tag {
            uint16_t vlan_tpid;
            uint16_t vlan_tci;
        };

        struct nd_vlan_tag *tag;

        data -= sizeof(struct vlan_tag);
        memmove((void *)data,
          data + sizeof(struct vlan_tag), _ND_VLAN_OFFSET);

        tag = (struct nd_vlan_tag *)(data + _ND_VLAN_OFFSET);

        if (hdr->hv1.tp_vlan_tpid &&
          (hdr->tp_status & TP_STATUS_VLAN_TPID_VALID))
            tag->vlan_tpid = htons(hdr->hv1.tp_vlan_tpid);
        else tag->vlan_tpid = htons(ETH_P_8021Q);

        tag->vlan_tci = htons(hdr->hv1.tp_vlan_tci);

        tp_snaplen += sizeof(struct vlan_tag);
        tp_len += sizeof(struct vlan_tag);

        status |= ndPacket::StatusFlags::VLAN_TAG_RESTORED;
    }

    if (ApplyFilter(data, tp_len, tp_snaplen)) {
        status = ndPacket::StatusFlags::FILTERED;
        return nullptr;
    }

    ndPacket *pkt = nullptr;
    // One-and-only packet copy...
    uint8_t *pkt_data = new uint8_t[tp_snaplen];

    if (pkt_data) {
        memcpy(pkt_data, data, tp_snaplen);
        pkt = new ndPacket(status, tp_len, tp_snaplen, pkt_data, tv);
    }

    if (pkt) status |= ndPacket::StatusFlags::OK;
    else status = ndPacket::StatusFlags::ALLOC_ERROR;

    return pkt;
}

ndCaptureTPv3::ndCaptureTPv3(int16_t cpu,
  nd_iface_ptr &iface, const ndDetectionThreads &threads_dpi,
  ndDNSHintCache *dhc, uint8_t private_addr)
  : ndCaptureThread(ndCaptureType::TPV3, cpu, iface,
      threads_dpi, dhc, private_addr),
    ring(nullptr) {
    dl_type = DLT_EN10MB;

    nd_dprintf("%s: TPv3 capture thread created.\n", tag.c_str());
}

ndCaptureTPv3::~ndCaptureTPv3() {
    Join();

    ndPacketRing *_ring = static_cast<ndPacketRing *>(ring);
    if (_ring != nullptr) delete _ring;

    nd_dprintf("%s: TPv3 capture thread destroyed.\n", tag.c_str());
}

void *ndCaptureTPv3::Entry(void) {
    fd_set fds_read;

    ndPacketRing *_ring = new ndPacketRing(iface->ifname,
      iface->config_tpv3, &stats);
    if (_ring == nullptr)
        throw runtime_error(strerror(ENOMEM));

    ring = static_cast<void *>(_ring);

    auto it_filter = ndGC.interface_filters.find(tag);

    if (it_filter != ndGC.interface_filters.end())
        _ring->SetFilter(it_filter->second);

    int sd_max = _ring->GetDescriptor();
    //    int sd_max = max(fd_ipc[0], _ring->GetDescriptor());

    int rc = 0;

    vector<ndPacket *> pkt_queue;
    pkt_queue.reserve(iface->config_tpv3.rb_blocks);

    capture_state = State::ONLINE;

    bool warnings = true;

    while (! ShouldTerminate() && rc >= 0) {
        ndPacketRingBlock *entry = _ring->Next();

        if (entry == nullptr) {
            if (rc == 1) {
                struct ifreq ifr;
                if (nd_ifreq(tag, SIOCGIFFLAGS, &ifr) == -1 ||
                  ! (ifr.ifr_flags & IFF_UP))
                {
                    capture_state = State::OFFLINE;

                    if (warnings) {
                        nd_printf(
                          "%s: WARNING: interface not "
                          "available.\n",
                          tag.c_str());
                        warnings = false;
                    }
                }

                sleep(1);
            }

            FD_ZERO(&fds_read);
            //            FD_SET(fd_ipc[0], &fds_read);
            FD_SET(_ring->GetDescriptor(), &fds_read);

            struct timeval tv = { 1, 0 };
            rc = select(sd_max + 1, &fds_read, NULL, NULL, &tv);

            if (rc == -1)
                printf("select: %s\n", strerror(errno));
#if 0
            if (rc > 0 && FD_ISSET(fd_ipc[0], &fds_read)) {
                // TODO: Not used.
                uint32_t ipc_id = RecvIPC();
            }
#endif
            continue;
        }
        else if (warnings == false && rc == 1) {
            rc = 0;
            warnings = true;
            capture_state = State::ONLINE;
        }

        entry->ProcessPackets(_ring, pkt_queue);
        entry->Release();

        if (pkt_queue.size()) {
            Lock();

            try {
                for (auto &pkt : pkt_queue) {
                    if (ProcessPacket(pkt) != nullptr)
                        delete pkt;
                }
            }
            catch (...) {
                Unlock();
                capture_state = State::OFFLINE;
                throw;
            }

            Unlock();

            pkt_queue.clear();
        }
    }

    capture_state = State::OFFLINE;

    nd_dprintf("%s: TPv3 capture ended on CPU: %lu\n",
      tag.c_str(), cpu >= 0 ? cpu : 0);

    return NULL;
}

void ndCaptureTPv3::GetCaptureStats(ndPacketStats &stats) {
    ndPacketRing *_ring = static_cast<ndPacketRing *>(ring);
    if (_ring != nullptr) _ring->GetStats();

    ndCaptureThread::GetCaptureStats(stats);
}
