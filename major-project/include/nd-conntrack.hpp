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

#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <sys/socket.h>

#include <ctime>
#include <unordered_map>

#include "nd-flow.hpp"
#include "nd-thread.hpp"

constexpr time_t _ND_CT_FLOW_TTL = 900;

class ndConntrackFlow
{
public:
    enum class Direction : uint8_t { SRC, DST };

    ndConntrackFlow(uint32_t id, struct nf_conntrack *ct);

    void Update(struct nf_conntrack *ct);

    inline uint32_t GetId(void) { return id; }

    inline bool HasExpired(void) {
        return (updated_at + _ND_CT_FLOW_TTL <= nd_time_monotonic()) ?
          true :
          false;
    }

protected:
    friend class ndConntrackThread;

    void CopyAddress(sa_family_t af,
      struct sockaddr_storage *dst,
      const void *src);
    void Hash(void);

    uint32_t id;
    uint32_t mark;
    time_t updated_at;
    std::string digest;
    sa_family_t l3_proto;
    uint8_t l4_proto;
    uint16_t orig_port[2];
    uint16_t repl_port[2];
    bool orig_addr_valid[2];
    bool repl_addr_valid[2];
    struct sockaddr_storage orig_addr[2];
    struct sockaddr_storage repl_addr[2];
};

class ndConntrackThread : public ndThread
{
public:
    ndConntrackThread(int16_t cpu = -1);
    virtual ~ndConntrackThread();

    virtual void *Entry(void);

    void ProcessConntrackEvent(nf_conntrack_msg_type type,
      struct nf_conntrack *ct);

    void UpdateFlow(nd_flow_ptr &flow);
    void PurgeFlows(void);

#ifdef _ND_DEBUG_CONNTRACK
    void DumpStats(void);
#endif

protected:
    void DumpConntrackTable(void);

    void PrintFlow(nd_flow_ptr &flow, std::string &text);
    void PrintFlow(ndConntrackFlow *flow, std::string &text,
      bool reorder = false, bool withreply = false);

    int ctfd;
    nfct_handle *cth;
    int cb_registered;

    typedef std::unordered_map<uint32_t, std::string> IdMap;
    typedef std::unordered_map<std::string, ndConntrackFlow *> FlowMap;

    IdMap ct_id_map;
    FlowMap ct_flow_map;
};
