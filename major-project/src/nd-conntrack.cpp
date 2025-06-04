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

#include <array>
#include <sstream>
#include <string>

#include <libmnl/libmnl.h>

#include "nd-conntrack.hpp"
#include "nd-except.hpp"

using namespace std;

// Enable Conntrack debug logging
// #define _ND_DEBUG_CONNTRACK     1

static time_t nd_ct_last_flow_purge_ttl = 0;

static int nd_ct_event_callback(enum nf_conntrack_msg_type type,
  struct nf_conntrack *ct, void *data) {
    ndConntrackThread *thread =
      reinterpret_cast<ndConntrackThread *>(data);

    thread->ProcessConntrackEvent(type, ct);

    time_t now = nd_time_monotonic();

    if (now > nd_ct_last_flow_purge_ttl) {
        thread->PurgeFlows();
#ifdef _ND_DEBUG_CONNTRACK
        thread->DumpStats();
#endif
        nd_ct_last_flow_purge_ttl = now + _ND_CT_FLOW_TTL +
          (_ND_CT_FLOW_TTL / 10);
    }

    return (thread->ShouldTerminate()) ? NFCT_CB_STOP : NFCT_CB_CONTINUE;
}

static int
nd_ct_netlink_callback(const struct nlmsghdr *nlh, void *data) {
    struct nf_conntrack *ct = nfct_new();

    if (ct == nullptr) {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "nfct_new");
    }

    if (nfct_nlmsg_parse(nlh, ct) == 0) {
        ndConntrackThread *thread =
          reinterpret_cast<ndConntrackThread *>(data);
        thread->ProcessConntrackEvent(NFCT_T_NEW, ct);
    }

    nfct_destroy(ct);

    return MNL_CB_OK;
}

ndConntrackThread::ndConntrackThread(int16_t cpu)
  : ndThread("nd-conntrack", (long)cpu), ctfd(-1),
    cth(nullptr), cb_registered(-1) {

    cth = nfct_open(NFNL_SUBSYS_CTNETLINK, NFCT_ALL_CT_GROUPS);

    if (cth == nullptr) {
        throw ndException("%s: nfct_open: %s%s",
          tag.c_str(), strerror(errno),
          (errno == EPROTONOSUPPORT) ?
            " (nfnetlink not loaded?)" :
            "");
    }

    ctfd = nfct_fd(cth);

    int on = 1;

    setsockopt(ctfd, SOL_NETLINK,
      NETLINK_BROADCAST_SEND_ERROR, &on, sizeof(int));

    setsockopt(ctfd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &on,
      sizeof(int));

    if ((cb_registered = nfct_callback_register(cth, NFCT_T_ALL,
           nd_ct_event_callback, (void *)this)) < 0)
    {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "nfct_callback_register");
    }

    DumpConntrackTable();

    nd_dprintf("%s: Created.\n", tag.c_str());
}

ndConntrackThread::~ndConntrackThread() {
    Join();

    if (cth != nullptr) {
        if (cb_registered != -1)
            nfct_callback_unregister(cth);
        nfct_close(cth);
    }

    for (FlowMap::const_iterator i = ct_flow_map.begin();
         i != ct_flow_map.end();
         i++)
        delete i->second;

    nd_dprintf("%s: Destroyed.\n", tag.c_str());
}

void ndConntrackThread::DumpConntrackTable(void) {
    int rc;
    struct mnl_socket *nl;
    struct nlmsghdr *nlh;
    struct nfgenmsg *nfh;
    unsigned int seq, portid;

    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == nullptr) {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "mnl_socket_open");
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "mnl_socket_bind");
    }

    portid = mnl_socket_get_portid(nl);

    vector<uint8_t> buffer(MNL_SOCKET_BUFFER_SIZE, '\0');
    nlh = mnl_nlmsg_put_header(buffer.data());

    nlh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = seq = nd_time_monotonic();

    nfh = reinterpret_cast<struct nfgenmsg *>(
      mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg)));
    nfh->nfgen_family = AF_UNSPEC;
    nfh->version = NFNETLINK_V0;
    nfh->res_id = 0;

    rc = mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
    if (rc == -1) {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "mnl_socket_sendto");
    }

    rc = mnl_socket_recvfrom(nl, buffer.data(), buffer.size());
    if (rc == -1) {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "mnl_socket_recvfrom");
    }

    while (rc > 0) {
        rc = mnl_cb_run(buffer.data(), rc, seq, portid,
          nd_ct_netlink_callback, this);
        if (rc <= MNL_CB_STOP) break;
        rc = mnl_socket_recvfrom(nl, buffer.data(), buffer.size());
    }

    if (rc == -1) {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "mnl_socket_recvfrom");
    }

    mnl_socket_close(nl);

    nd_dprintf("%s: Loaded %lu conntrack entries.\n",
      tag.c_str(), ct_id_map.size());
}

void *ndConntrackThread::Entry(void) {
    int rc;
    fd_set fds_read;

    nd_ct_last_flow_purge_ttl = nd_time_monotonic() + _ND_CT_FLOW_TTL;

    while (! ShouldTerminate()) {
        FD_ZERO(&fds_read);
        FD_SET(ctfd, &fds_read);

        struct timeval tv = { 1, 0 };

        rc = select(ctfd + 1, &fds_read, nullptr, nullptr, &tv);

        if (rc == -1) {
            throw ndExceptionSystemError(__PRETTY_FUNCTION__,
              "select");
        }

        if (FD_ISSET(ctfd, &fds_read)) {
            if (nfct_catch(cth) < 0) {
                throw ndExceptionSystemError(
                  __PRETTY_FUNCTION__, "nfct_catch");
            }
        }
    }

    nd_dprintf("%s: Exit.\n", tag.c_str());
    return nullptr;
}

void ndConntrackThread::ProcessConntrackEvent(
  enum nf_conntrack_msg_type type, struct nf_conntrack *ct) {
    ndConntrackFlow *ct_flow = nullptr;
    IdMap::iterator id_iter;
    FlowMap::iterator flow_iter;

    uint32_t id = nfct_get_attr_u32(ct, ATTR_ID);

    Lock();

    switch (type) {
    case NFCT_T_NEW:

#ifdef _ND_DEBUG_CONNTRACK
        id_iter = ct_id_map.find(id);
        if (id_iter != ct_id_map.end()) {
            nd_dprintf(
              "%s: [N:%u] ID exists for new flow.\n",
              tag.c_str(), id);
        }
#endif

        try {
            ct_flow = new ndConntrackFlow(id, ct);
        }
        catch (exception &e) {
            nd_printf("%s: %s.\n", tag.c_str(), e.what());
            Unlock();
            return;
        }

        ct_id_map[id] = ct_flow->digest;

        flow_iter = ct_flow_map.find(ct_flow->digest);
        if (flow_iter != ct_flow_map.end()) {
#ifdef _ND_DEBUG_CONNTRACK
            nd_dprintf(
              "%s: [N:%u] Digest found in flow map.\n",
              tag.c_str(), id);
#endif
            delete flow_iter->second;
        }

        ct_flow_map[ct_flow->digest] = ct_flow;
        break;

    case NFCT_T_UPDATE:

        id_iter = ct_id_map.find(id);
        if (id_iter == ct_id_map.end()) {
            Unlock();
            return;
        }

        flow_iter = ct_flow_map.find(id_iter->second);
        if (flow_iter == ct_flow_map.end()) {
            nd_dprintf(
              "%s: [U:%u] Digest not found in flow map.\n",
              tag.c_str(), id);
            ct_id_map.erase(id_iter);
            Unlock();
            return;
        }

        ct_flow = flow_iter->second;

        ct_flow->Update(ct);

        if (ct_flow->digest != id_iter->second) {
#ifdef _ND_DEBUG_CONNTRACK
            nd_dprintf("%s: [U:%u] Flow hash updated.\n",
              tag.c_str(), id);
#endif
            ct_flow_map.erase(flow_iter);

            ct_flow_map[ct_flow->digest] = ct_flow;
            ct_id_map[id] = ct_flow->digest;
        }
        break;

    case NFCT_T_DESTROY:

        id_iter = ct_id_map.find(id);
        if (id_iter != ct_id_map.end()) {
            flow_iter = ct_flow_map.find(id_iter->second);
            if (flow_iter != ct_flow_map.end()) {
                delete flow_iter->second;
                ct_flow_map.erase(flow_iter);
            }

            ct_id_map.erase(id_iter);
        }
        break;

    default:
        nd_printf(
          "%s: Unhandled connection tracking message type: "
          "0x%02x\n",
          tag.c_str(), type);
    }
#ifdef _ND_DEBUG_CONNTRACK
    if (ndGC_DEBUG) {
#if 0
        array<char, 1024> buffer;
        nfct_snprintf(buffer.data(), buffer.size(), ct, type, NFCT_O_PLAIN, NFCT_OF_TIME);
        nd_dprintf("%s: %02x [%u] %s\n", tag.c_str(), type, id, buffer.data());
#endif
    }
#endif
    Unlock();
}

void ndConntrackThread::PrintFlow(ndConntrackFlow *flow,
  string &text, bool reorder, bool withreply) {
    int addr_cmp = 0;
    ostringstream os;
    char ip[INET6_ADDRSTRLEN];
    struct sockaddr_in *sa_src = nullptr, *sa_dst = nullptr;
    struct sockaddr_in6 *sa6_src = nullptr, *sa6_dst = nullptr;

    os << "l3_proto: " << static_cast<unsigned>(flow->l3_proto)
       << ", l4_proto: " << static_cast<unsigned>(flow->l4_proto);

    switch (
      flow
        ->orig_addr[ndEnumCast(ndConntrackFlow::Direction, SRC)]
        .ss_family)
    {
    case AF_INET:
        sa_src = reinterpret_cast<struct sockaddr_in *>(
          &flow->orig_addr[ndEnumCast(ndConntrackFlow::Direction, SRC)]);
        sa_dst = reinterpret_cast<struct sockaddr_in *>(
          &flow->orig_addr[ndEnumCast(ndConntrackFlow::Direction, DST)]);
        if (reorder) {
            addr_cmp = memcmp(&sa_src->sin_addr,
              &sa_dst->sin_addr, sizeof(in_addr));
            if (addr_cmp < 0) {
                inet_ntop(AF_INET, &sa_src->sin_addr.s_addr,
                  ip, INET_ADDRSTRLEN);
                os << ", lower_ip: " << ip;
                inet_ntop(AF_INET, &sa_dst->sin_addr.s_addr,
                  ip, INET_ADDRSTRLEN);
                os << ", upper_ip: " << ip;
            }
            else {
                inet_ntop(AF_INET, &sa_dst->sin_addr.s_addr,
                  ip, INET_ADDRSTRLEN);
                os << ", lower_ip: " << ip;
                inet_ntop(AF_INET, &sa_src->sin_addr.s_addr,
                  ip, INET_ADDRSTRLEN);
                os << ", upper_ip: " << ip;
            }
        }
        else {
            inet_ntop(AF_INET, &sa_src->sin_addr.s_addr, ip,
              INET_ADDRSTRLEN);
            os << ", src_ip: " << ip;
            inet_ntop(AF_INET, &sa_dst->sin_addr.s_addr, ip,
              INET_ADDRSTRLEN);
            os << ", dst_ip: " << ip;
        }
        break;
    case AF_INET6:
        sa6_src = reinterpret_cast<struct sockaddr_in6 *>(
          &flow->orig_addr[ndEnumCast(ndConntrackFlow::Direction, SRC)]);
        sa6_dst = reinterpret_cast<struct sockaddr_in6 *>(
          &flow->orig_addr[ndEnumCast(ndConntrackFlow::Direction, DST)]);
        if (reorder) {
            addr_cmp = memcmp(&sa6_src->sin6_addr,
              &sa6_dst->sin6_addr, sizeof(struct in6_addr));
            if (addr_cmp < 0) {
                inet_ntop(AF_INET6, &sa6_src->sin6_addr.s6_addr,
                  ip, INET6_ADDRSTRLEN);
                os << ", lower_ip: " << ip;
                inet_ntop(AF_INET6, &sa6_dst->sin6_addr.s6_addr,
                  ip, INET6_ADDRSTRLEN);
                os << ", upper_ip: " << ip;
            }
            else {
                inet_ntop(AF_INET6, &sa6_dst->sin6_addr.s6_addr,
                  ip, INET6_ADDRSTRLEN);
                os << ", lower_ip: " << ip;
                inet_ntop(AF_INET6, &sa6_src->sin6_addr.s6_addr,
                  ip, INET6_ADDRSTRLEN);
                os << ", upper_ip: " << ip;
            }
        }
        else {
            inet_ntop(AF_INET6, &sa6_src->sin6_addr.s6_addr,
              ip, INET6_ADDRSTRLEN);
            os << ", src_ip: " << ip;
            inet_ntop(AF_INET6, &sa6_dst->sin6_addr.s6_addr,
              ip, INET6_ADDRSTRLEN);
            os << ", dst_ip: " << ip;
        }
        break;
    }

    if (reorder) {
        if (addr_cmp < 0) {
            os << ", lower_port: "
               << ntohs(flow->orig_port[ndEnumCast(
                    ndConntrackFlow::Direction, SRC)]);
            os << ", upper_port: "
               << ntohs(flow->orig_port[ndEnumCast(
                    ndConntrackFlow::Direction, DST)]);
        }
        else {
            os << ", lower_port: "
               << ntohs(flow->orig_port[ndEnumCast(
                    ndConntrackFlow::Direction, DST)]);
            os << ", upper_port: "
               << ntohs(flow->orig_port[ndEnumCast(
                    ndConntrackFlow::Direction, SRC)]);
        }
    }
    else {
        os << ", src_port: "
           << ntohs(flow->orig_port[ndEnumCast(ndConntrackFlow::Direction, SRC)]);
        os << ", dst_port: "
           << ntohs(flow->orig_port[ndEnumCast(ndConntrackFlow::Direction, DST)]);
    }

    if (! withreply ||
      ! flow->repl_addr_valid[ndEnumCast(ndConntrackFlow::Direction, SRC)] ||
      ! flow->repl_addr_valid[ndEnumCast(ndConntrackFlow::Direction, DST)])
    {
        text = os.str();
        return;
    }

    switch (
      flow
        ->repl_addr[ndEnumCast(ndConntrackFlow::Direction, SRC)]
        .ss_family)
    {
    case AF_INET:
        sa_src = reinterpret_cast<struct sockaddr_in *>(
          &flow->repl_addr[ndEnumCast(ndConntrackFlow::Direction, SRC)]);
        sa_dst = reinterpret_cast<struct sockaddr_in *>(
          &flow->repl_addr[ndEnumCast(ndConntrackFlow::Direction, DST)]);
        inet_ntop(AF_INET, &sa_src->sin_addr.s_addr, ip,
          INET_ADDRSTRLEN);
        os << ", repl_src_ip: " << ip;
        inet_ntop(AF_INET, &sa_dst->sin_addr.s_addr, ip,
          INET_ADDRSTRLEN);
        os << ", repl_dst_ip: " << ip;
        break;
    case AF_INET6:
        sa6_src = reinterpret_cast<struct sockaddr_in6 *>(
          &flow->repl_addr[ndEnumCast(ndConntrackFlow::Direction, SRC)]);
        sa6_dst = reinterpret_cast<struct sockaddr_in6 *>(
          &flow->repl_addr[ndEnumCast(ndConntrackFlow::Direction, DST)]);
        inet_ntop(AF_INET6, &sa6_src->sin6_addr.s6_addr, ip,
          INET6_ADDRSTRLEN);
        os << ", repl_src_ip: " << ip;
        inet_ntop(AF_INET6, &sa6_dst->sin6_addr.s6_addr, ip,
          INET6_ADDRSTRLEN);
        os << ", repl_dst_ip: " << ip;
        break;
    }

    os << ", repl_src_port: "
       << ntohs(flow->repl_port[ndEnumCast(ndConntrackFlow::Direction, SRC)]);
    os << ", repl_dst_port: "
       << ntohs(flow->repl_port[ndEnumCast(ndConntrackFlow::Direction, DST)]);

    text = os.str();
}

void ndConntrackThread::PrintFlow(nd_flow_ptr &flow, string &text) {
    ostringstream os;
    sa_family_t family = (flow->ip_version == 4) ? AF_INET : AF_INET6;

    os << "l3_proto: " << static_cast<unsigned>(family)
       << ", l4_proto: " << static_cast<unsigned>(flow->ip_protocol);

    os << ", lower_ip: " << flow->lower_addr.GetString();
    os << ", upper_ip: " << flow->upper_addr.GetString();
    os << ", lower_port: " << flow->lower_addr.GetPort();
    os << ", upper_port: " << flow->upper_addr.GetPort();

    text = os.str();
}

void ndConntrackThread::UpdateFlow(nd_flow_ptr &flow) {
    sha1 ctx;
    string digest;
    sa_family_t family;
    struct sockaddr_in *sa_orig_src = nullptr, *sa_orig_dst = nullptr;
    struct sockaddr_in *sa_repl_src = nullptr, *sa_repl_dst = nullptr;
    struct sockaddr_in6 *sa6_orig_src = nullptr, *sa6_orig_dst = nullptr;
    struct sockaddr_in6 *sa6_repl_src = nullptr, *sa6_repl_dst = nullptr;
    FlowMap::iterator flow_iter;

    if (flow->ip_version == 4) family = AF_INET;
    else family = AF_INET6;

    sha1_init(&ctx);

    sha1_write(&ctx, (const char *)&family, sizeof(sa_family_t));
    sha1_write(&ctx, (const char *)&flow->ip_protocol,
      sizeof(uint8_t));

    sha1_write(&ctx, flow->lower_addr.GetAddress(),
      flow->lower_addr.GetAddressSize());
    sha1_write(&ctx, flow->upper_addr.GetAddress(),
      flow->upper_addr.GetAddressSize());

    uint16_t port = flow->lower_addr.GetPort(false);
    sha1_write(&ctx, (const char *)&port, sizeof(uint16_t));
    port = flow->upper_addr.GetPort(false);
    sha1_write(&ctx, (const char *)&port, sizeof(uint16_t));

    array<uint8_t, SHA1_DIGEST_LENGTH> _digest;
    digest.assign(reinterpret_cast<const char *>(
                    sha1_result(&ctx, _digest.data())),
      SHA1_DIGEST_LENGTH);

    Lock();

    flow_iter = ct_flow_map.find(digest);
    if (flow_iter != ct_flow_map.end() &&
      flow_iter->second->repl_addr_valid[ndEnumCast(
        ndConntrackFlow::Direction, SRC)] &&
      flow_iter->second->repl_addr_valid[ndEnumCast(
        ndConntrackFlow::Direction, DST)])
    {
        ndConntrackFlow * const ct_flow = flow_iter->second;

        ct_flow->updated_at = nd_time_monotonic();

#if defined(_ND_ENABLE_CONNTRACK_MDATA)
        flow->conntrack.id = ct_flow->id;
        flow->conntrack.mark = ct_flow->mark;
#endif

        switch (ct_flow->l3_proto) {
        case AF_INET:
            sa_orig_src = reinterpret_cast<struct sockaddr_in *>(
              &ct_flow->orig_addr[ndEnumCast(ndConntrackFlow::Direction, SRC)]);
            sa_orig_dst = reinterpret_cast<struct sockaddr_in *>(
              &ct_flow->orig_addr[ndEnumCast(ndConntrackFlow::Direction, DST)]);
            sa_repl_src = reinterpret_cast<struct sockaddr_in *>(
              &ct_flow->repl_addr[ndEnumCast(ndConntrackFlow::Direction, SRC)]);
            sa_repl_dst = reinterpret_cast<struct sockaddr_in *>(
              &ct_flow->repl_addr[ndEnumCast(ndConntrackFlow::Direction, DST)]);
#if 0
            {
                string flow_text;
                PrintFlow(ct_flow, flow_text, false, true);
                nd_dprintf("%s: %s\n", tag.c_str(), flow_text.c_str());
            }
#endif
            if (memcmp(sa_orig_src, sa_repl_dst,
                  sizeof(struct sockaddr_in)) ||
              memcmp(sa_orig_dst, sa_repl_src,
                sizeof(struct sockaddr_in)))
                flow->flags.ip_nat = true;

            break;

        case AF_INET6:
            sa6_orig_src = reinterpret_cast<struct sockaddr_in6 *>(
              &ct_flow->orig_addr[ndEnumCast(ndConntrackFlow::Direction, SRC)]);
            sa6_orig_dst = reinterpret_cast<struct sockaddr_in6 *>(
              &ct_flow->orig_addr[ndEnumCast(ndConntrackFlow::Direction, DST)]);
            sa6_repl_src = reinterpret_cast<struct sockaddr_in6 *>(
              &ct_flow->repl_addr[ndEnumCast(ndConntrackFlow::Direction, SRC)]);
            sa6_repl_dst = reinterpret_cast<struct sockaddr_in6 *>(
              &ct_flow->repl_addr[ndEnumCast(ndConntrackFlow::Direction, DST)]);
#if 0
            {
                string flow_text;
                PrintFlow(ct_flow, flow_text, false, true);
                nd_dprintf("%s: %s\n", tag.c_str(), flow_text.c_str());
            }
#endif
            if (memcmp(sa6_orig_src, sa6_repl_dst,
                  sizeof(struct sockaddr_in6)) ||
              memcmp(sa6_orig_dst, sa6_repl_src,
                sizeof(struct sockaddr_in6)))
                flow->flags.ip_nat = true;

            break;
        }
    }

    Unlock();
}

void ndConntrackThread::PurgeFlows(void) {
    Lock();

    for (FlowMap::iterator i = ct_flow_map.begin();
         i != ct_flow_map.end();)
    {
        if (i->second->HasExpired()) {
            ct_id_map.erase(i->second->GetId());
            delete i->second;
            i = ct_flow_map.erase(i);
        }
        else i++;
    }

    Unlock();
}

#ifdef _ND_DEBUG_CONNTRACK
void ndConntrackThread::DumpStats(void) {
    Lock();

    nd_dprintf("%s: entries: ids: %lu, flows: %lu\n",
      tag.c_str(), ct_id_map.size(), ct_flow_map.size());

    Unlock();
}
#endif

ndConntrackFlow::ndConntrackFlow(uint32_t id, struct nf_conntrack *ct)
  : id(id), mark(0), updated_at(0), l3_proto(0), l4_proto(0) {
    orig_port[ndEnumCast(Direction, SRC)] = 0;
    orig_port[ndEnumCast(Direction, DST)] = 0;
    repl_port[ndEnumCast(Direction, SRC)] = 0;
    repl_port[ndEnumCast(Direction, DST)] = 0;

    Update(ct);
}

void ndConntrackFlow::Update(struct nf_conntrack *ct) {
    updated_at = nd_time_monotonic();

    mark = nfct_get_attr_u32(ct, ATTR_MARK);

    orig_addr_valid[ndEnumCast(Direction, SRC)] = false;
    orig_addr_valid[ndEnumCast(Direction, DST)] = false;
    repl_addr_valid[ndEnumCast(Direction, SRC)] = false;
    repl_addr_valid[ndEnumCast(Direction, DST)] = false;

    if (! nfct_attr_is_set(ct, ATTR_ORIG_L3PROTO)) {
        throw ndException("%s: ATTR_ORIG_L3PROTO not set",
          __PRETTY_FUNCTION__);
    }

    sa_family_t af = l3_proto = nfct_get_attr_u8(ct,
      ATTR_ORIG_L3PROTO);
    if (af != AF_INET && af != AF_INET6) {
        throw ndException("%s: unsupported address family",
          __PRETTY_FUNCTION__);
    }
    if (! nfct_attr_is_set(ct, ATTR_ORIG_L4PROTO)) {
        throw ndException("%s: ATTR_ORIG_L4PROTO not set",
          __PRETTY_FUNCTION__);
    }

    l4_proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);

    if ((! nfct_attr_is_set(ct, ATTR_ORIG_IPV4_SRC) &&
          ! nfct_attr_is_set(ct, ATTR_ORIG_IPV6_SRC)) ||
      (! nfct_attr_is_set(ct, ATTR_ORIG_IPV4_DST) &&
        ! nfct_attr_is_set(ct, ATTR_ORIG_IPV6_DST)))
    {
        throw ndException("%s: ATTR_ORIG_SRC/DST not set",
          __PRETTY_FUNCTION__);
    }

    switch (af) {
    case AF_INET:
        if (nfct_attr_is_set(ct, ATTR_ORIG_IPV4_SRC)) {
            CopyAddress(af, &orig_addr[ndEnumCast(Direction, SRC)],
              nfct_get_attr(ct, ATTR_ORIG_IPV4_SRC));
            orig_addr_valid[ndEnumCast(Direction, SRC)] = true;
        }
        if (nfct_attr_is_set(ct, ATTR_ORIG_IPV4_DST)) {
            CopyAddress(af, &orig_addr[ndEnumCast(Direction, DST)],
              nfct_get_attr(ct, ATTR_ORIG_IPV4_DST));
            orig_addr_valid[ndEnumCast(Direction, DST)] = true;
        }
        break;
    case AF_INET6:
        if (nfct_attr_is_set(ct, ATTR_ORIG_IPV6_SRC)) {
            CopyAddress(af, &orig_addr[ndEnumCast(Direction, SRC)],
              nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC));
            orig_addr_valid[ndEnumCast(Direction, SRC)] = true;
        }
        if (nfct_attr_is_set(ct, ATTR_ORIG_IPV6_DST)) {
            CopyAddress(af, &orig_addr[ndEnumCast(Direction, DST)],
              nfct_get_attr(ct, ATTR_ORIG_IPV6_DST));
            orig_addr_valid[ndEnumCast(Direction, DST)] = true;
        }
        break;
    }

    if (nfct_attr_is_set(ct, ATTR_ORIG_PORT_SRC))
        orig_port[ndEnumCast(Direction, SRC)] =
          nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC);
    if (nfct_attr_is_set(ct, ATTR_ORIG_PORT_DST))
        orig_port[ndEnumCast(Direction, DST)] =
          nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST);

    switch (af) {
    case AF_INET:
        if (nfct_attr_is_set(ct, ATTR_REPL_IPV4_SRC)) {
            CopyAddress(af, &repl_addr[ndEnumCast(Direction, SRC)],
              nfct_get_attr(ct, ATTR_REPL_IPV4_SRC));
            repl_addr_valid[ndEnumCast(Direction, SRC)] = true;
        }
        if (nfct_attr_is_set(ct, ATTR_REPL_IPV4_DST)) {
            CopyAddress(af, &repl_addr[ndEnumCast(Direction, DST)],
              nfct_get_attr(ct, ATTR_REPL_IPV4_DST));
            repl_addr_valid[ndEnumCast(Direction, DST)] = true;
        }
        break;
    case AF_INET6:
        if (nfct_attr_is_set(ct, ATTR_REPL_IPV6_SRC)) {
            CopyAddress(af, &repl_addr[ndEnumCast(Direction, SRC)],
              nfct_get_attr(ct, ATTR_REPL_IPV6_SRC));
            repl_addr_valid[ndEnumCast(Direction, SRC)] = true;
        }
        if (nfct_attr_is_set(ct, ATTR_REPL_IPV6_DST)) {
            CopyAddress(af, &repl_addr[ndEnumCast(Direction, DST)],
              nfct_get_attr(ct, ATTR_REPL_IPV6_DST));
            repl_addr_valid[ndEnumCast(Direction, DST)] = true;
        }
        break;
    }

    if (nfct_attr_is_set(ct, ATTR_REPL_PORT_SRC))
        repl_port[ndEnumCast(Direction, SRC)] =
          nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC);
    if (nfct_attr_is_set(ct, ATTR_REPL_PORT_DST))
        repl_port[ndEnumCast(Direction, DST)] =
          nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST);

    Hash();
}

void ndConntrackFlow::CopyAddress(sa_family_t af,
  struct sockaddr_storage *dst, const void *src) {
    struct sockaddr_in *sa =
      reinterpret_cast<struct sockaddr_in *>(dst);
    struct sockaddr_in6 *sa6 =
      reinterpret_cast<struct sockaddr_in6 *>(dst);

    memset(dst, 0, sizeof(struct sockaddr_storage));
    dst->ss_family = af;

    switch (af) {
    case AF_INET:
        memcpy(&sa->sin_addr, src, sizeof(struct in_addr));
        break;
    case AF_INET6:
        memcpy(&sa6->sin6_addr, src, sizeof(struct in6_addr));
        break;
    }
}

void ndConntrackFlow::Hash(void) {
    sha1 ctx;
    int addr_cmp = 0;
    struct sockaddr_in *sa_src = nullptr, *sa_dst = nullptr;
    struct sockaddr_in6 *sa6_src = nullptr, *sa6_dst = nullptr;

    sha1_init(&ctx);

    sha1_write(&ctx, reinterpret_cast<const char *>(&l3_proto),
      sizeof(sa_family_t));
    sha1_write(&ctx, reinterpret_cast<const char *>(&l4_proto),
      sizeof(uint8_t));

    switch (orig_addr[ndEnumCast(Direction, SRC)].ss_family) {
    case AF_INET:
        sa_src = repl_addr_valid[ndEnumCast(Direction, SRC)] ?
          reinterpret_cast<struct sockaddr_in *>(
            &repl_addr[ndEnumCast(Direction, SRC)]) :
          reinterpret_cast<struct sockaddr_in *>(
            &orig_addr[ndEnumCast(Direction, SRC)]);
        sa_dst = repl_addr_valid[ndEnumCast(Direction, DST)] ?
          reinterpret_cast<struct sockaddr_in *>(
            &repl_addr[ndEnumCast(Direction, DST)]) :
          reinterpret_cast<struct sockaddr_in *>(
            &orig_addr[ndEnumCast(Direction, DST)]);
        addr_cmp = memcmp(&sa_src->sin_addr,
          &sa_dst->sin_addr, sizeof(in_addr));
        if (addr_cmp < 0) {
            sha1_write(&ctx,
              reinterpret_cast<const char *>(&sa_src->sin_addr),
              sizeof(struct in_addr));
            sha1_write(&ctx,
              reinterpret_cast<const char *>(&sa_dst->sin_addr),
              sizeof(struct in_addr));
        }
        else {
            sha1_write(&ctx,
              reinterpret_cast<const char *>(&sa_dst->sin_addr),
              sizeof(struct in_addr));
            sha1_write(&ctx,
              reinterpret_cast<const char *>(&sa_src->sin_addr),
              sizeof(struct in_addr));
        }
        break;
    case AF_INET6:
        sa6_src = repl_addr_valid[ndEnumCast(Direction, SRC)] ?
          reinterpret_cast<struct sockaddr_in6 *>(
            &repl_addr[ndEnumCast(Direction, SRC)]) :
          reinterpret_cast<struct sockaddr_in6 *>(
            &orig_addr[ndEnumCast(Direction, SRC)]);
        sa6_dst = repl_addr_valid[ndEnumCast(Direction, DST)] ?
          reinterpret_cast<struct sockaddr_in6 *>(
            &repl_addr[ndEnumCast(Direction, DST)]) :
          reinterpret_cast<struct sockaddr_in6 *>(
            &orig_addr[ndEnumCast(Direction, DST)]);
        addr_cmp = memcmp(&sa6_src->sin6_addr,
          &sa6_dst->sin6_addr, sizeof(struct in6_addr));
        if (addr_cmp < 0) {
            sha1_write(&ctx,
              reinterpret_cast<const char *>(&sa6_src->sin6_addr),
              sizeof(struct in6_addr));
            sha1_write(&ctx,
              reinterpret_cast<const char *>(&sa6_dst->sin6_addr),
              sizeof(struct in6_addr));
        }
        else {
            sha1_write(&ctx,
              reinterpret_cast<const char *>(&sa6_dst->sin6_addr),
              sizeof(struct in6_addr));
            sha1_write(&ctx, (const char *)&sa6_src->sin6_addr,
              sizeof(struct in6_addr));
        }
        break;
    }

    if (addr_cmp < 0) {
        sha1_write(&ctx,
          reinterpret_cast<const char *>(
            &repl_port[ndEnumCast(Direction, SRC)]),
          sizeof(uint16_t));
        sha1_write(&ctx,
          reinterpret_cast<const char *>(
            &repl_port[ndEnumCast(Direction, DST)]),
          sizeof(uint16_t));
    }
    else {
        sha1_write(&ctx,
          reinterpret_cast<const char *>(
            &repl_port[ndEnumCast(Direction, DST)]),
          sizeof(uint16_t));
        sha1_write(&ctx,
          reinterpret_cast<const char *>(
            &repl_port[ndEnumCast(Direction, SRC)]),
          sizeof(uint16_t));
    }

    array<uint8_t, SHA1_DIGEST_LENGTH> _digest;
    digest.assign(reinterpret_cast<const char *>(
                    sha1_result(&ctx, _digest.data())),
      SHA1_DIGEST_LENGTH);
}
