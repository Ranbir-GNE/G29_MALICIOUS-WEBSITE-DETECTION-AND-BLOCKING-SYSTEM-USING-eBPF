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

#include <fcntl.h>
#include <libnfnetlink/libnfnetlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#include "nd-except.hpp"
#include "nd-instance.hpp"
#include "nd-netlink.hpp"

ndNetlink::ndNetlink(void) : nd(-1), seq(0), sa{ 0 } {

    sa.nl_family = AF_NETLINK;
    sa.nl_pid = getpid();
    sa.nl_groups = RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE |
      RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;

    nd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nd < 0) {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "socket");
    }

    if (::bind(nd, (struct sockaddr *)&sa,
          sizeof(struct sockaddr_nl)) < 0)
    {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "bind");
    }

    if (fcntl(nd, F_SETOWN, getpid()) < 0) {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "fnctl(F_SETOWN)");
    }

    if (fcntl(nd, F_SETSIG, SIGIO) < 0) {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "fnctl(F_SETSIG)");
    }

    int flags = fcntl(nd, F_GETFL);
    if (fcntl(nd, F_SETFL, flags | O_ASYNC | O_NONBLOCK) < 0)
    {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "fnctl(F_SETFL)");
    }
}

ndNetlink::~ndNetlink() {
    if (nd >= 0) close(nd);
}

void ndNetlink::Refresh(void) {
    struct nlmsghdr *nlh;

    buffer.fill('\0');
    nlh = (struct nlmsghdr *)buffer.data();

    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlh->nlmsg_type = RTM_GETROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_pid = 0;
    nlh->nlmsg_seq = seq++;

    if (send(nd, nlh, nlh->nlmsg_len, 0) < 0) {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "send");
    }

    ProcessEvent();

    buffer.fill('\0');
    nlh = (struct nlmsghdr *)buffer.data();

    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    nlh->nlmsg_type = RTM_GETADDR;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_pid = 0;
    nlh->nlmsg_seq = seq++;

    if (send(nd, nlh, nlh->nlmsg_len, 0) < 0) {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "send");
    }

    ProcessEvent();
}

bool ndNetlink::ProcessEvent(void) {
    ssize_t bytes;
    struct nlmsghdr *nlh;
    struct nlmsgerr *nlerror;
    unsigned added_net = 0, removed_net = 0, added_addr = 0,
             removed_addr = 0;

    while ((bytes = recv(nd, buffer.data(), buffer.size(), 0)) > 0)
    {
        for (nlh = (struct nlmsghdr *)buffer.data();
             NLMSG_OK(nlh, bytes);
             nlh = NLMSG_NEXT(nlh, bytes))
        {
#if 0
            nd_dprintf(
                "NLMSG: %hu, len: %u (%u, %u), flags: 0x%x, seq: %u, pid: %u\n",
                nlh->nlmsg_type, nlh->nlmsg_len,
                NLMSG_HDRLEN, NLMSG_LENGTH(nlh->nlmsg_len),
                nlh->nlmsg_flags, nlh->nlmsg_seq, nlh->nlmsg_pid);
#endif
            switch (nlh->nlmsg_type) {
            case NLMSG_DONE: break;
            case RTM_NEWROUTE:
                if (AddRemoveNetwork(nlh)) added_net++;
                break;
            case RTM_DELROUTE:
                if (AddRemoveNetwork(nlh, false))
                    removed_net++;
                break;
            case RTM_NEWADDR:
                if (AddRemoveAddress(nlh)) added_addr++;
                break;
            case RTM_DELADDR:
                if (AddRemoveAddress(nlh, false))
                    removed_addr++;
                break;
            case NLMSG_ERROR:
                nlerror = static_cast<struct nlmsgerr *>(
                  NLMSG_DATA(nlh));
                if (nlerror->error != 0) {
                    nd_printf("Netlink error: %d\n",
                      -nlerror->error);
                    return false;
                }
                break;
            case NLMSG_OVERRUN:
                nd_printf("Netlink overrun!\n");
                return false;
            default:
                nd_dprintf(
                  "Ignored netlink message: %04x\n", nlh->nlmsg_type);
            }
        }
    }
#ifndef _ND_LEAN_AND_MEAN
    if (ndGC_DEBUG) {
        if (added_net || removed_net) {
            nd_dprintf("Networks added: %d, removed: %d\n",
              added_net, removed_net);
        }
        if (added_addr || removed_addr) {
            nd_dprintf("Addresses added: %d, removed: %d\n",
              added_addr, removed_addr);
        }
    }
#endif
    return (added_net || removed_net || added_addr || removed_addr) ?
      true :
      false;
}

bool ndNetlink::CopyAddress(sa_family_t family, ndAddr &dst,
  void *src, uint8_t prefix) {
    switch (family) {
    case AF_INET:
        return ndAddr::Create(dst, (struct in_addr *)src, prefix);
    case AF_INET6:
        return ndAddr::Create(dst, (struct in6_addr *)src, prefix);
    }

    return false;
}

bool ndNetlink::AddRemoveNetwork(struct nlmsghdr *nlh, bool add) {
    ndAddr addr;
    char ifname[IFNAMSIZ] = { '\0' };
    size_t offset = RTM_PAYLOAD(nlh);

    struct rtmsg *rtm;
    rtm = static_cast<struct rtmsg *>(NLMSG_DATA(nlh));

    if (rtm->rtm_type != RTN_UNICAST) return false;

    struct rtattr *rta = static_cast<struct rtattr *>(RTM_RTA(rtm));
    for (; RTA_OK(rta, offset); rta = RTA_NEXT(rta, offset)) {
        switch (rta->rta_type) {
        case RTA_DST:
            CopyAddress(rtm->rtm_family, addr,
              RTA_DATA(rta), rtm->rtm_dst_len);
            break;
        case RTA_OIF:
            if_indextoname(*(int *)RTA_DATA(rta), ifname);
            break;
        }
    }

    if (addr.IsValid() && ifname[0] != '\0') {
        ndInstance &ndi = ndInstance::GetInstance();
        if (add) {
            return ndi.addr_lookup.AddAddress(
              ndAddr::Type::LOCAL, addr, ifname);
        }
        else {
            return ndi.addr_lookup.RemoveAddress(addr, ifname);
        }
    }

    return false;
}

bool ndNetlink::AddRemoveAddress(struct nlmsghdr *nlh, bool add) {
    ndAddr addr;
    ndAddr::Type type = ndAddr::Type::LOCAL;

    struct ifaddrmsg *addrm;
    addrm = static_cast<struct ifaddrmsg *>(NLMSG_DATA(nlh));

    size_t offset = IFA_PAYLOAD(nlh);

    char ifname[IFNAMSIZ] = { '\0' };
    if_indextoname(addrm->ifa_index, ifname);

    struct rtattr *rta;
    for (rta = static_cast<struct rtattr *>(IFA_RTA(addrm));
         RTA_OK(rta, offset);
         rta = RTA_NEXT(rta, offset))
    {
        switch (rta->rta_type) {
        case IFA_ADDRESS:
        case IFA_LOCAL:
            CopyAddress(addrm->ifa_family, addr, RTA_DATA(rta));
            break;
        case IFA_BROADCAST:
            type = ndAddr::Type::BROADCAST;
            CopyAddress(addrm->ifa_family, addr, RTA_DATA(rta));
            break;
        }
    }

    if (addr.IsValid() && ifname[0] != '\0') {
        ndInstance &ndi = ndInstance::GetInstance();
        if (add)
            return ndi.addr_lookup.AddAddress(type, addr, ifname);
        else
            return ndi.addr_lookup.RemoveAddress(addr, ifname);
    }

    return false;
}
