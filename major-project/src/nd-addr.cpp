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

#include <ifaddrs.h>
#include <sys/types.h>

#include "nd-addr.hpp"
#include "nd-flags.hpp"
#include "nd-instance.hpp"
#include "nd-util.hpp"

using namespace std;

bool ndAddr::Create(ndAddr &a, const string &addr) {
    string _addr(addr);

    size_t p;
    if ((p = addr.find_first_of("/")) != string::npos) {
        try {
            a.prefix = (uint8_t)stoul(addr.substr(p + 1),
              nullptr, 10);
        }
        catch (...) {
            nd_dprintf(
              "Invalid IP address prefix length: %s\n",
              addr.substr(p + 1).c_str());
            return false;
        }

        _addr.erase(p);
    }

    if (inet_pton(AF_INET, _addr.c_str(), &a.addr.in.sin_addr) == 1)
    {
        if (a.prefix > _ND_ADDR_BITSv4) {
            nd_dprintf(
              "Invalid IP address prefix length: %hhu\n", a.prefix);
            return false;
        }

        a.addr.ss.ss_family = AF_INET;
        return true;
    }

    if (inet_pton(AF_INET6, _addr.c_str(), &a.addr.in6.sin6_addr) == 1)
    {
        if (a.prefix > _ND_ADDR_BITSv6) {
            nd_dprintf(
              "Invalid IP address prefix length: %hhu\n", a.prefix);
            return false;
        }

        a.addr.ss.ss_family = AF_INET6;
        return true;
    }

    switch (addr.size()) {
    case ND_STR_ETHALEN:
    {
        stringstream ss(addr);
        uint8_t octet = 0, hw_addr[ETH_ALEN] = { 0 };

        do {
            if (! ss.good()) break;

            string byte;
            getline(ss, byte, ':');

            try {
                hw_addr[octet] = (uint8_t)stoul(byte, nullptr, 16);
            }
            catch (...) {
                nd_dprintf(
                  "Invalid hardware address, octet #%hhu\n", octet);

                return false;
            }
        }
        while (++octet < ETH_ALEN);

        if (octet == ETH_ALEN)
            return Create(a, hw_addr, ETH_ALEN);
    }
    default: break;
    }

    return false;
}

bool ndAddr::Create(ndAddr &a, const uint8_t *hw_addr, size_t length) {
    switch (length) {
    case ETH_ALEN:
#if defined(__linux__)
        a.addr.ss.ss_family = AF_PACKET;
        a.addr.ll.sll_hatype = ARPHRD_ETHER;
        a.addr.ll.sll_halen = ETH_ALEN;
        memcpy(a.addr.ll.sll_addr, hw_addr, ETH_ALEN);
#elif defined(__FreeBSD__)
        a.addr.ss.ss_family = AF_LINK;
        a.addr.dl.sdl_type = ARPHRD_ETHER;
        a.addr.dl.sdl_nlen = 0;
        a.addr.dl.sdl_alen = ETH_ALEN;
        memcpy(a.addr.dl.sdl_data, hw_addr, ETH_ALEN);
#endif
        return true;

    default:
        nd_dprintf("Invalid hardware address size: %lu\n", length);
        return false;
    }

    return false;
}

bool ndAddr::Create(ndAddr &a,
  const struct sockaddr_storage *ss_addr,
  uint8_t prefix) {
    switch (ss_addr->ss_family) {
    case AF_INET:
        if (prefix > _ND_ADDR_BITSv4) {
            nd_dprintf(
              "Invalid IP address prefix length: %hhu\n", prefix);
            return false;
        }

        if (prefix) a.prefix = prefix;
        else a.prefix = _ND_ADDR_BITSv4;

        memcpy(&a.addr.in, ss_addr, sizeof(struct sockaddr_in));
        break;

    case AF_INET6:
        if (prefix > _ND_ADDR_BITSv6) {
            nd_dprintf(
              "Invalid IP address prefix length: %hhu\n", prefix);
            return false;
        }

        if (prefix) a.prefix = prefix;
        else a.prefix = _ND_ADDR_BITSv6;

        memcpy(&a.addr.in6, ss_addr, sizeof(struct sockaddr_in6));
        break;

    default:
        nd_dprintf("Unsupported address family: %hu\n",
          ss_addr->ss_family);
        return false;
    }

    return true;
}

bool ndAddr::Create(ndAddr &a,
  const struct sockaddr_in *ss_in, uint8_t prefix) {
    if (ss_in->sin_family != AF_INET) {
        nd_dprintf("Unsupported address family: %hu\n",
          ss_in->sin_family);
        return false;
    }

    if (prefix > _ND_ADDR_BITSv4) {
        nd_dprintf(
          "Invalid IP address prefix length: %hhu\n", prefix);
        return false;
    }

    memcpy(&a.addr.in, ss_in, sizeof(struct sockaddr_in));

    if (prefix) a.prefix = prefix;
    else a.prefix = _ND_ADDR_BITSv4;

    return true;
}

bool ndAddr::Create(ndAddr &a,
  const struct sockaddr_in6 *ss_in6, uint8_t prefix) {
    if (ss_in6->sin6_family != AF_INET6) {
        nd_dprintf("Unsupported address family: %hu\n",
          ss_in6->sin6_family);
        return false;
    }

    if (prefix > _ND_ADDR_BITSv6) {
        nd_dprintf(
          "Invalid IP address prefix length: %hhu\n", prefix);
        return false;
    }

    memcpy(&a.addr.in6, ss_in6, sizeof(struct sockaddr_in6));

    if (prefix) a.prefix = prefix;
    else a.prefix = _ND_ADDR_BITSv6;

    return true;
}

bool ndAddr::Create(ndAddr &a,
  const struct in_addr *in_addr, uint8_t prefix) {
    if (prefix > _ND_ADDR_BITSv4) {
        nd_dprintf(
          "Invalid IP address prefix length: %hhu\n", prefix);
        return false;
    }

    a.addr.in.sin_family = AF_INET;
    a.addr.in.sin_port = 0;
    a.addr.in.sin_addr.s_addr = in_addr->s_addr;

    if (prefix) a.prefix = prefix;
    else a.prefix = _ND_ADDR_BITSv4;

    return true;
}

bool ndAddr::Create(ndAddr &a,
  const struct in6_addr *in6_addr, uint8_t prefix) {
    if (prefix > _ND_ADDR_BITSv6) {
        nd_dprintf(
          "Invalid IP address prefix length: %hhu\n", prefix);
        return false;
    }

    a.addr.in6.sin6_family = AF_INET6;
    a.addr.in6.sin6_port = 0;
    memcpy(&a.addr.in6.sin6_addr, in6_addr, sizeof(struct in6_addr));

    if (prefix) a.prefix = prefix;
    else a.prefix = _ND_ADDR_BITSv6;

    return true;
}

const uint8_t *ndAddr::GetAddress(void) const {
    if (! IsValid()) return nullptr;
    if (IsIPv4()) return (const uint8_t *)&addr.in.sin_addr;
    if (IsIPv6())
        return (const uint8_t *)&addr.in6.sin6_addr;

    return nullptr;
}

size_t ndAddr::GetAddressSize(void) const {
    if (! IsValid()) return 0;
    if (IsIPv4()) return sizeof(struct in_addr);
    if (IsIPv6()) return sizeof(struct in6_addr);

    return 0;
}

uint16_t ndAddr::GetPort(bool byte_swap) const {
    if (! IsValid()) return 0;
    if (IsIPv4())
        return (
          (byte_swap) ? ntohs(addr.in.sin_port) : addr.in.sin_port);
    if (IsIPv6())
        return ((byte_swap) ?
            ntohs(addr.in6.sin6_port) :
            addr.in6.sin6_port);

    return 0;
}

bool ndAddr::SetPort(uint16_t port) {
    if (! IsValid()) return false;
    if (IsIPv4()) {
        addr.in.sin_port = port;
        return true;
    }
    if (IsIPv6()) {
        addr.in6.sin6_port = port;
        return true;
    }

    return false;
}

bool ndAddr::MakeString(const ndAddr &a, string &result,
  ndFlags<MakeFlags> flags) {
    if (! a.IsValid()) return false;

    char sa[INET6_ADDRSTRLEN] = { 0 };

    switch (a.addr.ss.ss_family) {
#if defined(__linux__)
    case AF_PACKET:
        switch (a.addr.ll.sll_hatype) {
        case ARPHRD_ETHER:
        {
            char *p = sa;
            for (unsigned i = 0; i < a.addr.ll.sll_halen &&
                 (sa - p) < (INET6_ADDRSTRLEN - 1);
                 i++)
            {
                sprintf(p, "%02hhx", a.addr.ll.sll_addr[i]);
                p += 2;

                if (i < (unsigned)(a.addr.ll.sll_halen - 1) &&
                  (sa - p) < (INET6_ADDRSTRLEN - 1))
                {
                    *p = ':';
                    p++;
                }
            }
        }

            result = sa;

            return true;
        }
        break;
#elif defined(__FreeBSD__)
    case AF_LINK:
        switch (a.addr.dl.sdl_type) {
        case ARPHRD_ETHER:
        {
            char *p = sa;
            for (unsigned i = 0; i < a.addr.dl.sdl_alen &&
                 (sa - p) < (INET6_ADDRSTRLEN - 1);
                 i++)
            {
                sprintf(p, "%02hhx",
                  a.addr.dl.sdl_data[a.addr.dl.sdl_nlen + i]);
                p += 2;

                if (i < (unsigned)(a.addr.dl.sdl_alen - 1) &&
                  (sa - p) < (INET6_ADDRSTRLEN - 1))
                {
                    *p = ':';
                    p++;
                }
            }
        }

            result = sa;

            return true;
        }
        break;
#endif
    case AF_INET:
        if (inet_ntop(AF_INET,
              (const void *)&a.addr.in.sin_addr.s_addr, sa,
              INET_ADDRSTRLEN) == nullptr)
        {
            nd_dprintf(
              "error converting %s address to string: %s",
              "AF_INET", strerror(errno));
            return false;
        }

        result = sa;

        if (ndFlagBoolean(flags, MakeFlags::PREFIX) &&
          (a.prefix > 0 && a.prefix != _ND_ADDR_BITSv4))
            result.append("/" + to_string((size_t)a.prefix));

        if (ndFlagBoolean(flags, MakeFlags::PORT) &&
          a.addr.in.sin_port != 0)
        {
            result.append(
              ":" + to_string(ntohs(a.addr.in.sin_port)));
        }

        return true;

    case AF_INET6:
        if (inet_ntop(AF_INET6,
              (const void *)&a.addr.in6.sin6_addr.s6_addr,
              sa, INET6_ADDRSTRLEN) == nullptr)
        {
            nd_dprintf(
              "error converting %s address to string: %s",
              "AF_INET6", strerror(errno));
            return false;
        }

        if (ndFlagBoolean(flags, MakeFlags::IPV6_URI))
            result = "[";
        result.append(sa);
        if (ndFlagBoolean(flags, MakeFlags::IPV6_URI))
            result.append("]");

        if (ndFlagBoolean(flags, MakeFlags::PREFIX) &&
          a.prefix > 0 && a.prefix != _ND_ADDR_BITSv6)
            result.append("/" + to_string((size_t)a.prefix));

        if (ndFlagBoolean(flags, MakeFlags::PORT) &&
          a.addr.in6.sin6_port != 0)
        {
            result.append(
              ":" + to_string(ntohs(a.addr.in6.sin6_port)));
        }

        return true;
    }

    return false;
}

ndAddrLookup::ndAddrLookup() {
    // Add private networks
    AddAddress(ndAddr::Type::RESERVED, "127.0.0.0/8");
    AddAddress(ndAddr::Type::RESERVED, "10.0.0.0/8");
    AddAddress(ndAddr::Type::RESERVED, "100.64.0.0/10");
    AddAddress(ndAddr::Type::RESERVED, "172.16.0.0/12");
    AddAddress(ndAddr::Type::RESERVED, "192.168.0.0/16");

    AddAddress(ndAddr::Type::RESERVED, "::1/128");
    AddAddress(ndAddr::Type::RESERVED, "fc00::/7");
    AddAddress(ndAddr::Type::RESERVED, "fd00::/8");
    AddAddress(ndAddr::Type::RESERVED, "fe80::/10");

    // Add multicast networks
    AddAddress(ndAddr::Type::MULTICAST, "224.0.0.0/4");

    AddAddress(ndAddr::Type::MULTICAST, "ff00::/8");

    // Add broadcast addresses
    AddAddress(ndAddr::Type::BROADCAST, "169.254.255.255");
}

bool ndAddrLookup::AddAddress(ndAddr::Type type,
  const ndAddr &addr, const string &ifname) {
    if (! addr.IsValid()) {
        nd_printf("Invalid address: %s\n",
          addr.GetString(ndAddr::MakeFlags::PREFIX).c_str());
        return false;
    }
#ifdef _ND_ENABLE_DEBUG_STATS
    nd_dprintf("%s: %d: %s: %s\n", __func__, type,
      (! ifname.empty()) ? ifname.c_str() : "(global)",
      addr.GetString(ndAddr::MakeFlags::PREFIX).c_str());
#endif
    lock_guard<mutex> ul(lock);

    try {
        if (addr.IsEthernet()) {
            string mac = addr.GetString(ndAddr::MakeFlags::PREFIX);
            auto it = ether_reserved.find(mac);
            if (it != ether_reserved.end()) {
#ifdef _ND_ENABLE_DEBUG_STATS
                nd_dprintf(
                  "Reserved MAC address exists: %s\n", mac.c_str());
#endif
                return false;
            }
            ether_reserved[mac] = type;
            nd_dprintf("ether_reserved: %u\n",
              ether_reserved.size());
            return true;
        }

        if (type == ndAddr::Type::LOCAL && addr.IsNetwork())
            type = ndAddr::Type::LOCALNET;

        if (addr.IsIPv4() && ifname.empty()) {
            ndRadixNetworkEntry<_ND_ADDR_BITSv4> entry;
            if (ndRadixNetworkEntry<_ND_ADDR_BITSv4>::Create(entry, addr))
            {
                ipv4_reserved[entry] = type;
                return true;
            }
        }

        if (addr.IsIPv6() && ifname.empty()) {
            ndRadixNetworkEntry<_ND_ADDR_BITSv6> entry;
            if (ndRadixNetworkEntry<_ND_ADDR_BITSv6>::Create(entry, addr))
            {
                ipv6_reserved[entry] = type;
                return true;
            }
        }

        if (addr.IsIPv4() && ! ifname.empty()) {
            ndRadixNetworkEntry<_ND_ADDR_BITSv4> entry;
            if (ndRadixNetworkEntry<_ND_ADDR_BITSv4>::Create(entry, addr))
            {
                ipv4_iface[ifname][entry] = type;
                return true;
            }
        }

        if (addr.IsIPv6() && ! ifname.empty()) {
            ndRadixNetworkEntry<_ND_ADDR_BITSv6> entry;
            if (ndRadixNetworkEntry<_ND_ADDR_BITSv6>::Create(entry, addr))
            {
                ipv6_iface[ifname][entry] = type;
                return true;
            }
        }
    }
    catch (runtime_error &e) {
        nd_dprintf("Error adding address: %s: %s\n",
          addr.GetString(ndAddr::MakeFlags::PREFIX).c_str(),
          e.what());
    }

    return false;
}

bool ndAddrLookup::RemoveAddress(const ndAddr &addr,
  const string &ifname) {
    if (! addr.IsValid()) {
        nd_printf("Invalid address: %s\n",
          addr.GetString(ndAddr::MakeFlags::PREFIX).c_str());
        return false;
    }
#ifdef _ND_ENABLE_DEBUG_STATS
    nd_dprintf("%s: %s: %s\n", __func__,
      (! ifname.empty()) ? ifname.c_str() : "(global)",
      addr.GetString(ndAddr::MakeFlags::PREFIX).c_str());
#endif
    lock_guard<mutex> ul(lock);

    try {
        if (addr.IsEthernet()) {
            string mac = addr.GetString(ndAddr::MakeFlags::PREFIX);
            auto it = ether_reserved.find(mac);
            if (it != ether_reserved.end()) {
                ether_reserved.erase(it);
                return true;
            }
            return false;
        }

        if (addr.IsIPv4() && ifname.empty()) {
            ndRadixNetworkEntry<_ND_ADDR_BITSv4> entry;
            if (ndRadixNetworkEntry<_ND_ADDR_BITSv4>::Create(entry, addr))
            {
                return ipv4_reserved.erase(entry);
            }
        }

        if (addr.IsIPv6() && ifname.empty()) {
            ndRadixNetworkEntry<_ND_ADDR_BITSv6> entry;
            if (ndRadixNetworkEntry<_ND_ADDR_BITSv6>::Create(entry, addr))
            {
                return ipv6_reserved.erase(entry);
            }
        }

        if (addr.IsIPv4() && ifname.empty()) {
            ndRadixNetworkEntry<_ND_ADDR_BITSv4> entry;
            if (ndRadixNetworkEntry<_ND_ADDR_BITSv4>::Create(entry, addr))
            {
                auto it = ipv4_iface.find(ifname);
                if (it != ipv4_iface.end())
                    return it->second.erase(entry);
                return false;
            }
        }

        if (addr.IsIPv6() && ! ifname.empty()) {
            ndRadixNetworkEntry<_ND_ADDR_BITSv6> entry;
            if (ndRadixNetworkEntry<_ND_ADDR_BITSv6>::Create(entry, addr))
            {
                auto it = ipv6_iface.find(ifname);
                if (it != ipv6_iface.end())
                    return it->second.erase(entry);
                return false;
            }
        }
    }
    catch (runtime_error &e) {
        nd_dprintf("Error removing address: %s: %s\n",
          addr.GetString(ndAddr::MakeFlags::PREFIX).c_str(),
          e.what());
    }

    return false;
}

void ndAddrLookup::Classify(ndAddr::Type &type, const ndAddr &addr) {
    if (addr.IsValid()) type = ndAddr::Type::OTHER;
    else {
        type = ndAddr::Type::ERROR;
        return;
    }

    if (addr.IsEthernet()) {
        for (uint8_t i = 0x01; i <= 0x0f; i += 0x02) {
#if defined(__linux__)
            if ((i & addr.addr.ll.sll_addr[0]) != i)
                continue;
#elif defined(__FreeBSD__)
            if ((i & addr.addr.dl.sdl_data[addr.addr.dl.sdl_nlen]) != i)
                continue;
#endif
            type = ndAddr::Type::MULTICAST;
            return;
        }

#if defined(__linux__)
        uint8_t sll_addr[sizeof(addr.addr.ll.sll_addr)];

        memset(sll_addr, 0xff, addr.addr.ll.sll_halen);
        if (memcmp(addr.addr.ll.sll_addr, sll_addr,
              addr.addr.ll.sll_halen) == 0)
        {
            type = ndAddr::Type::BROADCAST;
            return;
        }

        memset(sll_addr, 0, addr.addr.ll.sll_halen);
        if (memcmp(addr.addr.ll.sll_addr, sll_addr,
              addr.addr.ll.sll_halen) == 0)
        {
            type = ndAddr::Type::NONE;
            return;
        }
#elif defined(__FreeBSD__)
        uint8_t sll_addr[sizeof(addr.addr.dl.sdl_data)];

        memset(sll_addr, 0xff, addr.addr.dl.sdl_alen);
        if (memcmp(&addr.addr.dl.sdl_data[addr.addr.dl.sdl_nlen],
              sll_addr, addr.addr.dl.sdl_alen) == 0)
        {
            type = ndAddr::Type::BROADCAST;
            return;
        }

        memset(sll_addr, 0, addr.addr.dl.sdl_alen);
        if (memcmp(&addr.addr.dl.sdl_data[addr.addr.dl.sdl_nlen],
              sll_addr, addr.addr.dl.sdl_alen) == 0)
        {
            type = ndAddr::Type::NONE;
            return;
        }
#endif
        if (ether_reserved.size()) {
            lock_guard<mutex> ul(lock);

            auto it = ether_reserved.find(addr.GetString());
            if (it != ether_reserved.end()) {
                type = it->second;
                return;
            }
        }
    }
    else if (addr.IsIPv4()) {
        if (addr.addr.in.sin_addr.s_addr == 0) {
            type = ndAddr::Type::LOCAL;
            return;
        }

        if (addr.addr.in.sin_addr.s_addr == 0xffffffff) {
            type = ndAddr::Type::BROADCAST;
            return;
        }

        for (auto &iface : ipv4_iface) {
            ndRadixNetworkEntry<_ND_ADDR_BITSv4> entry;
            if (ndRadixNetworkEntry<_ND_ADDR_BITSv4>::CreateQuery(
                  entry, addr))
            {
                lock_guard<mutex> ul(lock);

                nd_rn4_atype::iterator it;
                if ((it = iface.second.longest_match(entry)) !=
                  iface.second.end())
                {
                    type = it->second;
                    if (type == ndAddr::Type::LOCALNET &&
                      ! addr.IsNetwork())
                        type = ndAddr::Type::LOCAL;
                    return;
                }
            }
        }

        ndRadixNetworkEntry<_ND_ADDR_BITSv4> entry;
        if (ndRadixNetworkEntry<_ND_ADDR_BITSv4>::CreateQuery(
              entry, addr))
        {
            lock_guard<mutex> ul(lock);

            nd_rn4_atype::iterator it;
            if ((it = ipv4_reserved.longest_match(entry)) !=
              ipv4_reserved.end())
            {
                type = it->second;
                if (type == ndAddr::Type::LOCALNET &&
                  ! addr.IsNetwork())
                    type = ndAddr::Type::LOCAL;
                return;
            }
        }
    }
    else if (addr.IsIPv6()) {
        for (auto &iface : ipv6_iface) {
            ndRadixNetworkEntry<_ND_ADDR_BITSv6> entry;
            if (ndRadixNetworkEntry<_ND_ADDR_BITSv6>::CreateQuery(
                  entry, addr))
            {
                lock_guard<mutex> ul(lock);

                nd_rn6_atype::iterator it;
                if ((it = iface.second.longest_match(entry)) !=
                  iface.second.end())
                {
                    type = it->second;
                    if (type == ndAddr::Type::LOCALNET &&
                      ! addr.IsNetwork())
                        type = ndAddr::Type::LOCAL;
                    return;
                }
            }
        }

        ndRadixNetworkEntry<_ND_ADDR_BITSv6> entry;
        if (ndRadixNetworkEntry<_ND_ADDR_BITSv6>::CreateQuery(
              entry, addr))
        {
            lock_guard<mutex> ul(lock);

            nd_rn6_atype::iterator it;
            if ((it = ipv6_reserved.longest_match(entry)) !=
              ipv6_reserved.end())
            {
                type = it->second;
                if (type == ndAddr::Type::LOCALNET &&
                  ! addr.IsNetwork())
                    type = ndAddr::Type::LOCAL;
                return;
            }
        }
    }
}

size_t ndAddrLookup::GetInterfaceAddresses(const string &iface,
  set<string> &result, sa_family_t family) {
    lock_guard<mutex> ul(lock);

    if (family == AF_UNSPEC || family == AF_INET) {
        auto rn = ipv4_iface.find(iface);
        if (rn == ipv4_iface.end()) return result.size();

        for (auto &it : rn->second) {
            string ip;
            if (it.first.GetString(ip)) result.insert(ip);
        }
    }

    if (family == AF_UNSPEC || family == AF_INET6) {
        auto rn = ipv6_iface.find(iface);
        if (rn == ipv6_iface.end()) return result.size();

        for (auto &it : rn->second) {
            string ip;
            if (it.first.GetString(ip)) result.insert(ip);
        }
    }

    return result.size();
}

size_t ndInterface::UpdateAddrs(ndInterfaces &interfaces) {
    size_t count = 0;

    struct ifaddrs *if_addrs;

    if (getifaddrs(&if_addrs) == 0) {
        for (auto &i : interfaces) {
            i.second->addrs.Clear();
            i.second->UpdateAddrs(if_addrs);
        }

        freeifaddrs(if_addrs);
    }

    return count;
}

size_t ndInterface::UpdateAddrs(const struct ifaddrs *if_addrs) {
    size_t count = 0;
    const struct ifaddrs *ifa_addr = if_addrs;
#if defined(__linux__)
    struct sockaddr_ll *sa_ll;
#elif defined(__FreeBSD__)
    struct sockaddr_dl *sa_dl;
#endif
    const uint8_t *mac_addr = nullptr;

    for (; ifa_addr != NULL; ifa_addr = ifa_addr->ifa_next) {
        if (ifa_addr->ifa_addr == NULL ||
          (ifname != ifa_addr->ifa_name &&
            ifname_peer != ifa_addr->ifa_name))
            continue;

        ndAddr addr;
        uint8_t prefix = 0;
        ndInstance &ndi = ndInstance::GetInstance();

        switch (ifa_addr->ifa_addr->sa_family) {
        case AF_LINK:
#if defined(__linux__)
            sa_ll = (struct sockaddr_ll *)ifa_addr->ifa_addr;
            mac_addr = sa_ll->sll_addr;
#elif defined(__FreeBSD__)
            sa_dl = (struct sockaddr_dl *)ifa_addr->ifa_addr;
            mac_addr = (const uint8_t *)sa_dl->sdl_data +
              sa_dl->sdl_nlen;
#endif
            if (mac_addr != nullptr) {
                ndAddr::Create(addr, mac_addr, ETH_ALEN);
                if (addrs.Push(addr)) count++;
                if (ndGC_USE_GETIFADDRS) {
                    ndi.addr_lookup.AddAddress(
                      ndAddr::Type::LOCAL, addr, ifname);
                }
            }
            break;
        case AF_INET:
            prefix = nd_netmask_to_prefix(
              reinterpret_cast<struct sockaddr_storage *>(
                ifa_addr->ifa_netmask));
            ndAddr::Create(addr,
              reinterpret_cast<const struct sockaddr_in *>(
                ifa_addr->ifa_addr),
              prefix);
            if (addrs.Push(addr)) count++;
            if (ndGC_USE_GETIFADDRS) {
                ndi.addr_lookup.AddAddress(
                  ndAddr::Type::LOCAL, addr, ifname);
            }
            break;
        case AF_INET6:
            prefix = nd_netmask_to_prefix(
              reinterpret_cast<struct sockaddr_storage *>(
                ifa_addr->ifa_netmask));
            ndAddr::Create(addr,
              reinterpret_cast<const struct sockaddr_in6 *>(
                ifa_addr->ifa_addr),
              prefix);
            if (addrs.Push(addr)) count++;
            if (ndGC_USE_GETIFADDRS) {
                ndi.addr_lookup.AddAddress(
                  ndAddr::Type::LOCAL, addr, ifname);
            }
            break;
        default: break;
        }
    }

    return count;
}
