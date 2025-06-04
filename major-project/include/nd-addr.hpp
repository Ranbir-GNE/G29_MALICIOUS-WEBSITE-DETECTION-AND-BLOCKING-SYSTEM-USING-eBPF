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

#include <arpa/inet.h>
#include <sys/socket.h>
#if defined(__linux__)
#include <linux/if_packet.h>
#include <net/if_arp.h>
#elif defined(__FreeBSD__)
// XXX: net/if_arp.h must be included after sys/socket.h
#include <net/if_arp.h>
#include <net/if_dl.h>
#endif

#include <atomic>
#include <bitset>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <radix/radix_tree.hpp>
#include <set>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>

#include "nd-config.hpp"
#include "nd-flags.hpp"
#include "nd-serializer.hpp"
#include "nd-util.hpp"
#include "netifyd.hpp"

constexpr size_t _ND_ADDR_BITSv4 = 32;
constexpr size_t _ND_ADDR_BITSv6 = 128;

class ndAddr
{
public:
    enum class Type : uint8_t {
        NONE = 1,
        LOCAL = 2,
        LOCALNET = 3,
        RESERVED = 4,
        MULTICAST = 5,
        BROADCAST = 6,
        OTHER = 7,
        ERROR = 0x7f,
    };

    typedef std::pair<struct sockaddr_storage, struct sockaddr_storage> PrivatePair;

    ndAddr(uint8_t prefix = 0)
      : addr{ { 0 } }, prefix(prefix),
        cached_flags(MakeFlags::NONE),
        compare_flags(CompareFlags::ALL) { }

    ndAddr(const std::string &addr)
      : addr{ { 0 } }, prefix(0), cached_flags(MakeFlags::NONE),
        compare_flags(CompareFlags::ALL) {
        Create(*this, addr);
    }

    ndAddr(const uint8_t *hw_addr, size_t length = ETH_ALEN)
      : addr{ { 0 } }, prefix(0), cached_flags(MakeFlags::NONE),
        compare_flags(CompareFlags::ALL) {
        Create(*this, hw_addr, length);
    }

    ndAddr(const struct sockaddr_storage *ss_addr, uint8_t prefix = 0)
      : addr{ { 0 } }, prefix(0), cached_flags(MakeFlags::NONE),
        compare_flags(CompareFlags::ALL) {
        Create(*this, ss_addr, prefix);
    }
    ndAddr(const struct sockaddr_storage &ss_addr, uint8_t prefix = 0)
      : ndAddr(&ss_addr, prefix) { }

    ndAddr(const struct sockaddr_in *ss_in,
      uint8_t prefix = _ND_ADDR_BITSv4)
      : addr{ { 0 } }, prefix(0), cached_flags(MakeFlags::NONE),
        compare_flags(CompareFlags::ALL) {
        Create(*this, ss_in, prefix);
    }
    ndAddr(const struct sockaddr_in &ss_in,
      uint8_t prefix = _ND_ADDR_BITSv4)
      : ndAddr(&ss_in, prefix) { }

    ndAddr(const struct sockaddr_in6 *ss_in6,
      uint8_t prefix = _ND_ADDR_BITSv6)
      : addr{ { 0 } }, prefix(0), cached_flags(MakeFlags::NONE),
        compare_flags(CompareFlags::ALL) {
        Create(*this, ss_in6, prefix);
    }
    ndAddr(const struct sockaddr_in6 &ss_in6,
      uint8_t prefix = _ND_ADDR_BITSv6)
      : ndAddr(&ss_in6, prefix) { }

    ndAddr(const struct in_addr *in_addr, uint8_t prefix = _ND_ADDR_BITSv4)
      : addr{ { 0 } }, prefix(0), cached_flags(MakeFlags::NONE),
        compare_flags(CompareFlags::ALL) {
        Create(*this, in_addr, prefix);
    }
    ndAddr(const struct in_addr &in_addr, uint8_t prefix = _ND_ADDR_BITSv4)
      : ndAddr(&in_addr, prefix) { }

    ndAddr(const struct in6_addr *in6_addr,
      uint8_t prefix = _ND_ADDR_BITSv6)
      : addr{ { 0 } }, prefix(0), cached_flags(MakeFlags::NONE),
        compare_flags(CompareFlags::ALL) {
        Create(*this, in6_addr, prefix);
    }
    ndAddr(const struct in6_addr &in6_addr,
      uint8_t prefix = _ND_ADDR_BITSv6)
      : ndAddr(&in6_addr, prefix) { }

    static bool Create(ndAddr &a, const std::string &addr);

    static bool
    Create(ndAddr &a, const uint8_t *hw_addr, size_t length);

    static bool Create(ndAddr &a,
      const struct sockaddr_storage *ss_addr,
      uint8_t prefix = 0);

    static bool Create(ndAddr &a,
      const struct sockaddr_in *ss_in,
      uint8_t prefix = _ND_ADDR_BITSv4);

    static bool Create(ndAddr &a,
      const struct sockaddr_in6 *ss_in6,
      uint8_t prefix = _ND_ADDR_BITSv6);

    static bool Create(ndAddr &a,
      const struct in_addr *in_addr,
      uint8_t prefix = _ND_ADDR_BITSv4);

    static bool Create(ndAddr &a,
      const struct in6_addr *in6_addr,
      uint8_t prefix = _ND_ADDR_BITSv6);

    const uint8_t *GetAddress(void) const;
    size_t GetAddressSize(void) const;

    uint16_t GetPort(bool byte_swap = true) const;
    bool SetPort(uint16_t port);

    inline bool IsValid(void) const {
        return (addr.ss.ss_family != AF_UNSPEC);
    }
    inline bool HasValidPrefix(void) const {
        return (prefix > 0 &&
          ((addr.ss.ss_family == AF_INET && prefix <= _ND_ADDR_BITSv4) ||
            (addr.ss.ss_family == AF_INET6 &&
              prefix <= _ND_ADDR_BITSv6)));
    }
    inline bool IsNetwork(void) const {
        if (! HasValidPrefix()) return false;
        if (addr.ss.ss_family == AF_INET && prefix != _ND_ADDR_BITSv4)
            return true;
        return (addr.ss.ss_family == AF_INET6 &&
          prefix != _ND_ADDR_BITSv6);
    }
    inline bool IsEthernet(void) const {
        return (
#if defined(__linux__)
          addr.ss.ss_family == AF_PACKET &&
          addr.ll.sll_hatype == ARPHRD_ETHER &&
          addr.ll.sll_halen == ETH_ALEN
#elif defined(__FreeBSD__)
          addr.ss.ss_family == AF_LINK &&
          addr.dl.sdl_type == ARPHRD_ETHER && addr.dl.sdl_alen == ETH_ALEN
#endif
        );
    }
    inline bool IsIP(void) const {
        return (addr.ss.ss_family == AF_INET ||
          addr.ss.ss_family == AF_INET6);
    }
    inline bool IsIPv4(void) const {
        return (addr.ss.ss_family == AF_INET);
    }
    inline bool IsIPv6(void) const {
        return (addr.ss.ss_family == AF_INET6);
    }

    enum class MakeFlags : uint8_t {
        NONE = 0x0,
        PREFIX = 0x1,
        PORT = 0x2,
        IPV6_URI = 0x4,

        ALL = (PREFIX | PORT)
    };

    static bool MakeString(const ndAddr &a, std::string &result,
      ndFlags<MakeFlags> flags = MakeFlags::ALL);

    inline const std::string &
    GetString(ndFlags<MakeFlags> flags = MakeFlags::NONE) const {
        static std::recursive_mutex lock;
        std::lock_guard<std::recursive_mutex> lg(lock);
        if (flags != cached_flags || cached_addr.empty()) {
            cached_flags = flags;
            ndAddr::MakeString(*this, cached_addr, cached_flags);
        }
        return cached_addr;
    }

    friend std::ostream &
    operator<<(std::ostream &stream, const ndAddr &addr) {
        stream << addr.cached_addr;
        return stream;
    }

    enum class CompareFlags : uint8_t {
        ADDR = 0x1,
        PORT = 0x2,
        PREFIX = 0x4,

        ALL = (ADDR | PORT | PREFIX)
    };

    inline void SetCompareFlags(
      ndFlags<CompareFlags> flags = CompareFlags::ALL) {
        compare_flags = flags;
    }

    inline bool operator==(const ndAddr &a) const {
        if (a.addr.ss.ss_family != addr.ss.ss_family)
            return false;
        if (ndFlagBoolean(compare_flags, CompareFlags::PREFIX) &&
          a.prefix != prefix)
            return false;

        switch (addr.ss.ss_family) {
#if defined(__linux__)
        case AF_PACKET:
            if (! ndFlagBoolean(compare_flags, CompareFlags::ADDR))
                return true;
            return (memcmp(&addr.ll, &a.addr.ll,
                      sizeof(struct sockaddr_ll)) == 0);
#elif defined(__FreeBSD__)
        case AF_LINK:
            if (! ndFlagBoolean(compare_flags, CompareFlags::ADDR))
                return true;
            return (memcmp(&addr.dl, &a.addr.dl,
                      sizeof(struct sockaddr_dl)) == 0);
#endif
        case AF_INET:
            if (ndFlagBoolean(compare_flags, CompareFlags::ADDR) &&
              (ndFlagBoolean(compare_flags, CompareFlags::PORT)))
            {
                return (memcmp(&addr.in, &a.addr.in,
                          sizeof(struct sockaddr_in)) == 0);
            }
            if (ndFlagBoolean(compare_flags, CompareFlags::ADDR) &&
              memcmp(&addr.in.sin_addr, &a.addr.in.sin_addr,
                sizeof(struct in_addr)) == 0)
                return true;
            if (ndFlagBoolean(compare_flags, CompareFlags::PORT) &&
              addr.in.sin_port == a.addr.in.sin_port)
                return true;
            break;
        case AF_INET6:
            if (ndFlagBoolean(compare_flags, CompareFlags::ADDR) &&
              (ndFlagBoolean(compare_flags, CompareFlags::PORT)))
            {
                return (memcmp(&addr.in6, &a.addr.in6,
                          sizeof(struct sockaddr_in6)) == 0);
            }
            if (ndFlagBoolean(compare_flags, CompareFlags::ADDR) &&
              memcmp(&addr.in6.sin6_addr,
                &a.addr.in6.sin6_addr,
                sizeof(struct in6_addr)) == 0)
                return true;
            if (ndFlagBoolean(compare_flags, CompareFlags::PORT) &&
              addr.in6.sin6_port == a.addr.in6.sin6_port)
                return true;
            break;
        }
        return false;
    }

    inline bool operator!=(const ndAddr &a) const {
        return ! (a == *this);
    }

    struct ndAddrHash {
        template <class T>
        inline void hash_combine(size_t &seed, const T &v) const {
            std::hash<T> hasher;
            seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) +
              (seed >> 2);
        }

        size_t operator()(const ndAddr &a) const {
            size_t ss_hash = 0;

            switch (a.addr.ss.ss_family) {
#if defined(__linux__)
            case AF_PACKET:
                for (int i = 0; i < ETH_ALEN; i++) {
                    hash_combine<uint8_t>(ss_hash,
                      a.addr.ll.sll_addr[i]);
                }
                break;
#elif defined(__FreeBSD__)
            case AF_LINK:
                for (int i = 0; i < ETH_ALEN; i++) {
                    hash_combine<uint8_t>(ss_hash,
                      LLADDR(&a.addr.dl)[i]);
                }
                break;
#endif
            case AF_INET:
                hash_combine<uint32_t>(ss_hash,
                  a.addr.in.sin_addr.s_addr);
                break;
            case AF_INET6:
                hash_combine<uint32_t>(ss_hash,
                  a.addr.in6.sin6_addr.s6_addr32[0]);
                hash_combine<uint32_t>(ss_hash,
                  a.addr.in6.sin6_addr.s6_addr32[1]);
                hash_combine<uint32_t>(ss_hash,
                  a.addr.in6.sin6_addr.s6_addr32[2]);
                hash_combine<uint32_t>(ss_hash,
                  a.addr.in6.sin6_addr.s6_addr32[3]);
                break;
            }

            return ss_hash;
        }
    };

    struct ndAddrHashAll {
        template <class T>
        inline void hash_combine(size_t &seed, const T &v) const {
            std::hash<T> hasher;
            seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) +
              (seed >> 2);
        }

        size_t operator()(const ndAddr &a) const {
            size_t ss_hash = 0;

            hash_combine<uint8_t>(ss_hash, a.prefix);
            hash_combine<uint16_t>(ss_hash, a.addr.ss.ss_family);

            switch (a.addr.ss.ss_family) {
#if defined(__linux__)
            case AF_PACKET:
                for (int i = 0; i < ETH_ALEN; i++) {
                    hash_combine<uint8_t>(ss_hash,
                      a.addr.ll.sll_addr[i]);
                }
                break;
#elif defined(__FreeBSD__)
            case AF_LINK:
                for (int i = 0; i < ETH_ALEN; i++) {
                    hash_combine<uint8_t>(ss_hash,
                      LLADDR(&a.addr.dl)[i]);
                }
                break;
#endif
            case AF_INET:
                hash_combine<uint16_t>(ss_hash, a.addr.in.sin_port);
                hash_combine<uint32_t>(ss_hash,
                  a.addr.in.sin_addr.s_addr);
                break;
            case AF_INET6:
                hash_combine<uint16_t>(ss_hash, a.addr.in6.sin6_port);
                hash_combine<uint32_t>(ss_hash,
                  a.addr.in6.sin6_addr.s6_addr32[0]);
                hash_combine<uint32_t>(ss_hash,
                  a.addr.in6.sin6_addr.s6_addr32[1]);
                hash_combine<uint32_t>(ss_hash,
                  a.addr.in6.sin6_addr.s6_addr32[2]);
                hash_combine<uint32_t>(ss_hash,
                  a.addr.in6.sin6_addr.s6_addr32[3]);
                break;
            }

            return ss_hash;
        }
    };

    struct ndAddrEqual {
        bool operator()(const ndAddr &a1, const ndAddr &a2) const {
            if (a1.addr.ss.ss_family != a2.addr.ss.ss_family)
                return false;

            switch (a1.addr.ss.ss_family) {
#if defined(__linux__)
            case AF_PACKET:
                return (memcmp(&a1.addr.ll, &a2.addr.ll,
                          sizeof(struct sockaddr_ll)) == 0);
                break;
#elif defined(__FreeBSD__)
            case AF_LINK:
                return (memcmp(&a1.addr.dl, &a2.addr.dl,
                          sizeof(struct sockaddr_dl)) == 0);
                break;
#endif
            case AF_INET:
                return (memcmp(&a1.addr.in.sin_addr,
                          &a2.addr.in.sin_addr,
                          sizeof(struct in_addr)) == 0);
                break;
            case AF_INET6:
                return (memcmp(&a1.addr.in6.sin6_addr,
                          &a2.addr.in6.sin6_addr,
                          sizeof(struct in6_addr)) == 0);
                break;
            }

            return false;
        }
    };

    struct ndAddrEqualAll {
        bool operator()(const ndAddr &a1, const ndAddr &a2) const {
            return (a1 == a2);
        }
    };

    union {
        struct sockaddr_storage ss;
#if defined(__linux__)
        struct sockaddr_ll ll;
#elif defined(__FreeBSD__)
        struct sockaddr_dl dl;
#endif
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
    } addr;

    uint8_t prefix;

    mutable ndFlags<MakeFlags> cached_flags;
    mutable std::string cached_addr;

    ndFlags<CompareFlags> compare_flags;
};

template <size_t N>
bool operator<(const std::bitset<N> &x, const std::bitset<N> &y) {
    for (int i = N - 1; i >= 0; i--) {
        if (x[i] ^ y[i]) return y[i];
    }

    return false;
}

template <size_t N>
class ndRadixNetworkEntry
{
public:
    std::bitset<N> addr;
    size_t prefix_len;

    ndRadixNetworkEntry() : prefix_len(0) { }

    static bool
    Create(ndRadixNetworkEntry<N> &entry, const ndAddr &addr) {
        if (! addr.IsValid()) {
            nd_dprintf("Invalid radix address.\n");
            return false;
        }

        entry.prefix_len =
          (size_t)((addr.prefix == 0) ? N : addr.prefix);

        if (entry.prefix_len > N) {
            nd_dprintf(
              "Invalid radix address prefix length.\n");
            return false;
        }

        std::bitset<N> mask;

        size_t shift = N - entry.prefix_len;
        if (shift < N) {
            mask.set();
            for (size_t i = 0; i < shift; i++) mask.flip(i);
        }

        switch (N) {
        case _ND_ADDR_BITSv4:  // AF_INET
            entry.addr = ntohl(addr.addr.in.sin_addr.s_addr);
            entry.addr &= mask;
            return true;

        case _ND_ADDR_BITSv6:  // AF_INET6
            entry.addr |= ntohl(
              addr.addr.in6.sin6_addr.s6_addr32[0]);
            entry.addr <<= _ND_ADDR_BITSv4;
            entry.addr |= ntohl(
              addr.addr.in6.sin6_addr.s6_addr32[1]);
            entry.addr <<= _ND_ADDR_BITSv4;
            entry.addr |= ntohl(
              addr.addr.in6.sin6_addr.s6_addr32[2]);
            entry.addr <<= _ND_ADDR_BITSv4;
            entry.addr |= ntohl(
              addr.addr.in6.sin6_addr.s6_addr32[3]);
            entry.addr &= mask;
            return true;
        }

        nd_dprintf("Unsupported address size: %lu.\n", N);
        return false;
    }

    static void Create(ndRadixNetworkEntry<N> &entry,
      const std::string &addr) {
        Create(ndAddr(addr));
    }

    static bool CreateQuery(ndRadixNetworkEntry<N> &entry,
      const ndAddr &addr) {
        if (! addr.IsValid()) {
            nd_dprintf("Invalid radix address.\n");
            return false;
        }

        entry.prefix_len = N;

        switch (N) {
        case _ND_ADDR_BITSv4:  // AF_INET
            entry.addr = ntohl(addr.addr.in.sin_addr.s_addr);
            return true;

        case _ND_ADDR_BITSv6:  // AF_INET6
            entry.addr |= ntohl(
              addr.addr.in6.sin6_addr.s6_addr32[0]);
            entry.addr <<= _ND_ADDR_BITSv4;
            entry.addr |= ntohl(
              addr.addr.in6.sin6_addr.s6_addr32[1]);
            entry.addr <<= _ND_ADDR_BITSv4;
            entry.addr |= ntohl(
              addr.addr.in6.sin6_addr.s6_addr32[2]);
            entry.addr <<= _ND_ADDR_BITSv4;
            entry.addr |= ntohl(
              addr.addr.in6.sin6_addr.s6_addr32[3]);
            return true;
        }

        nd_dprintf("Unsupported address size: %lu.\n", N);
        return false;
    }

    bool operator[](int n) const {
        return addr[(N - 1) - n];
    }

    bool operator==(const ndRadixNetworkEntry &rhs) const {
        return prefix_len == rhs.prefix_len && addr == rhs.addr;
    }

    bool operator<(const ndRadixNetworkEntry &rhs) const {
        if (addr == rhs.addr)
            return prefix_len < rhs.prefix_len;
        else return addr < rhs.addr;
    }

    bool GetString(std::string &ip,
      ndFlags<ndAddr::MakeFlags> flags = ndAddr::MakeFlags::NONE) const {
        ndAddr a((uint8_t)prefix_len);
        switch (N) {
        case _ND_ADDR_BITSv4:
            a.addr.ss.ss_family = AF_INET;
            a.addr.in.sin_addr.s_addr = htonl(addr.to_ulong());
            break;
        case _ND_ADDR_BITSv6:
            a.addr.ss.ss_family = AF_INET6;
            for (auto i = 0; i < 4; i++) {
                std::bitset<N> b;
                for (size_t j = 0; j < 32; j++)
                    b[j] = addr[i * 32 + j];
                a.addr.in6.sin6_addr.s6_addr32[3 - i] =
                  htonl(b.to_ulong());
            }
            break;
        default: return false;
        }
        return ndAddr::MakeString(a, ip, flags);
    }
};

template <size_t N>
std::bitset<N> &operator-=(std::bitset<N> &x, const size_t y) {
    bool borrow = false;
    std::bitset<N> const _y(y);

    for (size_t i = 0; i < N; i++) {
        if (borrow) {
            if (x[i]) {
                x[i] = _y[i];
                borrow = _y[i];
            }
            else {
                x[i] = ! _y[i];
                borrow = true;
            }
        }
        else {
            if (x[i]) {
                x[i] = ! _y[i];
                borrow = false;
            }
            else {
                x[i] = _y[i];
                borrow = _y[i];
            }
        }
    }

    return x;
}

template <size_t N>
int radix_length(const ndRadixNetworkEntry<N> &entry) {
    return (int)entry.prefix_len;
}

template <size_t N>
ndRadixNetworkEntry<N> radix_substr(
  const ndRadixNetworkEntry<N> &entry, int offset, int length) {
    std::bitset<N> mask;

    if (length == N) mask = 0;
    else {
        mask = 1;
        mask <<= length;
    }

    mask -= 1;
    mask <<= N - length - offset;

    ndRadixNetworkEntry<N> result;
    result.addr = (entry.addr & mask) << offset;
    result.prefix_len = length;

    return result;
}

template <size_t N>
ndRadixNetworkEntry<N> radix_join(const ndRadixNetworkEntry<N> &x,
  const ndRadixNetworkEntry<N> &y) {
    ndRadixNetworkEntry<N> result;

    result.addr = x.addr;
    result.addr |= y.addr >> x.prefix_len;
    result.prefix_len = x.prefix_len + y.prefix_len;

    return result;
}

template <size_t N>
ndRadixNetworkEntry<N> radix_join(const ndRadixNetworkEntry<N> &x,
  const ndRadixNetworkEntry<N> &y);

typedef radix_tree<ndRadixNetworkEntry<_ND_ADDR_BITSv4>, ndAddr::Type> nd_rn4_atype;
typedef radix_tree<ndRadixNetworkEntry<_ND_ADDR_BITSv6>, ndAddr::Type> nd_rn6_atype;

class ndAddrLookup
{
public:
    ndAddrLookup();

    bool AddAddress(ndAddr::Type type, const ndAddr &addr,
      const std::string &ifname = "");
    inline bool AddAddress(ndAddr::Type type,
      const std::string &addr,
      const std::string &ifname = "") {
        return AddAddress(type, ndAddr(addr), ifname);
    }

    bool RemoveAddress(const ndAddr &addr,
      const std::string &ifname = "");
    inline bool RemoveAddress(const std::string &addr,
      const std::string &ifname = "") {
        return RemoveAddress(ndAddr(addr), ifname);
    }

    void Classify(ndAddr::Type &type, const ndAddr &addr);
    inline void
    Classify(ndAddr::Type &type, const std::string &addr) {
        Classify(type, ndAddr(addr));
    }

    size_t GetInterfaceAddresses(const std::string &iface,
      std::set<std::string> &result, sa_family_t family = AF_UNSPEC);

protected:
    mutable std::mutex lock;

    std::unordered_map<std::string, ndAddr::Type> ether_reserved;

    nd_rn4_atype ipv4_reserved;
    nd_rn6_atype ipv6_reserved;

    std::unordered_map<std::string, nd_rn4_atype> ipv4_iface;
    std::unordered_map<std::string, nd_rn6_atype> ipv6_iface;
};

typedef std::unordered_set<ndAddr, ndAddr::ndAddrHash, ndAddr::ndAddrEqual> ndInterfaceAddrs;

class ndInterfaceAddr : public ndSerializer
{
public:
    ndInterfaceAddr() { }

    ndInterfaceAddr(const ndAddr &a) { Push(a); }

    ndInterfaceAddr(const ndInterfaceAddr &iface)
      : addrs(iface.addrs) { }

    inline void Clear(bool locked = true) {
        if (locked) {
            std::lock_guard<std::mutex> ul(lock);
            addrs.clear();
        }
        else addrs.clear();
    }

    inline bool Push(const ndAddr &addr) {
        std::lock_guard<std::mutex> ul(lock);
        auto result = addrs.insert(addr);
        return result.second;
    }

    template <class T>
    void Encode(T &output, const std::string &key) const {
        std::lock_guard<std::mutex> ul(lock);
        if (addrs.empty()) return;
        std::vector<std::string> addresses;
        for (auto &a : addrs)
            addresses.push_back(a.GetString());
        serialize(output, { key }, addresses);
    }

    inline bool FindFirstOf(sa_family_t family, ndAddr &addr) const {
        std::lock_guard<std::mutex> ul(lock);
        for (auto &it : addrs) {
            if (it.addr.ss.ss_family != family) continue;
            addr = it;
            return true;
        }
        return false;
    }

    inline bool FindAllOf(const std::vector<sa_family_t> &families,
      std::vector<std::string> &results) const {
        size_t count = results.size();
        std::lock_guard<std::mutex> ul(lock);

        for (auto &it : addrs) {
            if (find_if(families.begin(), families.end(),
                  [it](const sa_family_t &f) {
                return (it.addr.ss.ss_family == f);
                }) == families.end())
                continue;

            results.push_back(it.GetString());
        }

        return (results.size() > count);
    }

protected:
    ndInterfaceAddrs addrs;
    mutable std::mutex lock;
};

typedef std::unordered_map<ndAddr, ndInterfaceAddr, ndAddr::ndAddrHash, ndAddr::ndAddrEqual> ndInterfaceEndpoints;

class ndInterface;
typedef std::map<std::string, std::shared_ptr<ndInterface>> ndInterfaces;

class ndInterface : public ndSerializer
{
public:
    ndInterface(const std::string &ifname,
      ndFlags<ndCaptureType>
        capture_type,
      ndInterfaceRole role = ndInterfaceRole::LAN)
      : ifname(ifname), ifname_peer(ifname),
        capture_type(capture_type), role(role) {
        endpoint_snapshot = false;
    }

    ndInterface(const ndInterface &iface)
      : ifname(iface.ifname), ifname_peer(iface.ifname_peer),
        capture_type(iface.capture_type), role(iface.role) {
        endpoint_snapshot = false;

        switch (ndCT_TYPE(capture_type.flags)) {
        case ndCaptureType::PCAP:
            config_pcap = iface.config_pcap;
            break;
#if defined(_ND_ENABLE_TPACKETV3)
        case ndCaptureType::TPV3:
            config_tpv3 = iface.config_tpv3;
            break;
#endif
#if defined(_ND_ENABLE_NFQUEUE)
        case ndCaptureType::NFQ:
            config_nfq = iface.config_nfq;
            break;
#endif
        default: break;
        }
    }

    static size_t UpdateAddrs(ndInterfaces &interfaces);

    size_t UpdateAddrs(const struct ifaddrs *if_addrs);

    template <class T>
    void Encode(T &output) const {
        switch (role) {
        case ndInterfaceRole::LAN:
            serialize(output, { "role" }, "LAN");
            break;
        case ndInterfaceRole::WAN:
            serialize(output, { "role" }, "WAN");
            break;
        default:
            serialize(output, { "role" }, "UNKNOWN");
            break;
        }

        switch (ndCT_TYPE(capture_type.flags)) {
        case ndCaptureType::PCAP:
            serialize(output, { "capture_type" }, "PCAP");
            break;
        case ndCaptureType::PCAP_OFFLINE:
            serialize(output, { "capture_type" }, "PCAP");
            serialize(output, { "capture_file" },
              config_pcap.capture_filename);
            break;
        case ndCaptureType::TPV3:
            serialize(output, { "capture_type" }, "TPv3");
            break;
        case ndCaptureType::NFQ:
            serialize(output, { "capture_type" }, "NFQ");
            break;
        default:
            serialize(output, { "capture_type" }, "UNKNOWN");
            break;
        }

        ndAddr mac;
#if defined(__linux__)
        if (addrs.FindFirstOf(AF_PACKET, mac))
#elif defined(__FreeBSD__)
        if (addrs.FindFirstOf(AF_LINK, mac))
#endif
            serialize(output, { "mac" }, mac.GetString());
        else
            serialize(output, { "mac" },
              "00:00:00:00:00:00");
    }

    template <class T>
    void EncodeAddrs(T &output, const std::vector<std::string> &keys,
      const std::string &delim = ",") const {
        std::vector<std::string> ip_addrs;
        if (addrs.FindAllOf({ AF_INET, AF_INET6 }, ip_addrs))
            serialize(output, keys, ip_addrs, delim);
    }

    inline bool NextEndpointSnapshot(void) {
        const bool snapshot = endpoint_snapshot.exchange(
          ! endpoint_snapshot.load());
        ClearEndpoints(endpoint_snapshot.load());
        return snapshot;
    }

    inline bool LastEndpointSnapshot(void) const {
        return ! endpoint_snapshot.load();
    }

    inline bool PushEndpoint(const ndAddr &mac, const ndAddr &ip) {
        std::lock_guard<std::mutex> ul(lock);
        auto result = endpoints[endpoint_snapshot.load()].emplace(
          std::make_pair(mac, ndInterfaceAddr(ip)));

        if (! result.second)
            return result.first->second.Push(ip);

        return true;
    }

    inline void ClearEndpoints(bool snapshot) {
        std::lock_guard<std::mutex> ul(lock);
        for (auto &it : endpoints[snapshot])
            it.second.Clear();
        endpoints[snapshot].clear();
    }

    template <class T>
    inline void EncodeEndpoints(bool snapshot, T &output) const {
        std::lock_guard<std::mutex> ul(lock);
        for (auto &i : endpoints[snapshot])
            i.second.Encode(output, i.first.GetString());
    }

    inline void GetEndpoints(bool snapshot,
      std::unordered_map<std::string, std::unordered_set<std::string>> &output) const {
        std::lock_guard<std::mutex> ul(lock);
        for (auto &i : endpoints[snapshot]) {
            std::vector<std::string> ip_addrs;
            if (! i.second.FindAllOf({ AF_INET, AF_INET6 }, ip_addrs))
                continue;

            for (auto &j : ip_addrs)
                output[i.first.GetString()].insert(j);
        }
    }

    inline void SetConfig(const nd_config_pcap *pcap) {
        config_pcap = *pcap;
    }
#if defined(_ND_ENABLE_TPACKETV3)
    inline void SetConfig(const nd_config_tpv3 *tpv3) {
        config_tpv3 = *tpv3;
    }
#endif
#if defined(_ND_ENABLE_NFQUEUE)
    inline void SetConfig(const nd_config_nfq *nfq) {
        config_nfq = *nfq;
    }
#endif

    inline bool operator==(const ndInterface &i) const {
        if (ifname != i.ifname || ifname_peer != i.ifname_peer)
            return false;
        if (capture_type != i.capture_type) return false;
        if (role != i.role) return false;

        switch (ndCT_TYPE(capture_type.flags)) {
        case ndCaptureType::PCAP:
        case ndCaptureType::PCAP_OFFLINE:
            return (config_pcap == i.config_pcap);
#if defined(_ND_ENABLE_TPACKETV3)
        case ndCaptureType::TPV3:
            return (config_tpv3 == i.config_tpv3);
#endif
#if defined(_ND_ENABLE_NFQUEUE)
        case ndCaptureType::NFQ:
            return (config_nfq == i.config_nfq);
#endif
        default: return false;
        }
        return true;
    }

    std::string ifname;
    std::string ifname_peer;
    ndFlags<ndCaptureType> capture_type;
    ndInterfaceRole role;

    nd_config_pcap config_pcap;
#if defined(_ND_ENABLE_TPACKETV3)
    nd_config_tpv3 config_tpv3;
#endif
#if defined(_ND_ENABLE_NFQUEUE)
    nd_config_nfq config_nfq;
#endif

protected:
    ndInterfaceAddr addrs;
    ndInterfaceEndpoints endpoints[2];
    std::atomic<bool> endpoint_snapshot;
    mutable std::mutex lock;
};

typedef std::shared_ptr<ndInterface> nd_iface_ptr;
