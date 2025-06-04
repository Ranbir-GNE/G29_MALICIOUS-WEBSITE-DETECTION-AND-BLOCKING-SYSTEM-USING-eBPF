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

#include <linux/netlink.h>

#include <array>
#include <string>

#include "nd-addr.hpp"

constexpr size_t _ND_NETLINK_BUFSIZ = 4096;

class ndNetlink
{
public:
    ndNetlink(void);
    virtual ~ndNetlink();

    int GetDescriptor(void) { return nd; }
    void Refresh(void);
    bool ProcessEvent(void);

protected:
    bool CopyAddress(sa_family_t family, ndAddr &dst,
      void *src, uint8_t prefix = 0);

    bool AddRemoveNetwork(struct nlmsghdr *nlh, bool add = true);

    bool AddRemoveAddress(struct nlmsghdr *nlh, bool add = true);

    int nd;
    unsigned seq;
    struct sockaddr_nl sa;
    std::array<uint8_t, _ND_NETLINK_BUFSIZ> buffer;
};
