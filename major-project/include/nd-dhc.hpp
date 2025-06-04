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

#include <string>

#include "nd-addr.hpp"
#include "nd-util.hpp"

class ndDNSHintCache : public ndLRUCache<std::string, std::string>
{
public:
    ndDNSHintCache(size_t cache_size);

    void Insert(const ndAddr &addr, const std::string &hostname);
    void Insert(const std::string &digest,
      const std::string &hostname);

    bool Lookup(const ndAddr &addr, std::string &hostname);
    inline bool
    Lookup(const std::string &digest, std::string &hostname) {
        return CacheLookup(digest, hostname);
    }

    void Load(void);
    void Save(void) const;
};
