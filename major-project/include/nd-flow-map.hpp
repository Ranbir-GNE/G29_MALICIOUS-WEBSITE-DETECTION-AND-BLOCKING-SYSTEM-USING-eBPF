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

#include <map>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <vector>

#include "nd-flow.hpp"

typedef std::shared_ptr<ndFlow> nd_flow_ptr;

class ndFlowMap
{
public:
    ndFlowMap(size_t buckets = ND_FLOW_MAP_BUCKETS);
    virtual ~ndFlowMap();

    nd_flow_ptr Lookup(const std::string &digest,
      bool acquire_lock = false);
    bool Insert(const std::string &digest,
      nd_flow_ptr &flow, bool unlocked = false);
    inline bool InsertUnlocked(const std::string &digest,
      nd_flow_ptr &flow) {
        return Insert(digest, flow, true);
    }

    bool Delete(const std::string &digest);

    nd_flow_map &Acquire(size_t b);
    const nd_flow_map &AcquireConst(size_t b) const;

    void Release(size_t b) const;
#if 0
    inline void Release(const string &digest) const {
        Release(HashToBucket(digest));
    }
#else
    void Release(const std::string &digest) const;
#endif
#ifndef _ND_LEAN_AND_MEAN
    void DumpBucketStats(void);
#endif

    inline size_t GetBuckets(void) const { return buckets; }

protected:
    unsigned HashToBucket(const std::string &digest) const {
        const char *p = digest.c_str();
        const uint64_t *b = (const uint64_t *)&p[0];
        return (*b % buckets);
    }

    size_t buckets;

    typedef std::vector<nd_flow_map *> FlowBucket;
    FlowBucket bucket;

    typedef std::vector<std::unique_ptr<std::mutex>> BucketLock;
    mutable BucketLock bucket_lock;
};
