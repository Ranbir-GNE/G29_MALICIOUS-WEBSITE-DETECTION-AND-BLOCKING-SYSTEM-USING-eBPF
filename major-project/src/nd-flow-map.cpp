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

#include "nd-except.hpp"
#include "nd-flow-map.hpp"

using namespace std;

ndFlowMap::ndFlowMap(size_t buckets) : buckets(buckets) {
    for (size_t i = 0; i < buckets; i++) {
        nd_flow_map *b = new nd_flow_map;
#ifdef HAVE_CXX11
        b->reserve(ND_HASH_BUCKETS_FLOWS);
#endif
        bucket.push_back(b);
        bucket_lock.emplace_back(new mutex);
    }

    nd_dprintf("Created %lu flow map buckets.\n", buckets);
}

ndFlowMap::~ndFlowMap() {
    for (size_t i = 0; i < buckets; i++) {
        lock_guard<mutex> lock(*bucket_lock[i]);

        delete bucket[i];
    }

    bucket.clear();
    bucket_lock.clear();
}

nd_flow_ptr
ndFlowMap::Lookup(const string &digest, bool acquire_lock) {
    nd_flow_ptr f;
    size_t b = HashToBucket(digest);

    bucket_lock[b]->lock();

    auto fi = bucket[b]->find(digest);
    if (fi != bucket[b]->end()) f = fi->second;

    if (! acquire_lock) bucket_lock[b]->unlock();

    return f;
}

bool ndFlowMap::Insert(const string &digest,
  nd_flow_ptr &flow, bool unlocked) {
    bool result = false;
    size_t b = HashToBucket(digest);

    if (! unlocked) bucket_lock[b]->lock();

    nd_flow_pair fp(digest, flow);
    nd_flow_insert fi = bucket[b]->insert(fp);

    result = fi.second;

    if (! unlocked) bucket_lock[b]->unlock();

    return result;
}

bool ndFlowMap::Delete(const string &digest) {
    bool deleted = false;
    size_t b = HashToBucket(digest);
    lock_guard<mutex> lock(*bucket_lock[b]);

    auto fi = bucket[b]->find(digest);
    if (fi != bucket[b]->end()) {
        deleted = true;
        bucket[b]->erase(fi);
    }

    return deleted;
}

nd_flow_map &ndFlowMap::Acquire(size_t b) {
    if (b >= buckets) {
        throw ndException("%s: %s: %s", __PRETTY_FUNCTION__,
          "bucket", strerror(EINVAL));
    }

    bucket_lock[b]->lock();

    return *bucket[b];
}

const nd_flow_map &ndFlowMap::AcquireConst(size_t b) const {
    if (b >= buckets) {
        throw ndException("%s: %s: %s", __PRETTY_FUNCTION__,
          "bucket", strerror(EINVAL));
    }

    bucket_lock[b]->lock();

    return *bucket[b];
}

void ndFlowMap::Release(size_t b) const {
    if (b >= buckets) {
        throw ndException("%s: %s: %s", __PRETTY_FUNCTION__,
          "bucket", strerror(EINVAL));
    }

    bucket_lock[b]->unlock();
}

void ndFlowMap::Release(const string &digest) const {
    Release(HashToBucket(digest));
}

#ifndef _ND_LEAN_AND_MEAN
void ndFlowMap::DumpBucketStats(void) {
    for (size_t i = 0; i < buckets; i++) {
        if (bucket_lock[i]->try_lock()) {
            nd_dprintf("ndFlowMap: %4u: %u flow(s).\n", i,
              bucket[i]->size());

            bucket_lock[i]->unlock();
        }
        else nd_dprintf("ndFlowMap: %4u: locked.\n", i);
    }
}
#endif
