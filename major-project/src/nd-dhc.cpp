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

#include <algorithm>
#include <fstream>
#include <vector>

#include "nd-config.hpp"
#include "nd-dhc.hpp"
#include "nd-instance.hpp"
#include "nd-util.hpp"

using namespace std;

constexpr const char *_ND_DHC_FILE_NAME = "/dns-cache.csv";

ndDNSHintCache::ndDNSHintCache(size_t cache_size)
  : ndLRUCache<string, string>(cache_size, true) {
    kvmap.reserve(ND_HASH_BUCKETS_DNSARS);
}

void ndDNSHintCache::Insert(const ndAddr &addr,
  const string &hostname) {
    if (! addr.IsValid() || ! addr.IsIP() || addr.IsNetwork())
    {
        nd_dprintf("Invalid DHC address: %s\n",
          addr.GetString().c_str());
        return;
    }

    ndAddr::Type type;
    ndInstance::GetInstance().addr_lookup.Classify(type, addr);

    if (type != ndAddr::Type::OTHER) {
        nd_dprintf("Invalid DHC address type: %d: %s\n",
          type, addr.GetString().c_str());
        return;
    }

    const uint8_t *sa = addr.GetAddress();
    if (sa == nullptr) {
        nd_dprintf("Invalid DHC address data.\n");
        return;
    }

    sha1 ctx;
    string digest;
    uint8_t _digest[SHA1_DIGEST_LENGTH];

    sha1_init(&ctx);
    sha1_write(&ctx, sa, addr.GetAddressSize());

    digest.assign((const char *)sha1_result(&ctx, _digest),
      SHA1_DIGEST_LENGTH);

    CacheInsert(digest, hostname, true);
}

void ndDNSHintCache::Insert(const string &digest,
  const string &hostname) {
    vector<uint8_t> _digest_bin;

    if (nd_string_to_sha1(digest, _digest_bin)) {
        string _digest(_digest_bin.begin(), _digest_bin.end());
        CacheInsert(_digest, hostname, true);
    }
}

bool ndDNSHintCache::Lookup(const ndAddr &addr, string &hostname) {
    if (! addr.IsValid() || ! addr.IsIP() || addr.IsNetwork())
    {
        nd_dprintf("Invalid DHC address: %s\n",
          addr.GetString().c_str());
        return false;
    }

    const uint8_t *sa = addr.GetAddress();
    size_t sa_length = addr.GetAddressSize();

    if (sa == nullptr || sa_length == 0) {
        nd_dprintf("Invalid DHC address data.\n");
        return false;
    }

    sha1 ctx;
    string digest;
    uint8_t _digest[SHA1_DIGEST_LENGTH];

    sha1_init(&ctx);
    sha1_write(&ctx, sa, sa_length);

    digest.assign((const char *)sha1_result(&ctx, _digest),
      SHA1_DIGEST_LENGTH);

    //    return Lookup(digest, hostname);
    return CacheLookup(digest, hostname);
}

void ndDNSHintCache::Load(void) {
    string filename;
    size_t loaded = 0, ln = 0;

    switch (ndGC.dhc_storage) {
    case ndDHCStorage::PERSISTENT:
        filename = ndGC.path_state_persistent + _ND_DHC_FILE_NAME;
        break;
    case ndDHCStorage::VOLATILE:
        filename = ndGC.path_state_volatile + _ND_DHC_FILE_NAME;
        break;
    default: return;
    }

    ifstream ifs(filename);

    if (! ifs.is_open()) {
        nd_printf("Error loading DHC hint cache: %s: %s\n",
          filename.c_str(), strerror(errno));
        return;
    }

    string line;
    while (getline(ifs, line)) {
        nd_ltrim(line);
        if (! ifs.good() || ++ln == 1 || line.empty())
            continue;

        size_t fc = count_if(line.begin(), line.end(),
          [](unsigned char c) {
            if (c == ',') return true;
            return false;
        });

        size_t p, dp;
        if ((p = line.find_first_of(",")) == string::npos) {
            nd_printf("%s: parse error at line #%u\n",
              filename.c_str(), ln);
            return;
        }

        string hostname(line.begin(), line.begin() + p);

        nd_trim(hostname);
        nd_trim(hostname, '"');

        switch (fc) {
        case 1: Insert(line.substr(p + 1), hostname); break;
        case 2:
            nd_dprintf(
              "Legacy-format DNS hint cache detected.\n");

            dp = p + 1;
            if ((p = line.find_first_of(",", dp)) == string::npos)
            {
                nd_printf("%s: parse error at line #%u\n",
                  filename.c_str(), ln);
                return;
            }
            Insert(line.substr(dp, p), hostname);
            break;
        default:
            nd_printf("%s: parse error at line #%u\n",
              filename.c_str(), ln);
            return;
        }

        loaded++;
    }

    nd_dprintf("Loaded %u DNS hint cache entries.\n", loaded);
}

void ndDNSHintCache::Save(void) const {
    string filename;
    size_t saved = 0;

    switch (ndGC.dhc_storage) {
    case ndDHCStorage::PERSISTENT:
        filename = ndGC.path_state_persistent + _ND_DHC_FILE_NAME;
        break;
    case ndDHCStorage::VOLATILE:
        filename = ndGC.path_state_volatile + _ND_DHC_FILE_NAME;
        break;
    default: return;
    }

    lock_guard<mutex> lg(lock);

    ofstream ofs(filename, ofstream::trunc);
    if (! ofs.is_open()) {
        nd_printf("Error saving DHC hint cache: %s: %s\n",
          filename.c_str(), strerror(errno));
        return;
    }

    ofs << "\"host\",\"addr_digest\"" << endl;

    for (auto &i : kvmap) {
        string digest;
        ndDigestDynamic digest_bin(i.first.begin(), i.first.end());
        nd_sha1_to_string(digest_bin, digest);

        ofs << "\"" << i.second.first << "\"," << digest << endl;

        if (ofs.good()) saved++;
        else {
            nd_dprintf(
              "Error while saving DNS hint cache: %s\n",
              filename.c_str());
            break;
        }
    }

    nd_dprintf("Saved %u DNS hint cache entries.\n", saved);
}
