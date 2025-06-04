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

// Enable flow hash cache debug logging
// #define _ND_DEBUG_FHC 1

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <fstream>
#include <vector>

#include "nd-config.hpp"
#include "nd-fhc.hpp"
#include "nd-util.hpp"

using namespace std;

constexpr const char *_ND_FHC_FILE_NAME =
  "/flow-hash-cache.csv";

ndFlowHashCache::ndFlowHashCache(size_t cache_size)
  : ndLRUCache<string, ndFlowHashCacheEntry>(cache_size, true) {
}

void ndFlowHashCache::Load(void) {
    string filename;
    size_t loaded = 0, ln = 0;

    switch (ndGC.fhc_storage) {
    case ndFHCStorage::PERSISTENT:
        filename = ndGC.path_state_persistent + _ND_FHC_FILE_NAME;
        break;
    case ndFHCStorage::VOLATILE:
        filename = ndGC.path_state_volatile + _ND_FHC_FILE_NAME;
        break;
    default: return;
    }

    ifstream ifs(filename);

    if (! ifs.is_open()) {
        nd_printf("Error loading flow hash cache: %s: %s\n",
          filename.c_str(), strerror(errno));
        return;
    }

    string line;
    while (getline(ifs, line)) {
        nd_ltrim(line);
        if (! ifs.good() || ++ln == 1 || line.empty())
            continue;

        size_t p;
        if ((p = line.find_first_of(",")) == string::npos) {
            nd_printf("%s: parse error at line #%u\n",
              filename.c_str(), ln);
            return;
        }

        string digest_lower(line.begin(), line.begin() + p);
        nd_trim(digest_lower);

        ndFlowHashCacheEntry entry;

        line = line.substr(p + 1);
        if ((p = line.find_first_of(",")) == string::npos) {
            nd_printf("%s: parse error at line #%u\n",
              filename.c_str(), ln);
            return;
        }

        if (! nd_string_to_sha1(line.substr(0, p), entry.digest))
        {
            nd_printf("%s: parse error at line #%u\n",
              filename.c_str(), ln);
            return;
        }

        line = line.substr(p + 1);
        if ((p = line.find_first_of(",")) == string::npos) {
            nd_printf("%s: parse error at line #%u\n",
              filename.c_str(), ln);
            return;
        }

        string value(line.substr(0, p));
        nd_trim(value);

        try {
            entry.app_id = (nd_app_id_t)stoul(value);
        }
        catch (invalid_argument &e) {
            nd_dprintf(
              "error converting string to app ID: %s: %s\n",
              e.what(), value.c_str());
            nd_printf("%s: parse error at line #%u\n",
              filename.c_str(), ln);
            return;
        }
        catch (out_of_range &e) {
            nd_printf("%s: parse error at line #%u\n",
              filename.c_str(), ln);
            return;
        }

        value = line.substr(p + 1);
        nd_trim(value);

        try {
            entry.proto_id = static_cast<ndProto::Id>(stoul(value));
        }
        catch (invalid_argument &e) {
            nd_dprintf(
              "error converting string to protocol ID: "
              "%s: %s\n",
              e.what(), value.c_str());
            nd_printf("%s: parse error at line #%u\n",
              filename.c_str(), ln);
            return;
        }
        catch (out_of_range &e) {
            nd_printf("%s: parse error at line #%u\n",
              filename.c_str(), ln);
            return;
        }

        ndDigest digest;
        if (! nd_string_to_sha1(digest_lower, digest)) {
            nd_printf("%s: parse error at line #%u\n",
              filename.c_str(), ln);
            return;
        }

        Insert(digest, entry);

        loaded++;
    }

    nd_dprintf("Loaded %u flow hash cache entries.\n", loaded);
}

void ndFlowHashCache::Save(void) const {
    string filename;
    size_t saved = 0;

    switch (ndGC.fhc_storage) {
    case ndFHCStorage::PERSISTENT:
        filename = ndGC.path_state_persistent + _ND_FHC_FILE_NAME;
        break;
    case ndFHCStorage::VOLATILE:
        filename = ndGC.path_state_volatile + _ND_FHC_FILE_NAME;
        break;
    default: return;
    }

    lock_guard<mutex> lg(lock);

    ofstream ofs(filename, ofstream::trunc);
    if (! ofs.is_open()) {
        nd_printf("Error saving flow hash cache: %s: %s\n",
          filename.c_str(), strerror(errno));
        return;
    }

    ofs << "\"lower_digest\",\"mdata_digest\",\"app_id\","
           "\"proto_id\""
        << endl;

    for (auto &i : kvmap) {
        string digest;
        ndDigestDynamic digest_bin(i.first.begin(), i.first.end());
        nd_sha1_to_string(digest_bin, digest);

        ofs << digest << "," << i.second.first << endl;

        if (ofs.good()) saved++;
        else {
            nd_dprintf(
              "Error while saving flow hash cache: %s\n",
              filename.c_str());
            break;
        }
    }

    nd_dprintf("Saved %u flow hash cache entries.\n", saved);
}
