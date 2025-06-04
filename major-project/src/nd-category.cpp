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

#include <fstream>

#include "nd-category.hpp"
#include "nd-config.hpp"
#include "nd-except.hpp"
#include "nd-util.hpp"
#include "netifyd.hpp"

using namespace std;
using json = nlohmann::json;

// #define _ND_LOG_DOMAINS   1

typedef radix_tree<ndRadixNetworkEntry<_ND_ADDR_BITSv4>, nd_cat_id_t> nd_rn4_cat;
typedef radix_tree<ndRadixNetworkEntry<_ND_ADDR_BITSv6>, nd_cat_id_t> nd_rn6_cat;

ndCategories::ndCategories()
  : networks4(nullptr), networks6(nullptr) {
    categories.emplace(Type::APP, ndCategory());
    categories.emplace(Type::PROTO, ndCategory());
}

ndCategories::~ndCategories() {
    ResetNetworks();
}

void ndCategories::ResetCategories(void) {
    for (auto &ci : categories) {
        ci.second.tag.clear();
        ci.second.index.clear();
    }
}

void ndCategories::ResetDomains(void) {
    domains.clear();
}

void ndCategories::ResetNetworks(bool free_only) {
    if (networks4 != nullptr) {
        nd_rn4_cat *rn4 = static_cast<nd_rn4_cat *>(networks4);
        delete rn4;
        networks4 = nullptr;
    }

    if (networks6 != nullptr) {
        nd_rn6_cat *rn6 = static_cast<nd_rn6_cat *>(networks6);
        delete rn6;
        networks6 = nullptr;
    }

    if (! free_only) {
        nd_rn4_cat *rn4 = new nd_rn4_cat;
        nd_rn6_cat *rn6 = new nd_rn6_cat;

        networks4 = static_cast<void *>(rn4);
        networks6 = static_cast<void *>(rn6);
    }
}

bool ndCategories::Load(const string &filename) {
    lock_guard<mutex> ul(lock);

    json jdata;

    ifstream ifs(filename);
    if (! ifs.is_open()) {
        nd_printf("Error opening categories: %s: %s\n",
          filename.c_str(), strerror(ENOENT));
        return false;
    }

    try {
        ifs >> jdata;
    }
    catch (exception &e) {
        nd_printf(
          "Error loading categories: %s: JSON parse "
          "error\n",
          filename.c_str());
        nd_dprintf("%s: %s\n", filename.c_str(), e.what());

        return false;
    }

    if (jdata.find("application_tag_index") == jdata.end() ||
      jdata.find("protocol_tag_index") == jdata.end())
    {
        nd_dprintf("legacy category format detected: %s\n",
          filename.c_str());
        return LoadLegacy(jdata);
    }

    ResetCategories();

    for (auto &ci : categories) {
        string key;

        switch (ci.first) {
        case Type::APP: key = "application"; break;
        case Type::PROTO: key = "protocol"; break;
        default: break;
        }

        if (! key.empty()) {
            ci.second.tag =
              jdata[key + "_tag_index"].get<ndCategory::index_tag>();
            ci.second.index =
              jdata[key + "_index"].get<ndCategory::index_cat>();
        }
    }

    return true;
}

bool ndCategories::LoadLegacy(const json &jdata) {

    ResetCategories();

    for (auto &ci : categories) {
        string key;
        nd_cat_id_t id = 1;

        switch (ci.first) {
        case Type::APP: key = "application"; break;
        case Type::PROTO: key = "protocol"; break;
        default: break;
        }

        auto it = jdata.find(key + "_index");
        for (auto &it_kvp : it->get<json::object_t>()) {
            if (it_kvp.second.type() != json::value_t::array)
                continue;

            ci.second.tag[it_kvp.first] = id;
            ci.second.index[id] =
              it_kvp.second.get<ndCategory::set_id>();

            id++;
        }
    }

    return true;
}

bool ndCategories::Load(Type type, json &jdata) {
    lock_guard<mutex> ul(lock);

    auto ci = categories.find(type);

    if (ci == categories.end()) {
        nd_dprintf("%s: category type not found: %u\n",
          __PRETTY_FUNCTION__, type);
        return false;
    }

    string key;

    switch (type) {
    case Type::APP: key = "application_category"; break;
    case Type::PROTO: key = "protocol_category"; break;
    default: break;
    }

    for (auto it = jdata.begin(); it != jdata.end(); it++) {
        auto it_cat = it->find(key);
        if (it_cat == it->end()) continue;

        nd_cat_id_t id = (*it)["id"].get<unsigned>();
        nd_cat_id_t cid = (*it_cat)["id"].get<nd_cat_id_t>();
        string tag = (*it_cat)["tag"].get<string>();

        auto it_tag_id = ci->second.tag.find(tag);

        if (it_tag_id == ci->second.tag.end())
            ci->second.tag[tag] = cid;

        auto it_entry = ci->second.index.find(cid);

        if (it_entry == ci->second.index.end())
            ci->second.index.insert(
              ndCategory::index_cat_insert(cid, { id }));
        else it_entry->second.insert(id);
    }

    return true;
}

bool ndCategories::Save(const string &filename) {
    lock_guard<mutex> ul(lock);

    json j;

    try {
        j["last_update"] = time(nullptr);

        for (auto &ci : categories) {
            switch (ci.first) {
            case Type::APP:
                j["application_tag_index"] = ci.second.tag;
                j["application_index"] = ci.second.index;
                break;
            case Type::PROTO:
                j["protocol_tag_index"] = ci.second.tag;
                j["protocol_index"] = ci.second.index;
                break;
            default: break;
            }
        }
    }
    catch (exception &e) {
        nd_printf("Error JSON encoding categories: %s\n",
          filename.c_str());
        nd_dprintf("%s: %s\n", filename.c_str(), e.what());

        return false;
    }

    ofstream ofs(filename);

    if (! ofs.is_open()) {
        nd_printf("Error opening categories: %s: %s\n",
          filename.c_str(), strerror(ENOENT));
        return false;
    }

    try {
        ofs << j;
    }
    catch (exception &e) {
        nd_printf(
          "Error saving categories: %s: JSON parse error\n",
          filename.c_str());
        nd_dprintf("%s: %s\n", filename.c_str(), e.what());

        return false;
    }

    return true;
}

void ndCategories::Dump(Type type) {
    lock_guard<mutex> ul(lock);

    for (auto &ci : categories) {
        if (type != Type::MAX && ci.first != type) continue;

        for (auto &li : ci.second.tag) {
            if (type != Type::MAX)
                printf("%6u: %s\n", li.second, li.first.c_str());
            else {
                string tag("unknown");

                switch (ci.first) {
                case Type::APP: tag = "application"; break;
                case Type::PROTO: tag = "protocol"; break;
                default: break;
                }

                printf("%6u: %s: %s\n", li.second,
                  tag.c_str(), li.first.c_str());
            }
        }
    }
}

bool ndCategories::IsMember(Type type, nd_cat_id_t cat_id,
  unsigned id) {
    lock_guard<mutex> ul(lock);
    auto ci = categories.find(type);

    if (ci == categories.end()) {
        nd_dprintf("%s: category type not found: %u\n",
          __PRETTY_FUNCTION__, type);
        return false;
    }

    auto mi = ci->second.index.find(cat_id);

    if (mi == ci->second.index.end()) return false;

    if (mi->second.find(id) == mi->second.end())
        return false;

    return true;
}

bool ndCategories::IsMember(Type type,
  const string &cat_tag, unsigned id) {
    lock_guard<mutex> ul(lock);
    auto ci = categories.find(type);

    if (ci == categories.end()) {
        nd_dprintf("%s: category type not found: %u\n",
          __PRETTY_FUNCTION__, type);
        return false;
    }

    auto ti = ci->second.tag.find(cat_tag);

    if (ti == ci->second.tag.end()) return false;

    auto mi = ci->second.index.find(ti->second);

    if (mi == ci->second.index.end()) return false;

    if (mi->second.find(id) == mi->second.end())
        return false;

    return true;
}

nd_cat_id_t ndCategories::Lookup(Type type, unsigned id) const {
    lock_guard<mutex> ul(lock);

    const auto index = categories.find(type);
    if (index == categories.end()) return ND_CAT_UNKNOWN;

    for (const auto &it : index->second.index) {
        if (it.second.find(id) == it.second.end()) continue;
        return it.first;
    }

    return ND_CAT_UNKNOWN;
}

nd_cat_id_t
ndCategories::LookupTag(Type type, const string &tag) const {
    lock_guard<mutex> ul(lock);

    const auto &index = categories.find(type);
    if (index == categories.end()) return ND_CAT_UNKNOWN;

    const auto &it = index->second.tag.find(tag);
    if (it != index->second.tag.end()) return it->second;

    return ND_CAT_UNKNOWN;
}

nd_cat_id_t ndCategories::ResolveTag(Type type, unsigned id,
  string &tag) const {
    nd_cat_id_t cat_id = Lookup(type, id);
    if (cat_id == ND_CAT_UNKNOWN) return ND_CAT_UNKNOWN;

    lock_guard<mutex> ul(lock);

    const auto &index = categories.find(type);

    if (index == categories.end()) return cat_id;

    for (const auto &i : index->second.tag) {
        if (i.second != cat_id) continue;
        tag = i.first;
        break;
    }

    return cat_id;
}

bool ndCategories::GetTag(Type type, nd_cat_id_t id,
  string &tag) const {
    lock_guard<mutex> ul(lock);

    auto ci = categories.find(type);
    if (ci == categories.end()) return false;

    for (auto &i : ci->second.tag) {
        if (i.second != id) continue;
        tag = i.first;
        return true;
    }

    return false;
}

bool ndCategories::LoadDotDirectory(const string &path) {
    lock_guard<mutex> ul(lock);

    auto it_apps = categories.find(Type::APP);
    if (it_apps == categories.end()) return false;

    vector<string> files;
    // /etc/netifyd/categories.d/10-adult.conf
    // /etc/netifyd/categories.d/{pri}-{cat_tag}.conf
    if (! nd_scan_dotd(path, files) || files.empty())
        return true;

    ResetDomains();
    ResetNetworks(false);

    for (auto &it : files) {
        size_t p1 = it.find_first_of("-");
        if (p1 == string::npos) {
            nd_dprintf(
              "Rejecting category file (wrong format; "
              "missing hyphen): %s\n",
              it.c_str());
            continue;
        }

        size_t p2 = it.find_last_of(".");
        if (p2 == string::npos) {
            nd_dprintf(
              "Rejecting category file (wrong format; "
              "missing extension): %s\n",
              it.c_str());
            continue;
        }

        string cat_tag = it.substr(p1 + 1, p2 - p1 - 1);

        auto tag = it_apps->second.tag.find(cat_tag);
        if (tag == it_apps->second.tag.end()) {
            nd_dprintf(
              "Rejecting category file (invalid category "
              "tag): ",
              it.c_str());
            continue;
        }

        nd_dprintf("Loading %s category file: %s\n",
          tag->first.c_str(), it.c_str());

        ifstream ifs(path + "/" + it);

        if (! ifs.is_open()) {
            nd_printf("Error opening category file: %s\n",
              it.c_str());
            continue;
        }

        string line;
        uint32_t networks = 0;
        unordered_set<string> entries;

        while (getline(ifs, line)) {
            nd_ltrim(line);
            if (line.empty() || line[0] == '#') continue;

            size_t p;
            if ((p = line.find_first_of(":")) == string::npos)
                continue;

            string type = line.substr(0, p);
            if (type == "dom")
                entries.insert(line.substr(p + 1));
            else if (type == "net") {
                ndAddr addr(line.substr(p + 1));

                if (! addr.IsValid() || ! addr.IsIP()) {
                    nd_printf(
                      "Invalid IPv4/6 network address: "
                      "%s: %s\n",
                      it.c_str(), line.substr(p + 1).c_str());
                    continue;
                }

                try {
                    if (addr.IsIPv4()) {
                        ndRadixNetworkEntry<_ND_ADDR_BITSv4> entry;
                        if (ndRadixNetworkEntry<_ND_ADDR_BITSv4>::Create(
                              entry, addr))
                        {
                            nd_rn4_cat *rn4 =
                              static_cast<nd_rn4_cat *>(networks4);
                            (*rn4)[entry] = tag->second;
                            networks++;
                        }
                    }
                    else {
                        ndRadixNetworkEntry<_ND_ADDR_BITSv6> entry;
                        if (ndRadixNetworkEntry<_ND_ADDR_BITSv6>::Create(
                              entry, addr))
                        {
                            nd_rn6_cat *rn6 =
                              static_cast<nd_rn6_cat *>(networks6);
                            (*rn6)[entry] = tag->second;
                            networks++;
                        }
                    }
                }
                catch (runtime_error &e) {
                    nd_dprintf(
                      "Error adding network: %s: %s: %s\n",
                      it.c_str(),
                      line.substr(p + 1).c_str(), e.what());
                }
            }
            else if (type == "rxp") {
                try {
                    rxps.emplace(tag->second,
                      regex(line.substr(p + 1),
                        regex::extended | regex::icase |
                          regex::optimize));
                }
                catch (const regex_error &e) {
                    string error;
                    nd_regex_error(e, error);
                    nd_printf(
                      "WARNING: Error compiling category "
                      "regex: %s: %s [%d]\n",
                      line.substr(p + 1).c_str(),
                      error.c_str(), e.code());
                }
            }
        }

        if (! entries.empty()) {
            domains.insert(make_pair(tag->second, entries));

            nd_dprintf(
              "Loaded %u %s domains from category "
              "file: %s\n",
              entries.size(), tag->first.c_str(), it.c_str());
        }

        if (networks) {
            nd_dprintf(
              "Loaded %u %s networks from category "
              "file: %s\n",
              networks, tag->first.c_str(), it.c_str());
        }
    }

    return true;
}

nd_cat_id_t ndCategories::LookupDotDirectory(const string &domain) {
    lock_guard<mutex> ul(lock);

    for (auto &it : rxps) {
        if (regex_match(domain, it.second)) return it.first;
    }

    string search(domain);
    size_t p = string::npos;

    do {
        for (auto &it : domains) {
#ifdef _ND_LOG_DOMAINS
            nd_dprintf(
              "%s: searching category %hu for: %s\n",
              __PRETTY_FUNCTION__, it.first, search.c_str());
#endif
            if (it.second.find(search) != it.second.end()) {
#ifdef _ND_LOG_DOMAINS
                nd_dprintf("%s: found: %s\n",
                  __PRETTY_FUNCTION__, search.c_str());
#endif
                return it.first;
            }
        }

        if ((p = search.find_first_of(".")) != string::npos)
            search = search.substr(p + 1);
    }
    while (search.size() && p != string::npos);

    return ND_CAT_UNKNOWN;
}

nd_cat_id_t ndCategories::LookupDotDirectory(const ndAddr &addr) {
    lock_guard<mutex> ul(lock);

    if (addr.IsIPv4()) {
        nd_rn4_cat *rn = static_cast<nd_rn4_cat *>(networks4);

        ndRadixNetworkEntry<_ND_ADDR_BITSv4> entry;
        if (rn != nullptr &&
          ndRadixNetworkEntry<_ND_ADDR_BITSv4>::CreateQuery(entry, addr))
        {
            nd_rn4_cat::iterator it;
            if ((it = rn->longest_match(entry)) != rn->end())
                return it->second;
        }
    }
    else if (addr.IsIPv6()) {
        nd_rn6_cat *rn = static_cast<nd_rn6_cat *>(networks6);

        ndRadixNetworkEntry<_ND_ADDR_BITSv6> entry;
        if (rn != nullptr &&
          ndRadixNetworkEntry<_ND_ADDR_BITSv6>::CreateQuery(entry, addr))
        {
            nd_rn6_cat::iterator it;
            if ((it = rn->longest_match(entry)) != rn->end())
                return it->second;
        }
    }

    return ND_CAT_UNKNOWN;
}
