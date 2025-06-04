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
#include <mutex>
#include <nlohmann/json.hpp>
#include <set>
#include <string>
#include <unordered_set>

#include "nd-addr.hpp"

#define ND_CAT_UNKNOWN 0

typedef unsigned nd_cat_id_t;

class ndCategory;

class ndCategories
{
public:
    enum class Type : uint8_t { NONE, APP, PROTO, MAX };

    ndCategories();
    virtual ~ndCategories();

    bool Load(const std::string &filename);
    bool Load(Type type, nlohmann::json &jdata);
    bool Save(const std::string &filename);
    void Dump(Type type = Type::MAX);

    bool LoadDotDirectory(const std::string &path);

    bool IsMember(Type type, nd_cat_id_t cat_id, unsigned id);
    bool IsMember(Type type, const std::string &cat_tag, unsigned id);

    nd_cat_id_t Lookup(Type type, unsigned id) const;
    nd_cat_id_t LookupTag(Type type, const std::string &tag) const;
    nd_cat_id_t
    ResolveTag(Type type, unsigned id, std::string &tag) const;

    bool GetTag(Type type, nd_cat_id_t id, std::string &tag) const;

    nd_cat_id_t LookupDotDirectory(const std::string &domain);
    nd_cat_id_t LookupDotDirectory(const ndAddr &addr);

protected:
    mutable std::mutex lock;

    typedef std::map<Type, ndCategory> cat_map;
    cat_map categories;

    typedef std::unordered_map<nd_cat_id_t, std::unordered_set<std::string>> cat_domain_map;
    cat_domain_map domains;

    typedef std::unordered_map<nd_cat_id_t, std::regex> cat_rx_map;
    cat_rx_map rxps;

    bool LoadLegacy(const nlohmann::json &jdata);

    void ResetCategories(void);
    inline void ResetDomains(void);
    void ResetNetworks(bool free_only = true);

private:
    void *networks4, *networks6;
};

class ndCategory
{
public:
    typedef std::map<std::string, nd_cat_id_t> index_tag;
    typedef std::set<unsigned> set_id;
    typedef std::map<nd_cat_id_t, set_id> index_cat;
    typedef std::pair<nd_cat_id_t, set_id> index_cat_insert;

protected:
    friend class ndCategories;

    index_tag tag;
    index_cat index;

    ndCategories::Type type;
};
