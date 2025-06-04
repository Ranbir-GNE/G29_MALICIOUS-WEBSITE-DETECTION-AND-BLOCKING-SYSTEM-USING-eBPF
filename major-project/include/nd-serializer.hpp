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
#include <vector>

#include <nlohmann/json.hpp>

#include "nd-risks.hpp"

class ndSerializer
{
public:
    inline void serialize(nlohmann::json &j,
      const std::vector<std::string> &keys,
      const nlohmann::json &value) const {
        if (keys.empty() || value.empty()) return;
        if (keys.size() == 2) j[keys[0]][keys[1]] = value;
        if (keys.size() == 1) j[keys[0]] = value;
    }

    inline void serialize(nlohmann::json &j,
      const std::vector<std::string> &keys,
      const std::string &value) const {
        if (keys.empty() || value.empty()) return;
        if (keys.size() == 2) j[keys[0]][keys[1]] = value;
        if (keys.size() == 1) j[keys[0]] = value;
    }

    inline void serialize(nlohmann::json &j,
      const std::vector<std::string> &keys, uint8_t value) const {
        if (keys.empty()) return;
        if (keys.size() == 2) j[keys[0]][keys[1]] = value;
        if (keys.size() == 1) j[keys[0]] = value;
    }

    inline void serialize(nlohmann::json &j,
      const std::vector<std::string> &keys, uint16_t value) const {
        if (keys.empty()) return;
        if (keys.size() == 2) j[keys[0]][keys[1]] = value;
        if (keys.size() == 1) j[keys[0]] = value;
    }

    inline void serialize(nlohmann::json &j,
      const std::vector<std::string> &keys, uint32_t value) const {
        if (keys.empty()) return;
        if (keys.size() == 2) j[keys[0]][keys[1]] = value;
        if (keys.size() == 1) j[keys[0]] = value;
    }

    inline void serialize(nlohmann::json &j,
      const std::vector<std::string> &keys, uint64_t value) const {
        if (keys.empty()) return;
        if (keys.size() == 2) j[keys[0]][keys[1]] = value;
        if (keys.size() == 1) j[keys[0]] = value;
    }

    inline void serialize(nlohmann::json &j,
      const std::vector<std::string> &keys, bool value) const {
        if (keys.empty()) return;
        if (keys.size() == 2) j[keys[0]][keys[1]] = value;
        if (keys.size() == 1) j[keys[0]] = value;
    }

    inline void serialize(nlohmann::json &j,
      const std::vector<std::string> &keys, const char *value) const {
        if (keys.empty()) return;
        if (keys.size() == 2) j[keys[0]][keys[1]] = value;
        if (keys.size() == 1) j[keys[0]] = value;
    }

    inline void serialize(nlohmann::json &j,
      const std::vector<std::string> &keys, double value) const {
        if (keys.empty()) return;
        if (keys.size() == 2) j[keys[0]][keys[1]] = value;
        if (keys.size() == 1) j[keys[0]] = value;
    }

    inline void serialize(nlohmann::json &j,
      const std::vector<std::string> &keys, time_t value) const {
        if (keys.empty()) return;
        if (keys.size() == 2) j[keys[0]][keys[1]] = value;
        if (keys.size() == 1) j[keys[0]] = value;
    }

    inline void serialize(nlohmann::json &j,
      const std::vector<std::string> &keys,
      const std::vector<ndRisk::Id> &values) const {
        if (keys.empty() || values.empty()) return;
        if (keys.size() == 2) j[keys[0]][keys[1]] = values;
        if (keys.size() == 1) j[keys[0]] = values;
    }

    inline void serialize(nlohmann::json &j,
      const std::vector<std::string> &keys,
      const std::vector<unsigned> &values) const {
        if (keys.empty() || values.empty()) return;
        if (keys.size() == 2) j[keys[0]][keys[1]] = values;
        if (keys.size() == 1) j[keys[0]] = values;
    }

    inline void serialize(nlohmann::json &j,
      const std::vector<std::string> &keys,
      const std::vector<std::string> &values,
      const std::string &delim = "") const {
        if (keys.empty() || values.empty()) return;
        if (keys.size() == 2) j[keys[0]][keys[1]] = values;
        if (keys.size() == 1) j[keys[0]] = values;
    }

    inline void serialize(nlohmann::json &j,
      const std::vector<std::string> &keys,
      const std::unordered_map<std::string, std::string> &values) const {
        if (keys.empty() || values.empty()) return;
        if (keys.size() == 2) j[keys[0]][keys[1]] = values;
        if (keys.size() == 1) j[keys[0]] = values;
    }

    inline void serialize(std::vector<std::string> &v,
      const std::vector<std::string> &keys,
      const std::string &value) const {
        if (keys.empty() || value.empty()) return;
        std::string key;
        for (auto &k : keys)
            key.append(key.empty() ? k : std::string(":") + k);
        v.push_back(key);
        v.push_back(value);
    }

    inline void serialize(std::vector<std::string> &v,
      const std::vector<std::string> &keys,
      uint8_t value) const {
        if (keys.empty()) return;
        std::string key;
        for (auto &k : keys)
            key.append(key.empty() ? k : std::string(":") + k);
        v.push_back(key);
        v.push_back(std::to_string(value));
    }

    inline void serialize(std::vector<std::string> &v,
      const std::vector<std::string> &keys,
      uint16_t value) const {
        if (keys.empty()) return;
        std::string key;
        for (auto &k : keys)
            key.append(key.empty() ? k : std::string(":") + k);
        v.push_back(key);
        v.push_back(std::to_string(value));
    }

    inline void serialize(std::vector<std::string> &v,
      const std::vector<std::string> &keys,
      uint32_t value) const {
        if (keys.empty()) return;
        std::string key;
        for (auto &k : keys)
            key.append(key.empty() ? k : std::string(":") + k);
        v.push_back(key);
        v.push_back(std::to_string(value));
    }

    inline void serialize(std::vector<std::string> &v,
      const std::vector<std::string> &keys,
      uint64_t value) const {
        if (keys.empty()) return;
        std::string key;
        for (auto &k : keys)
            key.append(key.empty() ? k : std::string(":") + k);
        v.push_back(key);
        v.push_back(std::to_string(value));
    }

    inline void serialize(std::vector<std::string> &v,
      const std::vector<std::string> &keys,
      bool value) const {
        if (keys.empty()) return;
        std::string key;
        for (auto &k : keys)
            key.append(key.empty() ? k : std::string(":") + k);
        v.push_back(key);
        v.push_back(std::to_string(value));
    }

    inline void serialize(std::vector<std::string> &v,
      const std::vector<std::string> &keys,
      const char *value) const {
        if (keys.empty()) return;
        std::string key;
        for (auto &k : keys)
            key.append(key.empty() ? k : std::string(":") + k);
        v.push_back(key);
        v.push_back(value);
    }

    inline void serialize(std::vector<std::string> &v,
      const std::vector<std::string> &keys,
      const std::vector<unsigned> &values) const {
        if (keys.empty() || values.empty()) return;
        std::string key;
        for (auto &k : keys)
            key.append(key.empty() ? k : std::string(":") + k);
        v.push_back(key);
        std::string _values;
        for (auto &value : values)
            _values.append(_values.empty() ?
                std::to_string(value) :
                std::string(",") + std::to_string(value));
        v.push_back(_values);
    }

    inline void serialize(std::vector<std::string> &v,
      const std::vector<std::string> &keys,
      const std::vector<ndRisk::Id> &values) const {
        if (keys.empty() || values.empty()) return;
        std::string key;
        for (auto &k : keys)
            key.append(key.empty() ? k : std::string(":") + k);
        v.push_back(key);
        std::string _values;
        for (auto &value : values)
            _values.append(_values.empty() ?
                std::to_string(static_cast<unsigned>(value)) :
                std::string(",") +
                  std::to_string(static_cast<unsigned>(value)));
        v.push_back(_values);
    }

    inline void serialize(std::vector<std::string> &v,
      const std::vector<std::string> &keys,
      const std::vector<std::string> &values,
      const std::string &delim = ",") const {
        if (values.empty()) return;
        if (! keys.empty()) {
            std::string key;
            for (auto &k : keys)
                key.append(key.empty() ? k : std::string(":") + k);
            v.push_back(key);
        }
        if (delim.empty()) {
            for (auto &i : values) v.push_back(i);
        }
        else {
            v.push_back(values.empty() ?
                std::string() :
                accumulate(++values.begin(), values.end(),
                  *values.begin(),
                  [delim](const std::string &a, const std::string &b) {
                return a + delim + b;
                }));
        }
    }

    inline void serialize(std::vector<std::string> &v,
      const std::vector<std::string> &keys,
      const std::unordered_map<std::string, std::string> &values) const {
        if (keys.empty() || values.empty()) return;
        std::string key;
        for (auto &k : keys)
            key.append(key.empty() ? k : std::string(":") + k);
        v.push_back(key);

        std::vector<std::string> _values;
        for (auto &v : values)
            _values.push_back(v.first + ":" + v.second);
        v.push_back(_values.empty() ?
            std::string() :
            accumulate(++_values.begin(), _values.end(),
              *_values.begin(),
              [](const std::string &a, const std::string &b) {
            return a + "," + b;
            }));
    }
};
