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

#include <sys/socket.h>
#include <sys/stat.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <ctime>
#include <exception>
#include <iomanip>
#include <list>
#include <map>
#include <mutex>
#include <regex>
#include <sstream>
#include <type_traits>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

#include "nd-except.hpp"
#include "nd-sha1.h"

constexpr unsigned ND_SHA1_BUFFER = 4096;
typedef std::array<uint8_t, SHA1_DIGEST_LENGTH> ndDigest;
typedef std::vector<uint8_t> ndDigestDynamic;

namespace ndTerm {

class Attr
{
public:
    static const char *RESET;
    static const char *CURSOR_HIDE;
    static const char *CURSOR_SHOW;
    static const char *CLEAR_EOL;
    static const char *BOLD;
    static const char *UNDERLINE;
};

class Color
{
public:
    static const char *RED;
    static const char *GREEN;
    static const char *YELLOW;
};

class Icon
{
public:
    static const char *INFO;
    static const char *OK;
    static const char *WARN;
    static const char *FAIL;
    static const char *NOTE;
    static const char *RARROW;
};

bool IsTTY(void);

}  // namespace ndTerm

constexpr const char *_ND_LOG_FILE_STAMP = "%Y%m%d-%H%M%S";
constexpr size_t _ND_LOG_FILE_STAMP_SIZE = sizeof(
  "YYYYMMDD-HHMMSS");

#define ndEnumCast(T, n) \
    static_cast<typename std::underlying_type<T>::type>(T::n)

void *nd_mem_alloc(size_t size);

void nd_mem_free(void *ptr);

class ndLogBuffer : public std::streambuf
{
public:
    int overflow(int ch = EOF);
    virtual int sync();

protected:
    std::ostringstream os;
};

class ndDebugLogBuffer : public ndLogBuffer
{
public:
    virtual int sync();
};

class ndDebugLogBufferUnlocked : public ndLogBuffer
{
public:
    virtual int sync();
};

class ndDebugLogBufferFlow : public ndLogBuffer
{
public:
    virtual int sync();
};

class ndLogStream : public std::ostream
{
public:
    ndLogStream() : std::ostream(new ndLogBuffer) { }

    virtual ~ndLogStream() {
        delete reinterpret_cast<ndLogBuffer *>(rdbuf());
    }
};

class ndDebugLogStream : public std::ostream
{
public:
    enum class Type : uint8_t {
        NONE,
        UNLOCKED,
        FLOW,
    };

    ndDebugLogStream(Type type = Type::NONE)
      : std::ostream((type == Type::NONE) ?
            new ndDebugLogBuffer :
            ((type == Type::UNLOCKED) ?
                reinterpret_cast<std::streambuf *>(new ndDebugLogBufferUnlocked) :
                reinterpret_cast<std::streambuf *>(
                  new ndDebugLogBufferFlow))),
        type(type) {
        imbue(std::locale());
    }

    virtual ~ndDebugLogStream() {
        switch (type) {
        case Type::NONE:
            delete reinterpret_cast<ndDebugLogBuffer *>(rdbuf());
            break;
        case Type::UNLOCKED:
            delete reinterpret_cast<ndDebugLogBufferUnlocked *>(
              rdbuf());
            break;
        case Type::FLOW:
            delete reinterpret_cast<ndDebugLogBufferFlow *>(rdbuf());
            break;
        }
    }

private:
    Type type;
};

class ndLogFormat
{
public:
    enum class Format : uint8_t {
        NONE,
        BYTES,
        PACKETS,
        PERCENT,
    };

    ndLogFormat(Format format, float value, int width = 0,
      int precision = 3)
      : format(format), value(value), width(width),
        precision(precision){};

    friend std::ostream &
    operator<<(std::ostream &os, const ndLogFormat &f) {
        using namespace std;
        ios old_state(nullptr);
        old_state.copyfmt(os);
        os << setw(f.width) << setprecision(f.precision);

        switch (f.format) {
        case Format::BYTES:
            if (f.value >= 1099511627776.0f) {
                os << (f.value / 1099511627776.0f)
                   << setw(0) << " TiB";
            }
            else if (f.value >= 1073741824.0f) {
                os << (f.value / 1073741824.0f) << setw(0) << " GiB";
            }
            else if (f.value >= 1048576.0f) {
                os << (f.value / 1048576.0f) << setw(0) << " MiB";
            }
            else if (f.value >= 1024.0f) {
                os << (f.value / 1024.0f) << setw(0) << " KiB";
            }
            else {
                os << f.value;
            }
            break;

        case Format::PACKETS:
            if (f.value >= 1000000000000.0f) {
                os << (f.value / 1000000000000.0f)
                   << setw(0) << " TP";
            }
            else if (f.value >= 1000000000.0f) {
                os << (f.value / 1000000000.0f) << setw(0) << " GP";
            }
            else if (f.value >= 1000000.0f) {
                os << (f.value / 1000000.0f) << setw(0) << " MP";
            }
            else if (f.value >= 1000.0f) {
                os << (f.value / 1000.0f) << setw(0) << " KP";
            }
            else {
                os << f.value;
            }
            break;

        case Format::PERCENT:
            os << f.value << " "
               << "%";
            break;
        default: os << f.value; break;
        }

        os.copyfmt(old_state);
        return os;
    }

protected:
    const Format format;
    const float value;
    const int width;
    const int precision;
};

void nd_output_lock(void);
void nd_output_unlock(void);

void nd_printf(const char *format, ...);
void nd_printf(const char *format, va_list ap);
void nd_dprintf(const char *format, ...);
void nd_dprintf(const char *format, va_list ap);
void nd_flow_printf(const char *format, ...);

#ifdef _ND_ENABLE_NDPI_DEBUG
void nd_ndpi_debug_printf(uint32_t protocol, void *ndpi,
  ndpi_log_level_t level, const char *file,
  const char *func, unsigned line, const char *format, ...);
#endif

void nd_ltrim(std::string &s, unsigned char c = 0);
void nd_rtrim(std::string &s, unsigned char c = 0);
void nd_trim(std::string &s, unsigned char c = 0);

int nd_sha1_file(const std::string &filename, ndDigest &digest);

void nd_sha1_to_string(const ndDigest &digest,
  std::string &digest_str);
void nd_sha1_to_string(const ndDigestDynamic &digest,
  std::string &digest_str);

bool nd_string_to_sha1(const std::string &digest_str,
  ndDigest &digest);
bool nd_string_to_sha1(const std::string &digest_str,
  ndDigestDynamic &digest);

bool nd_string_to_mac(const std::string &src, uint8_t *mac);
sa_family_t
nd_string_to_ip(const std::string &src, sockaddr_storage *ip);
bool nd_ip_to_string(sa_family_t af, const void *addr,
  std::string &dst);
bool nd_ip_to_string(const sockaddr_storage &ip, std::string &dst);

void nd_json_to_string(const nlohmann::json &j,
  std::string &output, bool pretty = false);

uint8_t nd_netmask_to_prefix(const struct sockaddr_storage *netmask);
uint8_t nd_netmask_to_prefix(const std::string &netmask);

bool nd_is_ipaddr(const char *ip);

void nd_private_ipaddr(uint8_t index, struct sockaddr_storage &addr);

bool nd_load_uuid(std::string &uuid,
  const std::string &path, size_t length);
bool nd_save_uuid(const std::string &uuid,
  const std::string &path, size_t length);

void nd_seed_rng(void);

void nd_generate_uuid(std::string &uuid);

const char *nd_get_version(void);
const std::string &nd_get_version_and_features(bool fancy = false);

bool nd_parse_app_tag(const std::string &tag, unsigned &id,
  std::string &name);

int nd_touch(const std::string &filename);

int nd_file_load(const std::string &filename, std::string &data);

void nd_file_save(const std::string &filename,
  const std::string &data, bool append = false,
  mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP,
  const char *user = NULL, const char *group = NULL);

int nd_ifreq(const std::string &name, unsigned long request,
  struct ifreq *ifr);

void nd_basename(const std::string &path, std::string &base);

pid_t nd_is_running(pid_t pid, const std::string &exe_base);
pid_t nd_load_pid(const std::string &pidfile);
int nd_save_pid(const std::string &pidfile, pid_t pid);

int nd_file_exists(const std::string &path);
int nd_dir_exists(const std::string &path);

void nd_uptime(time_t ut, std::string &uptime);

int nd_functions_exec(const std::string &func,
  const std::string &arg, std::string &output);

void nd_os_detect(std::string &os);

class ndLogDirectory
{
public:
    ndLogDirectory(const std::string &path, const std::string &prefix,
      const std::string &suffix, bool overwrite = false);
    virtual ~ndLogDirectory();

    FILE *Open(const std::string &ext = "");
    void Close(void);
    void Discard(void);

protected:
    std::string path;
    std::string prefix;
    std::string suffix;

    bool overwrite;

    FILE *hf_cur;
    std::string filename;
};

void nd_regex_error(const std::regex_error &e, std::string &error);

bool nd_scan_dotd(const std::string &path,
  std::vector<std::string> &files);

void nd_set_hostname(std::string &dst, bool strict = true);
void nd_set_hostname(std::string &dst, const char *src,
  size_t length, bool strict = true);
void nd_set_hostname(char *dst, const char *src,
  size_t length, bool strict = true);

void nd_expand_variables(const std::string &input,
  std::string &output, std::map<std::string, std::string> &vars);

void nd_gz_inflate(size_t length, const uint8_t *data,
  std::vector<uint8_t> &output);
void nd_gz_deflate(size_t length, const uint8_t *data,
  std::vector<uint8_t> &output);

class ndTimer
{
public:
    ndTimer(void) : sig(-1), valid(false), id(nullptr) { }
    virtual ~ndTimer() { Reset(); }

    void Create(int sig);
    void Reset(void);

    void Set(const struct itimerspec &itspec);

    inline bool IsValid(void) const { return valid; }
    inline int GetSignal(void) const { return sig; }

protected:
    int sig;
    bool valid;
    timer_t id;
};

void nd_get_ip_protocol_name(int protocol, std::string &result);

int nd_glob(const std::string &pattern,
  std::vector<std::string> &results);

time_t nd_time_monotonic(void);

void nd_tmpfile(const std::string &prefix, std::string &filename);

bool nd_copy_file(const std::string &src, const std::string &dst,
  mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP);

void nd_time_ago(time_t seconds, std::string &ago);

template <typename K, typename V = K>
class ndLRUCache
{
public:
    class CacheStats
    {
    public:
        std::atomic<uint64_t> insert_hit = { 0 };
        std::atomic<uint64_t> insert_miss = { 0 };
        std::atomic<uint64_t> lookup_hit = { 0 };
        std::atomic<uint64_t> lookup_miss = { 0 };
    };

    CacheStats stats;

    ndLRUCache(size_t max_size, bool lockable = false)
      : max_size(max_size), lockable(lockable) {
        if (! max_size)
            throw ndException(
              "maxiumum LRU cache size cannot be zero");
    }

    size_t GetSize(void) const {
        if (lockable) {
            std::lock_guard<std::mutex> lg(lock);
            return kvmap.size();
        }
        return kvmap.size();
    }

    void Encode(nlohmann::json &jstats) const {
        size_t cache_size = 0;

        if (lockable) {
            std::lock_guard<std::mutex> lg(lock);
            cache_size = kvmap.size();
        }

        uint64_t insert_hit = stats.insert_hit;
        uint64_t insert_miss = stats.insert_miss;
        uint64_t insert_total = insert_hit + insert_miss;

        float insert_hit_pct = 0;
        if (insert_total > 0) {
            insert_hit_pct = 100.0f * (float)insert_hit /
              (float)insert_total;
        }

        uint64_t lookup_hit = stats.lookup_hit;
        uint64_t lookup_miss = stats.lookup_miss;
        uint64_t lookup_total = lookup_hit + lookup_miss;

        float lookup_hit_pct = 0;
        if (lookup_total > 0) {
            lookup_hit_pct = 100.0f * (float)lookup_hit /
              (float)lookup_total;
        }

        jstats["cache_size"] = cache_size;
        jstats["insert_hit"] = insert_hit;
        jstats["insert_hit_pct"] = insert_hit_pct;
        jstats["insert_miss"] = insert_miss;
        jstats["lookup_hit"] = lookup_hit;
        jstats["lookup_hit_pct"] = lookup_hit_pct;
        jstats["lookup_miss"] = lookup_miss;
    }

    void Scoreboard(const std::string &tag) const {
        size_t cache_size = 0;
        uint64_t insert_hit = 0;
        float insert_hit_pct = 0.0;
        uint64_t insert_miss = 0;
        uint64_t insert_total = 0;
        uint64_t lookup_hit = 0;
        float lookup_hit_pct = 0;
        uint64_t lookup_miss = 0;
        uint64_t lookup_total = 0;

        try {
            nlohmann::json jstats;
            Encode(jstats);

            cache_size = jstats["cache_size"].get<unsigned>();
            insert_hit = jstats["insert_hit"].get<uint64_t>();
            insert_hit_pct = jstats["insert_hit_pct"].get<float>();
            insert_miss = jstats["insert_miss"].get<uint64_t>();
            insert_total = insert_hit + insert_miss;
            lookup_hit = jstats["lookup_hit"].get<uint64_t>();
            lookup_hit_pct = jstats["lookup_hit_pct"].get<float>();
            lookup_miss = jstats["lookup_miss"].get<uint64_t>();
            lookup_total = lookup_hit + lookup_miss;
        }
        catch (nlohmann::json::exception &e) {
            nd_dprintf(
              "%s: error decoding JSON status: %s\n",
              tag.c_str(), e.what());
            return;
        }

        nd_dprintf(
          "%s entries: %lu, inserts: %lu (%.01f%%), "
          "lookups: %lu (%.01f%%)\n",
          tag.c_str(), cache_size, insert_total,
          insert_hit_pct, lookup_total, lookup_hit_pct);
    }

protected:
    void CacheInsert(const K &key, const V &value,
      bool update = false) {
        std::unique_lock<std::mutex> lg(lock, std::defer_lock);

        if (lockable) lg.lock();

        auto i = kvmap.find(key);
        if (i == kvmap.end()) {
            stats.insert_miss++;

            entries.push_front(key);
            kvmap[key] = { value, entries.begin() };

            while (kvmap.size() > max_size) {
                kvmap.erase(entries.back());
                entries.pop_back();
            }
        }
        else {
            stats.insert_hit++;

            entries.erase(i->second.second);
            entries.push_front(key);

            i->second.second = entries.begin();
            if (update) i->second.first = value;
        }
    }

    bool CacheLookup(const K key, V &value) {
        std::unique_lock<std::mutex> lg(lock, std::defer_lock);

        if (lockable) lg.lock();

        auto i = kvmap.find(key);
        if (i == kvmap.end()) {
            stats.lookup_miss++;
            return false;
        }

        stats.lookup_hit++;

        entries.erase(i->second.second);
        entries.push_front(key);

        i->second.second = entries.begin();

        value = i->second.first;

        return true;
    }

    size_t max_size;
    bool lockable;

    mutable std::mutex lock;

    std::list<K> entries;
    std::unordered_map<K, std::pair<V, typename std::list<K>::iterator>> kvmap;
};

struct ndEnumHasher {
    template <class T>
    inline void hash_combine(size_t &seed, const T &v) const {
        std::hash<T> hasher;
        seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    }

    template <class T>
    size_t operator()(const T &v) const {
        size_t ss_hash = 0;

        hash_combine<unsigned>(ss_hash, static_cast<unsigned>(v));

        return ss_hash;
    }
};
