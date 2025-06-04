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

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <glob.h>
#include <grp.h>
#include <libgen.h>
#include <math.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#if defined(__FreeBSD__)
#include <sys/sysctl.h>
#include <sys/user.h>
#endif
#include <syslog.h>
#include <unistd.h>
#include <zlib.h>

#include <array>
#include <csignal>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include "nd-config.hpp"
#include "nd-except.hpp"
#include "nd-util.hpp"
#include "netifyd.hpp"

using namespace std;
using json = nlohmann::json;

static mutex nd_printf_mutex;

const bool nd_isatty = (isatty(STDOUT_FILENO) == 1 &&
  isatty(STDERR_FILENO) == 1);

const char *ndTerm::Color::RED =
  (nd_isatty) ? "\033[0;31m" : "";
const char *ndTerm::Color::GREEN =
  (nd_isatty) ? "\033[0;32m" : "";
const char *ndTerm::Color::YELLOW =
  (nd_isatty) ? "\033[0;33m" : "";

const char *ndTerm::Attr::RESET = (nd_isatty) ? "\033[0m" : "";
const char *ndTerm::Attr::CURSOR_HIDE =
  (nd_isatty) ? "\033[?25l" : "";
const char *ndTerm::Attr::CURSOR_SHOW =
  (nd_isatty) ? "\033[?25h" : "";
const char *ndTerm::Attr::CLEAR_EOL =
  (nd_isatty) ? "\033[0K" : "";
const char *ndTerm::Attr::BOLD =
  (nd_isatty) ? "\033[1m" : "";
const char *ndTerm::Attr::UNDERLINE =
  (nd_isatty) ? "\033[4m" : "";

const char *ndTerm::Icon::INFO = "•";
const char *ndTerm::Icon::OK = "✓";
const char *ndTerm::Icon::WARN = "!";
const char *ndTerm::Icon::FAIL = "✗";
const char *ndTerm::Icon::NOTE = "↪";
const char *ndTerm::Icon::RARROW = "→";

bool ndTerm::IsTTY(void) {
    return nd_isatty;
}

void *nd_mem_alloc(size_t size) {
    return malloc(size);
}

void nd_mem_free(void *ptr) {
    free(ptr);
}

void nd_output_lock(void) {
    nd_printf_mutex.lock();
}

void nd_output_unlock(void) {
    nd_printf_mutex.unlock();
}

void nd_printf(const char *format, ...) {
    if (ndGC_QUIET) return;

    va_list ap;
    va_start(ap, format);
    nd_printf(format, ap);
    va_end(ap);
}

void nd_printf(const char *format, va_list ap) {
    if (ndGC_QUIET) return;

    lock_guard<mutex> lock(nd_printf_mutex);

    vsyslog(LOG_DAEMON | LOG_INFO, format, ap);
}

void nd_dprintf(const char *format, ...) {
    if (! ndGC_DEBUG) return;

    va_list ap;
    va_start(ap, format);
    nd_dprintf(format, ap);
    va_end(ap);
}

void nd_dprintf(const char *format, va_list ap) {
    if (! ndGC_DEBUG) return;

    lock_guard<mutex> lock(nd_printf_mutex);

    vfprintf(stderr, format, ap);
}

void nd_flow_printf(const char *format, ...) {
    lock_guard<mutex> lock(nd_printf_mutex);

    va_list ap;
    va_start(ap, format);
    vfprintf(ndGC.h_flow, format, ap);
    va_end(ap);
}

#ifdef _ND_ENABLE_NDPI_DEBUG
void nd_ndpi_debug_printf(uint32_t protocol, void *ndpi,
  ndpi_log_level_t level, const char *file,
  const char *func, unsigned line, const char *format, ...) {
    if (ndGC_DEBUG && (ndGC_DEBUG_NDPI || level == NDPI_LOG_ERROR))
    {
        lock_guard<mutex> lock(nd_printf_mutex);

        va_list ap;
        va_start(ap, format);

        fprintf(stdout,
          "[nDPI:%08x:%p:%s]: %s/%s:%d: ", protocol, ndpi,
          (level == NDPI_LOG_ERROR)         ? "ERROR" :
            (level == NDPI_LOG_TRACE)       ? "TRACE" :
            (level == NDPI_LOG_DEBUG)       ? "DEBUG" :
            (level == NDPI_LOG_DEBUG_EXTRA) ? "DEXTRA" :
                                              "UNK???",
          file, func, line);

        vfprintf(stdout, format, ap);
        va_end(ap);
    }
}
#endif  // NDPI_ENABLE_DEBUG_MESSAGES

int ndLogBuffer::overflow(int ch) {
    if (ch != EOF) os << (char)ch;

    if (ch == '\n') return sync();

    return 0;
}

int ndLogBuffer::sync() {
    if (! os.str().empty()) {
        nd_printf("%s", os.str().c_str());
        os.str("");
    }

    return 0;
}

int ndDebugLogBuffer::sync() {
    if (! os.str().empty()) {
        nd_dprintf("%s", os.str().c_str());
        os.str("");
    }

    return 0;
}

int ndDebugLogBufferUnlocked::sync() {
    if (! os.str().empty()) {
        if (ndGC_DEBUG)
            fprintf(stderr, "%s", os.str().c_str());
        os.str("");
    }

    return 0;
}

int ndDebugLogBufferFlow::sync() {
    if (! os.str().empty()) {
        if (ndGC_DEBUG || ndGC.h_flow != stderr)
            fprintf(ndGC.h_flow, "%s", os.str().c_str());
        os.str("");
    }

    return 0;
}

void nd_ltrim(string &s, unsigned char c) {
    s.erase(s.begin(),
      find_if(s.begin(), s.end(), [c](unsigned char ch) {
          if (c == 0) return ! isspace(ch);
          else return (ch != c);
      }));
}

void nd_rtrim(string &s, unsigned char c) {
    s.erase(
      find_if(
        s.rbegin(), s.rend(),
        [c](unsigned char ch) {
        if (c == 0) return ! isspace(ch);
        else return (ch != c);
        })
        .base(),
      s.end());
}

void nd_trim(string &s, unsigned char c) {
    nd_ltrim(s, c);
    nd_rtrim(s, c);
}

int nd_sha1_file(const string &filename, ndDigest &digest) {
    sha1 ctx;
    int fd = open(filename.c_str(), O_RDONLY);
    uint8_t buffer[ND_SHA1_BUFFER];
    ssize_t bytes;

    sha1_init(&ctx);

    if (fd < 0) {
        nd_printf("Unable to hash file: %s: %s\n",
          filename.c_str(), strerror(errno));
        return -1;
    }

    do {
        bytes = read(fd, buffer, ND_SHA1_BUFFER);

        if (bytes > 0)
            sha1_write(&ctx, (const char *)buffer, bytes);
        else if (bytes < 0) {
            nd_printf("Unable to hash file: %s: %s\n",
              filename.c_str(), strerror(errno));
            close(fd);
            return -1;
        }
    }
    while (bytes != 0);

    close(fd);
    sha1_result(&ctx, digest.data());

    return 0;
}

void nd_sha1_to_string(const ndDigest &digest, string &digest_str) {
    array<char, SHA1_DIGEST_LENGTH * 2> _digest;
    char *p = _digest.data();

    for (int i = 0; i < SHA1_DIGEST_LENGTH; i++, p += 2)
        sprintf(p, "%02hhx", digest[i]);

    digest_str.assign(_digest.begin(), _digest.end());
}

void nd_sha1_to_string(const ndDigestDynamic &digest,
  string &digest_str) {
    if (digest.size() != SHA1_DIGEST_LENGTH) {
        throw ndException(
          "%s: invalid digest length: %lu != %u",
          __PRETTY_FUNCTION__, digest.size(), SHA1_DIGEST_LENGTH);
    }

    ndDigest _digest;
    memcpy(_digest.data(), digest.data(), SHA1_DIGEST_LENGTH);

    return nd_sha1_to_string(_digest, digest_str);
}

bool nd_string_to_sha1(const string &digest_str, ndDigest &digest) {
    digest.fill('\0');

    size_t i = 0;
    istringstream is(digest_str);
    while (i < SHA1_DIGEST_LENGTH && is.good()) {
        string octet;
        is >> setw(2) >> octet;
        if (octet.size() == 2) {
            try {
                uint8_t byte = (uint8_t)stoul(octet, nullptr, 16);
                digest[i++] = byte;
            }
            catch (invalid_argument &e) {
                nd_dprintf(
                  "error converting string to SHA1: %s: "
                  "%s\n",
                  e.what(), octet.c_str());
                return false;
            }
            catch (out_of_range &e) {
                nd_dprintf(
                  "error converting string to SHA1: %s: "
                  "%s\n",
                  e.what(), octet.c_str());
                return false;
            }
        }
    }

    return (i == SHA1_DIGEST_LENGTH);
}

bool nd_string_to_sha1(const string &digest_str,
  ndDigestDynamic &digest) {
    ndDigest _digest;
    if (! nd_string_to_sha1(digest_str, _digest))
        return false;

    digest.assign(_digest.begin(), _digest.end());

    return true;
}

bool nd_string_to_mac(const string &src, uint8_t *mac) {
    if (src.size() != ND_STR_ETHALEN) return false;

    uint8_t *p = mac;
    const char *s = src.c_str();

    for (int i = 0; i < ND_STR_ETHALEN; i += 3, p++) {
        if (sscanf(s + i, "%2hhx", p) != 1) return false;
    }

    return true;
}

sa_family_t
nd_string_to_ip(const string &src, sockaddr_storage *ip) {
    sa_family_t family = AF_UNSPEC;
    struct sockaddr_in *ipv4 =
      reinterpret_cast<struct sockaddr_in *>(ip);
    struct sockaddr_in6 *ipv6 =
      reinterpret_cast<struct sockaddr_in6 *>(ip);

    if (inet_pton(AF_INET, src.c_str(), &ipv4->sin_addr) == 1)
        family = AF_INET;
    else if (inet_pton(AF_INET6, src.c_str(), &ipv6->sin6_addr) == 1)
        family = AF_INET6;

    return family;
}

bool nd_ip_to_string(sa_family_t af, const void *addr, string &dst) {
    char ip[INET6_ADDRSTRLEN];

    switch (af) {
    case AF_INET:
        inet_ntop(AF_INET, addr, ip, INET_ADDRSTRLEN);
        break;
    case AF_INET6:
        inet_ntop(AF_INET6, addr, ip, INET6_ADDRSTRLEN);
        break;
    default: return false;
    }

    dst.assign(ip);

    return true;
}

bool nd_ip_to_string(const sockaddr_storage &ip, string &dst) {
    const struct sockaddr_in *ipv4 =
      reinterpret_cast<const struct sockaddr_in *>(&ip);
    const struct sockaddr_in6 *ipv6 =
      reinterpret_cast<const struct sockaddr_in6 *>(&ip);

    switch (ip.ss_family) {
    case AF_INET:
        return nd_ip_to_string(AF_INET,
          (const void *)&ipv4->sin_addr.s_addr, dst);
    case AF_INET6:
        return nd_ip_to_string(AF_INET6,
          (const void *)&ipv6->sin6_addr.s6_addr, dst);
    default: return false;
    }

    return false;
}

void nd_json_to_string(const json &j, string &output, bool pretty) {
    output = j.dump(pretty ? ND_JSON_INDENT : -1, ' ', true,
      json::error_handler_t::replace);

    vector<pair<regex *, string> >::const_iterator i;
    for (i = ndGC.privacy_regex.begin();
         i != ndGC.privacy_regex.end();
         i++)
    {
        string result = regex_replace(output, *((*i).first),
          (*i).second);
        if (result.size()) output = result;
    }
}

uint8_t nd_netmask_to_prefix(const struct sockaddr_storage *netmask) {
    uint8_t p = 0;

    if (netmask->ss_family == AF_INET) {
        const struct sockaddr_in *addr =
          reinterpret_cast<const struct sockaddr_in *>(netmask);
        unsigned n = ntohl(addr->sin_addr.s_addr);
        while (n > 0) {
            n = n << 1;
            p++;
        }
    }
    else if (netmask->ss_family == AF_INET6) {
        const struct sockaddr_in6 *addr =
          reinterpret_cast<const struct sockaddr_in6 *>(netmask);
        for (int i = 0; i < 4; i++) {
            unsigned n = ntohl(addr->sin6_addr.s6_addr32[i]);
            while (n > 0) {
                n = n << 1;
                p++;
            }
        }
    }

    return p;
}

uint8_t nd_netmask_to_prefix(const std::string &netmask) {
    sockaddr_storage addr;
    struct sockaddr_in *ipv4 =
      reinterpret_cast<struct sockaddr_in *>(&addr);
    struct sockaddr_in6 *ipv6 =
      reinterpret_cast<struct sockaddr_in6 *>(&addr);

    if (inet_pton(AF_INET, netmask.c_str(), &ipv4->sin_addr) == 1)
        return nd_netmask_to_prefix(&addr);
    else if (inet_pton(AF_INET6, netmask.c_str(), &ipv6->sin6_addr) == 1)
        return nd_netmask_to_prefix(&addr);

    return 0;
}

bool nd_is_ipaddr(const char *ip) {
    struct in_addr addr4;
    struct in6_addr addr6;

    if (inet_pton(AF_INET, ip, &addr4) == 1) return true;
    return (inet_pton(AF_INET6, ip, &addr6) == 1) ? true : false;
}

void nd_private_ipaddr(uint8_t index, struct sockaddr_storage &addr) {
    int rc = -1;
    ostringstream os;

    if (addr.ss_family == AF_INET) {
        os << ND_PRIVATE_IPV4 << (int)index;
        struct sockaddr_in *sa =
          reinterpret_cast<struct sockaddr_in *>(&addr);
        rc = inet_pton(AF_INET, os.str().c_str(), &sa->sin_addr);
    }
    else if (addr.ss_family == AF_INET6) {
        os << ND_PRIVATE_IPV6 << hex << (int)index;
        struct sockaddr_in6 *sa =
          reinterpret_cast<struct sockaddr_in6 *>(&addr);
        rc = inet_pton(AF_INET6, os.str().c_str(), &sa->sin6_addr);
    }

    switch (rc) {
    case -1:
        nd_dprintf("Invalid private address family.\n");
        break;
    case 0:
        nd_dprintf("Invalid private address: %s\n",
          os.str().c_str());
        break;
    }
}

bool nd_load_uuid(string &uuid, const string &path, size_t length) {
    struct stat sb;
    char _uuid[length + 1];

    if (stat(path.c_str(), &sb) == -1) {
        if (errno != ENOENT) {
            nd_printf("Error loading uuid: %s: %s\n",
              path.c_str(), strerror(errno));
        }
        return false;
    }

    if (! S_ISREG(sb.st_mode)) {
        nd_printf("Error loading uuid: %s: %s\n",
          path.c_str(), "Not a regular file");
        return false;
    }

    if (sb.st_mode & S_IXUSR) {
        FILE *ph = popen(path.c_str(), "r");

        if (ph == nullptr) {
            if (ndGC_DEBUG || errno != ENOENT) {
                nd_printf(
                  "Error loading uuid from pipe: %s: %s\n",
                  path.c_str(), strerror(errno));
            }
            return false;
        }

        size_t bytes = 0;

        bytes = fread((void *)_uuid, 1, length, ph);

        int rc = pclose(ph);

        if (bytes <= 0 || rc != 0) {
            nd_printf(
              "Error loading uuid from pipe: %s: %s: %d\n",
              path.c_str(), "Invalid pipe read", rc);
            return false;
        }

        _uuid[bytes - 1] = '\0';
    }
    else {
        FILE *fh = fopen(path.c_str(), "r");

        if (fh == nullptr) {
            if (ndGC_DEBUG || errno != ENOENT) {
                nd_printf(
                  "Error loading uuid from file: %s: %s\n",
                  path.c_str(), strerror(errno));
            }
            return false;
        }

        if (fread((void *)_uuid, 1, length, fh) != length) {
            fclose(fh);
            nd_printf(
              "Error reading uuid from file: %s: %s\n",
              path.c_str(), strerror(errno));
            return false;
        }

        fclose(fh);

        _uuid[length] = '\0';
    }

    uuid.assign(_uuid);

    nd_rtrim(uuid);

    return true;
}

bool nd_save_uuid(const string &uuid, const string &path,
  size_t length) {
    FILE *fh = fopen(path.c_str(), "w");

    if (fh == nullptr) {
        nd_printf("Error saving uuid: %s: %s\n",
          path.c_str(), strerror(errno));
        return false;
    }

    if (fwrite((const void *)uuid.c_str(), 1, length, fh) != length)
    {
        fclose(fh);
        nd_printf("Error writing uuid: %s: %s\n",
          path.c_str(), strerror(errno));
        return false;
    }

    fclose(fh);
    return true;
}

void nd_seed_rng(void) {
    FILE *fh = fopen("/dev/urandom", "r");
    unsigned int seed = (unsigned int)time(nullptr);

    if (fh == nullptr)
        nd_printf("Error opening random device: %s\n",
          strerror(errno));
    else {
        if (fread((void *)&seed, sizeof(unsigned int), 1, fh) != 1)
            nd_printf(
              "Error reading from random device: %s\n",
              strerror(errno));
        fclose(fh);
    }

    srand(seed);
}

void nd_generate_uuid(string &uuid) {
    int digit = 0;
    deque<char> result;
    uint64_t input = 623714775;
    const char *clist = {
        "0123456789abcdefghijklmnpqrstuvwxyz"
    };
    ostringstream os;

    input = (uint64_t)rand();
    input += (uint64_t)rand() << 32;

    while (input != 0) {
        result.push_front(toupper(clist[input % strlen(clist)]));
        input /= strlen(clist);
    }

    for (size_t i = result.size(); i < 8; i++)
        result.push_back('0');

    while (result.size() && digit < 8) {
        os << result.front();
        result.pop_front();
        if (digit == 1) os << "-";
        if (digit == 3) os << "-";
        if (digit == 5) os << "-";
        digit++;
    }

    uuid = os.str();
}

const char *nd_get_version(void) {
    return ND_VERSION_STR;
}

const string &nd_get_version_and_features(bool fancy) {
    static mutex lock;
    static string version;

    lock_guard<mutex> ul(lock);

    if (version.empty()) {
        string os;
        nd_os_detect(os);

        ostringstream ident;
        if (fancy) ident << ndTerm::Attr::BOLD;
        ident << ND_NAME << "/" << GIT_RELEASE;
        if (fancy) ident << ndTerm::Attr::RESET;
        ident << " (" << os
              << "; " << _ND_HOST_OS << "; " << _ND_HOST_CPU;

        if (ndGC_USE_CONNTRACK) ident << "; conntrack";
        if (ndGC_USE_NETLINK) ident << "; netlink";
        if (ndGC_USE_DHC) ident << "; dns-cache";
#ifdef _ND_ENABLE_TPACKETV3
        ident << "; tpv3";
#endif
#ifdef _ND_ENABLE_NFQUEUE
        ident << "; nfqueue";
#endif
#ifdef _ND_ENABLE_LIBTCMALLOC
        ident << "; tcmalloc";
#endif
        if (ndGC_SSL_USE_TLSv1) ident << "; ssl-tlsv1";
        if (! ndGC_SSL_VERIFY) ident << "; ssl-no-verify";
#ifdef HAVE_WORKING_REGEX
        ident << "; regex";
#endif
        ident << ")";

        version = ident.str();
    }

    return version;
}

bool nd_parse_app_tag(const string &tag, unsigned &id, string &name) {
    id = 0;
    name.clear();

    size_t p;
    if ((p = tag.find_first_of(".")) != string::npos) {
        id = (unsigned)strtoul(tag.substr(0, p).c_str(),
          nullptr, 0);
        name = tag.substr(p + 1);

        return true;
    }

    return false;
}

int nd_touch(const string &filename) {
    int fd;
    struct timespec now[2];

    fd = open(filename.c_str(),
      O_WRONLY | O_CREAT | O_NONBLOCK | O_NOCTTY,
      S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

    if (fd < 0) return fd;

    clock_gettime(CLOCK_REALTIME, &now[0]);
    clock_gettime(CLOCK_REALTIME, &now[1]);

    if (futimens(fd, now) < 0) return -1;

    close(fd);

    return 0;
}

int nd_file_load(const string &filename, string &data) {
    struct stat sb;
    int fd = open(filename.c_str(), O_RDONLY);

    if (fd < 0) {
        if (errno != ENOENT) {
            throw ndException("%s: open(%s): %s", __PRETTY_FUNCTION__,
              filename.c_str(), strerror(errno));
        }
        else {
            nd_dprintf("Unable to load file: %s: %s\n",
              filename.c_str(), strerror(errno));
            return -1;
        }
    }

    if (flock(fd, LOCK_SH) < 0) {
        close(fd);
        throw ndException("%s: flock(LOCK_SH, %s): %s",
          __PRETTY_FUNCTION__, filename.c_str(), strerror(errno));
    }

    if (fstat(fd, &sb) < 0) {
        close(fd);
        throw ndException("%s: fstat(%s): %s", __PRETTY_FUNCTION__,
          filename.c_str(), strerror(errno));
    }

    if (sb.st_size == 0) data.clear();
    else {
        auto buffer = make_shared<vector<uint8_t>>(sb.st_size);
        if (read(fd, (void *)buffer->data(), sb.st_size) < 0)
        {
            throw ndException("%s: read(%s): %s", __PRETTY_FUNCTION__,
              filename.c_str(), strerror(errno));
        }
        data.assign((const char *)buffer->data(), sb.st_size);
    }

    flock(fd, LOCK_UN);
    close(fd);

    return 0;
}

void nd_file_save(const string &filename, const string &data,
  bool append, mode_t mode, const char *user, const char *group) {
    int fd = open(filename.c_str(), O_WRONLY);
    struct passwd *owner_user = nullptr;
    struct group *owner_group = nullptr;

    if (fd < 0) {
        if (errno != ENOENT) {
            throw ndException("%s: open(%s): %s", __PRETTY_FUNCTION__,
              filename.c_str(), strerror(errno));
        }
        fd = open(filename.c_str(), O_WRONLY | O_CREAT, mode);
        if (fd < 0) {
            throw ndException("%s: open(%s): %s", __PRETTY_FUNCTION__,
              filename.c_str(), strerror(errno));
        }

        if (user != nullptr) {
            owner_user = getpwnam(user);
            if (owner_user == nullptr) {
                throw ndException("%s: getpwnam(%s): %s",
                  __PRETTY_FUNCTION__, user, strerror(errno));
            }
        }

        if (group != nullptr) {
            owner_group = getgrnam(group);
            if (owner_group == nullptr) {
                throw ndException("%s: getgrnam(%s): %s",
                  __PRETTY_FUNCTION__, group, strerror(errno));
            }
        }

        if (fchown(fd,
              (owner_user != nullptr) ? owner_user->pw_uid : -1,
              (owner_group != nullptr) ? owner_group->gr_gid : -1) < 0)
        {
            throw ndException("%s: fchown(%s, %s, %s): %s",
              __PRETTY_FUNCTION__, (user != nullptr) ? user : "-1",
              (group != nullptr) ? group : "-1",
              filename.c_str(), strerror(errno));
        }
    }

    if (flock(fd, LOCK_EX) < 0) {
        throw ndException("%s: flock(LOCK_EX, %s): %s",
          __PRETTY_FUNCTION__, filename.c_str(), strerror(errno));
    }

    if (lseek(fd, 0, (! append) ? SEEK_SET : SEEK_END) < 0) {
        throw ndException("%s: lseek(0, %s, %s): %s",
          __PRETTY_FUNCTION__, (! append) ? "SEEK_SET" : "SEEK_END",
          filename.c_str(), strerror(errno));
    }

    if (! append && ftruncate(fd, 0) < 0) {
        throw ndException("%s: ftruncate(%s): %s",
          __PRETTY_FUNCTION__, filename.c_str(), strerror(errno));
    }

    if (write(fd, (const void *)data.c_str(), data.length()) < 0)
    {
        throw ndException("%s: write(%s): %s", __PRETTY_FUNCTION__,
          filename.c_str(), strerror(errno));
    }

    flock(fd, LOCK_UN);
    close(fd);
}

int nd_ifreq(const string &name, unsigned long request,
  struct ifreq *ifr) {
    int fd, rc = -1;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        nd_printf("%s: error creating ifreq socket: %s\n",
          name.c_str(), strerror(errno));
        return rc;
    }

    memset(ifr, '\0', sizeof(struct ifreq));
    strncpy(ifr->ifr_name, name.c_str(), IFNAMSIZ - 1);

    if (ioctl(fd, request, (char *)ifr) == -1) {
        nd_dprintf(
          "%s: error sending interface request: %s\n",
          name.c_str(), strerror(errno));
    }
    else rc = 0;

    close(fd);
    return rc;
}

void nd_basename(const string &path, string &base) {
    base = path;
    size_t p = path.find_last_of("/");
    if (p == string::npos) return;
    base = path.substr(p + 1);
}

#if defined(__linux__)
pid_t nd_is_running(pid_t pid, const string &exe_base) {
    pid_t rc = -1;
    struct stat sb;
    ostringstream proc_exe_link;

    proc_exe_link << "/proc/" << pid << "/exe";

    if (lstat(proc_exe_link.str().c_str(), &sb) == -1) {
        if (errno != ENOENT) {
            nd_printf("%s: lstat: %s: %s\n", __PRETTY_FUNCTION__,
              proc_exe_link.str().c_str(), strerror(errno));
            return rc;
        }

        return 0;
    }

    vector<char> link_path(1024, '\0');
    ssize_t length = readlink(proc_exe_link.str().c_str(),
      &link_path[0], link_path.size());

    if (length != -1) {
        if (strncmp(basename(&link_path[0]),
              exe_base.c_str(), exe_base.size()))
        {
            rc = 0;
        }
        else rc = pid;
    }
    else {
        nd_printf("%s: readlink: %s: %s\n", __PRETTY_FUNCTION__,
          proc_exe_link.str().c_str(), strerror(errno));
    }

    return rc;
}
#elif defined(__FreeBSD__)
pid_t nd_is_running(pid_t pid, const string &exe_base) {
    int mib[4];
    pid_t rc = -1;
    size_t length = 4;
    char pathname[PATH_MAX];

    if (sysctlnametomib("kern.proc.pathname", mib, &length) < 0)
    {
        nd_printf("%s: sysctlnametomib: %s: %s\n", __PRETTY_FUNCTION__,
          "kern.proc.pathname", strerror(errno));
        return rc;
    }

    mib[3] = pid;
    length = sizeof(pathname);

    if (sysctl(mib, 4, pathname, &length, nullptr, 0) == -1) {
        nd_printf("%s: sysctl: %s(%ld): %s\n", __PRETTY_FUNCTION__,
          "kern.proc.pathname", pid, strerror(errno));
    }
    else if (length > 0) {
        char *pathname_base = basename(pathname);
        length = strlen(pathname_base);
        if (exe_base.size() < length)
            length = exe_base.size();

        if (strncmp(pathname_base, exe_base.c_str(), length) == 0)
        {
            rc = pid;
        }
        else rc = 0;
    }

    return rc;
}
#else
#error "Unsupported platform, not Linux or BSD >= 4.4."
#endif

int nd_load_pid(const string &pidfile) {
    pid_t pid = -1;
    FILE *hpid = fopen(pidfile.c_str(), "r");

    if (hpid != nullptr) {
        char _pid[32];
        if (fgets(_pid, sizeof(_pid), hpid))
            pid = (pid_t)strtol(_pid, nullptr, 0);
        fclose(hpid);
    }
    else if (errno == ENOENT) {
        pid = 0;
    }

    return pid;
}

int nd_save_pid(const string &pidfile, pid_t pid) {
    FILE *hpid = fopen(pidfile.c_str(), "w+");

    if (hpid == nullptr) {
        nd_printf("Error opening PID file: %s: %s\n",
          pidfile.c_str(), strerror(errno));

        return -1;
    }

    fprintf(hpid, "%d\n", pid);
    fclose(hpid);

    return 0;
}

int nd_file_exists(const string &path) {
    struct stat sb;

    if (stat(path.c_str(), &sb) == -1) {
        if (errno == ENOENT) return 0;
        return -1;
    }

    return 1;
}

int nd_dir_exists(const string &path) {
    struct stat sb;

    if (stat(path.c_str(), &sb) == -1) {
        if (errno == ENOENT) return 0;
        return -1;
    }

    if (! S_ISDIR(sb.st_mode)) return 0;

    return 1;
}

void nd_uptime(time_t ut, string &uptime) {
    constexpr time_t _ND_UT_MIN = 60;
    constexpr time_t _ND_UT_HOUR = (_ND_UT_MIN * 60);
    constexpr time_t _ND_UT_DAY = (_ND_UT_HOUR * 24);

    time_t seconds = ut;
    time_t days = 0, hours = 0, minutes = 0;

    if (seconds > 0) {
        days = seconds / _ND_UT_DAY;
        seconds -= days * _ND_UT_DAY;
    }

    if (seconds > 0) {
        hours = seconds / _ND_UT_HOUR;
        seconds -= hours * _ND_UT_HOUR;
    }

    if (seconds > 0) {
        minutes = seconds / _ND_UT_MIN;
        seconds -= minutes * _ND_UT_MIN;
    }

    ostringstream os;
    ios os_state(nullptr);
    os_state.copyfmt(os);

    os << days << "d";
    os << " " << setfill('0') << setw(2) << hours;
    os.copyfmt(os_state);
    os << ":" << setfill('0') << setw(2) << minutes;
    os.copyfmt(os_state);
    os << ":" << setfill('0') << setw(2) << seconds;

    uptime.assign(os.str());
}

int nd_functions_exec(const string &func, const string &arg,
  string &output) {
    ostringstream os;
    os << "sh -c \". " << ndGC.path_functions << " && " << func;
    if (! arg.empty()) os << " " << arg;
    os << "\" 2>&1";

    int rc = -1;
    FILE *ph = popen(os.str().c_str(), "r");

    if (ph != nullptr) {
        char buffer[64];
        size_t bytes = 0;

        do {
            if ((bytes = fread(buffer, 1, sizeof(buffer), ph)) > 0)
                output.append(buffer, bytes);
        }
        while (bytes > 0);

        rc = pclose(ph);
    }

    return rc;
}

void nd_os_detect(string &os) {
    string output;
    int rc = nd_functions_exec("detect_os", string(), output);

    if (rc == 0 && output.size()) {
        const char *ws = "\n";
        output.erase(output.find_last_not_of(ws) + 1);
        os.assign(output);
    }
    else os = "unknown";
}

ndLogDirectory::ndLogDirectory(const string &path,
  const string &prefix,
  const string &suffix,
  bool overwrite)
  : path(path), prefix(prefix), suffix(suffix),
    overwrite(overwrite), hf_cur(nullptr) {
    struct stat sb;

    if (stat(path.c_str(), &sb) == -1) {
        if (errno == ENOENT) {
            if (mkdir(path.c_str(), 0750) != 0)
                throw ndException("%s: mkdir(%s): %s",
                  __PRETTY_FUNCTION__, filename.c_str(),
                  strerror(errno));
        }
        else {
            throw ndException("%s: stat(%s): %s", __PRETTY_FUNCTION__,
              filename.c_str(), strerror(errno));
        }

        if (! S_ISDIR(sb.st_mode)) {
            throw ndException("%s: ! S_ISDIR(%s)",
              __PRETTY_FUNCTION__, filename.c_str());
        }
    }
}

ndLogDirectory::~ndLogDirectory() {
    Close();
}

FILE *ndLogDirectory::Open(const string &ext) {
    if (hf_cur != nullptr) {
        nd_dprintf(
          "Log file already open; close or discard "
          "first: "
          "%s\n",
          filename.c_str());
        return nullptr;
    }

    if (! overwrite) {
        time_t now = time(nullptr);
        struct tm tm_now;

        tzset();
        localtime_r(&now, &tm_now);

        char stamp[_ND_LOG_FILE_STAMP_SIZE];
        strftime(stamp, _ND_LOG_FILE_STAMP_SIZE,
          _ND_LOG_FILE_STAMP, &tm_now);

        filename = prefix + stamp + suffix + ext;
    }
    else filename = prefix + suffix + ext;

    string full_path = path + "/." + filename;

    if (! (hf_cur = fopen(full_path.c_str(), "w"))) {
        nd_dprintf("Error opening log file: %s: %s\n",
          full_path.c_str(), strerror(errno));
        return nullptr;
    }

    return hf_cur;
}

void ndLogDirectory::Close(void) {
    if (hf_cur != nullptr) {
        fclose(hf_cur);

        string src = path + "/." + filename;
        string dst = path + "/" + filename;

        if (overwrite) unlink(dst.c_str());

        if (rename(src.c_str(), dst.c_str()) != 0) {
            nd_dprintf(
              "Error renaming log file: %s -> %s: %s\n",
              src.c_str(), dst.c_str(), strerror(errno));
        }

        hf_cur = nullptr;
    }
}

void ndLogDirectory::Discard(void) {
    if (hf_cur != nullptr) {
        string full_path = path + "/." + filename;

        nd_dprintf("Discarding log file: %s\n", full_path.c_str());

        fclose(hf_cur);

        unlink(full_path.c_str());

        hf_cur = nullptr;
    }
}

void nd_regex_error(const regex_error &e, string &error) {
    switch (e.code()) {
    case regex_constants::error_collate:
        error =
          "The expression contains an invalid "
          "collating "
          "element name";
        break;
    case regex_constants::error_ctype:
        error =
          "The expression contains an invalid "
          "character "
          "class name";
        break;
    case regex_constants::error_escape:
        error =
          "The expression contains an invalid escaped "
          "character or a trailing escape";
        break;
    case regex_constants::error_backref:
        error =
          "The expression contains an invalid back "
          "reference";
        break;
    case regex_constants::error_brack:
        error =
          "The expression contains mismatched square "
          "brackets ('[' and ']')";
        break;
    case regex_constants::error_paren:
        error =
          "The expression contains mismatched "
          "parentheses "
          "('(' and ')')";
        break;
    case regex_constants::error_brace:
        error =
          "The expression contains mismatched curly "
          "braces "
          "('{' and '}')";
        break;
    case regex_constants::error_badbrace:
        error =
          "The expression contains an invalid range in "
          "a "
          "{} expression";
        break;
    case regex_constants::error_range:
        error =
          "The expression contains an invalid "
          "character "
          "range (e.g. [b-a])";
        break;
    case regex_constants::error_space:
        error =
          "There was not enough memory to convert the "
          "expression into a finite state machine";
        break;
    case regex_constants::error_badrepeat:
        error =
          "one of *?+{ was not preceded by a valid "
          "regular "
          "expression";
        break;
    case regex_constants::error_complexity:
        error =
          "The complexity of an attempted match "
          "exceeded a "
          "predefined level";
        break;
    case regex_constants::error_stack:
        error =
          "There was not enough memory to perform a "
          "match";
        break;
    default: error = e.what(); break;
    }
}

bool nd_scan_dotd(const string &path, vector<string> &files) {
    DIR *dh = opendir(path.c_str());

    if (dh == nullptr) {
        nd_printf("Error opening directory: %s: %s\n",
          path.c_str(), strerror(errno));
        return false;
    }

    files.clear();

    struct dirent *result = nullptr;
    while ((result = readdir(dh)) != nullptr) {
        if (
#ifdef _DIRENT_HAVE_D_RECLEN
          result->d_reclen == 0 ||
#endif
#ifdef _DIRENT_HAVE_D_TYPE
          (result->d_type != DT_LNK && result->d_type != DT_REG &&
            result->d_type != DT_UNKNOWN) ||
#endif
          ! isdigit(result->d_name[0]))
            continue;

        string name(result->d_name);
        size_t p = name.find_last_of('.');
        if (p == string::npos ||
          name.substr(p + 1) != "conf")
            continue;

        files.push_back(name);
    }

    closedir(dh);

    return true;
}

void nd_set_hostname(string &dst, bool strict) {
    transform(dst.begin(), dst.end(), dst.begin(),
      [strict](unsigned char c) {
        if (strict) {
            if (isalnum(c) || c == '-' || c == '_' || c == '.')
                return (unsigned char)tolower(c);
        }
        else {
            if (isalnum(c) || ispunct(c) || c == ' ') {
                return c;
            }
        }
        return (unsigned char)'_';
    });

    nd_trim(dst, '.');
}

void nd_set_hostname(string &dst, const char *src,
  size_t length, bool strict) {
    dst.clear();
    dst.reserve(length);

    // Sanitize host server name; RFC 952 plus underscore for
    // SSDP.
    if (strict) {
        for (size_t i = 0; i < length; i++) {
            if (src[i] == '\0') break;
            if (isalnum(src[i]) || src[i] == '-' ||
              src[i] == '_' || src[i] == '.')
                dst += (char)tolower(src[i]);
        }
    }
    else {
        for (size_t i = 0; i < length; i++) {
            if (src[i] == '\0') break;
            if (isalnum(src[i]) || ispunct(src[i]) ||
              src[i] == ' ' || src[i] == '\0')
                dst += src[i];
            else dst += '_';
        }
    }

    nd_trim(dst, '.');
}

void nd_set_hostname(char *dst, const char *src,
  size_t length, bool strict) {
    string buffer;
    nd_set_hostname(buffer, src, length, strict);
    strncpy(dst, buffer.c_str(), min(length, buffer.length()));
}

void nd_expand_variables(const string &input,
  string &output, map<string, string> &vars) {
    output = input;

    for (auto &var : vars) {
        size_t p;

        while ((p = output.find(var.first)) != string::npos) {
            if (var.second.size() > var.first.size()) {
                output.insert(p + var.first.size(),
                  var.second.size() - var.first.size(),
                  ' ');
            }

            output.replace(p, var.second.size(), var.second);

            if (var.second.size() < var.first.size()) {
                output.erase(p + var.second.size(),
                  var.first.size() - var.second.size());
            }
        }
    }
}

void nd_gz_inflate(size_t length, const uint8_t *data,
  vector<uint8_t> &output) {
    int rc;
    z_stream zs;
    array<uint8_t, ND_ZLIB_CHUNK_SIZE> chunk;

    zs.zalloc = Z_NULL;
    zs.zfree = Z_NULL;
    zs.opaque = Z_NULL;
    zs.next_in = Z_NULL;
    zs.avail_in = 0;

    if (inflateInit2(&zs, 15 + 32) != Z_OK) {
        throw ndException("%s: inflateInit: %s",
          __PRETTY_FUNCTION__, strerror(EINVAL));
    }

    zs.next_in = (uint8_t *)data;
    zs.avail_in = length;

    do {
        zs.avail_out = chunk.size();
        zs.next_out = chunk.data();

        if ((rc = inflate(&zs, Z_SYNC_FLUSH)) < 0) {
            throw ndException("%s: inflate: %d",
              __PRETTY_FUNCTION__, rc);
        }
        output.insert(output.end(), chunk.begin(),
          chunk.begin() + (chunk.size() - zs.avail_out));
    }
    while (zs.avail_out == 0);

    inflateEnd(&zs);

    if (rc != Z_STREAM_END) {
        throw ndException("%s: inflate: %d",
          __PRETTY_FUNCTION__, rc);
    }
}

void nd_gz_deflate(size_t length, const uint8_t *data,
  vector<uint8_t> &output) {
    int rc;
    z_stream zs;
    array<uint8_t, ND_ZLIB_CHUNK_SIZE> chunk;

    output.clear();

    zs.zalloc = Z_NULL;
    zs.zfree = Z_NULL;
    zs.opaque = Z_NULL;

    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
          15 /* window bits */ | 16 /* enable GZIP format */,
          8, Z_DEFAULT_STRATEGY) != Z_OK)
    {
        throw ndException("%s: deflateInit2: %s",
          __PRETTY_FUNCTION__, strerror(EINVAL));
    }

    zs.next_in = (uint8_t *)data;
    zs.avail_in = length;

    do {
        zs.avail_out = chunk.size();
        zs.next_out = chunk.data();
        if ((rc = deflate(&zs, Z_FINISH)) == Z_STREAM_ERROR) {
            throw ndException("%s: deflate: %s",
              __PRETTY_FUNCTION__, strerror(EINVAL));
        }
        output.insert(output.end(), chunk.begin(),
          chunk.begin() + (chunk.size() - zs.avail_out));
    }
    while (zs.avail_out == 0);

    deflateEnd(&zs);

    if (rc != Z_STREAM_END) {
        throw ndException("%s: deflate: %d",
          __PRETTY_FUNCTION__, rc);
    }
#if 0
    nd_dprintf(
        "%s: payload compressed: %lu -> %lu: %.1f%%\n",
        __PRETTY_FUNCTION__, length, output.size(),
        100.0f - ((float)output.size() * 100.0f / (float)length)
    );
#endif
}

void ndTimer::Create(int sig) {
    this->sig = sig;

    if (valid) {
        throw ndException("%s: timer: %s",
          __PRETTY_FUNCTION__, strerror(EEXIST));
    }

    struct sigevent sigev;
    memset(&sigev, 0, sizeof(struct sigevent));
    sigev.sigev_notify = SIGEV_SIGNAL;
    sigev.sigev_signo = sig;

    if (timer_create(CLOCK_MONOTONIC, &sigev, &id) < 0) {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "timer_create");
    }

    valid = true;
}

void ndTimer::Reset(void) {
    if (valid) {
        timer_delete(id);
        valid = false;
    }
}

void ndTimer::Set(const struct itimerspec &itspec) {
    if (! valid) {
        throw ndException("%s: timer: %s",
          __PRETTY_FUNCTION__, strerror(EEXIST));
    }

    if (timer_settime(id, 0, &itspec, nullptr) != 0) {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "timer_settime");
    }
}

void nd_get_ip_protocol_name(int protocol, string &result) {
    static mutex lock;
    static unordered_map<int, string> cache;

    lock_guard<mutex> ul(lock);

    auto it = cache.find(protocol);
    if (it != cache.end()) {
        result = it->second;
        return;
    }

    int rc = 0;
    struct protoent *pe_result;
#ifdef HAVE_GETPROTOBYNUMBER_R
    struct protoent pe_buffer;
    constexpr size_t _ND_GET_PROTO_BUFSIZ = 1024;
    array<uint8_t, _ND_GET_PROTO_BUFSIZ> buffer;

    rc = getprotobynumber_r(protocol, &pe_buffer,
      reinterpret_cast<char *>(buffer.data()),
      _ND_GET_PROTO_BUFSIZ, &pe_result);
#else
    // XXX: Fall back to non-reentrant version.
    // We're holding a static mutex lock here anyway...
    pe_result = getprotobynumber(protocol);
#endif
    if (rc != 0 || pe_result == nullptr)
        result = to_string(protocol);
    else {
        if (pe_result->p_aliases != nullptr &&
          pe_result->p_aliases[0] != nullptr)
            result = pe_result->p_aliases[0];
        else {
            result = pe_result->p_name;
            transform(result.begin(), result.end(), result.begin(),
              [](unsigned char c) { return toupper(c); });
        }
        cache.insert(make_pair(protocol, result));
    }
}

int nd_glob(const string &pattern, vector<string> &results) {
    int rc;
    glob_t gr = { 0 };
    if ((rc = glob(pattern.c_str(), 0, nullptr, &gr)) == 0) {
        for (size_t i = 0; i < gr.gl_pathc; i++)
            results.push_back(gr.gl_pathv[i]);
        globfree(&gr);
    }
    else results.push_back(pattern);

    switch (rc) {
    case 0: break;
    case GLOB_NOSPACE: rc = ENOMEM; break;
    case GLOB_NOMATCH: rc = ENOENT; break;
    default: rc = EINVAL; break;
    }

    return rc;
}

time_t nd_time_monotonic(void) {
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "clock_gettime");
    }

    return ts.tv_sec;
}

void nd_tmpfile(const string &prefix, string &filename) {
    int fd;
    string path;
    vector<char> buffer;

    size_t p = prefix.find_last_of("/");
    if (p == string::npos) {
        const string temp = prefix + "XXXXXX";
        buffer.assign(temp.begin(), temp.end());
    }
    else {
        // XXX: Old glibc mkstemp can not include a path!
        path = prefix.substr(0, p);
        const string base = prefix.substr(p + 1) + "XXXXXX";
        if (chdir(path.c_str()) != 0) {
            nd_dprintf(
              "WARNING: unable to change working "
              "directory "
              "to: "
              "%s\n",
              path.c_str());
        }
        buffer.assign(base.begin(), base.end());
    }

    buffer.push_back('\0');

    filename.clear();

    if ((fd = mkstemp(&buffer[0])) < 0) {
        throw ndException("%s: mkstemp(%s): %s",
          __PRETTY_FUNCTION__, "clock_gettime", strerror(errno));
    }

    close(fd);

    if (! path.empty()) filename = path + "/";
    filename.append(buffer.begin(), buffer.end());
}

bool nd_copy_file(const string &src, const string &dst, mode_t mode) {
    ifstream ifs(src, ios::binary);
    if (! ifs.is_open()) {
        nd_dprintf("error opening source file: %s\n", src.c_str());
        return false;
    }

    ofstream ofs(dst, ofstream::trunc | ios::binary);
    if (! ofs.is_open()) {
        nd_dprintf("error opening destination file: %s\n",
          dst.c_str());
        return false;
    }

    ofs << ifs.rdbuf();

    nd_dprintf("copied file: %s -> %s\n", src.c_str(), dst.c_str());

    if (chmod(dst.c_str(), mode) != 0) {
        nd_dprintf(
          "WARNING: unable to change file permissions: "
          "%s: %s\n",
          dst.c_str(), strerror(errno));
    }

    return true;
}

void nd_time_ago(time_t seconds, string &ago) {
    string unit = "second";
    bool plural = false;
    double days = 0, hours = 0, minutes = 0;
    double value = seconds;

    if (seconds >= 86400) {
        unit = "day";
        value = days = round(seconds / 86400);
    }
    else if (seconds >= 3600) {
        unit = "hour";
        value = hours = round(seconds / 3600);
    }
    else if (seconds >= 60) {
        unit = "minute";
        value = minutes = round(seconds / 60);
    }

    if ((days && days > 1) || (hours && hours > 1) ||
      (minutes && minutes > 1))
        plural = true;
    else if (! days && ! hours && ! minutes && seconds != 1)
        plural = true;

    ago = to_string((time_t)value) + " " + unit +
      ((plural) ? "s" : "");
}
