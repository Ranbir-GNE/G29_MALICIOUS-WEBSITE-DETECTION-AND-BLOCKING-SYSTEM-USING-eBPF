// Netify Agent 🥷
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

#include <netdb.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstring>
#include <list>

#include "INIReader.h"

#include "nd-config.hpp"
#include "nd-except.hpp"
#include "nd-plugin.hpp"
#include "nd-util.hpp"
#include "netifyd.hpp"

using namespace std;

ndGlobalConfig::ndGlobalConfig()
  : napi_tls_verify(true), napi_vendor(ND_API_VENDOR),
    path_agent_status(ND_AGENT_STATUS_PATH),
    path_app_config(ND_CONF_APP_PATH),
    path_cat_config(ND_CONF_CAT_PATH),
    path_categories(ND_CATEGORIES_PATH),
    path_config(ND_CONF_FILE_NAME),
    path_functions(ND_FUNCTIONS_PATH),
    path_interfaces(ND_INTERFACES_PATH),
    path_legacy_config(ND_CONF_LEGACY_PATH),
    path_pid_file(ND_PID_FILE_NAME), path_plugins(ND_PLUGINS_PATH),
    path_plugin_libdir(ND_PLUGIN_LIBDIR),
    path_shared_data(ND_SHARED_DATADIR),
    path_state_persistent(ND_PERSISTENT_STATEDIR),
    path_state_volatile(ND_VOLATILE_STATEDIR),
    path_uuid(ND_AGENT_UUID_PATH),
    path_uuid_serial(ND_AGENT_SERIAL_PATH),
    path_uuid_site(ND_SITE_UUID_PATH),
    url_napi_bootstrap(ND_URL_API_BOOTSTRAP),
    dhc_storage(ndDHCStorage::PERSISTENT),
    fhc_storage(ndFHCStorage::PERSISTENT),
    capture_type(ndCaptureType::NONE),
    capture_read_timeout(ND_CAPTURE_READ_TIMEOUT),
    h_flow(stderr), ca_capture_base(0), ca_conntrack(-1),
    ca_detection_base(0), ca_detection_cores(-1),
    max_packet_queue(ND_MAX_PKT_QUEUE_KB * 1024),
    max_capture_length(ND_PCAP_SNAPLEN),
    flags(ndGlobalFlags::NONE), verbosity(0),
    verbosity_flags(ndVerbosityFlags::EVENT_DPI_COMPLETE),
    fhc_purge_divisor(ND_FHC_PURGE_DIVISOR),
    fm_buckets(ND_FLOW_MAP_BUCKETS),
    max_detection_pkts(ND_MAX_DETECTION_PKTS),
    max_dhc(ND_MAX_DHC_ENTRIES),
    max_fhc(ND_MAX_FHC_ENTRIES), max_flows(0),
    ttl_capture_delay(0), ttl_idle_flow(ND_TTL_IDLE_FLOW),
    ttl_idle_tcp_flow(ND_TTL_IDLE_TCP_FLOW),
    ttl_napi_tick(ND_TTL_API_TICK),
    ttl_napi_update(ND_TTL_API_UPDATE), update_imf(1),
    update_interval(ND_STATS_INTERVAL), reader(nullptr) {
    flags |= ndGlobalFlags::SSL_VERIFY;
    flags |= ndGlobalFlags::AUTO_FLOW_EXPIRY;
#ifdef _ND_ENABLE_CONNTRACK
    flags |= ndGlobalFlags::USE_CONNTRACK;
#endif
#ifdef _ND_ENABLE_NETLINK
    flags |= ndGlobalFlags::USE_NETLINK;
#endif
    flags |= ndGlobalFlags::SOFT_DISSECTORS;
#if defined(__FreeBSD__)
    flags |= ndGlobalFlags::USE_GETIFADDRS;
#endif
}

ndGlobalConfig::~ndGlobalConfig() {
    Close();
    ClearInterfaces(true);
}

bool ndGlobalConfig::Open(const string &filename) {
    if (reader == nullptr) {
        reader = static_cast<void *>(new INIReader(filename));
        if (reader == nullptr) {
            fprintf(stderr, "Can not allocated reader: %s\n",
              strerror(ENOMEM));
            return false;
        }
    }

    return true;
}

void ndGlobalConfig::Close(void) {
    if (reader != nullptr) {
        delete static_cast<INIReader *>(reader);
        reader = nullptr;
    }
}

bool ndGlobalConfig::Load(const string &filename) {
    struct stat extern_config_stat;
    if (stat(filename.c_str(), &extern_config_stat) < 0) {
        if (errno == ENOENT) {
            fprintf(stderr,
              "Configuration file not found: %s\n",
              filename.c_str());
            return true;
        }
        fprintf(stderr,
          "Can not stat configuration file: %s: %s\n",
          filename.c_str(), strerror(errno));
        return false;
    }

    if (! Open(filename)) return false;

    INIReader *r = static_cast<INIReader *>(reader);

    int rc = r->ParseError();

    switch (rc) {
    case -1:
        fprintf(stderr,
          "Error opening configuration file: %s: %s\n",
          filename.c_str(), strerror(errno));
        return false;
    case 0: break;
    default:
        fprintf(stderr,
          "Error while parsing line #%d of "
          "configuration file: %s\n",
          rc, filename.c_str());
        return false;
    }

    string value;

    // Netify section
    ndGC_SetFlag(ndGlobalFlags::AUTO_INFORMATICS,
      r->GetBoolean("netifyd", "auto_informatics", false));

    if (uuid.empty())
        uuid = r->Get(ND_NAME_SHORT, "uuid", ND_AGENT_UUID_NULL);

    if (uuid_serial.empty())
        uuid_serial = r->Get(ND_NAME_SHORT, "uuid_serial",
          ND_AGENT_SERIAL_NULL);

    if (uuid_site.empty())
        uuid_site = r->Get(ND_NAME_SHORT, "uuid_site",
          ND_SITE_UUID_NULL);

    path_state_persistent = r->Get("netifyd",
      "path_state_persistent", ND_PERSISTENT_STATEDIR);

    path_state_volatile = r->Get("netifyd",
      "path_state_volatile", ND_VOLATILE_STATEDIR);

    path_shared_data = r->Get("netifyd", "path_shared_data",
      ND_SHARED_DATADIR);

    UpdatePaths();
    UpdateConfigVars();

    value = r->Get("netifyd", "path_pid_file",
      path_state_volatile + "/" + ND_PID_FILE_BASE);
    nd_expand_variables(value, path_pid_file, conf_vars);

    value = r->Get("netifyd", "path_plugins",
      path_state_persistent + "/" + ND_PLUGINS_BASE);
    nd_expand_variables(value, path_plugins, conf_vars);

    value = r->Get("netifyd", "path_plugin_libdir", ND_PLUGIN_LIBDIR),
    nd_expand_variables(value, path_plugin_libdir, conf_vars);

    value = r->Get("netifyd", "path_categories",
      path_state_persistent + "/" + ND_CATEGORIES_BASE);
    nd_expand_variables(value, path_categories, conf_vars);

    value = r->Get("netifyd", "path_interfaces",
      path_state_persistent + "/" + ND_INTERFACES_BASE);
    nd_expand_variables(value, path_interfaces, conf_vars);

    path_uuid = r->Get("netifyd", "path_uuid",
      path_state_persistent + "/" + ND_AGENT_UUID_BASE);

    path_uuid_serial = r->Get("netifyd", "path_uuid_serial",
      path_state_persistent + "/" + ND_AGENT_SERIAL_BASE);

    path_uuid_site = r->Get("netifyd", "path_uuid_site",
      path_state_persistent + "/" + ND_SITE_UUID_BASE);

    UpdateConfigVars();

    update_interval = (unsigned)r->GetInteger("netifyd",
      "update_interval", ND_STATS_INTERVAL);

    max_packet_queue =
      r->GetInteger("netifyd", "max_packet_queue_kb",
        ND_MAX_PKT_QUEUE_KB) *
      1024;

    ndGC_SetFlag(ndGlobalFlags::SSL_VERIFY,
      r->GetBoolean("netifyd", "ssl_verify", true));

    ndGC_SetFlag(ndGlobalFlags::SSL_USE_TLSv1,
      r->GetBoolean("netifyd", "ssl_use_tlsv1", false));

    max_capture_length = (uint16_t)r->GetInteger("netifyd",
      "max_capture_length", ND_PCAP_SNAPLEN);

    max_detection_pkts = (unsigned)r->GetInteger("netifyd",
      "max_detection_pkts", ND_MAX_DETECTION_PKTS);

    ndGC_SetFlag(ndGlobalFlags::SYN_SCAN_PROTECTION,
      r->GetBoolean("netifyd", "syn_scan_protection", false));
    ndGC_SetFlag(ndGlobalFlags::AUTO_FLOW_EXPIRY,
      r->GetBoolean("netifyd", "auto_flow_expiry", true));

    ttl_idle_flow = (unsigned)r->GetInteger("netifyd",
      "ttl_idle_flow", ND_TTL_IDLE_FLOW);
    ttl_idle_tcp_flow = (unsigned)r->GetInteger("netifyd",
      "ttl_idle_tcp_flow", ND_TTL_IDLE_TCP_FLOW);

    max_flows = (size_t)r->GetInteger("netifyd", "max_flows", 0);

    ndGC_SetFlag(ndGlobalFlags::SOFT_DISSECTORS,
      r->GetBoolean("netifyd", "soft_dissectors", true));

    ndGC_SetFlag(ndGlobalFlags::DOTD_CATEGORIES,
      r->GetBoolean("netifyd", "dotd_categories", true));

    fm_buckets = (unsigned)r->GetInteger("netifyd",
      "flow_map_buckets", ND_FLOW_MAP_BUCKETS);

    ndGC_SetFlag(ndGlobalFlags::USE_GETIFADDRS,
      r->GetBoolean(ND_NAME_SHORT, "use_getifaddrs",
#if defined(__FreeBSD__)
        true
#else
        false
#endif
        ));

    // Threading section
    ca_capture_base = (int16_t)r->GetInteger("threads",
      "capture_base", this->ca_capture_base);
    ca_conntrack = (int16_t)r->GetInteger("threads",
      "conntrack", this->ca_conntrack);
    ca_detection_base = (int16_t)r->GetInteger("threads",
      "detection_base", this->ca_detection_base);
    ca_detection_cores = (int16_t)r->GetInteger("threads",
      "detection_cores", this->ca_detection_cores);

    // Capture defaults section
    capture_read_timeout = (unsigned)r->GetInteger(
      "capture-defaults", "read_timeout", ND_CAPTURE_READ_TIMEOUT);
    capture_type = LoadCaptureType(reader,
      "capture-defaults", "capture_type");

    if (capture_type == ndCaptureType::NONE) {
#if defined(_ND_ENABLE_LIBPCAP)
        capture_type = ndCaptureType::PCAP;
#elif defined(_ND_ENABLE_TPACKETV3)
        capture_type = ndCaptureType::TPV3;
#elif defined(_ND_ENABLE_NFQUEUE)
        capture_type = ndCaptureType::TPV3;
#else
        fprintf(stderr,
          "Not default capture type could be "
          "determined.\n");
        return false;
#endif
    }

    // TPv3 capture defaults section
    ndFlags<ndCaptureType> ct = ndCaptureType::TPV3;
    if (
      ! LoadCaptureSettings(reader, "capture-defaults-tpv3",
        ct, static_cast<void *>(&tpv3_defaults)))
        return false;

    // Flow Hash Cache section
    ndGC_SetFlag(ndGlobalFlags::USE_FHC,
      r->GetBoolean("flow-hash-cache", "enable", true));

    string fhc_storage_mode = r->Get("flow-hash-cache",
      "save", "persistent");

    if (fhc_storage_mode == "persistent")
        fhc_storage = ndFHCStorage::PERSISTENT;
    else if (fhc_storage_mode == "volatile")
        fhc_storage = ndFHCStorage::VOLATILE;
    else fhc_storage = ndFHCStorage::DISABLED;

    max_fhc = (size_t)r->GetInteger("flow-hash-cache",
      "cache_size", ND_MAX_FHC_ENTRIES);
    fhc_purge_divisor = (size_t)r->GetInteger(
      "flow-hash-cache", "purge_divisor", ND_FHC_PURGE_DIVISOR);

    // DNS Cache section
    ndGC_SetFlag(ndGlobalFlags::USE_DHC,
      r->GetBoolean("dns-hint-cache", "enable", true));
    ndGC_SetFlag(ndGlobalFlags::DHC_PARTIAL_LOOKUPS,
      r->GetBoolean("dns-hint-cache", "partial_lookups", false));

    string dhc_storage_mode = r->Get("dns-hint-cache",
      "save", "persistent");

    if (dhc_storage_mode == "persistent" ||
      dhc_storage_mode == "1" || dhc_storage_mode == "yes" ||
      dhc_storage_mode == "true")
        dhc_storage = ndDHCStorage::PERSISTENT;
    else if (dhc_storage_mode == "volatile")
        dhc_storage = ndDHCStorage::VOLATILE;
    else dhc_storage = ndDHCStorage::DISABLED;

    max_dhc = (unsigned)r->GetInteger("dns-hint-cache",
      "cache-size", ND_MAX_DHC_ENTRIES);

    // Privacy filter section
    for (int i = 0;; i++) {
        ostringstream os;
        os << "mac[" << i << "]";
        string mac_addr = r->Get("privacy-filter", os.str(),
          "");

        if (mac_addr.size() == 0) break;

        uint8_t mac[ETH_ALEN];
        if (nd_string_to_mac(mac_addr, mac)) {
            uint8_t *p = new uint8_t[ETH_ALEN];
            memcpy(p, mac, ETH_ALEN);
            privacy_filter_mac.push_back(p);
        }
    }

    for (int i = 0;; i++) {
        ostringstream os;
        os << "host[" << i << "]";
        string host_addr = r->Get("privacy-filter",
          os.str(), "");

        if (host_addr.size() == 0) break;

        struct addrinfo hints;
        struct addrinfo *result, *rp;

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;

        int rc = getaddrinfo(host_addr.c_str(), NULL,
          &hints, &result);
        if (rc != 0) {
            fprintf(stderr, "host[%d]: %s: %s\n", i,
              host_addr.c_str(), gai_strerror(rc));
            continue;
        }

        for (rp = result; rp != NULL; rp = rp->ai_next) {
            struct sockaddr *saddr = new struct sockaddr;
            //reinterpret_cast<struct sockaddr *>(
            //  new uint8_t[rp->ai_addrlen]);
            memcpy(saddr, rp->ai_addr, rp->ai_addrlen);
            privacy_filter_host.push_back(saddr);
        }

        freeaddrinfo(result);
    }

    for (int i = 0;; i++) {
        ostringstream os;
        os << "regex_search[" << i << "]";
        string search = r->Get("privacy-filter", os.str(),
          "");

        os.str("");
        os << "regex_replace[" << i << "]";
        string replace = r->Get("privacy-filter", os.str(),
          "");

        if (search.size() == 0 || replace.size() == 0)
            break;

        try {
            regex *rx_search = new regex(search,
              regex::extended | regex::icase | regex::optimize);
            privacy_regex.push_back(make_pair(rx_search, replace));
        }
        catch (const regex_error &e) {
            string error;
            nd_regex_error(e, error);
            fprintf(stderr,
              "WARNING: %s: Error compiling privacy regex: "
              "%s: %s [%d]\n",
              filename.c_str(), search.c_str(),
              error.c_str(), e.code());
        }
    }

    ndGC_SetFlag(ndGlobalFlags::PRIVATE_EXTADDR,
      r->GetBoolean("privacy-filter",
        "private_external_addresses", false));

    // Netify API section
    ndGC_SetFlag(ndGlobalFlags::USE_NAPI,
      r->GetBoolean("netify-api", "enable", false));
    ttl_napi_tick = r->GetInteger("netify-api",
      "tick_interval", ND_TTL_API_TICK);
    ttl_napi_update = r->GetInteger("netify-api",
      "update_interval", ND_TTL_API_UPDATE);
    url_napi_bootstrap = r->Get("netify-api",
      "bootstrap_url", ND_URL_API_BOOTSTRAP);
    napi_vendor = r->Get("netify-api", "vendor", ND_API_VENDOR);
    napi_tls_verify = r->GetBoolean("netify-api",
      "tls_verify", true);

    // Protocols section
    r->GetSection("protocols", protocols);

    // Add plugins
    vector<string> files;
    if (nd_scan_dotd(path_plugins, files)) {
        for (auto &f : files) {
            if (! AddPlugin(path_plugins + "/" + f))
                return false;
        }
    }

    return true;
}

bool ndGlobalConfig::LoadUUID(ndUUID which, string &uuid) {
    size_t length = 0;
    string *dest = nullptr, path;
    lock_guard<mutex> ul(lock_uuid);

    uuid.clear();

    switch (which) {
    case ndUUID::NONE: return false;
    case ndUUID::AGENT:
        if (ndGC.uuid != ND_AGENT_UUID_NULL) {
            uuid = ndGC.uuid;
            return true;
        }
        dest = &ndGC.uuid;
        path = ndGC.path_uuid;
        length = ND_AGENT_UUID_LEN;
        break;
    case ndUUID::SITE:
        if (ndGC.uuid_site != ND_SITE_UUID_NULL) {
            uuid = ndGC.uuid_site;
            return true;
        }
        dest = &ndGC.uuid_site;
        path = ndGC.path_uuid_site;
        length = ND_SITE_UUID_LEN;
        break;
    case ndUUID::SERIAL:
        if (ndGC.uuid_serial != ND_AGENT_SERIAL_NULL) {
            uuid = ndGC.uuid_serial;
            return true;
        }
        dest = &ndGC.uuid_serial;
        path = ndGC.path_uuid_serial;
        length = ND_AGENT_SERIAL_LEN;
        break;
    }

    if (length > 0) {
        string _uuid;
        if (nd_load_uuid(_uuid, path, length)) {
            if (_uuid.empty()) return false;
            *dest = _uuid;
            uuid = _uuid;
            return true;
        }
    }

    return false;
}

bool ndGlobalConfig::SaveUUID(ndUUID which, const string &uuid) {
    size_t length = 0;
    string *dest = nullptr, path;
    lock_guard<mutex> ul(lock_uuid);

    switch (which) {
    case ndUUID::NONE: return false;
    case ndUUID::AGENT:
        dest = &ndGC.uuid;
        path = ndGC.path_uuid;
        length = ND_AGENT_UUID_LEN;
        break;
    case ndUUID::SITE:
        dest = &ndGC.uuid_site;
        path = ndGC.path_uuid_site;
        length = ND_SITE_UUID_LEN;
        break;
    case ndUUID::SERIAL:
        dest = &ndGC.uuid_serial;
        path = ndGC.path_uuid_serial;
        length = ND_AGENT_SERIAL_LEN;
        break;
    }

    if (length > 0) {
        if (uuid.size() != length) return false;

        if (nd_save_uuid(uuid, path, length)) {
            *dest = uuid;
            return true;
        }
    }

    return false;
}

void ndGlobalConfig::GetUUID(ndUUID which, string &uuid) {
    lock_guard<mutex> ul(lock_uuid);

    switch (which) {
    case ndUUID::AGENT: uuid = ndGC.uuid; break;
    case ndUUID::SITE: uuid = ndGC.uuid_site; break;
    case ndUUID::SERIAL: uuid = ndGC.uuid_serial; break;
    default: uuid.clear(); break;
    }
}

bool ndGlobalConfig::ForceReset(void) {
    vector<string> files = { path_uuid, path_uuid_site };

    int seconds = 3;
    fprintf(stdout,
      "%sWARNING%s: Resetting Agent state files in "
      "%s%d%s seconds...\n",
      ndTerm::Color::RED, ndTerm::Attr::RESET,
      ndTerm::Color::RED, seconds, ndTerm::Attr::RESET);
    for (; seconds >= 0; seconds--) {
        fprintf(stdout,
          "%sWARNING%s: Press CTRL-C to abort: %s%d%s\r",
          ndTerm::Color::RED, ndTerm::Attr::RESET,
          ndTerm::Color::RED, seconds, ndTerm::Attr::RESET);
        fflush(stdout);
        sleep(1);
    }
    fputc('\n', stdout);
    sleep(2);

    bool success = true;

    for (vector<string>::const_iterator i = files.begin();
         i != files.end();
         i++)
    {
        fprintf(stdout, "Deleting file: %s\n", (*i).c_str());
        if (unlink((*i).c_str()) != 0 && errno != ENOENT) {
            success = false;
            fprintf(stderr,
              "Error while removing file: %s: %s\n",
              (*i).c_str(), strerror(errno));
        }
    }

    string result;
    int rc = nd_functions_exec("restart_netifyd", string(), result);

    if (rc != 0) {
        success = false;
        fprintf(stderr,
          "Error while restarting agent.\n"
          "Manual restart is required for the reset to "
          "be completed.\n");
    }

    if (result.size())
        fprintf(stdout, "%s", result.c_str());

    if (rc == 0) fprintf(stdout, "Reset successful.\n");

    return success;
}

bool ndGlobalConfig::LoadInterfaces(const string &filename) {
    if (ndGC_IGNORE_IFACE_CONFIGS) return true;

    ClearInterfaces();

    if (! Open(filename)) return false;

    INIReader *config_reader = static_cast<INIReader *>(reader);
    if (! LoadInterfaces(static_cast<void *>(config_reader)))
        return false;

    vector<string> files;
    if (nd_scan_dotd(path_interfaces, files)) {
        for (auto &file : files) {
            INIReader r = INIReader(path_interfaces + "/" + file);

            int rc = r.ParseError();

            switch (rc) {
            case -1:
                fprintf(stderr,
                  "Error opening interface configuration "
                  "file: %s: %s\n",
                  file.c_str(), strerror(errno));
                return false;
            case 0: break;
            default:
                fprintf(stderr,
                  "Error while parsing line #%d of "
                  "interface file: %s\n",
                  rc, file.c_str());
                return false;
            }

            if (! LoadInterfaces(static_cast<void *>(&r)))
                return false;
        }
    }

    return true;
}

bool ndGlobalConfig::AddInterface(const string &iface,
  ndInterfaceRole role, ndFlags<ndCaptureType> type, void *config) {
    for (auto &r : interfaces) {
        auto i = interfaces[r.first].find(iface);
        if (i != interfaces[r.first].end()) {
            fprintf(stderr,
              "WARNING: interface already configured: %s\n",
              iface.c_str());
            return true;
        }
    }

    if (ndCT_TYPE(type.flags) == ndCaptureType::NONE) {
        if (ndCT_TYPE(capture_type.flags) == ndCaptureType::NONE)
        {
            fprintf(stderr,
              "WARNING: capture type not set for "
              "interface: %s\n",
              iface.c_str());
            return false;
        }

        type = capture_type;
    }

    if (config == nullptr) {
        switch (ndCT_TYPE(type.flags)) {
        case ndCaptureType::PCAP:
        case ndCaptureType::PCAP_OFFLINE:
            config = static_cast<void *>(new nd_config_pcap);
            break;
        case ndCaptureType::TPV3:
            config = static_cast<void *>(new nd_config_tpv3);
            memcpy(config, &tpv3_defaults, sizeof(nd_config_tpv3));
            break;
        case ndCaptureType::NFQ:
            config = static_cast<void *>(new nd_config_nfq);
        default: break;
        }
    }

    auto result = interfaces[role].insert(
      make_pair(iface, make_pair(type, config)));

    if (! result.second) {
        switch (ndCT_TYPE(type.flags)) {
        case ndCaptureType::PCAP:
        case ndCaptureType::PCAP_OFFLINE:
            delete static_cast<nd_config_pcap *>(config);
            break;
        case ndCaptureType::TPV3:
            delete static_cast<nd_config_tpv3 *>(config);
            break;
        case ndCaptureType::NFQ:
            delete static_cast<nd_config_nfq *>(config);
            break;
        default: break;
        }
    }

    return result.second;
}

bool ndGlobalConfig::AddInterfaceAddress(const string &iface,
  const string &addr) {
    auto it = interface_addrs.find(iface);

    if (it != interface_addrs.end()) {
        auto result = it->second.insert(addr);

        if (result.second == false) {
            fprintf(stderr,
              "WARNING: address (%s) already associated "
              "with interface: %s\n",
              addr.c_str(), iface.c_str());

            return false;
        }

        return true;
    }

    auto result = interface_addrs[iface].insert(addr);

    return result.second;
}

bool ndGlobalConfig::AddInterfacePeer(const string &iface,
  const string &peer) {
    auto result = interface_peers.insert(make_pair(iface, peer));

    if (result.second == false) {
        fprintf(stderr,
          "WARNING: peer (%s) already associated with "
          "interface: %s\n",
          peer.c_str(), iface.c_str());
    }

    return result.second;
}

bool ndGlobalConfig::AddInterfaceFilter(const string &iface,
  const string &filter) {
    auto result = interface_filters.insert(make_pair(iface, filter));

    if (result.second == false) {
        fprintf(stderr,
          "WARNING: a filter is already attached to "
          "interface: %s\n",
          iface.c_str());
    }

    return result.second;
}

bool ndGlobalConfig::LoadInterfaces(void *config_reader) {
    INIReader *r = static_cast<INIReader *>(config_reader);

    set<string> sections;
    r->GetSections(sections);

    for (auto &s : sections) {
        std::cout << "string: " << s << std::endl;
        static const char *key = "capture-interface-";
        static const size_t key_len = strlen(key);

        if (strncasecmp(s.c_str(), key, key_len)) continue;

        size_t p = strlen(key) >= s.size() ?
          string::npos :
          strlen(key);
        if (p == string::npos) continue;

        string iface = s.substr(p);

        string interface_role = r->Get(s, "role", "none");

        ndInterfaceRole role = ndInterfaceRole::NONE;

        if (! strcasecmp("LAN", interface_role.c_str()) ||
          ! strncasecmp("INT", interface_role.c_str(), 3))
            role = ndInterfaceRole::LAN;
        else if (! strcasecmp("WAN", interface_role.c_str()) ||
          ! strncasecmp("EXT", interface_role.c_str(), 3))
            role = ndInterfaceRole::WAN;

        if (role == ndInterfaceRole::NONE) {
            fprintf(stderr,
              "WARNING: interface role not set or invalid: "
              "%s\n",
              iface.c_str());
            continue;
        }

        auto ri = interfaces.find(role);
        if (ri != interfaces.end()) {
            auto i = interfaces[ri->first].find(iface);
            if (i != interfaces[ri->first].end()) {
                fprintf(stderr,
                  "WARNING: interface already configured: "
                  "%s\n",
                  iface.c_str());
                continue;
            }
        }

        ndFlags<ndCaptureType> type = LoadCaptureType(r, s,
          "capture_type");

        void *config = nullptr;

        switch (ndCT_TYPE(type.flags)) {
        case ndCaptureType::PCAP:
            config = static_cast<void *>(new nd_config_pcap);
            if (! LoadCaptureSettings(r, s, type, config)) {
                delete static_cast<nd_config_pcap *>(config);
                return false;
            }
            break;
        case ndCaptureType::TPV3:
            config = static_cast<void *>(new nd_config_tpv3);
            memcpy(config, &tpv3_defaults, sizeof(nd_config_tpv3));
            if (! LoadCaptureSettings(r, s, type, config)) {
                delete static_cast<nd_config_tpv3 *>(config);
                return false;
            }
            break;
        case ndCaptureType::NFQ:
            p = iface.find_first_of("0123456789");
            if (p == string::npos ||
              strncasecmp(iface.c_str(), "nfq", 3))
            {
                fprintf(stderr,
                  "Invalid NFQUEUE identifier: %s\n",
                  iface.c_str());
                return false;
            }
            config = static_cast<void *>(new nd_config_nfq);
            if (! LoadCaptureSettings(r, s, type, config)) {
                delete static_cast<nd_config_nfq *>(config);
                return false;
            }
            static_cast<nd_config_nfq *>(config)->queue_id =
              (unsigned)strtol(iface.substr(p).c_str(), NULL, 0);
            break;
        default: break;
        }

        AddInterface(iface, role, type, config);

        for (int i = 0;; i++) {
            ostringstream os;
            os << "address[" << i << "]";
            string addr = r->Get(s, os.str(), "");

            if (addr.size() == 0) break;

            AddInterfaceAddress(iface, addr);
        }

        string peer = r->Get(s, "peer", "");

        if (peer.size()) AddInterfacePeer(iface, peer);

        string filter = r->Get(s, "filter", "");

        if (filter.size())
            AddInterfaceFilter(iface, filter);
    }

    return true;
}

void ndGlobalConfig::ClearInterfaces(bool cmdline_entries) {
    list<string> clear_list;

    if (interfaces.size()) {
        for (auto &r : interfaces) {
            for (auto &i : r.second) {
                if (((i.second.first & ndCaptureType::CMDLINE) ==
                      ndCaptureType::CMDLINE) &&
                  ! cmdline_entries)
                    continue;

                clear_list.push_back(i.first);
            }
        }
    }

    for (const string &iface : clear_list) {
        for (auto &r : interfaces) {
            auto it = r.second.find(iface);
            if (it == r.second.end()) continue;

            if (it->second.second != nullptr) {
                switch (ndCT_TYPE(it->second.first.flags)) {
                case ndCaptureType::PCAP:
                case ndCaptureType::PCAP_OFFLINE:
                    delete static_cast<nd_config_pcap *>(
                      it->second.second);
                    break;
                case ndCaptureType::TPV3:
                    delete static_cast<nd_config_tpv3 *>(
                      it->second.second);
                    break;
                case ndCaptureType::NFQ:
                    delete static_cast<nd_config_nfq *>(
                      it->second.second);
                    break;
                default: break;
                }
            }

            r.second.erase(it);
        }

        auto ifp = interface_peers.find(iface);
        if (ifp != interface_peers.end())
            interface_peers.erase(ifp);

        auto ifa = interface_addrs.find(iface);
        if (ifa != interface_addrs.end())
            interface_addrs.erase(ifa);
    }
}

ndFlags<ndCaptureType>
ndGlobalConfig::LoadCaptureType(void *config_reader,
  const string &section, const string &key) const {
    INIReader *r = static_cast<INIReader *>(config_reader);

    ndFlags<ndCaptureType> ct = ndCaptureType::NONE;
    string capture_type = r->Get(section, key, "auto");

    if (capture_type == "auto") {
#if defined(_ND_ENABLE_LIBPCAP)
        ct = ndCaptureType::PCAP;
#elif defined(_ND_ENABLE_TPACKETV3)
        ct = ndCaptureType::TPV3;
#else
#error "No available capture types!"
#endif
    }
#if defined(_ND_ENABLE_LIBPCAP)
    else if (capture_type == "pcap")
        ct = ndCaptureType::PCAP;
#endif
#if defined(_ND_ENABLE_TPACKETV3)
    else if (capture_type == "tpv3")
        ct = ndCaptureType::TPV3;
#endif
#if defined(_ND_ENABLE_NFQUEUE)
    else if (capture_type == "nfqueue")
        ct = ndCaptureType::NFQ;
#endif
    else {
        throw ndException("invalid capture type: %s",
          capture_type.c_str());
    }

    return ct;
}

bool ndGlobalConfig::LoadCaptureSettings(void *config_reader,
  const string &section, ndFlags<ndCaptureType> &type,
  void *config) const {
    INIReader *r = static_cast<INIReader *>(config_reader);

    if (ndCT_TYPE(type.flags) == ndCaptureType::PCAP) {
        nd_config_pcap *pcap = static_cast<nd_config_pcap *>(config);
        string capture_filename = r->Get(section,
          "filename", "");

        if (! capture_filename.empty()) {
            if (! nd_file_exists(capture_filename)) {
                fprintf(stderr,
                  "Capture file not found: %s\n",
                  capture_filename.c_str());
                return false;
            }

            if (! ((type & ndCaptureType::CMDLINE) ==
                  ndCaptureType::CMDLINE))
                type = ndCaptureType::PCAP_OFFLINE;
            else
                type = ndCaptureType::PCAP_OFFLINE |
                  ndCaptureType::CMDLINE;
            pcap->capture_filename = capture_filename;
        }
    }
    else if (ndCT_TYPE(type.flags) == ndCaptureType::TPV3) {
        nd_config_tpv3 *tpv3 = static_cast<nd_config_tpv3 *>(config);

        string fanout_mode = r->Get(section, "fanout_mode",
          "none");

        if (fanout_mode == "hash")
            tpv3->fanout_mode = ndTPv3FanoutMode::HASH;
        else if (fanout_mode == "lb" ||
          fanout_mode == "load_balanced")
            tpv3->fanout_mode = ndTPv3FanoutMode::LOAD_BALANCED;
        else if (fanout_mode == "cpu")
            tpv3->fanout_mode = ndTPv3FanoutMode::CPU;
        else if (fanout_mode == "rollover")
            tpv3->fanout_mode = ndTPv3FanoutMode::ROLLOVER;
        else if (fanout_mode == "random")
            tpv3->fanout_mode = ndTPv3FanoutMode::RANDOM;
        else tpv3->fanout_mode = ndTPv3FanoutMode::DISABLED;

        string fanout_flags = r->Get(section,
          "fanout_flags", "none");

        if (fanout_flags != "none") {
            stringstream ss(fanout_flags);

            while (ss.good()) {
                string flag;
                getline(ss, flag, ',');

                nd_trim(flag, ' ');

                if (flag == "defrag")
                    tpv3->fanout_flags |= ndTPv3FanoutFlags::DEFRAG;
                else if (flag == "rollover")
                    tpv3->fanout_flags |= ndTPv3FanoutFlags::ROLLOVER;
                else {
                    fprintf(stderr,
                      "Invalid fanout flag: %s\n", flag.c_str());
                    return false;
                }
            }
        }

        tpv3->fanout_instances = (unsigned)r->GetInteger(
          section, "fanout_instances", 0);

        if (tpv3->fanout_mode != ndTPv3FanoutMode::DISABLED &&
          tpv3->fanout_instances < 2)
        {
            tpv3->fanout_mode = ndTPv3FanoutMode::DISABLED;
            tpv3->fanout_instances = 0;
        }

        tpv3->rb_block_size = (unsigned)r->GetInteger(section,
          "rb_block_size", tpv3_defaults.rb_block_size);

        tpv3->rb_frame_size = (unsigned)r->GetInteger(section,
          "rb_frame_size", tpv3_defaults.rb_frame_size);

        tpv3->rb_blocks = (unsigned)r->GetInteger(section,
          "rb_blocks", tpv3_defaults.rb_blocks);
    }
    else if (ndCT_TYPE(type.flags) == ndCaptureType::NFQ) {
        nd_config_nfq *nfq = static_cast<nd_config_nfq *>(config);
        nfq->instances = (unsigned)r->GetInteger(section,
          "queue_instances", 1);
    }

    return true;
}

bool ndGlobalConfig::AddPlugin(const string &filename) {
    INIReader r = INIReader(filename);

    int rc = r.ParseError();

    switch (rc) {
    case -1:
        fprintf(stderr,
          "Error opening plugin configuration file: "
          "%s: %s\n",
          filename.c_str(), strerror(errno));
        return false;
    case 0: break;
    default:
        fprintf(stderr,
          "Error while parsing line #%d of plugin "
          "configuration file: %s\n",
          rc, filename.c_str());
        return false;
    }

    set<string> sections;
    r.GetSections(sections);

    for (auto &tag : sections) {
        size_t p = string::npos;
        Plugins *mpi = nullptr;
        ndPlugin::Type type = ndPlugin::Type::BASE;

        if ((p = tag.find("proc-")) != string::npos) {
            mpi = &plugin_processors;
            type = ndPlugin::Type::PROC;
        }
        else if ((p = tag.find("sink-")) != string::npos) {
            mpi = &plugin_sinks;
            type = ndPlugin::Type::SINK;
        }

        if (mpi == nullptr || p != 0) continue;
        if (! r.GetBoolean(tag, "enable", true)) continue;

        string so_name;
        nd_expand_variables(r.Get(tag, "plugin_library", ""),
          so_name, conf_vars);

        if (so_name.empty()) {
            fprintf(stderr, "Plugin library not set: %s\n",
              tag.c_str());
            return false;
        }

        static vector<string> keys = {
            "conf_filename",
        };

        ndPlugin::Params params;

        for (auto &key : keys) {
            string value = r.Get(tag, key, "");
            if (value.empty()) continue;
            switch (type) {
#if 0
            case ndPlugin::Type::SINK:
                if (key == "sink_targets") {
                    fprintf(stderr, "Invalid plugin option: %s: %s\n",
                        tag.c_str(), key.c_str()
                    );
                    return false;
                }
                break;
#endif
            default: break;
            }

            string expanded;
            nd_expand_variables(value, expanded, conf_vars);
            params.insert(make_pair(key, expanded));
        }
#if 0
        // XXX: Do we really need to validate the plugin here?
        try {
            ndPluginLoader loader(tag, so_name, params);

            if (type != loader.GetPlugin()->GetType()) {
                fprintf(stderr,
                  "Invalid plugin type: %s: %d (expected: "
                  "%d)\n",
                  tag.c_str(),
                  static_cast<unsigned>(loader.GetPlugin()->GetType()),
                  static_cast<unsigned>(type));
                return false;
            }
        }
        catch (exception &e) {
            fprintf(stderr, "Plugin cannot be loaded: %s\n",
              e.what());
            return false;
        }
#endif
        if (! mpi
                ->insert(make_pair(tag, make_pair(so_name, params)))
                .second)
        {
            fprintf(stderr,
              "Duplicate plugin tag found: %s\n", tag.c_str());
            return false;
        }
    }

    return true;
}

void ndGlobalConfig::UpdatePaths(void) {
    path_app_config = path_state_persistent + "/" + ND_CONF_APP_BASE;

    path_cat_config = path_state_persistent + "/" + ND_CONF_CAT_BASE;

    path_legacy_config = path_state_persistent + "/" +
      ND_CONF_LEGACY_BASE;

    path_agent_status = path_state_volatile + "/" + ND_AGENT_STATUS_BASE;

    path_plugins = path_state_persistent + "/" + ND_PLUGINS_BASE;

    path_plugin_libdir = ND_PLUGIN_LIBDIR;

    path_categories = path_state_persistent + "/" + ND_CATEGORIES_BASE;

    path_functions = path_shared_data + "/" + ND_FUNCTIONS_BASE;

    path_interfaces = path_state_persistent + "/" + ND_INTERFACES_BASE;
}

void ndGlobalConfig::UpdateConfigVars(void) {
    conf_vars.clear();

    conf_vars.insert(make_pair("${path_state_persistent}",
      path_state_persistent));
    conf_vars.insert(make_pair("${path_state_volatile}",
      ndGC.path_state_volatile));
    conf_vars.insert(
      make_pair("${path_app_config}", path_app_config));
    conf_vars.insert(
      make_pair("${path_category_config}", path_cat_config));
    conf_vars.insert(make_pair("${path_plugins}", path_plugins));
    conf_vars.insert(
      make_pair("${path_plugin_libdir}", path_plugin_libdir));
    conf_vars.insert(
      make_pair("${path_categories}", path_categories));
    conf_vars.insert(
      make_pair("${path_interfaces}", path_interfaces));
}
