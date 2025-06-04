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

#include <iostream>
#include <map>
#include <mutex>
#include <regex>
#include <set>
#include <string>
#include <type_traits>
#include <vector>

#include "nd-flags.hpp"
#include "nd-sha1.h"
#include "nd-util.hpp"
#include "netifyd.hpp"

enum class ndUUID : uint8_t {
    NONE,
    AGENT,
    SITE,
    SERIAL,
};

enum class ndVerbosityFlags : uint8_t {
    NONE = 0,
    EVENT_DPI_NEW = (1 << 0),
    EVENT_DPI_UPDATE = (1 << 1),
    EVENT_DPI_COMPLETE = (1 << 2),
};

enum class ndDHCStorage : uint8_t {
    DISABLED,
    PERSISTENT,
    VOLATILE,
};

enum class ndFHCStorage : uint8_t {
    DISABLED,
    PERSISTENT,
    VOLATILE,
};

enum class ndCaptureType : uint32_t {
    NONE = 0,
    CMDLINE = (1 << 0),
    PCAP = (1 << 1),
    PCAP_OFFLINE = (1 << 2),
    TPV3 = (1 << 3),
    NFQ = (1 << 4),

    USER = (1 << 30),
};

#define ndCT_TYPE(t) \
    static_cast<ndCaptureType>( \
      static_cast<std::underlying_type<ndCaptureType>::type>(t) & \
      static_cast<std::underlying_type<ndCaptureType>::type>( \
        ~ndCaptureType::CMDLINE))

enum class ndInterfaceRole : uint8_t {
    NONE,
    LAN,
    WAN,
};

enum class ndTPv3FanoutMode : uint8_t {
    DISABLED,
    HASH,
    LOAD_BALANCED,
    CPU,
    ROLLOVER,
    RANDOM,
    QUEUE_MAP,
};

enum class ndTPv3FanoutFlags : uint8_t {
    NONE = 0,
    DEFRAG = (1 << 0),
    ROLLOVER = (1 << 1),
};

enum class ndGlobalFlags : uint32_t {
    NONE = 0,
    DEBUG = (1 << 0),
    DEBUG_CURL = (1 << 1),
    FREE_BIT3 = (1 << 2),
    DEBUG_NDPI = (1 << 3),
    QUIET = (1 << 4),
    SYN_SCAN_PROTECTION = (1 << 5),
    PRIVATE_EXTADDR = (1 << 6),
    SSL_USE_TLSv1 = (1 << 7),
    SSL_VERIFY = (1 << 8),
    USE_CONNTRACK = (1 << 9),
    USE_NETLINK = (1 << 10),
    USE_NAPI = (1 << 11),
    USE_DHC = (1 << 12),
    USE_FHC = (1 << 13),
    EXPORT_JSON = (1 << 14),
    VERBOSE = (1 << 15),
    DHC_PARTIAL_LOOKUPS = (1 << 16),
    REPLAY_DELAY = (1 << 17),
    REMAIN_IN_FOREGROUND = (1 << 18),
    ALLOW_UNPRIV = (1 << 19),
    IGNORE_IFACE_CONFIGS = (1 << 20),
    UPLOAD_ENABLED = (1 << 21),
    UPLOAD_NAT_FLOWS = (1 << 22),
    AUTO_FLOW_EXPIRY = (1 << 23),
    SOFT_DISSECTORS = (1 << 24),
    DOTD_CATEGORIES = (1 << 25),
    RUN_WITHOUT_SOURCES = (1 << 26),
    AUTO_INFORMATICS = (1 << 27),
    USE_GETIFADDRS = (1 << 28),
};

#define ndGC_DEBUG \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::DEBUG)
#define ndGC_DEBUG_CURL \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::DEBUG_CURL)
#define ndGC_DEBUG_NDPI \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::DEBUG_NDPI)
#define ndGC_QUIET \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::QUIET)
#define ndGC_OVERRIDE_LEGACY_CONFIG \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::OVERRIDE_LEGACY_CONFIG)
#define ndGC_SYN_SCAN_PROTECTION \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::SYN_SCAN_PROTECTION)
#define ndGC_PRIVATE_EXTADDR \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::PRIVATE_EXTADDR)
#define ndGC_SSL_USE_TLSv1 \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::SSL_USE_TLSv1)
#define ndGC_SSL_VERIFY \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::SSL_VERIFY)
#define ndGC_USE_CONNTRACK \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::USE_CONNTRACK)
#define ndGC_USE_NETLINK \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::USE_NETLINK)
#define ndGC_USE_NAPI \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::USE_NAPI)
#define ndGC_USE_DHC \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::USE_DHC)
#define ndGC_USE_FHC \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::USE_FHC)
#define ndGC_EXPORT_JSON \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::EXPORT_JSON)
#define ndGC_VERBOSE \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::VERBOSE)
#define ndGC_DHC_PARTIAL_LOOKUPS \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::DHC_PARTIAL_LOOKUPS)
#define ndGC_REPLAY_DELAY \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::REPLAY_DELAY)
#define ndGC_REMAIN_IN_FOREGROUND \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::REMAIN_IN_FOREGROUND)
#define ndGC_ALLOW_UNPRIV \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::ALLOW_UNPRIV)
#define ndGC_IGNORE_IFACE_CONFIGS \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::IGNORE_IFACE_CONFIGS)
#define ndGC_UPLOAD_ENABLED \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::UPLOAD_ENABLED)
#define ndGC_UPLOAD_NAT_FLOWS \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::UPLOAD_NAT_FLOWS)
#define ndGC_AUTO_FLOW_EXPIRY \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::AUTO_FLOW_EXPIRY)
#define ndGC_SOFT_DISSECTORS \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::SOFT_DISSECTORS)
#define ndGC_DOTD_CATEGORIES \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::DOTD_CATEGORIES)
#define ndGC_RUN_WITHOUT_SOURCES \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::RUN_WITHOUT_SOURCES)
#define ndGC_AUTO_INFORMATICS \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::AUTO_INFORMATICS)
#define ndGC_USE_GETIFADDRS \
    ndFlagBoolean(ndGlobalConfig::GetInstance().flags, \
      ndGlobalFlags::USE_GETIFADDRS)

#define ndGC ndGlobalConfig::GetInstance()

#define ndGC_SetFlag(flag, value) \
    if (value) \
        ndGlobalConfig::GetInstance().flags |= flag; \
    else ndGlobalConfig::GetInstance().flags &= ~flag

typedef struct nd_config_pcap_t {
    std::string capture_filename;

    inline bool operator==(const struct nd_config_pcap_t &i) const {
        return (capture_filename == i.capture_filename);
    }
} nd_config_pcap;

typedef struct nd_config_tpv3_t {
    ndTPv3FanoutMode fanout_mode{ ndTPv3FanoutMode::DISABLED };
    ndFlags<ndTPv3FanoutFlags> fanout_flags{ ndTPv3FanoutFlags::NONE };
    unsigned fanout_instances{ 0 };
    unsigned rb_block_size{ ND_TPV3_RB_BLOCK_SIZE };
    unsigned rb_frame_size{ ND_TPV3_RB_FRAME_SIZE };
    unsigned rb_blocks{ ND_TPV3_RB_BLOCKS };

    inline bool operator==(const struct nd_config_tpv3_t &i) const {
        if (fanout_mode != i.fanout_mode) return false;
        if (fanout_flags != i.fanout_flags) return false;
        if (fanout_instances != i.fanout_instances)
            return false;
        if (rb_block_size != i.rb_block_size) return false;
        if (rb_frame_size != i.rb_frame_size) return false;
        if (rb_blocks != i.rb_blocks) return false;
        return true;
    }
} nd_config_tpv3;

typedef struct nd_config_nfq_t {
    unsigned queue_id{ 0 };
    unsigned instances{ 0 };

    inline bool operator==(const struct nd_config_nfq_t &i) const {
        return (queue_id == i.queue_id && instances == i.instances);
    }
} nd_config_nfq;

class ndGlobalConfig
{
public:
    bool napi_tls_verify;
    std::string napi_vendor;
    std::string path_agent_status;
    std::string path_app_config;
    std::string path_cat_config;
    std::string path_categories;
    std::string path_config;
    std::string path_export_json;
    std::string path_functions;
    std::string path_interfaces;
    std::string path_legacy_config;
    std::string path_pid_file;
    std::string path_plugins;
    std::string path_plugin_libdir;
    std::string path_shared_data;
    std::string path_state_persistent;
    std::string path_state_volatile;
    std::string path_uuid;
    std::string path_uuid_serial;
    std::string path_uuid_site;
    std::string url_napi_bootstrap;
    ndDHCStorage dhc_storage;
    ndFHCStorage fhc_storage;
    ndFlags<ndCaptureType> capture_type;
    unsigned capture_read_timeout;
    nd_config_tpv3 tpv3_defaults;
    FILE *h_flow;
    int16_t ca_capture_base;
    int16_t ca_conntrack;
    int16_t ca_detection_base;
    int16_t ca_detection_cores;
    size_t max_packet_queue;
    uint16_t max_capture_length;
    ndFlags<ndGlobalFlags> flags;
    uint8_t verbosity;
    ndFlags<ndVerbosityFlags> verbosity_flags;
    unsigned fhc_purge_divisor;
    unsigned fm_buckets;
    unsigned max_detection_pkts;
    unsigned max_dhc;
    unsigned max_fhc;
    unsigned max_flows;
    unsigned ttl_capture_delay;
    unsigned ttl_idle_flow;
    unsigned ttl_idle_tcp_flow;
    unsigned ttl_napi_tick;
    unsigned ttl_napi_update;
    unsigned update_imf;
    unsigned update_interval;

    typedef std::vector<std::pair<std::string, std::string>> SocketHosts;
    SocketHosts socket_host;

    typedef std::vector<std::string> SocketPaths;
    SocketPaths socket_path;

    typedef std::vector<struct sockaddr *> PrivacyFilterHosts;
    PrivacyFilterHosts privacy_filter_host;

    typedef std::vector<uint8_t *> PrivacyFilterMACs;
    PrivacyFilterMACs privacy_filter_mac;

    typedef std::vector<std::pair<std::regex *, std::string>> PrivacyFilterRegex;
    PrivacyFilterRegex privacy_regex;

    typedef std::map<std::string, std::string> InterfaceFilters;
    InterfaceFilters interface_filters;

    typedef std::map<std::string,
      std::pair<std::string, std::map<std::string, std::string>>>
      Plugins;
    Plugins plugin_processors;
    Plugins plugin_sinks;

    typedef std::map<std::string, std::string> CustomHeaders;
    CustomHeaders custom_headers;

    typedef std::map<std::string, std::string> Protocols;
    Protocols protocols;

    typedef std::map<std::string, std::pair<ndFlags<ndCaptureType>, void *>> Interfaces;
    typedef std::map<ndInterfaceRole, Interfaces> InterfacesByRole;
    InterfacesByRole interfaces;

    typedef std::map<std::string, std::set<std::string>> InterfaceAddrs;
    InterfaceAddrs interface_addrs;

    typedef std::map<std::string, std::string> InterfacePeers;
    InterfacePeers interface_peers;

    typedef std::map<std::string, std::string> ConfVars;
    ConfVars conf_vars;

    typedef std::vector<std::string> FlowDebugExpressions;
    FlowDebugExpressions debug_flow_print_exprs;

    ndGlobalConfig(const ndGlobalConfig &) = delete;
    ndGlobalConfig &operator=(const ndGlobalConfig &) = delete;

    static inline ndGlobalConfig &GetInstance() {
        static ndGlobalConfig config;
        return config;
    }

    bool Open(const std::string &filename);
    void Close(void);

    bool Load(const std::string &filename);

    bool LoadUUID(ndUUID which, std::string &uuid);
    bool SaveUUID(ndUUID which, const std::string &uuid);
    void GetUUID(ndUUID which, std::string &uuid);

    bool ForceReset(void);

    bool LoadInterfaces(const std::string &filename);

    bool AddInterface(const std::string &iface,
      ndInterfaceRole role,
      ndFlags<ndCaptureType> type = ndCaptureType::NONE,
      void *config = nullptr);

    bool AddInterfaceAddress(const std::string &iface,
      const std::string &addr);
    bool AddInterfacePeer(const std::string &iface,
      const std::string &peer);

    bool AddInterfaceFilter(const std::string &iface,
      const std::string &filter);

protected:
    void *reader;
    std::mutex lock_uuid;

    std::string uuid;
    std::string uuid_serial;
    std::string uuid_site;

    bool LoadInterfaces(void *config_reader);
    void ClearInterfaces(bool cmdline_entries = false);

    ndFlags<ndCaptureType> LoadCaptureType(void *config_reader,
      const std::string &section, const std::string &key) const;
    bool LoadCaptureSettings(void *config_reader,
      const std::string &section,
      ndFlags<ndCaptureType> &type, void *config) const;

    bool AddPlugin(const std::string &filename);

    void UpdatePaths(void);
    void UpdateConfigVars(void);

private:
    ndGlobalConfig();
    virtual ~ndGlobalConfig();
};
