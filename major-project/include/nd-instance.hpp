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

#include <atomic>
#include <csignal>
#include <type_traits>

#include "nd-apps.hpp"
#include "nd-category.hpp"
#include "nd-config.hpp"
#include "nd-dhc.hpp"
#include "nd-except.hpp"
#include "nd-fhc.hpp"
#include "nd-flow-map.hpp"
#include "nd-napi.hpp"
#include "nd-packet.hpp"
#include "nd-plugin.hpp"
#include "nd-protos.hpp"
#include "nd-serializer.hpp"
#include "nd-signal.hpp"
#include "nd-thread.hpp"
#include "nd-util.hpp"

#ifdef _ND_ENABLE_CONNTRACK
#include "nd-conntrack.hpp"
#endif

#ifdef _ND_ENABLE_NETLINK
#include "nd-netlink.hpp"
#endif

class ndInstanceStatus : public ndSerializer
{
public:
    ndInstanceStatus();

    long cpus = { 0 };
    struct timespec ts_epoch = { 0, 0 };
    struct timespec ts_now = { 0, 0 };
    std::atomic<size_t> flows = { 0 };
    size_t flows_prev = { 0 };
    size_t flows_purged = { 0 };
    size_t flows_expiring = { 0 };
    size_t flows_expired = { 0 };
    size_t flows_active = { 0 };
    size_t flows_in_use = { 0 };
    double cpu_user = { 0 };
    double cpu_user_prev = { 0 };
    double cpu_system = { 0 };
    double cpu_system_prev = { 0 };
    size_t maxrss_kb = { 0 };
    size_t maxrss_kb_prev = { 0 };
#ifdef _ND_ENABLE_LIBTCMALLOC
    size_t tcm_alloc_kb = { 0 };
    size_t tcm_alloc_kb_prev = { 0 };
#endif
    bool dhc_status = { false };
    bool fhc_status = { false };

    template <class T>
    void Encode(T &output) const {
        serialize(output, { "timestamp" }, time(NULL));
        serialize(output, { "update_interval" }, ndGC.update_interval);
        serialize(output, { "update_imf" }, ndGC.update_imf);
        serialize(output, { "uptime" },
          unsigned(ts_now.tv_sec - ts_epoch.tv_sec));
        serialize(output, { "cpu_cores" }, (unsigned)cpus);
        serialize(output, { "cpu_user" }, cpu_user);
        serialize(output, { "cpu_user_prev" }, cpu_user_prev);
        serialize(output, { "cpu_system" }, cpu_system);
        serialize(output, { "cpu_system_prev" }, cpu_system_prev);
        serialize(output, { "flow_count" }, flows.load());
        serialize(output, { "flow_count_prev" }, flows_prev);
        serialize(output, { "flows_purged" }, flows_purged);
        serialize(output, { "flows_expiring" }, flows_expiring);
        serialize(output, { "flows_expired" }, flows_expired);
        serialize(output, { "flows_active" }, flows_active);
        serialize(output, { "flows_in_use" }, flows_in_use);
        serialize(output, { "maxrss_kb" }, maxrss_kb);
        serialize(output, { "maxrss_kb_prev" }, maxrss_kb_prev);
#ifdef _ND_ENABLE_LIBTCMALLOC
        serialize(output, { "tcm_kb" }, (unsigned)tcm_alloc_kb);
        serialize(output, { "tcm_kb_prev" },
          (unsigned)tcm_alloc_kb_prev);
#endif  // _ND_ENABLE_LIBTCMALLOC
        serialize(output, { "dhc_status" }, dhc_status);
        serialize(output, { "fhc_status" }, fhc_status);
    }
};

class ndCaptureThread;
class ndDetectionThread;
class ndNetifyApiManager;
#ifdef _ND_ENABLE_CONNTRACK
class ndConntrackThread;
#endif

typedef std::map<int16_t, ndDetectionThread *> ndDetectionThreads;
typedef std::map<std::string, std::vector<ndCaptureThread *>> ndCaptureThreads;
typedef std::map<std::string, ndPacketStats> ndInterfaceStats;

class ndInstance : public ndThread, public ndSerializer
{
public:
    static ndInstance &
    Create(const std::string &tag = "nd-instance");

    static void Destroy(void);

    ndInstance() = delete;
    ndInstance(const ndInstance &) = delete;
    ndInstance &operator=(const ndInstance &) = delete;

    static inline ndInstance &GetInstance() {
        if (instance == nullptr) {
            throw ndException("%s: instance not found",
              __PRETTY_FUNCTION__);
        }
        return *instance;
    }

    static void
    InitializeSignals(sigset_t &sigset, bool minimal = false);

    enum class ConfigResult : uint32_t {
        OK,
        AGENT_STATUS,
        DISABLED_OPTION,
        DISABLE_PLUGIN,
        DUMP_LIST,
        EDIT_PLUGIN,
        ENABLE_PLUGIN,
        EXPORT_APPS,
        FORCE_RESULT,
        GENERATE_UUID,
        HASH_TEST,
        INVALID_INTERFACE,
        INVALID_INTERFACES,
        INVALID_OPTION,
        INVALID_PERMS,
        INVALID_VALUE,
        LIBCURL_FAILURE,
        LOAD_FAILURE,
        LOOKUP_ADDR,
        PROVISION_UUID,
        SAVE_UUID_FAILURE,
        SET_CONFIG,
        USAGE_OR_VERSION,
    };

#define ndCR_Pack(r, c) \
    ((c << 16) + (ndEnumCast(ndInstance::ConfigResult, r) & 0x0000ffff))
#define ndCR_Code(c) ((c & 0xffff0000) >> 16)
#define ndCR_Result(r) \
    static_cast<ndInstance::ConfigResult>(r & 0x0000ffff)

    uint32_t InitializeConfig(int argc, char * const argv[]);

    bool InitializeTimers(int sig_update = ND_SIG_UPDATE,
      int sig_update_napi = ND_SIG_UPDATE_NAPI);

    bool Daemonize(void);

    enum class DumpFlags : uint16_t {
        NONE = 0,
        TYPE_PROTOS = (1 << 0),
        TYPE_APPS = (1 << 1),
        TYPE_CAT_APP = (1 << 2),
        TYPE_CAT_PROTO = (1 << 3),
        TYPE_RISKS = (1 << 4),
        TYPE_VALID = (1 << 5),
        SORT_BY_TAG = (1 << 6),
        WITH_CATS = (1 << 7),
        TYPE_CATS = (TYPE_CAT_APP | TYPE_CAT_PROTO),
        TYPE_ALL = (TYPE_PROTOS | TYPE_APPS)
    };

    template <class T>
    void Encode(T &output) const {
        serialize(output, { "build_version" },
          nd_get_version_and_features());
        serialize(output, { "agent_version" }, nd_get_version());
        serialize(output, { "json_version" },
          1.9  // XXX: Deprecated, keep for compatibility
        );
    }

    bool RestartAgent(bool conditional = true) const;
    bool EnablePlugin(const std::string &tag, bool enable = true) const;
    bool EditPlugin(const std::string &tag) const;
    bool EnableInformatics(bool enable = true) const;

    bool DumpList(ndFlags<DumpFlags> type = DumpFlags::TYPE_ALL);

    bool LookupAddress(const std::string &ip);

    void CommandLineHelp(bool version_only = false);

    bool AddInterface(const std::string &ifname,
      ndInterfaceRole role, ndFlags<ndCaptureType> type) const;

    bool CheckAgentUUID(void) const;

    bool SaveAgentStatus(const ndCaptureThreads &threads,
      const ndInterfaceStats &stats);
    bool DisplayAgentStatus(void);

    int Run(void);

    void Terminate(void) {
        if (ShouldTerminate()) {
            nd_dprintf("%s: Forcing termination...\n", tag.c_str());
            terminate_force = true;
        }
        ndThread::Terminate();
    }

    inline const std::string &GetVersion() const {
        return version;
    }
    inline const ndInstanceStatus &GetStatus() const {
        return status;
    }

    template <class T>
    void EncodeApplications(T &output) {
        nd_apps_t entries;
        apps.Get(entries);
        for (auto &app : entries) {
            T jo;

            jo["id"] = app.second;
            jo["tag"] = app.first;

            output.push_back(jo);
        }
    };
    template <class T>
    void EncodeProtocols(T &output) const {
        for (auto &proto : ndProto::Tags) {
            T jo;

            jo["id"] = proto.first;
            jo["tag"] = proto.second;

            output.push_back(jo);
        }
    };

    enum class InstanceEvent : uint32_t {
        NONE,
        NETLINK_IO,
        RELOAD,
        TERMINATE,
        UPDATE,
        UPDATE_NAPI,
    };

    inline void SendIPC(InstanceEvent event) {
        ndThread::SendIPC(static_cast<uint32_t>(event));
    }

    bool SendSignal(const siginfo_t &si);

    int exit_code = { EXIT_FAILURE };

    ndInstanceStatus status;
    ndPacketStats pkt_stats_global;
    ndApplications apps;
    ndCategories categories;
    ndInterfaces interfaces;
    ndAddrLookup addr_lookup;
    ndDNSHintCache *dns_hint_cache = { nullptr };
    ndFlowHashCache *flow_hash_cache = { nullptr };
    ndFlowMap *flow_buckets = { nullptr };
#ifdef _ND_ENABLE_NETLINK
    ndNetlink *netlink = { nullptr };
#endif
    ndNetifyApiManager api_manager;
#ifdef _ND_ENABLE_CONNTRACK
    ndConntrackThread *thread_conntrack = { nullptr };
#endif
    ndDetectionThreads thread_detection;
    ndPluginManager plugins;

protected:
    friend class ndInstanceThread;

    static ndInstance *instance;

    void *Entry(void);

    bool Reload(bool broadcast = true, bool silent = true);

    void CreateCaptureInterfaces(ndInterfaces &ifaces) const;

    bool CreateCaptureThreads(ndInterfaces &ifaces,
      ndCaptureThreads &threads);
    void DestroyCaptureThreads(ndCaptureThreads &threads,
      bool expire_flows = false);
    size_t ReapCaptureThreads(ndCaptureThreads &threads);
    bool ReloadCaptureThreads(ndCaptureThreads &threads);

    uint32_t WaitForIPC(int timeout = -1);

    void UpdateStatus(void);

    //void DisplayDebugScoreboard(void) const;

    bool ExpireFlow(nd_flow_ptr &flow);

    void ProcessUpdate(const ndCaptureThreads &threads);

    void ProcessFlows(void);

    ndTimer timer_update, timer_update_napi;

    std::string tag;
    std::string self;
    pid_t self_pid = { -1 };
    std::string version;

    std::atomic<bool> terminate_force = { false };

    std::string conf_filename;

private:
    ndInstance(const std::string &tag = "nd-instance");
    virtual ~ndInstance();
};

class ndInstanceClient
{
public:
    ndInstanceClient() : ndi(ndInstance::GetInstance()) { }

    ndInstance &ndi;
};
