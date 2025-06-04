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

#include <getopt.h>
#include <sys/resource.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <ios>
#include <iostream>

#if defined(_ND_ENABLE_LIBTCMALLOC) && \
  defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H)
#include <gperftools/malloc_extension.h>
#elif defined(HAVE_MALLOC_TRIM)
#include <malloc.h>
#endif

#include "INIReader.h"

#include "nd-config.hpp"
#include "nd-detection.hpp"
#include "nd-instance.hpp"
#include "nd-progress.hpp"
#include "nd-util.hpp"
#ifdef _ND_ENABLE_LIBPCAP
#include "nd-capture-pcap.hpp"
#endif
#ifdef _ND_ENABLE_TPACKETV3
#include "nd-capture-tpv3.hpp"
#endif
#ifdef _ND_ENABLE_NFQUEUE
#include "nd-capture-nfq.hpp"
#endif

using namespace std;
using json = nlohmann::json;
extern int map_fd; // extern in nd-detection.cpp
extern std::unordered_map<std::string, int> ip_user_mapping; // ip to user

extern unordered_map<int, unordered_set<string>> user_blocked_websites;
extern unordered_map<int, unordered_set<int>> blocked_applications;
extern unordered_map<int, unordered_set<int>> blocked_protocols;
extern std::string last_interface;
// #define _ND_PROCESS_FLOW_DEBUG    1

ndInstance *ndInstance::instance = nullptr;

ndInstanceStatus::ndInstanceStatus()
  : cpus(sysconf(_SC_NPROCESSORS_ONLN)) {
    if (cpus == -1L)
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "sysconf(_SC_NPROCESSORS_ONLN)");
}

ndInstance::ndInstance(const string &tag)
  : ndThread(tag, -1, true),
    tag(tag.empty() ? ND_NAME_SHORT : tag),
    self(ND_NAME_SHORT), conf_filename(ND_CONF_FILE_NAME) {
}

ndInstance::~ndInstance() {

    if (! ShouldTerminate()) Terminate();

    Join();

    api_manager.Terminate();

    for (unsigned p = 0; p < 2; p++) {
#ifdef _ND_ENABLE_CONNTRACK
        if (ndGC_USE_CONNTRACK && thread_conntrack) {
            if (p == 0) thread_conntrack->Terminate();
            else {
                delete thread_conntrack;
                thread_conntrack = nullptr;
            }
        }
#endif

        for (auto i : thread_detection) {
            if (p == 0) i.second->Terminate();
            else delete i.second;
        }

        if (p > 0 && thread_detection.size())
            thread_detection.clear();
    }

    if (dns_hint_cache != nullptr) {
        dns_hint_cache->Save();
        delete dns_hint_cache;
        dns_hint_cache = nullptr;
    }

    if (flow_hash_cache != nullptr) {
        flow_hash_cache->Save();
        delete flow_hash_cache;
        flow_hash_cache = nullptr;
    }

    if (flow_buckets != nullptr) {
        delete flow_buckets;
        flow_buckets = nullptr;
    }

#ifdef _ND_ENABLE_NETLINK
    if (netlink != nullptr) {
        delete netlink;
        netlink = nullptr;
    }
#endif

    if (this == instance) {
        instance = nullptr;

        curl_global_cleanup();
    }

    if (self_pid > 0 && self_pid == nd_is_running(self_pid, self))
    {
        if (unlink(ndGC.path_pid_file.c_str()) != 0) {
            nd_dprintf("%s: unlink: %s: %s\n", tag.c_str(),
              ndGC.path_pid_file.c_str(), strerror(errno));
        }
    }
}

ndInstance &ndInstance::Create(const string &tag) {
    if (instance != nullptr) {
        throw ndException("%s: %s: %s", __PRETTY_FUNCTION__,
          "instance", strerror(EEXIST));
    }

    instance = new ndInstance(tag);

    return *instance;
}

void ndInstance::Destroy(void) {
    if (instance == nullptr) {
        throw ndException("%s: %s: %s", __PRETTY_FUNCTION__,
          "instance", strerror(EINVAL));
    }

    delete instance;
}

uint32_t
ndInstance::InitializeConfig(int argc, char * const argv[]) {
    string last_iface;
    ndFlags<DumpFlags> dump_flags = DumpFlags::NONE;

    nd_basename(argv[0], self);

    static struct option options[] = { { "config", 1, 0, 'c' },
        { "debug", 0, 0, 'd' }, { "debug-ndpi", 0, 0, 'n' },
        { "debug-curl", 0, 0, 'D' },
        { "debug-flow-expression", 1, 0, 'x' },
        { "device-address", 1, 0, 'A' },
        { "device-filter", 1, 0, 'F' }, { "device-peer", 1, 0, 'N' },
        { "disable-conntrack", 0, 0, 't' },
        { "disable-netlink", 0, 0, 'l' },
        { "export-json", 1, 0, 'j' }, { "external", 1, 0, 'E' },
        { "hash-file", 1, 0, 'S' }, { "help", 0, 0, 'h' },
        { "internal", 1, 0, 'I' }, { "interval", 1, 0, 'i' },
        { "ndpi-config", 1, 0, 'f' }, { "provision", 0, 0, 'p' },
        { "remain-in-foreground", 0, 0, 'R' },
        { "replay-delay", 0, 0, 'r' },
        { "status", 0, 0, 's' }, { "test-output", 1, 0, 'T' },
        { "uuid", 1, 0, 'u' }, { "uuidgen", 0, 0, 'U' },
        { "verbose", 0, 0, 'v' }, { "version", 0, 0, 'V' },
#define _ND_LO_ENABLE_PLUGIN  1
#define _ND_LO_DISABLE_PLUGIN 2
#define _ND_LO_EDIT_PLUGIN    3
        { "enable-plugin", 1, 0, _ND_LO_ENABLE_PLUGIN },
        { "disable-plugin", 1, 0, _ND_LO_DISABLE_PLUGIN },
        { "edit-plugin", 1, 0, _ND_LO_EDIT_PLUGIN },
#define _ND_LO_ENABLE_INFORMATICS  4
#define _ND_LO_DISABLE_INFORMATICS 5
        { "enable-informatics", 0, 0, _ND_LO_ENABLE_INFORMATICS },
        { "disable-informatics", 0, 0, _ND_LO_DISABLE_INFORMATICS },
        { "enable-sink", 0, 0, _ND_LO_ENABLE_INFORMATICS },
        { "disable-sink", 0, 0, _ND_LO_DISABLE_INFORMATICS },
#define _ND_LO_FORCE_RESET 6
        { "force-reset", 0, 0, _ND_LO_FORCE_RESET },
#define _ND_LO_CA_CAPTURE_BASE    7
#define _ND_LO_CA_CONNTRACK       8
#define _ND_LO_CA_DETECTION_BASE  9
#define _ND_LO_CA_DETECTION_CORES 10
        { "thread-capture-base", 1, 0, _ND_LO_CA_CAPTURE_BASE },
        { "thread-conntrack", 1, 0, _ND_LO_CA_CONNTRACK },
        { "thread-detection-base", 1, 0, _ND_LO_CA_DETECTION_BASE },
        { "thread-detection-cores", 1, 0, _ND_LO_CA_DETECTION_CORES },
#define _ND_LO_DUMP_PROTOS 11
#define _ND_LO_DUMP_APPS   12
#define _ND_LO_DUMP_CAT    13
#define _ND_LO_DUMP_CATS   14
#define _ND_LO_DUMP_RISKS  15
        { "dump-all", 0, 0, 'P' },
        { "dump-protos", 0, 0, _ND_LO_DUMP_PROTOS },
        { "dump-protocols", 0, 0, _ND_LO_DUMP_PROTOS },
        { "dump-apps", 0, 0, _ND_LO_DUMP_APPS },
        { "dump-applications", 0, 0, _ND_LO_DUMP_APPS },
        { "dump-category", 1, 0, _ND_LO_DUMP_CAT },
        { "dump-categories", 0, 0, _ND_LO_DUMP_CATS },
        { "dump-risks", 0, 0, _ND_LO_DUMP_RISKS },
#define _ND_LO_DUMP_SORT_BY_TAG 16
        { "dump-sort-by-tag", 0, 0, _ND_LO_DUMP_SORT_BY_TAG },
#define _ND_LO_DUMP_WITH_CATS 17
        { "dump-with-categories", 0, 0, _ND_LO_DUMP_WITH_CATS },
#define _ND_LO_EXPORT_APPS 18
        { "export-apps", 0, 0, _ND_LO_EXPORT_APPS },
#define _ND_LO_EXPORT_APPS_LEGACY 19
        { "export-legacy", 0, 0, _ND_LO_EXPORT_APPS_LEGACY },
#define _ND_LO_LOOKUP_IP 20
        { "lookup-ip", 1, 0, _ND_LO_LOOKUP_IP },
#define _ND_LO_CAPTURE_DELAY 21
        { "capture-delay", 1, 0, _ND_LO_CAPTURE_DELAY },
#define _ND_LO_ALLOW_UNPRIV 22
        { "allow-unprivileged", 0, 0, _ND_LO_ALLOW_UNPRIV },
#define _ND_LO_IGNORE_IFACE_CONFIGS 23
        { "ignore-interface-configs", 0, 0, _ND_LO_IGNORE_IFACE_CONFIGS },
#define _ND_LO_DISABLE_AUTO_FLOW_EXPIRY 24
        { "disable-auto-flow-expiry", 0, 0, _ND_LO_DISABLE_AUTO_FLOW_EXPIRY },
#define _ND_LO_RUN_WITHOUT_SOURCES 25
        { "run-without-sources", 0, 0, _ND_LO_RUN_WITHOUT_SOURCES },
#define _ND_LO_VERBOSE_FLAG 26
        { "verbose-flag", 1, 0, _ND_LO_VERBOSE_FLAG },

        { NULL, 0, 0, 0 } };

    static const char *flags = {
        "?A:c:DdE:F:f:hI:i:j:lN:nPpRrS:stT:Uu:Vvx:"
    };

    int rc;
    while (true) {
        if ((rc = getopt_long(argc, argv, flags, options, NULL)) == -1)
            break;

        switch (rc) {
        case _ND_LO_IGNORE_IFACE_CONFIGS:
            ndGC_SetFlag(ndGlobalFlags::IGNORE_IFACE_CONFIGS, true);
            break;
        case '?':
            cerr << "Try `--help' for more information.\n";
            return ndEnumCast(ConfigResult, INVALID_OPTION);
        case 'c': conf_filename = optarg; break;
        case 'd':
            ndGC_SetFlag(ndGlobalFlags::DEBUG, true);
            break;
        default: break;
        }
    }

        DatabaseManager db_manager(
            "tcp://127.0.0.1:3306",
            "root",
            "1",
            "nebero"
        );
        db_manager.fetchBlockedApplications();
        db_manager.fetchBlockedWebsites();

    // ip_user_mapping["192.168.1.4"] = 1;
    // ip_user_mapping["10.1.1.56"] = 2;
    // ip_user_mapping["10.1.1.58"] = 3;
    // ip_user_mapping["10.1.1.98"] = 4;


    
    // blocked_applications[3].insert(119); // facebook
    // blocked_applications[3].insert(10401); // facebook messenger

    // blocked_applications[1].insert(119); // facebook
    // blocked_applications[1].insert(10401); // facebook messenger

    // blocked_applications[1].insert(122); // gmail
    // blocked_applications[1].insert(124); // youtube
    // blocked_applications[3].insert(124); // youtube
    // blocked_applications[4].insert(124); // youtube

    // blocked_applications[1].insert(126); // google
    // blocked_applications[1].insert(156); // spotify

    // user_blocked_websites[1].insert("www.facebook.com");
    // user_blocked_websites[1].insert("www.youtube.com");
    // user_blocked_websites[1].insert("m.youtube.com");
    // user_blocked_websites[1].insert("www.instagram.com");
    // user_blocked_websites[1].insert("www.twitter.com");

    // blocked_applications[2].insert(176); // wikipedia
    // blocked_applications[2].insert(142); // whatsapp
    // blocked_applications[1].insert(178); // amazon
    // blocked_applications[2].insert(10002); // github

    // user_blocked_websites[2].insert("www.facebook.com");
    // // user_blocked_websites[2].insert("www.youtube.com");
    // user_blocked_websites[2].insert("www.instagram.com");
    // user_blocked_websites[2].insert("www.twitter.com");
    


    // loadBpfProgram();
    optind = 1;
    while (true) {
        if ((rc = getopt_long(argc, argv, flags, options, NULL)) == -1)
            break;

        switch (rc) {
        case _ND_LO_ENABLE_PLUGIN:
            ndGC.Load(conf_filename);
            return ndCR_Pack(ENABLE_PLUGIN,
              (EnablePlugin(optarg) && RestartAgent()) ? 0 : 1);
        case _ND_LO_DISABLE_PLUGIN:
            ndGC.Load(conf_filename);
            return ndCR_Pack(DISABLE_PLUGIN,
              (EnablePlugin(optarg, false) && RestartAgent()) ? 0 : 1);
        case _ND_LO_EDIT_PLUGIN:
            ndGC.Load(conf_filename);
            if (! ndTerm::IsTTY())
                return ndCR_Pack(EDIT_PLUGIN, 1);
            return ndCR_Pack(EDIT_PLUGIN,
              (EditPlugin(optarg) && RestartAgent()) ? 0 : 1);
        case _ND_LO_ENABLE_INFORMATICS:
            return ndCR_Pack(ENABLE_PLUGIN,
              (EnableInformatics()) ? 0 : 1);
        case _ND_LO_DISABLE_INFORMATICS:
            return ndCR_Pack(DISABLE_PLUGIN,
              (EnableInformatics(false)) ? 0 : 1);
        case '?':
            cerr << "Try `--help' for more information.\n";
            return ndEnumCast(ConfigResult, INVALID_OPTION);
        default: break;
        }
    }

    if (conf_filename != "/dev/null") {
        if (ndGC.Load(conf_filename) == false) {
            cerr << "Error while loading configuration: "
                 << conf_filename << endl;
            return ndCR_Pack(LOAD_FAILURE, 1);
        }

        ndGC.Close();
    }

    optind = 1;
    while (true) {
        if ((rc = getopt_long(argc, argv, flags, options, NULL)) == -1)
            break;

        switch (rc) {
        case 'c':
        case 'd': break;
        case _ND_LO_DUMP_SORT_BY_TAG:
            dump_flags |= DumpFlags::SORT_BY_TAG;
            break;
        case _ND_LO_DUMP_WITH_CATS:
            dump_flags |= DumpFlags::WITH_CATS;
            break;
        case _ND_LO_IGNORE_IFACE_CONFIGS:
            ndGC_SetFlag(ndGlobalFlags::IGNORE_IFACE_CONFIGS, true);
            break;
        case _ND_LO_ENABLE_PLUGIN:
        case _ND_LO_DISABLE_PLUGIN:
        case _ND_LO_ENABLE_INFORMATICS:
        case _ND_LO_DISABLE_INFORMATICS: break;
        case _ND_LO_FORCE_RESET:
            rc = ndGC.ForceReset();
            return ndCR_Pack(FORCE_RESULT, (rc) ? 0 : 1);
        case _ND_LO_CA_CAPTURE_BASE:
            ndGC.ca_capture_base = (int16_t)atoi(optarg);
            if (ndGC.ca_capture_base > status.cpus) {
                cerr << "Capture thread base greater than "
                        "online cores.\n";
                return ndEnumCast(ConfigResult, INVALID_VALUE);
            }
            break;
        case _ND_LO_CA_CONNTRACK:
            ndGC.ca_conntrack = (int16_t)atoi(optarg);
            if (ndGC.ca_conntrack > status.cpus) {
                cerr << "Conntrack thread ID greater than "
                        "online cores.\n";
                return ndEnumCast(ConfigResult, INVALID_VALUE);
            }
            break;
        case _ND_LO_CA_DETECTION_BASE:
            ndGC.ca_detection_base = (int16_t)atoi(optarg);
            if (ndGC.ca_detection_base > status.cpus) {
                cerr << "Detection thread base greater "
                        "than online cores.\n";
                return ndEnumCast(ConfigResult, INVALID_VALUE);
            }
            break;
        case _ND_LO_CA_DETECTION_CORES:
            ndGC.ca_detection_cores = (int16_t)atoi(optarg);
            if (ndGC.ca_detection_cores > status.cpus) {
                cerr << "Detection cores greater than "
                        "online cores.\n";
                return ndEnumCast(ConfigResult, INVALID_VALUE);
            }
            break;
        case _ND_LO_CAPTURE_DELAY:
            ndGC.ttl_capture_delay = atoi(optarg);
            break;
        case _ND_LO_ALLOW_UNPRIV:
            ndGC_SetFlag(ndGlobalFlags::ALLOW_UNPRIV, true);
            break;
        case _ND_LO_DISABLE_AUTO_FLOW_EXPIRY:
            ndGC_SetFlag(ndGlobalFlags::AUTO_FLOW_EXPIRY, false);
            break;
        case _ND_LO_RUN_WITHOUT_SOURCES:
            ndGC_SetFlag(ndGlobalFlags::RUN_WITHOUT_SOURCES, true);
            break;
        case _ND_LO_VERBOSE_FLAG:
            if (! strcasecmp(optarg, "event-dpi-new"))
                ndGC.verbosity_flags |= ndVerbosityFlags::EVENT_DPI_NEW;
            else if (
              ! strcasecmp(optarg, "no-event-dpi-new"))
                ndGC.verbosity_flags &= ~ndVerbosityFlags::EVENT_DPI_NEW;
            else if (
              ! strcasecmp(optarg, "event-dpi-update"))
                ndGC.verbosity_flags |= ndVerbosityFlags::EVENT_DPI_UPDATE;
            else if (
              ! strcasecmp(optarg, "no-event-dpi-update"))
                ndGC.verbosity_flags &= ~ndVerbosityFlags::EVENT_DPI_UPDATE;
            else if (
              ! strcasecmp(optarg, "event-dpi-complete"))
                ndGC.verbosity_flags |= ndVerbosityFlags::EVENT_DPI_COMPLETE;
            else if (
              ! strcasecmp(optarg, "no-event-dpi-complete"))
                ndGC.verbosity_flags &= ~ndVerbosityFlags::EVENT_DPI_COMPLETE;
            else {
                nd_printf(
                  "WARNING: Invalid verbose-flag: %s\n", optarg);
            }
            break;
        case _ND_LO_LOOKUP_IP: break;
        case _ND_LO_EXPORT_APPS:
        case _ND_LO_EXPORT_APPS_LEGACY:
        case _ND_LO_DUMP_PROTOS:
        case _ND_LO_DUMP_APPS:
        case _ND_LO_DUMP_CAT:
        case _ND_LO_DUMP_CATS:
        case _ND_LO_DUMP_RISKS:
        case 'P':
        case 's':
            ndGC_SetFlag(ndGlobalFlags::DOTD_CATEGORIES, false);
            break;
        case 'D':
            ndGC_SetFlag(ndGlobalFlags::DEBUG_CURL, true);
            break;
        case 'f': ndGC.path_legacy_config = optarg; break;
        case 'A':
            if (last_iface.size() == 0) {
                cerr << "You must specify an interface "
                        "first (-I/E).\n";
                return ndEnumCast(ConfigResult, INVALID_OPTION);
            }
            ndGC.AddInterfaceAddress(last_iface, optarg);
            break;
        case 'E':
            if (! AddInterface(optarg, ndInterfaceRole::WAN,
                  ndCaptureType::PCAP | ndCaptureType::CMDLINE))
                return ndEnumCast(ConfigResult, INVALID_INTERFACE);
            last_iface = optarg;
            break;
        case 'F':
            if (last_iface.size() == 0) {
                cerr << "You must specify an interface "
                        "first (-I/E).\n";
                return ndEnumCast(ConfigResult, INVALID_OPTION);
            }
            ndGC.AddInterfaceFilter(last_iface, optarg);
            break;
        case 'I':
            if (! AddInterface(optarg, ndInterfaceRole::LAN,
                  ndCaptureType::PCAP | ndCaptureType::CMDLINE))
                return ndEnumCast(ConfigResult, INVALID_INTERFACE);
            last_iface = optarg;
            break;
        case 'i':
            ndGC.update_interval = atoi(optarg);
            break;
        case 'j': ndGC.path_export_json = optarg; break;
        case 'l':
            ndGC_SetFlag(ndGlobalFlags::USE_NETLINK, false);
            break;
        case 'n':
            ndGC_SetFlag(ndGlobalFlags::DEBUG_NDPI, true);
            break;
        case 'N':
            if (last_iface.size() == 0) {
                cerr << "You must specify an interface "
                        "first (-I/E).\n";
                return ndEnumCast(ConfigResult, INVALID_OPTION);
            }
            ndGC.AddInterfacePeer(last_iface, optarg);
            break;
        case 'p':
            if ((rc = CheckAgentUUID())) {
                string uuid;
                ndGC.GetUUID(ndUUID::AGENT, uuid);
                cout << "Agent UUID: " << uuid << endl;
            }
            return ndCR_Pack(PROVISION_UUID, (rc) ? 0 : 1);
        case 'R':
            ndGC_SetFlag(ndGlobalFlags::REMAIN_IN_FOREGROUND, true);
            break;
        case 'r':
            ndGC_SetFlag(ndGlobalFlags::REPLAY_DELAY, true);
            break;
        case 'S':
#ifndef _ND_LEAN_AND_MEAN
        {
            ndDigest digest;

            if ((rc = nd_sha1_file(optarg, digest)) == 0) {
                string sha1;
                nd_sha1_to_string(digest, sha1);
                cout << sha1 << " " << optarg << endl;
            }
            return ndCR_Pack(HASH_TEST, rc);
        }
#else
            cerr << "Sorry, this feature was disabled "
                    "(embedded).\n";
            return ndEnumCast(ConfigResult, DISABLED_OPTION);
#endif
        case 't':
            ndGC_SetFlag(ndGlobalFlags::USE_CONNTRACK, false);
            break;
        case 'T':
            if ((ndGC.h_flow = fopen(optarg, "w")) == NULL) {
                cerr
                  << "Error while opening test output log: " << optarg
                  << ": " << strerror(errno) << endl;
                return ndEnumCast(ConfigResult, INVALID_VALUE);
            }
            break;
        case 'U':
        {
            string uuid;
            nd_generate_uuid(uuid);
            cout << uuid << endl;
            return ndEnumCast(ConfigResult, GENERATE_UUID);
        }
        case 'u':
            rc = ndGC.SaveUUID(ndUUID::AGENT, optarg);
            return ndCR_Pack(SAVE_UUID_FAILURE, (rc) ? 0 : 1);
        case 'V':
            CommandLineHelp(true);
            return ndEnumCast(ConfigResult, USAGE_OR_VERSION);
        case 'v':
            ndGC_SetFlag(ndGlobalFlags::VERBOSE, true);
            ndGC.verbosity++;
            break;
        case 'x':
            ndGC_SetFlag(ndGlobalFlags::VERBOSE, false);
            ndGC.debug_flow_print_exprs.push_back(optarg);
            break;
        default:
            CommandLineHelp();
            return ndEnumCast(ConfigResult, INVALID_OPTION);
        }
    }
    // std::cout << "Last Interface: " << last_iface << "Optarg: " << optarg << std::endl;
    last_interface = last_iface;

    Reload(false);

    optind = 1;
    while (true) {
        if ((rc = getopt_long(argc, argv, flags, options, NULL)) == -1)
            break;

        switch (rc) {
        case _ND_LO_LOOKUP_IP:
            rc = LookupAddress(optarg);
            return ndCR_Pack(LOOKUP_ADDR, (rc) ? 0 : 1);
            break;
        case _ND_LO_EXPORT_APPS:
#ifndef _ND_LEAN_AND_MEAN
            rc = apps.Save("/dev/stdout");
            return ndCR_Pack(EXPORT_APPS, (rc) ? 0 : 1);
#else
            cerr << "Sorry, this feature was disabled "
                    "(embedded).\n";
            return ndEnumCast(ConfigResult, DISABLED_OPTION);
#endif
        case _ND_LO_EXPORT_APPS_LEGACY:
#ifndef _ND_LEAN_AND_MEAN
            rc = apps.SaveLegacy("/dev/stdout");
            return ndCR_Pack(EXPORT_APPS, (rc) ? 0 : 1);
#else
            cerr << "Sorry, this feature was disabled "
                    "(embedded).\n";
            return ndEnumCast(ConfigResult, DISABLED_OPTION);
#endif
        case _ND_LO_DUMP_PROTOS:
            rc = DumpList(dump_flags | DumpFlags::TYPE_PROTOS);
            return ndCR_Pack(DUMP_LIST, (rc) ? 0 : 1);
        case _ND_LO_DUMP_APPS:
            rc = DumpList(dump_flags | DumpFlags::TYPE_APPS);
            return ndCR_Pack(DUMP_LIST, (rc) ? 0 : 1);
        case _ND_LO_DUMP_CAT:
            if (strncasecmp("application", optarg, 11) == 0)
                rc = DumpList(dump_flags | DumpFlags::TYPE_CAT_APP);
            else if (strncasecmp("protocol", optarg, 8) == 0)
                rc = DumpList(dump_flags | DumpFlags::TYPE_CAT_PROTO);
            else {
                cerr << "Invalid catetory type \"" << optarg
                     << "\", valid types: applications, "
                        "protocols\n";
                rc = 0;
            }
            return ndCR_Pack(DUMP_LIST, (rc) ? 0 : 1);
        case _ND_LO_DUMP_CATS:
            rc = DumpList(dump_flags | DumpFlags::TYPE_CATS);
            return ndCR_Pack(DUMP_LIST, (rc) ? 0 : 1);
        case _ND_LO_DUMP_RISKS:
            rc = DumpList(dump_flags | DumpFlags::TYPE_RISKS);
            return ndCR_Pack(DUMP_LIST, (rc) ? 0 : 1);
        case 'P':
            rc = DumpList(dump_flags | DumpFlags::TYPE_ALL);
            return ndCR_Pack(DUMP_LIST, (rc) ? 0 : 1);
        case 's':
            rc = DisplayAgentStatus();
            return ndCR_Pack(AGENT_STATUS, (rc) ? 0 : 1);
        default: break;
        }
    }

    if (! ndGC_ALLOW_UNPRIV) {
        // Require UID 0 from this point on...
        if (geteuid() != 0) {
            cerr << "Error starting Agent: " << strerror(EPERM)
                 << " (not root)\n";
            return ndEnumCast(ConfigResult, INVALID_PERMS);
        }
    }

    // Test mode enabled?  Override certain config
    // parameters
    if (ndGC.h_flow != stderr) {
        ndGC_SetFlag(ndGlobalFlags::USE_FHC, true);
        ndGC_SetFlag(ndGlobalFlags::REMAIN_IN_FOREGROUND, true);

        ndGC.update_interval = 1;

        ndGC.plugin_processors.clear();
        ndGC.plugin_sinks.clear();

        ndGC.dhc_storage = ndDHCStorage::DISABLED;
        ndGC.fhc_storage = ndFHCStorage::DISABLED;
    }

    // Global libCURL initialization
    if (ndGC_DEBUG_CURL) {
        curl_version_info_data *curl_version =
          curl_version_info(CURLVERSION_NOW);
        cout << tag << ": libCURL version "
             << ((curl_version->version_num >> 16) & 0xff) << "."
             << ((curl_version->version_num >> 8) & 0xff) << "."
             << (curl_version->version_num & 0xff) << endl;
#if (LIBCURL_VERSION_NUM >= 0x075600)
        const curl_ssl_backend **curl_ssl_backends;
        curl_global_sslset((curl_sslbackend)-1, NULL,
          &curl_ssl_backends);

        for (int i = 0; curl_ssl_backends[i]; i++) {
            cout << tag << ": libCURL SSL backend #" << i
                 << ": " << curl_ssl_backends[i]->name
                 << " (ID: " << curl_ssl_backends[i]->id << endl;
        }
#endif
    }

    CURLcode cc;
    if ((cc = curl_global_init(CURL_GLOBAL_DEFAULT)) != 0) {
        cerr << tag << ": Unable to initialize libCURL: " << cc
             << endl;
        return ndEnumCast(ConfigResult, LIBCURL_FAILURE);
    }

    // Configuration is valid when version is set
    version = nd_get_version_and_features();

    return ndEnumCast(ConfigResult, OK);
}

bool ndInstance::InitializeTimers(int sig_update, int sig_update_napi) {
    try {
        timer_update.Create(sig_update);
        if (ndGC_USE_NAPI || ndGC_AUTO_INFORMATICS)
            timer_update_napi.Create(sig_update_napi);
    }
    catch (exception &e) {
        cout << tag << ": Error creating timer(s): " << tag
             << ": " << e.what() << endl;

        exit_code = EXIT_FAILURE;

        return false;
    }

    return true;
}

bool ndInstance::Daemonize(void) {
    if (! ndGC_DEBUG && ! ndGC_REMAIN_IN_FOREGROUND) {
        if (daemon(1, 0) != 0) {
            cerr << tag << ": Error while daemonizing: "
                 << strerror(errno) << endl;
            return false;
        }
    }

    if (! nd_dir_exists(ndGC.path_state_volatile)) {
        if (mkdir(ndGC.path_state_volatile.c_str(), 0755) != 0)
        {
            nd_printf(
              "%s: Error creating volatile state path: %s: "
              "%s\n",
              tag.c_str(), ndGC.path_state_volatile.c_str(),
              strerror(errno));
            return false;
        }
    }

    pid_t old_pid = nd_load_pid(ndGC.path_pid_file);

    if (old_pid > 0 && old_pid == nd_is_running(old_pid, self))
    {
        nd_printf(
          "%s: An instance is already running: PID %d\n",
          tag.c_str(), old_pid);
        return false;
    }

    self_pid = getpid();
    if (nd_save_pid(ndGC.path_pid_file, self_pid) != 0)
        return false;

    return true;
}

bool ndInstance::RestartAgent(bool conditional) const {
    if (! ndGC_ALLOW_UNPRIV) {
        // Require UID 0 from this point on...
        if (geteuid() != 0) {
            cerr << "Error restarting Agent: " << strerror(EPERM)
                 << " (not root)\n";
            return false;
        }
    }

    pid_t pid = nd_load_pid(ndGC.path_pid_file);
    pid = nd_is_running(pid, self);

    if (pid < 1 && conditional) return true;

    ndProgress progress("Restarting the Netify Agent...",
      "The Netify Agent was restarted.");
    progress.Start();

    string output;
    int rc = nd_functions_exec("restart_netifyd",
      (conditional) ? "true" : "false", output);

    if (rc != 0) {
        progress.Stop(
          "An error occured while restarting the Netify "
          "Agent.");

        if (ndGC_DEBUG) cerr << output;

        return false;
    }

    progress.Stop();

    return true;
}

bool ndInstance::EnablePlugin(const string &tag, bool enable) const {

    bool current_state = false;
    string filename,
      func((enable) ? "config_enable_plugin" : "config_disable_plugin");

    vector<string> configs;
    if (nd_scan_dotd(ndGC.path_plugins, configs)) {
        for (auto &config : configs) {
            string fullpath(ndGC.path_plugins + "/" + config);

            INIReader r = INIReader(fullpath);
            if (r.ParseError() != 0) continue;

            set<string> sections;
            r.GetSections(sections);

            if (sections.find(tag) == sections.end())
                continue;

            filename = fullpath;
            current_state = r.GetBoolean(tag, "enable", false);
            break;
        }
    }

    if (filename.empty()) {
        cerr << "Unable to find configuration file for "
                "plugin: "
             << tag << endl;
        return false;
    }

    if (current_state == enable) {
        cerr << "The " << tag << " plugin is already "
             << ((enable) ? "enabled." : "disabled.") << endl;
        return false;
    }

    string output;
    int rc = nd_functions_exec(func, filename, output);
    if (rc != 0) {
        cerr << "Error " << ((enable) ? "enabling" : "disabling")
             << " plugin: " << tag.c_str() << endl;

        if (ndGC_DEBUG) cerr << output;

        return false;
    }

    return true;
}

bool ndInstance::EditPlugin(const string &tag) const {
    string filename;

    vector<string> configs;
    if (nd_scan_dotd(ndGC.path_plugins, configs)) {
        for (auto &config : configs) {
            string fullpath(ndGC.path_plugins + "/" + config);

            INIReader r = INIReader(fullpath);
            if (r.ParseError() != 0) continue;

            set<string> sections;
            r.GetSections(sections);

            if (sections.find(tag) == sections.end())
                continue;

            filename = r.Get(tag, "conf_filename", "");
            break;
        }
    }

    if (filename.empty()) {
        fprintf(stderr, "No plugin configuration set.\n");
        return false;
    }

    nd_expand_variables(filename, filename, ndGC.conf_vars);

    const char *editor = getenv("EDITOR");
    if (editor == nullptr) editor = "vi";

    if (execlp(editor, editor, filename.c_str(), nullptr) == -1)
        return false;

    return true;
}

bool ndInstance::EnableInformatics(bool enable) const {
    ndGC.Load(conf_filename);

    string output;
    int rc = nd_functions_exec(
      (enable) ? "config_enable_informatics" : "config_disable_informatics",
      conf_filename, output);

    if (rc != 0) {
        cerr << "WARNING: Error "
             << ((enable) ? "enabling" : "disabling")
             << " \"auto_informatics\" in: " << conf_filename
             << endl;
        if (ndGC_DEBUG) cerr << output;
    }

    if (! enable) {
        rc = (int)EnablePlugin("proc-core-auto", false);
        rc += (int)EnablePlugin("sink-http-auto", false);

        if (rc == 0) {
            cerr << "No configuration changes were made.\n";
            return false;
        }

        return RestartAgent();
    }

    auto copy_configs = [](const string &tag) {
        string conf = "/" ND_PLUGINS_BASE "/99-netify-" +
          tag + ".conf";

        string src(ndGC.path_shared_data);
        src.append(conf);
        string dst(ndGC.path_state_persistent);
        dst.append(conf);

        if (! nd_copy_file(src, dst)) return false;

        conf = "/netify-" + tag + ".json";

        src = ndGC.path_shared_data + conf;
        dst = ndGC.path_state_persistent + conf;

        if (! nd_copy_file(src, dst)) return false;

        return true;
    };

    if (! copy_configs("proc-core-auto")) {
        cerr << "Error while copying Informatics processor "
                "plugin configuration files.\n";
        return false;
    }

    if (! copy_configs("sink-http-auto")) {
        cerr << "Error while copying Informatics sink "
                "plugin configuration files.\n";
        return false;
    }

    return RestartAgent();
}

bool ndInstance::DumpList(ndFlags<DumpFlags> flags) {
    if (! ndFlagBoolean(flags, DumpFlags::TYPE_PROTOS) &&
      ! ndFlagBoolean(flags, DumpFlags::TYPE_APPS) &&
      ! ndFlagBoolean(flags, DumpFlags::TYPE_CATS) &&
      ! ndFlagBoolean(flags, DumpFlags::TYPE_RISKS))
    {
        cerr << "No filter flags specified "
                "(application, "
                "protocol).\n";
        return false;
    }

    if (ndFlagBoolean(flags, DumpFlags::TYPE_CATS) &&
      ! ndFlagBoolean(flags, DumpFlags::TYPE_PROTOS) &&
      ! ndFlagBoolean(flags, DumpFlags::TYPE_APPS))
    {
        if (ndFlagBoolean(flags, DumpFlags::TYPE_CAT_APP) &&
          ! ndFlagBoolean(flags, DumpFlags::TYPE_CAT_PROTO))
            categories.Dump(ndCategories::Type::APP);
        else if (! ndFlagBoolean(flags, DumpFlags::TYPE_CAT_APP) &&
          ndFlagBoolean(flags, DumpFlags::TYPE_CAT_PROTO))
            categories.Dump(ndCategories::Type::PROTO);
        else categories.Dump();
    }

    map<unsigned, string> entries_by_id;
    map<string, unsigned> entries_by_tag;

    if (ndFlagBoolean(flags, DumpFlags::TYPE_PROTOS)) {
        for (auto &proto : ndProto::Tags) {
            if (proto.first == ndProto::Id::TODO) continue;

            if (! ndFlagBoolean(flags, DumpFlags::SORT_BY_TAG))
                entries_by_id[static_cast<unsigned>(proto.first)] =
                  proto.second;
            else
                entries_by_tag[proto.second] =
                  static_cast<unsigned>(proto.first);
        }
    }

    if (ndFlagBoolean(flags, DumpFlags::TYPE_APPS)) {
        nd_apps_t applist;
        apps.Get(applist);
        for (auto &app : applist) {
            if (! ndFlagBoolean(flags, DumpFlags::SORT_BY_TAG))
                entries_by_id[app.second] = app.first;
            else entries_by_tag[app.first] = app.second;
        }
    }

    if (ndFlagBoolean(flags, DumpFlags::TYPE_RISKS)) {
        for (auto &risk : ndRisk::Tags) {
            if (risk.first == ndRisk::Id::TODO) continue;

            if (! ndFlagBoolean(flags, DumpFlags::SORT_BY_TAG))
                entries_by_id[static_cast<unsigned>(risk.first)] =
                  risk.second;
            else
                entries_by_tag[risk.second] =
                  static_cast<unsigned>(risk.first);
        }
    }

    for (auto &entry : entries_by_id) {
        if (ndFlagBoolean(flags, DumpFlags::WITH_CATS) &&
          (ndFlagBoolean(flags, DumpFlags::TYPE_PROTOS) ||
            ndFlagBoolean(flags, DumpFlags::TYPE_APPS)))
        {
            string tag;
            nd_cat_id_t cat_id = categories.ResolveTag(
              ndFlagBoolean(flags, DumpFlags::TYPE_PROTOS) ?
                ndCategories::Type::PROTO :
                ndCategories::Type::APP,
              entry.first, tag);

            if (cat_id == ND_CAT_UNKNOWN || tag.empty())
                tag = "unknown/" + to_string(cat_id);

            cout << right << setw(6) << entry.first << left
                 << setw(0) << ": " << entry.second << ": "
                 << tag << endl;
        }
        else {
            cout << right << setw(6) << entry.first << left
                 << setw(0) << ": " << entry.second << endl;
        }
    }

    for (auto &entry : entries_by_tag) {
        if (ndFlagBoolean(flags, DumpFlags::WITH_CATS) &&
          (ndFlagBoolean(flags, DumpFlags::TYPE_PROTOS) ||
            ndFlagBoolean(flags, DumpFlags::TYPE_APPS)))
        {
            string tag;
            nd_cat_id_t cat_id = categories.ResolveTag(
              ndFlagBoolean(flags, DumpFlags::TYPE_PROTOS) ?
                ndCategories::Type::PROTO :
                ndCategories::Type::APP,
              entry.second, tag);

            if (cat_id == ND_CAT_UNKNOWN || tag.empty())
                tag = "unknown/" + to_string(cat_id);

            cout << right << setw(6) << entry.second << left
                 << setw(0) << ": " << entry.first << ": "
                 << tag << endl;
        }
        else {
            cout << right << setw(6) << entry.second << left
                 << setw(0) << ": " << entry.first << endl;
        }
    }

    return true;
}

bool ndInstance::LookupAddress(const string &ip) {
    ndAddr addr(ip);

    if (! addr.IsValid() || ! addr.IsIP()) {
        cerr << "Invalid IP address: " << ip << endl;
        return false;
    }

    nd_app_id_t id_app = apps.Find(addr);
    nd_cat_id_t id_cat = categories.LookupDotDirectory(addr);

    cout << "Application ID:" << endl;
    cout << right << setw(6) << id_app << ": " << left
         << setw(0) << apps.Lookup(id_app) << endl;

    string tag;
    if (! categories.GetTag(ndCategories::Type::APP, id_cat, tag))
        tag = "unknown";

    cout << "Category ID (" << ndGC.path_categories << ")" << endl;
    cout << right << setw(6) << id_cat << ": " << left
         << setw(0) << tag << endl;

    return true;
}

void ndInstance::CommandLineHelp(bool version_only) {
    if (! ndGC_DEBUG) {
        ndGC_SetFlag(ndGlobalFlags::QUIET, true);
    }

    fprintf(stdout, "%s\n%s\n",
      nd_get_version_and_features(true).c_str(), PACKAGE_URL);

    if (version_only) {
        fprintf(stdout,
          "\nThis application uses nDPI v%s\n"
          "https://www.ntop.org/products/"
          "deep-packet-inspection/ndpi/\n"
          "https://github.com/ntop/nDPI\n",
          ndpi_version());

        fprintf(stdout,
          "\n  This program comes with ABSOLUTELY NO "
          "WARRANTY.\n"
          "  Netifyd is dual-licensed under commercial "
          "and open source licenses. The\n"
          "  commercial license gives you the full "
          "rights to create and distribute software\n"
          "  on your own terms without any open source "
          "license obligations.\n\n"
          "  Netifyd is also available under GPL and "
          "LGPL open source licenses.  The open\n"
          "  source licensing is ideal for "
          "student/academic purposes, hobby projects,\n"
          "  internal research project, or other "
          "projects where all open source license\n"
          "  obligations can be met.\n");
#ifdef PACKAGE_BUGREPORT
        fprintf(stdout, "\nReport bugs to: %s\n", PACKAGE_BUGREPORT);
#endif
        try {
            plugins.Load(ndPlugin::Type::BASE, false);

            if (! ndGC.plugin_processors.empty()) {
                fprintf(stdout, "\nProcessor plugins:\n\n");
                plugins.DumpVersions(ndPlugin::Type::PROC);
            }

            if (! ndGC.plugin_sinks.empty()) {
                fprintf(stdout, "\nSink plugins:\n\n");
                plugins.DumpVersions(ndPlugin::Type::SINK);
            }
        }
        catch (exception &e) {
            fprintf(stderr,
              "\nError while loading plugins: %s\n",
              e.what());
        }
    }
    else {
        fprintf(stdout,
          "\nStatus options:\n"
          "  -s, --status\n    Display Agent status.\n"

          "\nGlobal options:\n"
          "  -d, --debug\n    Enable debug output and "
          "remain in foreground.\n"
          "  -n, --debug-ndpi\n    In debug mode, display "
          "nDPI debug message when enabled "
          "(compile-time).\n"
          "  -D, --debug-curl\n    In debug mode, display "
          "debug output from libCURL.\n"
          "  -x, --debug-flow-expression <expr>\n    "
          "In debug mode, filter flow detections by "
          "expression.\n"
          "  -v, --verbose\n    In debug mode, display "
          "real-time flow detections.  Specify multiple "
          "times to increase verbosity.\n"
          "  --verbose-flag "
          "[no-]event-dpi-new|[no-]event-dpi-update|[no-]"
          "event-dpi-complete\n    In debug mode, display "
          "or hide specified flow event types.  Can be "
          "specify multiple "
          "times to select multiple events.\n"
          "  -R, --remain-in-foreground\n    Remain in "
          "foreground, don't daemonize (OpenWrt).\n"
          "  --allow-unprivileged\n    Allow executing the "
          "Agent as a non-root user.\n"
          "  --run-without-sources\n    Continue running "
          "with no capture sources.\n"

          "\nConfiguration options:\n"
          "  -u, --uuid <uuid>\n    Set Agent UUID.\n"
          "  -U, --uuidgen\n    Generate (but don't save) "
          "a new Agent UUID.\n"
          "  -p, --provision\n    Provision Agent "
          "(generate and save Agent UUID).\n"
          "  -c, --config <filename>\n    Specify an "
          "alternate Agent configuration.\n"
          "    Default: %s\n"
          "  -f, --ndpi-config <filename>\n    Specify an "
          "alternate legacy (nDPI) application "
          "configuration file.\n"
          "    Default: %s\n"
          "  --force-reset\n    Reset global sink "
          "configuration options.\n"
          "    Deletes: %s, %s\n"

          "\nPlugin options:\n"
          "  --enable-plugin <plugin>\n    Enable the "
          "loader for <plugin> and restart the Agent.\n"
          "  --disable-plugin <plugin>\n    Disable the "
          "loader for <plugin> and restart the Agent.\n"
          "  --edit-plugin <plugin>\n    Edit the "
          "the plugin configuration and restart the "
          "Agent.\n"
          "  --enable-informatics\n    Automatically "
          "configure and enable the "
          "plugins required for Netify Informatics.\n"
          "  --disable-informatics\n    Disable and remove "
          "any automatically configured "
          "Netify Informatics plugins.\n"

          "\nDump options:\n"
          "  --dump-sort-by-tag\n    Sort entries by tag.\n"
          "    Default: sort entries by ID.\n"
          "  -P, --dump-all\n    Dump all applications and "
          "protocols.\n"
          "  --dump-apps\n    Dump applications only.\n"
          "  --dump-protos\n    Dump protocols only.\n"
          "  --dump-categories\n    Dump application and "
          "protocol categories.\n"
          "  --dump-category <type>\n    Dump categories "
          "by type: application or protocol\n"
          "  --dump-risks\n    Dump flow security risks.\n"
          "  --lookup-ip <addr>\n    Perform application "
          "and category query by IP address.\n"

          "\nCapture options:\n"
          "  --capture-delay <seconds>\n     Wait "
          "<seconds> before starting capture thread(s).\n"
          "  --ignore-interface-configs\n    Don't load "
          "capture interface configuration file entries.  "
          "Only configure capture interfaces set using "
          "command-line options.\n"
          "  --disable-auto-flow-expiry\n    Don't "
          "auto-expire flows on exit.\n"
          "  -I, --internal [<interface>|<file>]\n    "
          "Specify an internal (LAN) interface, or file, "
          "to capture from.\n"
          "  -E, --external [<interface>|<file>]\n    "
          "Specify an external (WAN) interface, or file, "
          "to capture from.\n"
          "  -A, --device-address <address>\n    "
          "Interface/device option: consider address is "
          "assigned to interface.\n"
          "  -F, --device-filter <BPF expression>\n    "
          "Interface/device option: attach a BPF filter "
          "expression to interface.\n"
          "  -N, --device-peer <interface>\n    "
          "Interface/device option: associate interface "
          "with a peer (ex: PPPoE interface, pppX).\n"
          "  -t, --disable-conntrack\n    Disable "
          "connection tracking thread.\n"
          "  -l, --disable-netlink\n    Don't process "
          "Netlink messages for capture interfaces.\n"
          "  -r, --replay-delay\n    Simulate "
          "packet-to-packet arrival times in offline "
          "playback mode.\n"

          "\nThreading options:\n"
          "  --thread-capture-base <offset>\n    Specify a "
          "thread affinity base or offset for capture "
          "threads.\n"
          "  --thread-conntrack <cpu>\n    Specify a CPU "
          "affinity ID for the conntrack thread.\n"
          "  --thread-detection-base <offset>\n    Specify "
          "a thread affinity base or offset for detection "
          "(DPI) threads.\n"
          "  --thread-detection-cores <count>\n    Specify "
          "the number of detection (DPI) threads to "
          "start.\n"

          "\nSee %s(8) and %s.conf(5) for "
          "further options.\n",
          ND_CONF_FILE_NAME, ND_CONF_LEGACY_PATH,
          ndGC.path_uuid.c_str(), ndGC.path_uuid_site.c_str(),
          ND_NAME_SHORT, ND_NAME_SHORT);
    }
}

bool ndInstance::AddInterface(const string &ifname,
  ndInterfaceRole role, ndFlags<ndCaptureType> type) const {
    static unsigned pcap_id = 0;

    if ((ndCT_TYPE(type.flags) == ndCaptureType::PCAP ||
          ndCT_TYPE(type.flags) == ndCaptureType::NONE) &&
      nd_file_exists(ifname))
    {
        nd_config_pcap *pcap = new nd_config_pcap;

        pcap->capture_filename = ifname;
        string iface("offline");
        iface.append(to_string(pcap_id++));

        return ndGC.AddInterface(iface, role,
          ndCaptureType::PCAP_OFFLINE | ndCaptureType::CMDLINE,
          static_cast<void *>(pcap));
    }

    return ndGC.AddInterface(ifname, role, type);
}

bool ndInstance::CheckAgentUUID(void) const {
    string uuid;
    ndGC.GetUUID(ndUUID::AGENT, uuid);

    if (uuid.empty() || uuid == ND_AGENT_UUID_NULL) {
        string uuid;
        if (! ndGC.LoadUUID(ndUUID::AGENT, uuid)) {
            nd_generate_uuid(uuid);

            cout << "Generated a new Agent UUID: " << uuid << endl;
            if (! ndGC.SaveUUID(ndUUID::AGENT, uuid))
                return false;
        }
    }

    return (! uuid.empty());
}

bool ndInstance::SaveAgentStatus(const ndCaptureThreads &threads,
  const ndInterfaceStats &stats) {
    json jstatus;

    try {
        jstatus["type"] = "agent_status";
        jstatus["agent_version"] = ND_VERSION;

        apps.Encode(jstatus);
        plugins.Encode(jstatus);
        status.Encode(jstatus);

        if (dns_hint_cache != nullptr) {
            json jstats;
            dns_hint_cache->Encode(jstats);
            jstatus["dns_hint_cache"] = jstats;
        }

        if (flow_hash_cache != nullptr) {
            json jstats;
            flow_hash_cache->Encode(jstats);
            jstatus["flow_hash_cache"] = jstats;
        }

        if (ndGC_USE_NAPI || ndGC_AUTO_INFORMATICS) {
            json jnetify_api;
            jstatus["netify_api"] = api_manager.GetStatus();
        }

        for (auto &i : stats) {
            json jstats;
            i.second.Encode(jstats);
            jstatus["stats"][i.first] = jstats;

            auto ifa = interfaces.find(i.first);
            if (ifa != interfaces.end()) {
                json jiface;
                ifa->second->Encode(jiface);
                jstatus["interfaces"][i.first] = jiface;
            }

            auto ct = threads.find(i.first);
            if (ct != threads.end() && ct->second.size() > 0)
            {
                jstatus["interfaces"][i.first]["state"] =
                  ct->second[0]->GetState();
            }
        }

        string json_string;
        nd_json_to_string(jstatus, json_string);
        json_string.append("\n");

        nd_file_save(ndGC.path_agent_status, json_string);

        return true;
    }
    catch (exception &e) {
        nd_printf(
          "%s: Error saving Agent status to file: %s\n",
          tag.c_str(), e.what());
    }

    return false;
}

static void DisplayApiStatus(json &jstatus,
  const string &key, const string &label) {
    int code = -10;
    time_t last_update = 0;
    string updated_ago = "last update unknown";
    string message = "No update data";
    const char *icon = ndTerm::Icon::INFO;
    const char *color = ndTerm::Attr::RESET;

    auto jnetify_api = jstatus.find("netify_api");
    if (jnetify_api != jstatus.end() && jnetify_api->is_object())
    {
        auto jbootstrap = jnetify_api->find(key);

        if (jbootstrap != jnetify_api->end() &&
          jbootstrap->is_object())
        {
            auto jcode = jbootstrap->find("code");

            if (jcode != jbootstrap->end() && jcode->is_number())
            {
                code = jcode->get<int>();
            }

            auto jmessage = jbootstrap->find("message");

            if (jmessage != jbootstrap->end() &&
              jmessage->is_string())
            {
                message = jmessage->get<string>();
            }

            auto jlast_update = jbootstrap->find(
              "last_update");
            if (jlast_update != jbootstrap->end() &&
              jlast_update->is_number())
            {
                last_update = jlast_update->get<time_t>();
            }
        }
    }

    switch (code) {
    case -1:
        icon = ndTerm::Icon::FAIL;
        color = ndTerm::Color::RED;
        break;
    case -10:
        icon = ndTerm::Icon::WARN;
        color = ndTerm::Color::YELLOW;
        break;
    default:
        icon = ndTerm::Icon::OK;
        color = ndTerm::Color::GREEN;
        break;
    }

    if (last_update != 0) {
        nd_time_ago(time(nullptr) - last_update, updated_ago);
        updated_ago.append(" ago");
    }

    fprintf(stdout, "%s%s%s API %s (%s): [%d] %s%s%s\n",
      color, icon, ndTerm::Attr::RESET, label.c_str(),
      updated_ago.c_str(), code, color, message.c_str(),
      ndTerm::Attr::RESET);
}

bool ndInstance::DisplayAgentStatus(void) {
    const char *icon = ndTerm::Icon::INFO;
    const char *color = ndTerm::Attr::RESET;

    fprintf(stdout, "%s\n",
      nd_get_version_and_features(true).c_str());

    if (geteuid() != 0) {
        fprintf(stderr,
          "%s%s%s Error while retrieving agent status: "
          "%s%s%s\n",
          ndTerm::Color::RED, ndTerm::Icon::FAIL,
          ndTerm::Attr::RESET, ndTerm::Color::RED,
          strerror(EPERM), ndTerm::Attr::RESET);
        return false;
    }

    pid_t nd_pid = nd_load_pid(ndGC.path_pid_file);
    nd_pid = nd_is_running(nd_pid, self);

    fprintf(stdout, "%s%s%s agent %s: PID %d\n",
      (nd_pid < 0)    ? ndTerm::Color::YELLOW :
        (nd_pid == 0) ? ndTerm::Color::RED :
                        ndTerm::Color::GREEN,
      (nd_pid < 0)    ? ndTerm::Icon::WARN :
        (nd_pid == 0) ? ndTerm::Icon::FAIL :
                        ndTerm::Icon::OK,
      ndTerm::Attr::RESET,
      (nd_pid < 0)    ? "status could not be determined" :
        (nd_pid == 0) ? "is not running" :
                        "is running",
      nd_pid);

    json jstatus;

    try {
        string status;
        if (nd_file_load(ndGC.path_agent_status, status) < 0 ||
          status.size() == 0)
        {
            fprintf(stdout,
              "%s%s%s agent run-time status could not be "
              "determined.\n",
              ndTerm::Color::YELLOW, ndTerm::Icon::WARN,
              ndTerm::Attr::RESET);

            return false;
        }

        jstatus = json::parse(status);

        if (jstatus["type"].get<string>() != "agent_status")
            throw runtime_error(
              "Required type: agent_status");

        char timestamp[64];
        time_t ts = jstatus["timestamp"].get<time_t>();
        const struct tm *tm_local = localtime(&ts);

        if (nd_pid <= 0) {
            fprintf(stdout,
              "%s%s The following run-time information is "
              "likely out-dated.%s\n",
              ndTerm::Color::YELLOW, ndTerm::Icon::WARN,
              ndTerm::Attr::RESET);
        }

        if (strftime(timestamp, sizeof(timestamp), "%c", tm_local) > 0)
        {
            fprintf(stdout, "%s%s%s agent timestamp: %s\n",
              ndTerm::Color::GREEN, ndTerm::Icon::INFO,
              ndTerm::Attr::RESET, timestamp);
        }

        string uptime;
        nd_uptime(jstatus["uptime"].get<time_t>(), uptime);
        fprintf(stdout, "%s agent uptime: %s\n",
          ndTerm::Icon::INFO, uptime.c_str());

        string uuid;
        ndGC.LoadUUID(ndUUID::AGENT, uuid);

        if (uuid.size() != ND_AGENT_UUID_LEN || uuid == ND_AGENT_UUID_NULL)
        {
            fprintf(stdout,
              "%s%s%s agent UUID is not set.\n", ndTerm::Color::RED,
              ndTerm::Icon::FAIL, ndTerm::Attr::RESET);
            fprintf(stdout,
              "  %s To generate a new one, run the "
              "following command:\n",
              ndTerm::Icon::NOTE);
            fprintf(stdout, "  %s # %s --provision\n",
              ND_NAME_SHORT, ndTerm::Icon::NOTE);
        }
        else {
            fprintf(stdout, "%s%s%s agent UUID: %s\n",
              ndTerm::Color::GREEN, ndTerm::Icon::OK,
              ndTerm::Attr::RESET, uuid.c_str());
        }

        ndGC.LoadUUID(ndUUID::SERIAL, uuid);

        if (! uuid.empty() && uuid != ND_AGENT_SERIAL_NULL) {
            fprintf(stdout, "%s%s%s serial UUID: %s\n",
              ndTerm::Color::GREEN, ndTerm::Icon::INFO,
              ndTerm::Attr::RESET, uuid.c_str());
        }

        ndGC.LoadUUID(ndUUID::SITE, uuid);

        if (uuid.empty() || uuid == ND_SITE_UUID_NULL) {
            fprintf(stdout, "%s%s%s site UUID is not set.\n",
              ndTerm::Color::YELLOW, ndTerm::Icon::WARN,
              ndTerm::Attr::RESET);
            fprintf(stdout,
              "  %s A new site UUID will be automatically "
              "set after this agent has been "
              "provisioned.\n",
              ndTerm::Icon::NOTE);
        }
        else {
            fprintf(stdout, "%s%s%s agent site UUID: %s\n",
              ndTerm::Color::GREEN, ndTerm::Icon::OK,
              ndTerm::Attr::RESET, uuid.c_str());
        }

        fprintf(stdout, "%s%s%s API updates: %s%s%s\n",
          (ndGC_USE_NAPI || ndGC_AUTO_INFORMATICS) ?
            ndTerm::Color::GREEN :
            ndTerm::Color::YELLOW,
          (ndGC_USE_NAPI || ndGC_AUTO_INFORMATICS) ?
            ndTerm::Icon::INFO :
            ndTerm::Icon::WARN,
          ndTerm::Attr::RESET,
          (ndGC_USE_NAPI || ndGC_AUTO_INFORMATICS) ?
            ndTerm::Color::GREEN :
            ndTerm::Color::YELLOW,
          (ndGC_USE_NAPI || ndGC_AUTO_INFORMATICS) ?
            "enabled" :
            "disabled",
          ndTerm::Attr::RESET);

        if ((! ndGC_USE_NAPI) && (! ndGC_AUTO_INFORMATICS)) {
            fprintf(stdout,
              "  %s Netify API updates can be enabled from "
              "the configuration file:\n    %s\n",
              ndTerm::Icon::NOTE, conf_filename.c_str());
        }
        else {
            DisplayApiStatus(jstatus, "bootstrap",
              "provision status");
            DisplayApiStatus(jstatus, "applications",
              "applications update");
            DisplayApiStatus(jstatus, "categories",
              "categories update");
        }

        double flows = jstatus["flow_count"].get<double>();
        double flow_utilization = (ndGC.max_flows > 0) ?
          flows * 100.0 / (double)ndGC.max_flows :
          0;
        string max_flows = (ndGC.max_flows == 0) ?
          "unlimited" :
          to_string(ndGC.max_flows);

        if (flows > 0) {
            if (ndGC.max_flows) {
                if (flow_utilization < 75) {
                    icon = ndTerm::Icon::OK;
                    color = ndTerm::Color::GREEN;
                }
                else if (flow_utilization < 90) {
                    icon = ndTerm::Icon::WARN;
                    color = ndTerm::Color::YELLOW;
                }
                else {
                    icon = ndTerm::Icon::FAIL;
                    color = ndTerm::Color::RED;
                }
            }
            else {
                icon = ndTerm::Icon::OK;
                color = ndTerm::Color::GREEN;
            }
        }
        else {
            icon = ndTerm::Icon::WARN;
            color = ndTerm::Color::YELLOW;
        }

        fprintf(stdout,
          "%s%s%s active flows: %s%u%s / %s "
          "(%s%.01lf%%%s)\n",
          color, icon, ndTerm::Attr::RESET, color, (unsigned)flows,
          ndTerm::Attr::RESET, max_flows.c_str(), color,
          flow_utilization, ndTerm::Attr::RESET);

        unsigned long flows_in_use =
          (unsigned long)jstatus["flows_in_use"].get<unsigned>();

        icon = ndTerm::Icon::INFO;
        color = ndTerm::Attr::RESET;

        fprintf(stdout,
          "%s%s%s flows purged: %lu, in-use: %s%lu%s\n",
          color, icon, ndTerm::Attr::RESET,
          (unsigned long)jstatus["flows_purged"].get<unsigned>(),
          color, flows_in_use, ndTerm::Attr::RESET);

        fprintf(stdout,
          "%s%s%s flows expiring: %lu, expired: %lu\n",
          color, icon, ndTerm::Attr::RESET,
          (unsigned long)jstatus["flows_expiring"].get<unsigned>(),
          (unsigned long)jstatus["flows_expired"].get<unsigned>());

        fprintf(stdout, "%s minimum flow size: %lu\n",
          ndTerm::Icon::INFO,
          sizeof(ndFlow) + sizeof(struct ndpi_flow_struct));

        fprintf(stdout, "%s CPU cores: %u\n", ndTerm::Icon::INFO,
          jstatus["cpu_cores"].get<unsigned>());

        double cpu_user_delta = jstatus["cpu_user"].get<double>() -
          jstatus["cpu_user_prev"].get<double>();
        double cpu_system_delta =
          jstatus["cpu_system"].get<double>() -
          jstatus["cpu_system_prev"].get<double>();
        double cpu_max_time =
          jstatus["update_interval"].get<double>() *
          jstatus["cpu_cores"].get<double>();

        double cpu_user_percent = cpu_user_delta * 100.0 / cpu_max_time;
        double cpu_system_percent = cpu_system_delta *
          100.0 / cpu_max_time;
        double cpu_total = cpu_user_percent + cpu_system_percent;

        if (cpu_total < 33.34) {
            icon = ndTerm::Icon::OK;
            color = ndTerm::Color::GREEN;
        }
        else if (cpu_total < 66.67) {
            icon = ndTerm::Icon::WARN;
            color = ndTerm::Color::YELLOW;
        }
        else {
            icon = ndTerm::Icon::FAIL;
            color = ndTerm::Color::RED;
        }

        fprintf(stdout,
          "%s%s%s CPU utilization (user + system): "
          "%s%.1f%%%s\n",
          color, icon, ndTerm::Attr::RESET, color,
          cpu_total, ndTerm::Attr::RESET);
        fprintf(stdout,
          "%s%s%s CPU time (user / system): %.1fs / "
          "%.1fs\n",
          color, icon, ndTerm::Attr::RESET, cpu_user_delta,
          cpu_system_delta);

#if (defined(_ND_ENABLE_LIBTCMALLOC) && \
  defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H))
        fprintf(stdout,
          "%s%s%s current memory usage: %u kB\n",
          ndTerm::Color::GREEN, ndTerm::Icon::INFO,
          ndTerm::Attr::RESET, jstatus["tcm_kb"].get<unsigned>());
#endif  // _ND_ENABLE_LIBTCMALLOC
        fprintf(stdout,
          "%s%s%s maximum memory usage: %u kB\n",
          ndTerm::Color::GREEN, ndTerm::Icon::INFO,
          ndTerm::Attr::RESET,
          jstatus["maxrss_kb"].get<unsigned>());

        if (jstatus.find("interfaces") == jstatus.end() ||
          jstatus["interfaces"].empty())
        {
            color = (ndGC_RUN_WITHOUT_SOURCES) ?
              ndTerm::Color::YELLOW :
              ndTerm::Color::RED;
            icon = (ndGC_RUN_WITHOUT_SOURCES) ?
              ndTerm::Icon::WARN :
              ndTerm::Icon::FAIL;

            fprintf(stdout,
              "%s%s No capture sources (interfaces) "
              "configured.%s\n",
              color, icon, ndTerm::Attr::RESET);
        }
        else {
            for (auto &i : jstatus["interfaces"].items()) {
                const json &j = i.value();
                const string &iface = i.key();
                double dropped_percent = 0;

                icon = ndTerm::Icon::FAIL;
                color = ndTerm::Color::RED;
                string state = "unknown";

                const char *colors[2] = { ndTerm::Color::RED,
                    ndTerm::Attr::RESET };

                try {
                    auto jstate = j.find("state");

                    if (jstate != j.end()) {
                        switch (static_cast<ndCaptureThread::State>(
                          jstate->get<unsigned>()))
                        {
                        case ndCaptureThread::State::INIT:
                            icon = ndTerm::Icon::WARN;
                            colors[0] = color = ndTerm::Color::YELLOW;
                            state = "initializing";
                            break;
                        case ndCaptureThread::State::ONLINE:
                            icon = ndTerm::Icon::OK;
                            colors[0] = color = ndTerm::Color::GREEN;
                            state = "online";
                            break;
                        case ndCaptureThread::State::OFFLINE:
                            state = "offline";
                            break;
                        default: state = "invalid"; break;
                        }
                    }

                    unsigned pkts = 0, dropped = 0;

                    pkts = jstatus["stats"][iface]["raw"].get<unsigned>();
                    dropped = jstatus["stats"][iface]
                                     ["capture_dropped"]
                                       .get<unsigned>();
                    dropped += jstatus["stats"][iface]
                                      ["queue_dropped"]
                                        .get<unsigned>();

                    if (pkts == 0) {
                        icon = ndTerm::Icon::WARN;
                        colors[1] = color = ndTerm::Color::YELLOW;
                    }
                    else {
                        dropped_percent = (double)dropped *
                          100 / (double)pkts;

                        if (dropped_percent > 0.001) {
                            icon = ndTerm::Icon::WARN;
                            colors[1] = color = ndTerm::Color::YELLOW;
                        }
                        else if (dropped_percent > 5.0) {
                            icon = ndTerm::Icon::FAIL;
                            colors[1] = color = ndTerm::Color::RED;
                        }
                    }
                }
                catch (json::exception &e) {
                    fprintf(stdout,
                      "%s%s%s: error decoding interface "
                      "stats.\n",
                      ndTerm::Color::RED, ndTerm::Icon::FAIL,
                      ndTerm::Attr::RESET);
                }

                fprintf(stdout,
                  "%s%s%s %s [%s %s %s]: %s%s%s: packets "
                  "dropped: %s%.03lf%%%s\n",
                  color, icon, ndTerm::Attr::RESET,
                  iface.c_str(), j["role"].get<string>().c_str(),
                  ndTerm::Icon::RARROW,
                  j["capture_type"].get<string>().c_str(),
                  colors[0], state.c_str(),
                  ndTerm::Attr::RESET, colors[1],
                  dropped_percent, ndTerm::Attr::RESET);
                auto jcapture_file = j.find("capture_file");
                if (jcapture_file != j.end()) {
                    fprintf(stdout, "  %s %s\n", ndTerm::Icon::NOTE,
                      jcapture_file->get<string>().c_str());
                }
            }
        }

        json jsig = jstatus["signatures"];
        fprintf(stdout,
          "%s apps: %u, domains: %u, networks: %u, "
          "soft-dissectors: %u, transforms: %u\n",
          ndTerm::Icon::INFO, jsig["apps"].get<unsigned>(),
          jsig["domains"].get<unsigned>(),
          jsig["networks"].get<unsigned>(),
          jsig["soft_dissectors"].get<unsigned>(),
          jsig["transforms"].get<unsigned>());

        bool dhc_status = jstatus["dhc_status"].get<bool>();
        fprintf(stdout, "%s%s%s DNS hint cache: %s%s%s\n",
          (dhc_status) ? ndTerm::Color::GREEN : ndTerm::Color::YELLOW,
          (dhc_status) ? ndTerm::Icon::OK : ndTerm::Icon::WARN,
          ndTerm::Attr::RESET,
          (dhc_status) ? ndTerm::Color::GREEN : ndTerm::Color::YELLOW,
          (dhc_status) ? "enabled" : "disabled",
          ndTerm::Attr::RESET);

        if (dhc_status) {
            json jstats = jstatus["dns_hint_cache"];

            size_t cache_size = 0;
            uint64_t insert_hit = 0;
            float insert_hit_pct = 0;
            uint64_t insert_miss = 0;
            uint64_t insert_total = 0;
            uint64_t lookup_hit = 0;
            float lookup_hit_pct = 0;
            uint64_t lookup_miss = 0;
            uint64_t lookup_total = 0;

            try {
                cache_size = jstats["cache_size"].get<unsigned>();
                insert_hit = jstats["insert_hit"].get<uint64_t>();
                insert_hit_pct =
                  jstats["insert_hit_pct"].get<float>();
                insert_miss = jstats["insert_miss"].get<uint64_t>();
                insert_total = insert_hit + insert_miss;
                lookup_hit = jstats["lookup_hit"].get<uint64_t>();
                lookup_hit_pct =
                  jstats["lookup_hit_pct"].get<float>();
                lookup_miss = jstats["lookup_miss"].get<uint64_t>();
                lookup_total = lookup_hit + lookup_miss;

                fprintf(stdout,
                  "%s %s entries: %lu, inserts: %lu "
                  "(%.01f%%), lookups: %lu (%.01f%%)\n",
                  ndTerm::Icon::INFO, "DHC", cache_size,
                  insert_total, insert_hit_pct,
                  lookup_total, lookup_hit_pct);
            }
            catch (json::exception &e) {
                fprintf(stdout,
                  "%s%s%s error decoding %s status.\n",
                  ndTerm::Color::RED, ndTerm::Icon::FAIL,
                  ndTerm::Attr::RESET, "DHC");
            }
        }

        bool fhc_status = jstatus["fhc_status"].get<bool>();
        fprintf(stdout, "%s%s%s flow hash cache: %s%s%s\n",
          (fhc_status) ? ndTerm::Color::GREEN : ndTerm::Color::YELLOW,
          (fhc_status) ? ndTerm::Icon::OK : ndTerm::Icon::WARN,
          ndTerm::Attr::RESET,
          (fhc_status) ? ndTerm::Color::GREEN : ndTerm::Color::YELLOW,
          (fhc_status) ? "enabled" : "disabled",
          ndTerm::Attr::RESET);

        if (fhc_status) {
            json jstats = jstatus["flow_hash_cache"];

            size_t cache_size = 0;
            uint64_t insert_hit = 0;
            float insert_hit_pct = 0;
            uint64_t insert_miss = 0;
            uint64_t insert_total = 0;
            uint64_t lookup_hit = 0;
            float lookup_hit_pct = 0;
            uint64_t lookup_miss = 0;
            uint64_t lookup_total = 0;

            try {
                cache_size = jstats["cache_size"].get<unsigned>();
                insert_hit = jstats["insert_hit"].get<uint64_t>();
                insert_hit_pct =
                  jstats["insert_hit_pct"].get<float>();
                insert_miss = jstats["insert_miss"].get<uint64_t>();
                insert_total = insert_hit + insert_miss;
                lookup_hit = jstats["lookup_hit"].get<uint64_t>();
                lookup_hit_pct =
                  jstats["lookup_hit_pct"].get<float>();
                lookup_miss = jstats["lookup_miss"].get<uint64_t>();
                lookup_total = lookup_hit + lookup_miss;

                fprintf(stdout,
                  "%s %s entries: %lu, inserts: %lu "
                  "(%.01f%%), lookups: %lu (%.01f%%)\n",
                  ndTerm::Icon::INFO, "FHC", cache_size,
                  insert_total, insert_hit_pct,
                  lookup_total, lookup_hit_pct);
            }
            catch (json::exception &e) {
                fprintf(stdout,
                  "%s%s%s error decoding %s status.\n",
                  ndTerm::Color::RED, ndTerm::Icon::FAIL,
                  ndTerm::Attr::RESET, "FHC");
            }
        }
    }
    catch (exception &e) {
        fprintf(stdout,
          "%s%s%s agent run-time status exception: "
          "%s%s%s\n",
          ndTerm::Color::RED, ndTerm::Icon::FAIL,
          ndTerm::Attr::RESET, ndTerm::Color::RED, e.what(),
          ndTerm::Attr::RESET);
    }

    fprintf(stdout, "%s persistent state path: %s\n",
      ndTerm::Icon::INFO, ndGC.path_state_persistent.c_str());
    fprintf(stdout, "%s volatile state path: %s\n",
      ndTerm::Icon::INFO, ndGC.path_state_volatile.c_str());

    try {
        plugins.Load(ndPlugin::Type::BASE, false);
        plugins.DisplayStatus(jstatus);
    }
    catch (exception &e) {
        fprintf(stdout,
          "%s%s%s error loading plugin status: "
          "%s%s%s\n",
          ndTerm::Color::RED, ndTerm::Icon::FAIL,
          ndTerm::Attr::RESET, ndTerm::Color::RED, e.what(),
          ndTerm::Attr::RESET);
    }

    return true;
}

int ndInstance::Run(void) {
    if (version.empty()) {
        nd_printf(
          "%s: Instance configuration not "
          "initialized.\n",
          tag.c_str());
        goto ndInstance_RunReturn;
    }

    nd_printf("%s: %s\n", tag.c_str(), version.c_str());
    nd_dprintf("%s: online CPU cores: %ld\n", tag.c_str(),
      status.cpus);

    CheckAgentUUID();

    ndpi_global_init();

    if (ndGC_USE_DHC) {
        dns_hint_cache = new ndDNSHintCache(ndGC.max_dhc);
        dns_hint_cache->Load();
    }

    if (ndGC_USE_FHC) {
        flow_hash_cache = new ndFlowHashCache(ndGC.max_fhc);
        flow_hash_cache->Load();
    }

    flow_buckets = new ndFlowMap(ndGC.fm_buckets);

#ifdef _ND_ENABLE_NETLINK
    if (ndGC_USE_NETLINK) netlink = new ndNetlink();
#endif

    try {
#ifdef _ND_ENABLE_CONNTRACK
        if (ndGC_USE_CONNTRACK) {
            thread_conntrack = new ndConntrackThread(ndGC.ca_conntrack);
            thread_conntrack->Create();
        }
#endif
        plugins.Load();

        int16_t cpu =
          (ndGC.ca_detection_base > -1 &&
            ndGC.ca_detection_base < (int16_t)status.cpus) ?
          ndGC.ca_detection_base :
          0;
        int16_t cpus =
          (ndGC.ca_detection_cores > (int16_t)status.cpus ||
            ndGC.ca_detection_cores <= 0) ?
          (int16_t)status.cpus :
          ndGC.ca_detection_cores;

        for (int16_t i = 0; i < cpus; i++) {
            thread_detection[i] = new ndDetectionThread(cpu,
              string("dpi") + to_string(cpu),
#ifdef _ND_ENABLE_NETLINK
              netlink,
#endif
#ifdef _ND_ENABLE_CONNTRACK
              (! ndGC_USE_CONNTRACK) ? nullptr : thread_conntrack,
#endif
              dns_hint_cache, flow_hash_cache, (uint8_t)cpu);

            thread_detection[i]->Create();

            if (++cpu == cpus) cpu = 0;
        }
        loadBpfProgram();

    }
    catch (exception &e) {
        nd_printf("%s: Fatal exception: %s\n", tag.c_str(),
          e.what());
        goto ndInstance_RunReturn;
    }

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &status.ts_epoch) != 0)
    {
        nd_printf(
          "%s: Error loading epoch time "
          "(clock_gettime): "
          "%s\n",
          tag.c_str(), strerror(errno));
        goto ndInstance_RunReturn;
    }

    ndThread::Create();
    exit_code = EXIT_SUCCESS;

ndInstance_RunReturn:
    return exit_code;
}

bool ndInstance::SendSignal(const siginfo_t &si) {
    switch (si.si_signo) {
#ifdef _ND_ENABLE_NETLINK
    case SIGIO:
        if (ndGC_USE_NETLINK && netlink != nullptr &&
          netlink->GetDescriptor() == si.si_fd)
        {
            ndThread::SendIPC(
              static_cast<uint32_t>(InstanceEvent::NETLINK_IO));
            return true;
        }
        break;
#endif
    case SIGHUP:
        ndThread::SendIPC(
          static_cast<uint32_t>(InstanceEvent::RELOAD));
        return true;
    case SIGINT:
    case SIGTERM:
#ifdef SIGPWR
    case SIGPWR:
#endif
        ndThread::SendIPC(
          static_cast<uint32_t>(InstanceEvent::TERMINATE));
        return true;
    case SIGUSR1:
        if (dns_hint_cache != nullptr)
            dns_hint_cache->Save();
        if (flow_hash_cache != nullptr)
            flow_hash_cache->Save();
        break;
    case SIGUSR2: break;
    default:
        if (timer_update.GetSignal() >= 0 &&
          si.si_signo == timer_update.GetSignal())
        {
            ndThread::SendIPC(
              static_cast<uint32_t>(InstanceEvent::UPDATE));
            return true;
        }
        else if (timer_update_napi.GetSignal() >= 0 &&
          si.si_signo == timer_update_napi.GetSignal())
        {
            ndThread::SendIPC(static_cast<uint32_t>(
              InstanceEvent::UPDATE_NAPI));
            return true;
        }
        break;
    }
    return false;
}
void *ndInstance::ndInstance::Entry(void) {
    size_t proc_plugins = 0;
    ndCaptureThreads thread_capture;

#ifdef _ND_ENABLE_NETLINK
    if (ndGC_USE_NETLINK) netlink->Refresh();
#endif

    if (ndGC.ttl_capture_delay != 0) {
        for (unsigned i = 0; i < ndGC.ttl_capture_delay; i++)
        {
            nd_printf(
              "%s: starting capture thread(s) in "
              "%us...\n",
              tag.c_str(), ndGC.ttl_capture_delay - i);
            sleep(1);
        }
    }

    // Create and start capture threads
    if (! ReloadCaptureThreads(thread_capture))
        return nullptr;

    ndGC.Close();

    // Process an initial update on start-up
    ProcessUpdate(thread_capture);

    struct itimerspec itspec;
    itspec.it_value.tv_sec = ndGC.update_interval;
    itspec.it_value.tv_nsec = 0;
    itspec.it_interval.tv_sec = ndGC.update_interval;
    itspec.it_interval.tv_nsec = 0;

    timer_update.Set(itspec);

    if (ndGC_USE_NAPI || ndGC_AUTO_INFORMATICS) {
        itspec.it_value.tv_sec = min(5u, ndGC.ttl_napi_tick);
        itspec.it_value.tv_nsec = 0;
        itspec.it_interval.tv_sec = ndGC.ttl_napi_tick;
        itspec.it_interval.tv_nsec = 0;

        timer_update_napi.Set(itspec);
    }

    for (;;) {
        int ipc = static_cast<int>(InstanceEvent::NONE);

        switch (static_cast<InstanceEvent>(ipc = WaitForIPC(1)))
        {
        case InstanceEvent::NONE: break;
        case InstanceEvent::NETLINK_IO:
            nd_dprintf("%s: received IPC: [%d] %s\n",
              tag.c_str(), ipc, "Netlink data available");
#ifdef _ND_ENABLE_NETLINK
            if (ndGC_USE_NETLINK && netlink != nullptr)
                netlink->ProcessEvent();
#endif
            break;
        case InstanceEvent::RELOAD:
            nd_dprintf("%s: received IPC: [%d] %s\n", tag.c_str(),
              ipc, "Reload run-time configuration");
            Reload(true, false);
            if (! ReloadCaptureThreads(thread_capture)) {
                exit_code = EXIT_FAILURE;
                goto ndInstance_EntryReturn;
            }
            ndGC.Close();
            break;
        case InstanceEvent::TERMINATE:
            Terminate();
            if (! terminate_force.load())
                DestroyCaptureThreads(thread_capture, true);
            exit_code = EXIT_SUCCESS;
            break;
        case InstanceEvent::UPDATE:
            nd_dprintf("%s: received IPC: [%d] %s\n",
              tag.c_str(), ipc, "Update");
            ReapCaptureThreads(thread_capture);
            ProcessUpdate(thread_capture);
            break;
        case InstanceEvent::UPDATE_NAPI:
            nd_dprintf("%s: received IPC: [%d] %s\n",
              tag.c_str(), ipc, "Netify API update");
            if (ndGC_USE_NAPI || ndGC_AUTO_INFORMATICS) {
                if (api_manager.Update()) {
                    Reload(false, false);
                }
            }
            break;
        default:
            nd_dprintf("%s: received IPC: [%d] %s\n",
              tag.c_str(), ipc, "Ignored");
        }

        if (plugins.Reap()) {
            exit_code = EXIT_FAILURE;
            break;
        }

        if (terminate_force.load()) break;

        if (ShouldTerminate() && status.flows == 0) break;
    };

    proc_plugins = plugins.Terminate(ndPlugin::Type::PROC);

    do {
        nd_dprintf(
          "%s: waiting on %d processor plugins to "
          "exit.\n",
          tag.c_str(), proc_plugins);

        proc_plugins -= plugins.Reap(ndPlugin::Type::PROC);

        if (proc_plugins > 0) sleep(1);
    }
    while (proc_plugins > 0);

ndInstance_EntryReturn:
    if (! ShouldTerminate()) Terminate();

    DestroyCaptureThreads(thread_capture);

    // Process a final update on shutdown
    ProcessUpdate(thread_capture);

    if (exit_code == 0)
        nd_printf("%s: Normal exit.\n", tag.c_str());
    else {
        nd_printf("%s: Exit on error: %d\n", tag.c_str(), exit_code);
    }

    return nullptr;
}

bool ndInstance::Reload(bool broadcast, bool silent) {
    bool result = true;

    nd_dprintf("%s: reloading configuration...\n", tag.c_str());

    if (! (result = apps.Load(ndGC.path_app_config)))
        result = apps.LoadLegacy(ndGC.path_legacy_config);

    result = categories.Load(ndGC.path_cat_config);
    // XXX: Uncomment if converting from legacy format:
    //categories.Save("/tmp/netify-categories.json");

    if (ndGC_DOTD_CATEGORIES) {
        result = categories.LoadDotDirectory(ndGC.path_categories);
    }

    if (broadcast) {
        plugins.BroadcastEvent(ndPlugin::Type::BASE,
          ndPlugin::Event::RELOAD);
    }

    if (silent) {
        nd_dprintf("%s: configuration reloaded %s.\n",
          tag.c_str(), (result) ? "successfully" : "with errors");
    }
    else {
        nd_printf("%s: Configuration reloaded %s.\n",
          tag.c_str(), (result) ? "successfully" : "with errors");
    }

    return result;
}

void ndInstance::CreateCaptureInterfaces(ndInterfaces &ifaces) const {
    for (auto &r : ndGC.interfaces) {
        for (auto &i : r.second) {
            auto result = ifaces.insert(make_pair(i.first,
              make_shared<ndInterface>(i.first,
                i.second.first, r.first)));

            if (result.second) {
                switch (ndCT_TYPE(i.second.first.flags)) {
                case ndCaptureType::PCAP:
                case ndCaptureType::PCAP_OFFLINE:
                    result.first->second->SetConfig(
                      static_cast<nd_config_pcap *>(i.second.second));
                    break;
#if defined(_ND_ENABLE_TPACKETV3)
                case ndCaptureType::TPV3:
                    result.first->second->SetConfig(
                      static_cast<nd_config_tpv3 *>(i.second.second));
                    break;
#endif
#if defined(_ND_ENABLE_NFQUEUE)
                case ndCaptureType::NFQ:
                    result.first->second->SetConfig(
                      static_cast<nd_config_nfq *>(i.second.second));
                    break;
#endif
                default: break;
                }
            }

            auto peer = ndGC.interface_peers.find(i.first);
            if (peer != ndGC.interface_peers.end())
                result.first->second->ifname_peer = peer->second;
        }
    }
}

bool ndInstance::CreateCaptureThreads(ndInterfaces &ifaces,
  ndCaptureThreads &threads) {
    if (threads.size() != 0) {
        nd_printf("%s: Capture threads already created.\n",
          tag.c_str());
        return false;
    }

    static uint8_t private_addr = 0;
    vector<ndCaptureThread *> thread_group;

    static int16_t cpu =
      (ndGC.ca_capture_base > -1 &&
        ndGC.ca_capture_base < (int16_t)status.cpus) ?
      ndGC.ca_capture_base :
      0;

    for (auto &it : ifaces) {
        switch (ndCT_TYPE(it.second->capture_type.flags)) {
        case ndCaptureType::PCAP:
        case ndCaptureType::PCAP_OFFLINE:
        {
            auto thread = new ndCapturePcap(
              (interfaces.size() > 1) ? cpu++ : -1,
              it.second, thread_detection, dns_hint_cache,
              (it.second->role == ndInterfaceRole::LAN) ? 0 : ++private_addr);

            thread_group.push_back(thread);
            break;
        }
#if defined(_ND_ENABLE_TPACKETV3)
        case ndCaptureType::TPV3:
        {
            unsigned instances = it.second->config_tpv3.fanout_instances;
            if (it.second->config_tpv3.fanout_mode ==
                ndTPv3FanoutMode::DISABLED ||
              it.second->config_tpv3.fanout_instances < 2)
                instances = 1;

            for (unsigned i = 0; i < instances; i++) {
                auto thread = new ndCaptureTPv3(
                  (instances > 1) ? cpu++ : -1, it.second,
                  thread_detection, dns_hint_cache,
                  (it.second->role == ndInterfaceRole::LAN) ?
                    0 :
                    ++private_addr);

                thread_group.push_back(thread);

                if (cpu == (int16_t)status.cpus) cpu = 0;
            }

            break;
        }
#endif
#if defined(_ND_ENABLE_NFQUEUE)
        case ndCaptureType::NFQ:
        {
            unsigned instances = it.second->config_nfq.instances;
            if (it.second->config_nfq.instances == 0)
                instances = 1;

            for (unsigned i = 0; i < instances; i++) {
                auto thread = new ndCaptureNFQueue(
                  (instances > 1) ? cpu++ : -1, it.second,
                  thread_detection,
                  i,  // instance_id
                  dns_hint_cache,
                  (it.second->role == ndInterfaceRole::LAN) ?
                    0 :
                    ++private_addr);

                thread_group.push_back(thread);

                if (cpu == (int16_t)status.cpus) cpu = 0;
            }

            break;
        }
#endif
        default:
            nd_printf(
              "%s: WARNING: Unsupported capture type: "
              "%s: "
              "%u\n",
              tag.c_str(), it.second->ifname.c_str(),
              static_cast<unsigned>(it.second->capture_type.flags));
        }

        if (! thread_group.size()) continue;

        threads[it.second->ifname] = thread_group;

        thread_group.clear();

        if (cpu == (int16_t)status.cpus) cpu = 0;
    }

    for (auto &it : threads) {
        for (auto &it_instance : it.second)
            it_instance->Create();
    }

    return true;
}

void ndInstance::DestroyCaptureThreads(
  ndCaptureThreads &threads, bool expire_flows) {
    for (auto &it : threads) {
        for (auto &it_instance : it.second)
            it_instance->Terminate();
    }
    for (auto &it : threads) {
        for (auto &it_instance : it.second)
            delete it_instance;
    }

    threads.clear();

    if (! expire_flows) return;

    size_t count = 0, total = 0;
    size_t buckets = flow_buckets->GetBuckets();

    for (size_t b = 0; b < buckets; b++) {
        auto &fm = flow_buckets->Acquire(b);

        for (auto &it : fm) {
            if (it.second->flags.expired.load() == false &&
              it.second->flags.expiring.load() == false)
            {
                total++;
                if (ExpireFlow(it.second)) count++;
            }
        }

        flow_buckets->Release(b);
    }

    nd_dprintf("%s: forcibly expired %lu of %lu flow(s).\n",
      tag.c_str(), count, total);
}

size_t ndInstance::ReapCaptureThreads(ndCaptureThreads &threads) {
    size_t count = threads.size();

    for (auto &it : threads) {
        for (auto &it_instance : it.second) {
            if (it_instance->HasTerminated()) count--;
        }
    }

    if (ShouldTerminate() == false && count == 0 &&
      ! ndGC_RUN_WITHOUT_SOURCES)
    {
        nd_printf(
          "%s: Exiting, no remaining capture "
          "threads.\n",
          tag.c_str());

        DestroyCaptureThreads(threads, ndGC_AUTO_FLOW_EXPIRY);
        Terminate();
    }

    return count;
}

bool ndInstance::ReloadCaptureThreads(ndCaptureThreads &threads) {
    ndInterfaces ifaces, ifaces_new, ifaces_common, ifaces_delete;

    ndGlobalConfig::InterfaceAddrs old_addrs;
    old_addrs.insert(ndGC.interface_addrs.begin(),
      ndGC.interface_addrs.end());

    ndGC.LoadInterfaces(conf_filename);
    CreateCaptureInterfaces(ifaces);

    set_difference(ifaces.begin(), ifaces.end(),
      interfaces.begin(), interfaces.end(),
      inserter(ifaces_new, ifaces_new.begin()),
      ifaces.value_comp());
    set_intersection(ifaces.begin(), ifaces.end(),
      interfaces.begin(), interfaces.end(),
      inserter(ifaces_common, ifaces_common.begin()),
      ifaces.value_comp());
    set_difference(interfaces.begin(), interfaces.end(),
      ifaces.begin(), ifaces.end(),
      inserter(ifaces_delete, ifaces_delete.begin()),
      interfaces.value_comp());

    for (auto &iface : ifaces_common) {
        auto i = interfaces.find(iface.first);

        if (i == interfaces.end()) {
            nd_dprintf("%s: interface not found: %s\n",
              tag.c_str(), iface.first.c_str());
            return false;
        }

        if (*i->second == *iface.second) {
            set<string> ifaddrs_a, ifaddrs_b;

            auto it = ndGC.interface_addrs.find(iface.first);
            if (it != ndGC.interface_addrs.end()) {
                for (auto &a : it->second)
                    ifaddrs_a.insert(a);
            }

            it = old_addrs.find(iface.first);
            if (it != old_addrs.end()) {
                for (auto &a : it->second)
                    ifaddrs_b.insert(a);
            }

            if (ifaddrs_a.empty() && ifaddrs_b.empty())
                continue;

            set<string> ifaddrs_new, ifaddrs_delete;

            set_difference(ifaddrs_a.begin(), ifaddrs_a.end(),
              ifaddrs_b.begin(), ifaddrs_b.end(),
              inserter(ifaddrs_new, ifaddrs_new.begin()));
            set_difference(ifaddrs_b.begin(), ifaddrs_b.end(),
              ifaddrs_a.begin(), ifaddrs_a.end(),
              inserter(ifaddrs_delete, ifaddrs_delete.begin()));

            for (auto &a : ifaddrs_new) {
                addr_lookup.AddAddress(ndAddr::Type::LOCAL,
                  a, iface.first);
            }
            for (auto &a : ifaddrs_delete)
                addr_lookup.RemoveAddress(a, iface.first);

            continue;
        }

        nd_dprintf("%s: interface config changed.\n",
          iface.first.c_str());

        ifaces_new.insert(iface);
        ifaces_delete.insert(iface);
    }

    for (auto &iface : ifaces_delete) {
        auto ifa = ndGC.interface_addrs.find(iface.first);

        if (ifa != ndGC.interface_addrs.end()) {
            for (auto &a : ifa->second)
                addr_lookup.RemoveAddress(a, iface.first);

            ndGC.interface_addrs.erase(ifa);
        }
        {
            auto it = threads.find(iface.first);

            if (it != threads.end()) {
                for (auto &i : it->second) {
                    i->Terminate();
                    delete i;
                }

                threads.erase(it);
            }
        }
        {
            auto it = interfaces.find(iface.first);

            if (it != interfaces.end())
                interfaces.erase(it);
        }
    }

    ndCaptureThreads threads_new;

    if (! CreateCaptureThreads(ifaces_new, threads_new))
        return false;

    for (auto &iface : ifaces_new) {
        interfaces.insert(iface);

        auto ifa = ndGC.interface_addrs.find(iface.first);
        if (ifa != ndGC.interface_addrs.end()) {
            for (auto &a : ifa->second) {
                addr_lookup.AddAddress(ndAddr::Type::LOCAL,
                  a, iface.first);
            }
        }
    }

    for (auto &thread : threads_new) threads.insert(thread);

    return true;
}

uint32_t ndInstance::WaitForIPC(int timeout) {
    int rc;
    uint32_t event = 0;
    fd_set fds_read;

    do {
        FD_ZERO(&fds_read);
        FD_SET(fd_ipc[ndEnumCast(ndThread::PipeEnd, READ)], &fds_read);

        struct timeval tv = { 1, 0 };

        rc = select(fd_ipc[ndEnumCast(ndThread::PipeEnd, READ)] + 1,
          &fds_read, NULL, NULL, &tv);

        if (rc == -1) {
            throw ndExceptionSystemError(__PRETTY_FUNCTION__,
              "select");
        }

        if (rc > 0) {
            if (! FD_ISSET(fd_ipc[ndEnumCast(ndThread::PipeEnd, READ)],
                  &fds_read))
            {
                throw ndException(
                  "%s: %s: invalid descriptor",
                  __PRETTY_FUNCTION__, "select");
            }

            event = RecvIPC();
            break;
        }
    }
    while (! ShouldTerminate() && timeout < 0 && --timeout != 0);

    return event;
}

void ndInstance::UpdateStatus(void) {
#if defined(_ND_ENABLE_LIBTCMALLOC) && \
  defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H)
    size_t tcm_alloc_bytes = 0;

    MallocExtension::instance()->ReleaseFreeMemory();
    MallocExtension::instance()->GetNumericProperty(
      "generic.current_allocated_bytes", &tcm_alloc_bytes);
    status.tcm_alloc_kb_prev = status.tcm_alloc_kb;
    status.tcm_alloc_kb = tcm_alloc_bytes / 1024;
#endif
    struct rusage rusage_data;
    getrusage(RUSAGE_SELF, &rusage_data);

    status.cpu_user_prev = status.cpu_user;
    status.cpu_user = (double)rusage_data.ru_utime.tv_sec +
      ((double)rusage_data.ru_utime.tv_usec / 1000000.0);
    status.cpu_system_prev = status.cpu_system;
    status.cpu_system = (double)rusage_data.ru_stime.tv_sec +
      ((double)rusage_data.ru_stime.tv_usec / 1000000.0);

    status.maxrss_kb_prev = status.maxrss_kb;
    status.maxrss_kb = rusage_data.ru_maxrss;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &status.ts_now) != 0)
    {
        memcpy(&status.ts_now, &status.ts_epoch,
          sizeof(struct timespec));
    }

    status.dhc_status = ndGC_USE_DHC;
    status.fhc_status = ndGC_USE_FHC;
}

//void ndInstance::DisplayDebugScoreboard(void) const {
//}

bool ndInstance::ExpireFlow(nd_flow_ptr &flow) {

const uint8_t *lower_addr = flow->lower_addr.GetAddress();
const size_t lower_addr_len = flow->lower_addr.GetAddressSize();
const uint8_t *upper_addr = flow->upper_addr.GetAddress();
const size_t upper_addr_len = flow->upper_addr.GetAddressSize();
__be16 upper_port = htons(flow->upper_addr.GetPort());
__be16 lower_port = htons(flow->lower_addr.GetPort());
__be32 upper_addr_be32;
__be32 lower_addr_be32;
if (lower_addr_len == 4) {
    memcpy(&lower_addr_be32, lower_addr, sizeof(__be32));
} else {
    lower_addr_be32 = 0; // Invalid address length
}
if (upper_addr_len == 4) {
    memcpy(&upper_addr_be32, upper_addr, sizeof(__be32));
} else {
    upper_addr_be32 = 0; // Invalid address length
}
__be32 index = 0;
index = lower_addr_be32 ^ upper_addr_be32 ^ lower_port ^ upper_port;
remove_bpf_map_entry(index);

    if (flow->flags.detection_complete.load() == true)
        flow->flags.expired = true;
    else if (flow->flags.expiring.load() == false) {
        flow->flags.expiring = true;

        auto it = thread_detection.find(flow->dpi_thread_id);
        if (it != thread_detection.end()) {
            it->second->QueuePacket(flow);

            plugins.BroadcastProcessorEvent(
              ndPluginProcessor::Event::FLOW_EXPIRING, flow);

            return true;
        }
        else flow->flags.expired = true;
    }

    return false;
}

void ndInstance::ProcessUpdate(const ndCaptureThreads &threads) {
    UpdateStatus();
#if ! defined(_ND_ENABLE_LIBTCMALLOC) && defined(HAVE_MALLOC_TRIM)
    // Attempt to release heap back to OS when supported
    malloc_trim(0);
#endif
    if (dns_hint_cache != nullptr)
        dns_hint_cache->Scoreboard(tag + ": DHC");
    if (flow_hash_cache != nullptr)
        flow_hash_cache->Scoreboard(tag + ": FHC");

    plugins.BroadcastEvent(ndPlugin::Type::BASE,
      ndPlugin::Event::STATUS_UPDATE);

    plugins.BroadcastProcessorEvent(
      ndPluginProcessor::Event::UPDATE_INIT, &status);

    ndInterface::UpdateAddrs(interfaces);

    for (auto &it : interfaces)
        it.second->NextEndpointSnapshot();

    plugins.BroadcastProcessorEvent(
      ndPluginProcessor::Event::INTERFACES, &interfaces);

    ndInterfaceStats pkt_stats_ifaces;

    for (auto &it : threads) {
        ndPacketStats pkt_stats;

        for (auto &it_instance : it.second) {
            it_instance->Lock();

            it_instance->GetCaptureStats(pkt_stats);

            it_instance->Unlock();
        }

        pkt_stats_global += pkt_stats;
        pkt_stats_ifaces.insert(make_pair(it.first, pkt_stats));

        plugins.BroadcastProcessorEvent(
          ndPluginProcessor::Event::PKT_CAPTURE_STATS,
          it.first, &pkt_stats);
    }

    SaveAgentStatus(threads, pkt_stats_ifaces);

    plugins.BroadcastProcessorEvent(
      ndPluginProcessor::Event::PKT_GLOBAL_STATS, &pkt_stats_global);

    plugins.BroadcastProcessorEvent(
      ndPluginProcessor::Event::FLOW_MAP, flow_buckets);

    plugins.BroadcastProcessorEvent(
      ndPluginProcessor::Event::UPDATE_COMPLETE);

    ProcessFlows();
}

void ndInstance::ProcessFlows(void) {
    time_t now = time(NULL);
    size_t buckets = flow_buckets->GetBuckets();
#ifdef _ND_PROCESS_FLOW_DEBUG
    size_t tcp = 0, tcp_fin = 0, tcp_fin_ack_1 = 0,
           tcp_fin_ack_gt2 = 0;
#endif
    size_t flows_pre_init = 0, flows_total = 0;

    status.flows_purged = 0;
    status.flows_expiring = 0;
    status.flows_expired = 0;
    status.flows_active = 0;
    status.flows_in_use = 0;

    // flow_buckets->DumpBucketStats();

    for (size_t b = 0; b < buckets; b++) {
        auto &fm = flow_buckets->Acquire(b);
        auto i = fm.begin();

        flows_total += fm.size();

        while (i != fm.end()) {
#ifdef _ND_PROCESS_FLOW_DEBUG
            if (i->second->ip_protocol == IPPROTO_TCP)
                tcp++;
            if (i->second->ip_protocol == IPPROTO_TCP &&
              i->second->flags.tcp_fin.load())
                tcp_fin++;
            if (i->second->ip_protocol == IPPROTO_TCP &&
              i->second->flags.tcp_fin.load() &&
              i->second->flags.tcp_fin_ack.load() == 1)
                tcp_fin_ack_1++;
            if (i->second->ip_protocol == IPPROTO_TCP &&
              i->second->flags.tcp_fin.load() &&
              i->second->flags.tcp_fin_ack.load() >= 2)
                tcp_fin_ack_gt2++;
#endif
            if (i->second.use_count() > 1)
                status.flows_in_use++;

            if (i->second->flags.expired.load() == false) {
                time_t ttl = ((i->second->ip_protocol != IPPROTO_TCP) ?
                    ndGC.ttl_idle_flow :
                    ((i->second->tcp.fin_ack.load()) ?
                        ndGC.ttl_idle_flow :
                        ndGC.ttl_idle_tcp_flow));

                if (((time_t)(i->second->ts_last_seen.load() / 1000) +
                      ttl) < now)
                    if (ExpireFlow(i->second))
                        status.flows_expiring++;
            }

            if (i->second->flags.expired.load() == true) {
                status.flows_expired++;

                if (i->second.use_count() == 1) {
                    if (i->second->flags.expiry_broadcast.load() == false)
                    {
                        i->second->flags.expiry_broadcast = true;
                        plugins.BroadcastProcessorEvent(
                          ndPluginProcessor::Event::FLOW_EXPIRE,
                          i->second);
                    }
                    else {
                        i = fm.erase(i);
                        status.flows_purged++;
                    }

                    continue;
                }
            }
            else {
                if (i->second->flags.detection_init.load()) {
                    if (i->second->stats.lower_packets.load() ||
                      i->second->stats.upper_packets.load())
                    {
                        status.flows_active++;
                        i->second->Reset();
                    }
                }
                else {
                    flows_pre_init++;
                    // i->second->Print(ndFlow::PRINTF_ALL);
                }
            }

            i++;
        }

        flow_buckets->Release(b);
    }

    size_t flows_new = 0;

    if (status.flows_prev < flows_total)
        flows_new = flows_total - status.flows_prev;

    status.flows_prev = status.flows.load();
    status.flows -= status.flows_purged;

    nd_dprintf(
      "%s: new: %lu, pre-dpi: %lu, in-use: %lu, purged "
      "%lu, active: %lu, idle: %lu, expiring: "
      "%lu, "
      "expired: %lu, total: %lu\n",
      tag.c_str(),

      flows_new, flows_pre_init, status.flows_in_use,
      status.flows_purged, status.flows_active,
      flows_total - status.flows_active - flows_pre_init,
      status.flows_expiring, status.flows_expired, flows_total);
#ifdef _ND_PROCESS_FLOW_DEBUG
    nd_dprintf(
      "TCP: %lu, TCP+FIN: %lu, TCP+FIN+ACK1: %lu, "
      "TCP+FIN+ACK>=2: %lu\n",
      tcp, tcp_fin, tcp_fin_ack_1, tcp_fin_ack_gt2);
#endif
}
