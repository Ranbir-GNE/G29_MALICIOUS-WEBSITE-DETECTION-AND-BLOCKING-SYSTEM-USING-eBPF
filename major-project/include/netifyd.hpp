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

#ifndef AF_LINK
#define AF_LINK AF_PACKET
#endif

#ifndef ETH_ALEN
#include <net/ethernet.h>
#if ! defined(ETH_ALEN) && defined(ETHER_ADDR_LEN)
#define ETH_ALEN ETHER_ADDR_LEN
#endif
#endif
#ifndef ETH_ALEN
#error Unable to define ETH_ALEN.
#endif

#ifdef _ND_ENABLE_NETLINK
#include <linux/netlink.h>
#endif

#include <sys/param.h>
#include <sys/socket.h>

#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif

#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif

#if __cplusplus >= 201103L && \
  (! defined(__GLIBCXX__) || (__cplusplus >= 201402L) || \
    (defined(_GLIBCXX_REGEX_DFS_QUANTIFIERS_LIMIT) || \
      defined(_GLIBCXX_REGEX_STATE_LIMIT) || \
      (defined(_GLIBCXX_RELEASE) && _GLIBCXX_RELEASE > 4)))
#define HAVE_WORKING_REGEX 1
#else
#undef HAVE_WORKING_REGEX
#endif

#include "nd-version.hpp"

#define ND_STATS_INTERVAL \
    15  // Collect stats every N seconds
#define ND_MAX_BACKLOG_KB \
    2048  // Maximum upload queue size in kB
#define ND_DETECTION_TICKS \
    1000  // Ticks-per-second (1000 = milliseconds)
#define ND_TTL_IDLE_FLOW \
    30  // Purge idle flows older than this (30s)
#define ND_TTL_IDLE_TCP_FLOW \
    300  // Purge idle TCP flows older than this (5m)
#define ND_HASH_BUCKETS_FLOWS \
    1613  // Initial flows map bucket count.
#define ND_HASH_BUCKETS_DNSARS \
    1613  // DNS cache address record hash buckets.

#define ND_MAX_DHC_ENTRIES \
    1000  // Maximum number of DNS hint cache entries.
#define ND_MAX_FHC_ENTRIES \
    1000  // Maximum number of flow hash cache entries.
#define ND_FHC_PURGE_DIVISOR \
    10  // Divisor of FHC_ENTRIES to delete on purge.

#define ND_FLOW_MAP_BUCKETS \
    128  // Default number of flow map buckets.

#define ND_MAX_PKT_QUEUE_KB \
    8192  // Maximum packet queue size in kB
#define ND_PKTQ_FLUSH_DIVISOR \
    10  // Divisor of PKT_QUEUE_KB packets to flush.

#define ND_MAX_DETECTION_PKTS \
    32  // Maximum number of packets to process.

#ifndef ND_VOLATILE_STATEDIR
#define ND_VOLATILE_STATEDIR "/var/run/netifyd"
#endif

#ifndef ND_PERSISTENT_STATEDIR
#define ND_PERSISTENT_STATEDIR "/etc/netifyd"
#endif

#ifndef ND_SHARED_DATADIR
#define ND_SHARED_DATADIR "/usr/share/netifyd"
#endif

#ifndef ND_CONF_FILE_NAME
#define ND_CONF_FILE_NAME "/etc/netifyd.conf"
#endif

#ifndef ND_PID_FILE_NAME
#define ND_PID_FILE_NAME ND_VOLATILE_STATEDIR "/netifyd.pid"
#endif
#define ND_PID_FILE_BASE "netifyd.pid"
#define ND_PID_FILE_PATH \
    ND_VOLATILE_STATEDIR "/" ND_PID_FILE_BASE

#define ND_PLUGINS_BASE "plugins.d"
#define ND_PLUGINS_PATH \
    ND_PERSISTENT_STATEDIR "/" ND_PLUGINS_BASE

#ifndef ND_PLUGIN_LIBDIR
#define ND_PLUGIN_LIBDIR "/usr/lib"
#endif

#define ND_CATEGORIES_BASE "categories.d"
#define ND_CATEGORIES_PATH \
    ND_PERSISTENT_STATEDIR "/" ND_CATEGORIES_BASE

#define ND_FUNCTIONS_BASE "functions.sh"
#define ND_FUNCTIONS_PATH \
    ND_SHARED_DATADIR "/" ND_FUNCTIONS_BASE

#define ND_INTERFACES_BASE "interfaces.d"
#define ND_INTERFACES_PATH \
    ND_PERSISTENT_STATEDIR "/" ND_INTERFACES_BASE

#define ND_JSON_DATA_CHUNKSIZ   4096
#define ND_JSON_INDENT          4

#define ND_CAPTURE_READ_TIMEOUT 500  // Milliseconds

#define ND_PCAP_SNAPLEN         65535  // Capture snap length

#define ND_TPV3_RB_BLOCK_SIZE   (1 << 22)  // Bytes
#define ND_TPV3_RB_FRAME_SIZE   (1 << 11)  // Bytes
#define ND_TPV3_RB_BLOCKS       64

#define ND_AGENT_STATUS_BASE    "status.json"
#define ND_AGENT_STATUS_PATH \
    ND_VOLATILE_STATEDIR "/" ND_AGENT_STATUS_BASE

#define ND_COOKIE_JAR      ND_VOLATILE_STATEDIR "/cookie.jar"

#define ND_AGENT_UUID_BASE "agent.uuid"
#define ND_AGENT_UUID_PATH \
    ND_PERSISTENT_STATEDIR "/" ND_AGENT_UUID_BASE
#define ND_AGENT_UUID_NULL   "00-00-00-00"
#define ND_AGENT_UUID_LEN    11

#define ND_AGENT_SERIAL_BASE "serial.uuid"
#define ND_AGENT_SERIAL_PATH \
    ND_PERSISTENT_STATEDIR "/" ND_AGENT_SERIAL_BASE
#define ND_AGENT_SERIAL_NULL "-"
#define ND_AGENT_SERIAL_LEN  32

#define ND_SITE_UUID_BASE    "site.uuid"
#define ND_SITE_UUID_PATH \
    ND_PERSISTENT_STATEDIR "/" ND_SITE_UUID_BASE
#define ND_SITE_UUID_NULL    "-"
#define ND_SITE_UUID_LEN     36

#define ND_ZLIB_CHUNK_SIZE   16384

#define ND_SOCKET_PORT       "7150"
#define ND_SOCKET_PATH_MODE  0640
#define ND_SOCKET_PATH_USER  "root"
#define ND_SOCKET_PATH_GROUP "root"

#define ND_CONF_APP_BASE     "netify-apps.conf"
#define ND_CONF_APP_PATH \
    ND_PERSISTENT_STATEDIR "/" ND_CONF_APP_BASE

#define ND_CONF_CAT_BASE "netify-categories.json"
#define ND_CONF_CAT_PATH \
    ND_PERSISTENT_STATEDIR "/" ND_CONF_CAT_BASE

#define ND_CONF_LEGACY_BASE "netify-sink.conf"
#define ND_CONF_LEGACY_PATH \
    ND_PERSISTENT_STATEDIR "/" ND_CONF_LEGACY_BASE

#define ND_STR_ETHALEN    (ETH_ALEN * 2 + ETH_ALEN - 1)

#define ND_PRIVATE_IPV4   "127.255.0."
#define ND_PRIVATE_IPV6   "fe:80::ffff:7fff:"

#define ND_TTL_API_TICK   30
#define ND_TTL_API_UPDATE (3600 * 24)
#define ND_URL_API_BOOTSTRAP \
    "https://agents.netify.ai/api/v2/bootstrap"
#define ND_API_VENDOR "EG"
