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

#include <ndpi_protocol_ids.h>

#include "nd-config.hpp"
#include "nd-flow.hpp"
#include "nd-ndpi.hpp"
#include "nd-protos.hpp"
#include "nd-thread.hpp"
#include "nd-util.hpp"

static ndpi_init_prefs nd_ndpi_prefs = ndpi_no_prefs;
static NDPI_PROTOCOL_BITMASK ndpi_protos;

void ndpi_global_init(void) {
    nd_dprintf("Initializing nDPI v%s, API v%u...\n",
      ndpi_revision(), NDPI_API_VERSION);

    if (ndpi_get_api_version() != NDPI_API_VERSION) {
        throw ndException(
          "%s: nDPI library version mis-match", __PRETTY_FUNCTION__);
    }

    set_ndpi_malloc(nd_mem_alloc);
    set_ndpi_free(nd_mem_free);

    nd_ndpi_prefs = ndpi_no_prefs;

    nd_ndpi_prefs |= ndpi_dont_init_risk_ptree;
    nd_ndpi_prefs |= ndpi_dont_load_amazon_aws_list;
    nd_ndpi_prefs |= ndpi_dont_load_asn_lists;
    nd_ndpi_prefs |= ndpi_dont_load_azure_list;
    nd_ndpi_prefs |= ndpi_dont_load_cachefly_list;
    nd_ndpi_prefs |= ndpi_dont_load_cloudflare_list;
    nd_ndpi_prefs |= ndpi_dont_load_crawlers_list;
    nd_ndpi_prefs |= ndpi_dont_load_ethereum_list;
    nd_ndpi_prefs |= ndpi_dont_load_google_cloud_list;
    nd_ndpi_prefs |= ndpi_dont_load_google_list;
    nd_ndpi_prefs |= ndpi_dont_load_icloud_private_relay_list;
    nd_ndpi_prefs |= ndpi_dont_load_microsoft_list;
    nd_ndpi_prefs |= ndpi_dont_load_mullvad_list;
    nd_ndpi_prefs |= ndpi_dont_load_protonvpn_exit_nodes_list;
    nd_ndpi_prefs |= ndpi_dont_load_protonvpn_list;
    nd_ndpi_prefs |= ndpi_dont_load_tor_list;
    nd_ndpi_prefs |= ndpi_dont_load_whatsapp_list;
    nd_ndpi_prefs |= ndpi_dont_load_zoom_list;
    nd_ndpi_prefs |= ndpi_enable_ja3_plus;

    // ndpi_disable_fully_encrypted_heuristic
    // ndpi_dont_init_libgcrypt
    // ndpi_enable_tcp_ack_payload_heuristic;
    // ndpi_track_flow_payload;

    NDPI_BITMASK_RESET(ndpi_protos);

    auto it = ndGC.protocols.find("ALL");
    if (it == ndGC.protocols.end()) {
        it = ndGC.protocols.find("all");
        if (it == ndGC.protocols.end())
            it = ndGC.protocols.find("All");
    }

    if (it != ndGC.protocols.end()) {
        if (strcasecmp(it->second.c_str(), "include") == 0) {
            NDPI_BITMASK_SET_ALL(ndpi_protos);
            nd_dprintf("Enabled all protocols.\n");
        }
        else if (strcasecmp(it->second.c_str(), "exclude") == 0)
        {
            nd_dprintf("Disabled all protocols.\n");
        }
    }

    for (auto it : ndGC.protocols) {
        signed action = -1;
        if (strcasecmp(it.second.c_str(), "include") == 0)
            action = 0;
        else if (strcasecmp(it.second.c_str(), "exclude") == 0)
            action = 1;
        else continue;

        uint16_t id = NDPI_PROTOCOL_UNKNOWN;
        ndProto::Id proto = ndProto::GetId(it.first);

        if (proto == ndProto::Id::UNKNOWN) {
            id = ndProto::nDPI::Find(static_cast<ndProto::Id>(
              strtoul(it.first.c_str(), nullptr, 0)));
        }
        else id = ndProto::nDPI::Find(proto);

        if (id == NDPI_PROTOCOL_UNKNOWN) continue;

        switch (action) {
        case 0:
            NDPI_ADD_PROTOCOL_TO_BITMASK(ndpi_protos, id);
            nd_dprintf("Enabled protocol: %s\n", it.first.c_str());
            break;

        case 1:
            NDPI_DEL_PROTOCOL_FROM_BITMASK(ndpi_protos, id);
            nd_dprintf("Disabled protocol: %s\n", it.first.c_str());
            break;
        }
    }

    if (ndGC.protocols.empty()) {
        NDPI_BITMASK_SET_ALL(ndpi_protos);
        nd_dprintf("Enabled all protocols.\n");
    }

    for (auto &it : ndProto::nDPI::Disabled) {
        NDPI_DEL_PROTOCOL_FROM_BITMASK(ndpi_protos, it);
        if (ndGC.verbosity > 4)
            nd_dprintf("Banned protocol by ID: %hu\n", it);
    }
}

struct ndpi_detection_module_struct *nd_ndpi_init(void) {

    struct ndpi_detection_module_struct *ndpi = nullptr;
    ndpi = ndpi_init_detection_module(nd_ndpi_prefs);

    if (ndpi == nullptr) {
        throw ndException("%s: %s", __PRETTY_FUNCTION__,
          "ndpi_init_detection_module");
    }

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
    if (ndGC_DEBUG) {
        ndpi->ndpi_log_level = NDPI_LOG_ERROR;
        if (! ndGC_QUIET)
            ndpi->ndpi_log_level = NDPI_LOG_DEBUG;
        if (ndGC_DEBUG_NDPI)
            ndpi->ndpi_log_level = NDPI_LOG_DEBUG_EXTRA;
        set_ndpi_debug_function(ndpi, nd_ndpi_debug_printf);
    }
#endif

    ndpi_set_detection_preferences(ndpi,
      ndpi_pref_enable_tls_block_dissection, 1);
    ndpi_set_detection_preferences(ndpi,
      ndpi_pref_direction_detect_disable, 0);

    ndpi_set_protocol_detection_bitmask2(ndpi, &ndpi_protos);

    ndpi_finalize_initialization(ndpi);

    return ndpi;
}

void nd_ndpi_free(struct ndpi_detection_module_struct *ndpi) {
    ndpi_exit_detection_module(ndpi);
}
