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

#include <iomanip>
#include <locale>
#include <mutex>

#include "nd-apps.hpp"
#include "nd-category.hpp"
#include "nd-flags.hpp"
#include "nd-flow.hpp"
#include "nd-risks.hpp"
#include "nd-sha1.h"
#include "nd-util.hpp"

using namespace std;

// Enable lower map debug output
// #define _ND_DEBUG_LOWER_MAP	1

void ndFlowStats::UpdateRate(bool lower, uint64_t timestamp,
  uint64_t bytes) {
    const unsigned interval = ndGC.update_interval;

    unsigned index = (unsigned)fmod(
      floor((double)timestamp / (double)1000), (double)interval);

    atomic<float> &rate = lower ? lower_rate : upper_rate;
    vector<uint64_t> &samples =
      lower ? lower_rate_samples : upper_rate_samples;

    samples[index] += bytes;

    uint64_t total = 0;
    unsigned divisor = 0;
    for (unsigned i = 0; i < interval; i++) {
        if (samples[i] == 0) continue;
        total += samples[i];
        divisor++;
    }

    rate = (divisor > 0) ? ((float)total / (float)divisor) : 0.0f;
}

ndFlow::ndFlow(nd_iface_ptr &iface)
  : iface(iface), digest_lower{ 0 }, flags{}, tcp{},
    detected_protocol_name("Unknown") {
}

ndFlow::ndFlow(const ndFlow &flow)
  : iface(flow.iface), lower_mac(flow.lower_mac),
    upper_mac(flow.upper_mac), lower_addr(flow.lower_addr),
    upper_addr(flow.upper_addr), direction(flow.direction),
    ip_version(flow.ip_version), ip_protocol(flow.ip_protocol),
    vlan_id(flow.vlan_id), ts_first_seen(flow.ts_first_seen),
    ts_last_seen(flow.ts_last_seen.load()),
    tunnel_type(flow.tunnel_type), origin(flow.origin),
    digest_lower(flow.digest_lower), flags{}, tcp{},
#if defined(_ND_ENABLE_CONNTRACK) && \
  defined(_ND_ENABLE_CONNTRACK_MDATA)
    conntrack(flow.conntrack),
#endif
    gtp(flow.gtp), detected_protocol_name("Unknown") {
    digest_mdata.push_back(digest_lower);
    tcp.last_seq = flow.tcp.last_seq.load();
    tcp.fin_ack = flow.tcp.fin_ack.load();
}

ndFlow::~ndFlow() {
    Release();
}

void ndFlow::Hash(const string &device, bool hash_mdata,
  const uint8_t *key, size_t key_length) {
    sha1 ctx;

    sha1_init(&ctx);
    sha1_write(&ctx, (const char *)device.c_str(), device.size());

    sha1_write(&ctx, (const char *)&ip_version, sizeof(ip_version));
    sha1_write(&ctx, (const char *)&ip_protocol,
      sizeof(ip_protocol));
    sha1_write(&ctx, (const char *)&vlan_id, sizeof(vlan_id));

    switch (ip_version) {
    case 4:
        sha1_write(&ctx,
          (const char *)&lower_addr.addr.in.sin_addr,
          sizeof(struct in_addr));
        sha1_write(&ctx,
          (const char *)&upper_addr.addr.in.sin_addr,
          sizeof(struct in_addr));

        if (lower_addr.addr.in.sin_addr.s_addr == 0 &&
          upper_addr.addr.in.sin_addr.s_addr == 0xffffffff)
        {
            // XXX: Hash in lower MAC for ethernet broadcasts
            // (DHCPv4).
#if defined(__linux__)
            sha1_write(&ctx,
              (const char *)lower_mac.addr.ll.sll_addr,
              ETH_ALEN);
#elif defined(__FreeBSD__)
            sha1_write(&ctx,
              (const char *)LLADDR(&lower_mac.addr.dl),
              ETH_ALEN);
#endif
        }

        break;
    case 6:
        sha1_write(&ctx,
          (const char *)&lower_addr.addr.in6.sin6_addr,
          sizeof(struct in6_addr));
        sha1_write(&ctx,
          (const char *)&upper_addr.addr.in6.sin6_addr,
          sizeof(struct in6_addr));
        break;
    default: break;
    }

    uint16_t port = lower_addr.GetPort(false);
    sha1_write(&ctx, (const char *)&port, sizeof(port));
    port = upper_addr.GetPort(false);
    sha1_write(&ctx, (const char *)&port, sizeof(port));

    if (hash_mdata) {
        sha1_write(&ctx, (const char *)&detected_protocol,
          sizeof(ndProto::Id));
        sha1_write(&ctx, (const char *)&detected_application,
          sizeof(nd_app_id_t));

        if (! host_server_name.empty()) {
            sha1_write(&ctx, host_server_name.c_str(),
              host_server_name.size());
        }

        if (HasBTInfoHash()) {
            sha1_write(&ctx, bt.info_hash.data(),
              bt.info_hash.size());
        }
    }

    if (key != nullptr && key_length > 0)
        sha1_write(&ctx, (const char *)key, key_length);

    if (! hash_mdata)
        sha1_result(&ctx, digest_lower.data());
    else {
        ndDigest mdata;
        sha1_result(&ctx, mdata.data());

        if (! digest_mdata.empty() && mdata != digest_mdata.back())
        {
            digest_mdata.push_back(mdata);
        }
    }
}

void ndFlow::Release(void) {
    lock_guard<recursive_mutex> lg(lock);

    if (ndpi_flow != nullptr) {
        ndpi_free_flow(ndpi_flow);
        ndpi_flow = nullptr;
    }
}

ndProto::Id ndFlow::GetMasterProtocol(void) const {
    switch (detected_protocol) {
    case ndProto::Id::HTTPS:
    case ndProto::Id::TLS:
    case ndProto::Id::FTPS:
    case ndProto::Id::FTPS_DATA:
    case ndProto::Id::MAIL_IMAPS:
    case ndProto::Id::MAIL_POPS:
    case ndProto::Id::MAIL_SMTPS:
    case ndProto::Id::MQTTS:
    case ndProto::Id::NNTPS:
    case ndProto::Id::SIPS: return ndProto::Id::TLS;
    case ndProto::Id::HTTP:
    case ndProto::Id::HTTP_CONNECT:
    case ndProto::Id::HTTP_PROXY:
    case ndProto::Id::OOKLA:
    case ndProto::Id::PPSTREAM:
    case ndProto::Id::QQ:
    case ndProto::Id::RTSP:
    case ndProto::Id::STEAM:
    case ndProto::Id::TEAMVIEWER:
    case ndProto::Id::XBOX: return ndProto::Id::HTTP;
    case ndProto::Id::DNS:
    case ndProto::Id::MDNS:
    case ndProto::Id::LLMNR: return ndProto::Id::DNS;
    default: break;
    }

    return detected_protocol;
}

bool ndFlow::HasDhcpFingerprint(void) const {
    return (detected_protocol == ndProto::Id::DHCP &&
      ! dhcp.fingerprint.empty());
}

bool ndFlow::HasDhcpClassIdent(void) const {
    return (detected_protocol == ndProto::Id::DHCP &&
      ! dhcp.class_ident.empty());
}

bool ndFlow::HasHttpUserAgent(void) const {
    return (GetMasterProtocol() == ndProto::Id::HTTP &&
      ! http.user_agent.empty());
}

bool ndFlow::HasHttpURL(void) const {
    return (GetMasterProtocol() == ndProto::Id::HTTP &&
      ! http.url.empty());
}

bool ndFlow::HasSSHClientAgent(void) const {
    return (detected_protocol == ndProto::Id::SSH &&
      ! ssh.client_agent.empty());
}

bool ndFlow::HasSSHServerAgent(void) const {
    return (detected_protocol == ndProto::Id::SSH &&
      ! ssh.server_agent.empty());
}

bool ndFlow::HasTLSClientSNI(void) const {
    return ((GetMasterProtocol() == ndProto::Id::TLS ||
              detected_protocol == ndProto::Id::DTLS ||
              detected_protocol == ndProto::Id::QUIC) &&
      host_server_name.empty() == false);
}

bool ndFlow::HasTLSEncryptedCH(void) const {
    return ((GetMasterProtocol() == ndProto::Id::TLS ||
              detected_protocol == ndProto::Id::DTLS ||
              detected_protocol == ndProto::Id::QUIC) &&
      tls.ech.version != 0);
}

bool ndFlow::HasTLSEncryptedSNI(void) const {
    return ((GetMasterProtocol() == ndProto::Id::TLS ||
              detected_protocol == ndProto::Id::DTLS ||
              detected_protocol == ndProto::Id::QUIC) &&
      tls.esni.esni.empty() == false);
}

bool ndFlow::HasTLSServerCN(void) const {
    return ((GetMasterProtocol() == ndProto::Id::TLS ||
              detected_protocol == ndProto::Id::DTLS ||
              detected_protocol == ndProto::Id::QUIC) &&
      ! tls.server_cn.empty());
}

bool ndFlow::HasTLSIssuerDN(void) const {
    return ((GetMasterProtocol() == ndProto::Id::TLS ||
              detected_protocol == ndProto::Id::DTLS ||
              detected_protocol == ndProto::Id::QUIC) &&
      ! tls.issuer_dn.empty());
}

bool ndFlow::HasTLSSubjectDN(void) const {
    return ((GetMasterProtocol() == ndProto::Id::TLS ||
              detected_protocol == ndProto::Id::DTLS ||
              detected_protocol == ndProto::Id::QUIC) &&
      ! tls.subject_dn.empty());
}

bool ndFlow::HasTLSClientJA3(void) const {
    return ((GetMasterProtocol() == ndProto::Id::TLS ||
              detected_protocol == ndProto::Id::DTLS) &&
      ! tls.client_ja3.empty());
}

bool ndFlow::HasTLSServerJA3(void) const {
    return ((GetMasterProtocol() == ndProto::Id::TLS ||
              detected_protocol == ndProto::Id::DTLS) &&
      ! tls.server_ja3.empty());
}

bool ndFlow::HasBTInfoHash(void) const {
    return (detected_protocol == ndProto::Id::BITTORRENT &&
      ! bt.info_hash.empty());
}

bool ndFlow::HasSSDPUserAgent(void) const {
    return (GetMasterProtocol() == ndProto::Id::SSDP &&
      ! http.user_agent.empty());
}

bool ndFlow::HasMDNSDomainName(void) const {
    return (detected_protocol == ndProto::Id::MDNS &&
      ! mdns.domain_name.empty());
}

void ndFlow::Print(ndFlags<PrintFlags> pflags,
  const string &prefix) const {
    bool multiline = false;
    ndDebugLogStream dls(ndDebugLogStream::Type::FLOW);

    lock_guard<recursive_mutex> lg(lock);

    const string &p = (prefix.empty()) ? iface->ifname : prefix;
    size_t plen = p.size();

    nd_output_lock();

    try {
        dls << p << ": ";

        if (ndFlagBoolean(pflags, PrintFlags::HASHES)) {
            for (unsigned i = 0; i < 5; i++) {
                dls << setw(2) << setfill('0') << hex
                    << (int)digest_lower[i];
            }
            dls << ": ";
            auto mdata = digest_mdata.rbegin();

            for (unsigned i = 0; i < 5; i++) {
                dls << setw(2) << setfill('0') << hex
                    << (int)((mdata == digest_mdata.rend()) ?
                           0x00 :
                           (*mdata)[i]);
            }

            if (mdata != digest_mdata.rend()) mdata++;

            dls << ":";
            for (unsigned i = 0; i < 5; i++) {
                dls << setw(2) << setfill('0') << hex
                    << (int)((mdata == digest_mdata.rend()) ?
                           0x00 :
                           (*mdata)[i]);
            }
            dls << " ";
        }

        dls
          << setfill(' ') << dec
          << ((iface->role == ndInterfaceRole::LAN) ? 'i' : 'e')
          << ((ip_version == 4)    ? '4' :
                 (ip_version == 6) ? '6' :
                                     '-')
          << (flags.detection_init.load() ? 'p' : '-')
          << (flags.detection_complete.load() ? 'c' : '-')
          << (flags.detection_updated.load() ? 'u' : '-')
          << (flags.detection_guessed.load() ? 'g' : '-')
          << (flags.expiring.load() ? 'x' : '-')
          << (flags.expired.load() ? 'X' : '-')
          << (flags.dhc_hit.load() ? 'd' : '-')
          << (flags.fhc_hit.load() ? 'f' : '-')
          << (flags.ip_nat.load() ? 'n' : '-')
          << (risk.risks.empty() ? '-' : 'r')
          << (flags.soft_dissector.load() ? 's' : '-')
          << (tcp.fin_ack.load() ? 'F' : '-')
          << (ndFlagBoolean(privacy_mask,
                (PrivacyMask::LOWER_MAC | PrivacyMask::LOWER_IP)) ?
                 'v' :
                 ndFlagBoolean(privacy_mask,
                   (PrivacyMask::UPPER_MAC | PrivacyMask::UPPER_IP)) ?
                 'V' :
                 ndFlagBoolean(privacy_mask,
                   (PrivacyMask::LOWER_MAC | PrivacyMask::LOWER_IP |
                     PrivacyMask::UPPER_MAC | PrivacyMask::UPPER_IP)) ?
                 '?' :
                 '-')
          << " ";

        string proto;
        nd_get_ip_protocol_name(ip_protocol, proto);
        dls << proto << " ";

        switch (lower_map) {
        case LowerMap::UNKNOWN: dls << "[U"; break;
        case LowerMap::LOCAL: dls << "[L"; break;
        case LowerMap::OTHER: dls << "[O"; break;
        }

        char ot = '?';
        switch (other_type) {
        case OtherType::UNKNOWN: ot = 'U'; break;
        case OtherType::UNSUPPORTED: ot = 'X'; break;
        case OtherType::LOCAL: ot = 'L'; break;
        case OtherType::MULTICAST: ot = 'M'; break;
        case OtherType::BROADCAST: ot = 'B'; break;
        case OtherType::REMOTE: ot = 'R'; break;
        case OtherType::ERROR: ot = 'E'; break;
        }

        if (lower_map == LowerMap::OTHER) dls << ot;

        dls << "] ";

        if (ndFlagBoolean(pflags, PrintFlags::MACS))
            dls << lower_mac.GetString() << " ";

        dls
          << lower_addr.GetString() << ":"
          << lower_addr.GetPort() << " "
          << ((origin == Origin::LOWER || origin == Origin::UNKNOWN) ? '-' : '<')
          << ((origin == Origin::UNKNOWN) ? '?' : '-')
          << ((origin == Origin::UPPER || origin == Origin::UNKNOWN) ? '-' : '>')
          << " ";

        switch (lower_map) {
        case LowerMap::UNKNOWN: dls << "[U"; break;
        case LowerMap::LOCAL: dls << "[O"; break;
        case LowerMap::OTHER: dls << "[L"; break;
        }

        if (lower_map == LowerMap::LOCAL) dls << ot;

        dls << "] ";

        if (ndFlagBoolean(pflags, PrintFlags::MACS))
            dls << upper_mac.GetString() << " ";

        dls << upper_addr.GetString() << ":"
            << upper_addr.GetPort();

        if (ndFlagBoolean(pflags, PrintFlags::METADATA) &&
          flags.detection_init.load())
        {
            multiline = true;

            dls
              << endl
              << setw(plen) << " "
              << ": " << detected_protocol_name
              << ((! detected_application_name.empty()) ? "." : "")
              << ((! detected_application_name.empty()) ?
                     detected_application_name :
                     "");

            if (! dns_host_name.empty() ||
              ! host_server_name.empty())
            {
                dls << endl
                    << setw(plen) << " "
                    << ":";
                if (! dns_host_name.empty())
                    dls << " D: " << dns_host_name;
                if (! host_server_name.empty() &&
                  dns_host_name.compare(host_server_name)) {
                    dls << endl
                    << setw(plen) << " "
                    << ": Local Bytes: " << stats.lower_bytes.load()
                    << ", Other Bytes: " << stats.upper_bytes.load(); 
                    dls << " H: " << host_server_name;
                  }
            }

            if (HasMDNSDomainName()) {
                dls << endl
                    << setw(plen) << " "
                    << ":";
                dls << " MDNS/DN: " << mdns.domain_name;
            }

            if (HasBTInfoHash()) {
                string digest;
                nd_sha1_to_string(bt.info_hash, digest);

                dls << endl
                    << setw(plen) << " "
                    << ":";
                dls << " BT/HASH: " << digest;
            }

            if (HasDhcpFingerprint() || HasDhcpClassIdent()) {
                dls << endl
                    << setw(plen) << " "
                    << ":";
                if (HasDhcpFingerprint())
                    dls << " DHCP/FP: " << dhcp.fingerprint;
                if (HasDhcpClassIdent())
                    dls << " DHCP/CI: " << dhcp.class_ident;
            }

            if (HasHttpUserAgent() || HasSSDPUserAgent()) {
                dls << endl
                    << setw(plen) << " "
                    << ":";
                dls << " HTTP/UA: " << http.user_agent;
            }

            if (HasHttpURL()) {
                dls << endl
                    << setw(plen) << " "
                    << ":";
                dls << " URL: " << http.url;
            }

            if (HasSSHClientAgent() || HasSSHServerAgent()) {
                dls << endl
                    << setw(plen) << " "
                    << ":";
                if (HasSSHClientAgent())
                    dls << " SSH/CA: " << ssh.client_agent;
                if (HasSSHServerAgent())
                    dls << " SSH/SA: " << ssh.server_agent;
            }

            if ((GetMasterProtocol() == ndProto::Id::TLS ||
                  detected_protocol == ndProto::Id::DTLS ||
                  detected_protocol == ndProto::Id::QUIC) &&
              (tls.version || tls.cipher_suite))
            {
                dls << endl
                    << setw(plen) << " "
                    << ": ";
                dls << "V: 0x" << setfill('0') << setw(4) << hex
                    << tls.version << setfill(' ') << dec;

                if (tls.cipher_suite) {
                    dls << " "
                        << "CS: 0x" << setfill('0')
                        << setw(4) << hex << tls.cipher_suite
                        << setfill(' ') << dec;
                }
            }

            if (HasTLSClientSNI() || HasTLSServerCN()) {
                dls << endl
                    << setw(plen) << " "
                    << ":";
                if (HasTLSClientSNI())
                    dls << " TLS/SNI: " << host_server_name;
                if (HasTLSServerCN())
                    dls << " TLS/CN: " << tls.server_cn;
            }

            if (HasTLSEncryptedCH()) {
                dls << endl
                    << setw(plen) << " "
                    << ": TLS/ECH: v" << hex
                    << tls.ech.version << dec;
            }

            if (HasTLSEncryptedSNI()) {
                dls << endl
                    << setw(plen) << " "
                    << ": TLS/ESNI: v" << hex << tls.esni.cipher_suite
                    << dec << ": " << tls.esni.esni;
            }

            if (HasTLSIssuerDN() || HasTLSSubjectDN()) {
                dls << endl
                    << setw(plen) << " "
                    << ":";
                if (HasTLSIssuerDN())
                    dls << " TLS/IDN: " << tls.issuer_dn;
                if (HasTLSSubjectDN())
                    dls << " TLS/SDN: " << tls.subject_dn;
            }
        }

        if (ndFlagBoolean(pflags, PrintFlags::RISKS)) {
            if (! risk.risks.empty()) {
                auto r = risk.risks.begin();
                if (r != risk.risks.end()) {
                    dls
                      << endl
                      << setw(plen) << " " << setw(0) << ": RID"
                      << setw(3) << static_cast<unsigned>(*r)
                      << ": " << setw(0) << ndRisk::GetName(*r);
                }
                if (risk.risks.size() > 1) {
                    for (r = next(risk.risks.begin());
                         r != risk.risks.end();
                         r++)
                    {
                        dls
                          << endl
                          << setw(plen) << " " << setw(0)
                          << ": RID" << setw(3)
                          << static_cast<unsigned>(*r) << ": "
                          << setw(0) << ndRisk::GetName(*r);
                    }
                }
            }
        }

        if (ndFlagBoolean(pflags, PrintFlags::STATS)) {
            multiline = true;

            dls << endl
                << setw(plen) << " "
                << ": "
                << "DP: "
                << ndLogFormat(ndLogFormat::Format::BYTES,
                     stats.detection_packets.load());

            if (ndFlagBoolean(pflags, PrintFlags::STATS_FULL))
            {
                dls
                  << " "
                  << "TP: "
                  << ndLogFormat(ndLogFormat::Format::PACKETS,
                       stats.total_packets.load())
                  << " "
                  << "TB: "
                  << ndLogFormat(ndLogFormat::Format::BYTES,
                       stats.total_bytes.load());
            }
        }

        if (multiline) dls << endl;
        dls << endl;
    }
    catch (exception &e) {
        nd_output_unlock();

        nd_dprintf("exception caught printing flow: %s\n",
          e.what());
        return;
    }

    nd_output_unlock();
}

void ndFlow::UpdateLowerMaps(void) {
    if (lower_map == LowerMap::UNKNOWN)
        GetLowerMap(lower_type, upper_type, lower_map, other_type);

    switch (tunnel_type) {
    case TunnelType::GTP:
        if (gtp.lower_map == LowerMap::UNKNOWN) {
            GetLowerMap(gtp.lower_type, gtp.upper_type,
              gtp.lower_map, gtp.other_type);
        }
        break;
    default: break;
    }
}

void ndFlow::GetLowerMap(ndAddr::Type lt, ndAddr::Type ut,
  LowerMap &lm, OtherType &ot) {
    if (lt == ndAddr::Type::ERROR || ut == ndAddr::Type::ERROR)
    {
        ot = OtherType::ERROR;
    }
    else if (lt == ndAddr::Type::LOCAL && ut == ndAddr::Type::LOCAL)
    {
        lm = LowerMap::LOCAL;
        ot = OtherType::LOCAL;
    }
    else if (lt == ndAddr::Type::LOCAL && ut == ndAddr::Type::LOCALNET)
    {
        lm = LowerMap::LOCAL;
        ot = OtherType::LOCAL;
    }
    else if (lt == ndAddr::Type::LOCALNET && ut == ndAddr::Type::LOCAL)
    {
        lm = LowerMap::LOCAL;
        ot = OtherType::LOCAL;
    }
    else if (lt == ndAddr::Type::MULTICAST) {
        lm = LowerMap::OTHER;
        ot = OtherType::MULTICAST;
    }
    else if (ut == ndAddr::Type::MULTICAST) {
        lm = LowerMap::LOCAL;
        ot = OtherType::MULTICAST;
    }
    else if (lt == ndAddr::Type::BROADCAST) {
        lm = LowerMap::OTHER;
        ot = OtherType::BROADCAST;
    }
    else if (ut == ndAddr::Type::BROADCAST) {
        lm = LowerMap::LOCAL;
        ot = OtherType::BROADCAST;
    }
    else if (lt == ndAddr::Type::RESERVED &&
      ut == ndAddr::Type::LOCALNET)
    {
        lm = LowerMap::OTHER;
        ot = OtherType::LOCAL;
    }
    else if (lt == ndAddr::Type::LOCALNET &&
      ut == ndAddr::Type::RESERVED)
    {
        lm = LowerMap::LOCAL;
        ot = OtherType::LOCAL;
    }
    // TODO: Further investigation required!
    // This appears to catch corrupted IPv6 headers.
    // Spend some time to figure out if there are any
    // possible over-matches for different methods of
    // deployment (gateway/port mirror modes).
    else if (ip_version != 6 && lt == ndAddr::Type::RESERVED &&
      ut == ndAddr::Type::RESERVED)
    {
        lm = LowerMap::LOCAL;
        ot = OtherType::LOCAL;
    }
    else if (lt == ndAddr::Type::RESERVED && ut == ndAddr::Type::LOCAL)
    {
        lm = LowerMap::OTHER;
        ot = OtherType::REMOTE;
    }
    else if (lt == ndAddr::Type::LOCAL && ut == ndAddr::Type::RESERVED)
    {
        lm = LowerMap::LOCAL;
        ot = OtherType::REMOTE;
    }
    else if (lt == ndAddr::Type::LOCALNET &&
      ut == ndAddr::Type::LOCALNET)
    {
        lm = LowerMap::LOCAL;
        ot = OtherType::LOCAL;
    }
    else if (lt == ndAddr::Type::OTHER) {
        lm = LowerMap::OTHER;
        ot = OtherType::REMOTE;
    }
    else if (ut == ndAddr::Type::OTHER) {
        lm = LowerMap::LOCAL;
        ot = OtherType::REMOTE;
    }
#if _ND_DEBUG_LOWER_MAP
    const static vector<string> lower_maps = { "lmUNKNOWN",
        "lmLOCAL", "lmOTHER" };
    const static vector<string> other_types = { "otUNKNOWN",
        "otUNSUPPORTED", "otLOCAL", "otMULTICAST",
        "otBROADCAST", "otREMOTE", "otERROR" };
    const static vector<string> at = { "atNONE", "atLOCAL",
        "atLOCALNET", "atRESERVED", "atMULTICAST",
        "atBROADCAST", "atOTHER" };

    if (lm == lmUNKNOWN) {
        nd_dprintf("lower map: %s, other type: %s\n",
          lower_maps[lm].c_str(),
          other_types[ot].c_str());
        nd_dprintf(
          "lower type: %s: %s, upper_type: %s: %s\n",
          lower_addr.GetString().c_str(),
          (lt == ndAddr::Type::ERROR) ? "atERROR" : at[lt].c_str(),
          upper_addr.GetString().c_str(),
          (ut == ndAddr::Type::ERROR) ? "atERROR" : at[ut].c_str());
    }
#endif
}
