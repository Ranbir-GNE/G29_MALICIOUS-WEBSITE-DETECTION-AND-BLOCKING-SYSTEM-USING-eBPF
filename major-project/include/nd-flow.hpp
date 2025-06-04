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
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "nd-addr.hpp"
#include "nd-apps.hpp"
#include "nd-category.hpp"
#include "nd-config.hpp"
#include "nd-flags.hpp"
#include "nd-protos.hpp"
#include "nd-serializer.hpp"
#include "nd-sha1.h"
#include "nd-util.hpp"

// TLS SNI hostname/common-name length. Reference: RFC 4366
constexpr size_t ND_FLOW_TLS_CNLEN = 256;

class ndFlowStats
{
public:
    ndFlowStats()
      : lower_bytes(0), upper_bytes(0), total_bytes(0),
        lower_packets(0), upper_packets(0),
        total_packets(0), detection_packets(0)
#ifdef _ND_ENABLE_EXTENDED_STATS
        ,
        lower_rate_samples(ndGC.update_interval, 0),
        upper_rate_samples(ndGC.update_interval, 0),
        lower_rate(0), upper_rate(0), tcp_seq_errors(0),
        tcp_resets(0), tcp_retrans(0)
#endif
    {
    }

    ndFlowStats(const ndFlowStats &stats)
      : lower_bytes(stats.lower_bytes.load()),
        upper_bytes(stats.upper_bytes.load()),
        total_bytes(stats.total_bytes.load()),
        lower_packets(stats.lower_packets.load()),
        upper_packets(stats.upper_packets.load()),
        total_packets(stats.total_packets.load()),
        detection_packets(stats.detection_packets.load())
#ifdef _ND_ENABLE_EXTENDED_STATS
        ,
        lower_rate_samples(ndGC.update_interval, 0),
        upper_rate_samples(ndGC.update_interval, 0),
        lower_rate(stats.lower_rate.load()),
        upper_rate(stats.upper_rate.load()),
        tcp_seq_errors(stats.tcp_seq_errors.load()),
        tcp_resets(stats.tcp_resets.load()),
        tcp_retrans(stats.tcp_retrans.load())
#endif
    {
    }

    inline ndFlowStats &operator=(const ndFlowStats &fs) {
        lower_bytes = fs.lower_bytes.load();
        upper_bytes = fs.upper_bytes.load();
        total_bytes = fs.total_bytes.load();
        lower_packets = fs.lower_packets.load();
        upper_packets = fs.upper_packets.load();
        total_packets = fs.total_packets.load();
        detection_packets = fs.detection_packets.load();
#ifdef _ND_ENABLE_EXTENDED_STATS
        lower_rate = fs.lower_rate.load();
        upper_rate = fs.upper_rate.load();
        tcp_seq_errors = fs.tcp_seq_errors.load();
        tcp_resets = fs.tcp_resets.load();
        tcp_retrans = fs.tcp_retrans.load();
#endif
        return *this;
    };

    inline void Reset(void) {
        lower_bytes = 0;
        upper_bytes = 0;
        lower_packets = 0;
        upper_packets = 0;
#ifdef _ND_ENABLE_EXTENDED_STATS
        lower_rate_samples.assign(ndGC.update_interval, 0);
        upper_rate_samples.assign(ndGC.update_interval, 0);
        tcp_seq_errors = 0;
        tcp_resets = 0;
        tcp_retrans = 0;
#endif
    }

    std::atomic<uint64_t> lower_bytes;
    std::atomic<uint64_t> upper_bytes;
    std::atomic<uint64_t> total_bytes;

    std::atomic<uint32_t> lower_packets;
    std::atomic<uint32_t> upper_packets;
    std::atomic<uint32_t> total_packets;

    std::atomic<uint8_t> detection_packets;

#ifdef _ND_ENABLE_EXTENDED_STATS
    std::vector<uint64_t> lower_rate_samples;
    std::vector<uint64_t> upper_rate_samples;
    std::atomic<float> lower_rate;
    std::atomic<float> upper_rate;

    void UpdateRate(bool lower, uint64_t timestamp, uint64_t bytes);

    std::atomic<uint32_t> tcp_seq_errors;
    std::atomic<uint32_t> tcp_resets;
    std::atomic<uint32_t> tcp_retrans;
#endif
};

class ndFlow : public ndSerializer
{
public:
    nd_iface_ptr iface;

    ndAddr lower_mac;
    ndAddr upper_mac;

    ndAddr lower_addr;
    ndAddr upper_addr;

    ndAddr::Type lower_type = { ndAddr::Type::NONE };
    ndAddr::Type upper_type = { ndAddr::Type::NONE };

    int direction = { 0 };

    uint8_t ip_version = { 0 };
    uint8_t ip_protocol = { 0 };

    uint16_t vlan_id = { 0 };

    uint64_t ts_first_seen = { 0 };
    std::atomic<uint64_t> ts_last_seen = { 0 };

    enum class LowerMap : uint8_t { UNKNOWN, LOCAL, OTHER };

    LowerMap lower_map = { LowerMap::UNKNOWN };

    enum class OtherType : uint8_t {
        UNKNOWN,
        UNSUPPORTED,
        LOCAL,
        MULTICAST,
        BROADCAST,
        REMOTE,
        ERROR
    };

    OtherType other_type = { OtherType::UNKNOWN };

    enum class TunnelType : uint8_t { NONE, GTP };

    TunnelType tunnel_type = { TunnelType::NONE };

    enum class Origin : uint8_t {
        UNKNOWN,
        LOWER,
        UPPER,
    };

    Origin origin = { Origin::UNKNOWN };

    enum class PrivacyMask : uint8_t {
        NONE = 0,
        LOWER_MAC = (1 << 0),
        UPPER_MAC = (1 << 1),
        UPPER_IP = (1 << 2),
        LOWER_IP = (1 << 3)
    };

    ndFlags<PrivacyMask> privacy_mask = { PrivacyMask::NONE };

    ndDigest digest_lower;

    typedef std::vector<ndDigest> DigestVec;
    DigestVec digest_mdata;

    struct {
        std::atomic<bool> detection_complete;
        std::atomic<bool> detection_guessed;
        std::atomic<bool> detection_init;
        std::atomic<bool> detection_updated;
        std::atomic<bool> dhc_hit;
        std::atomic<bool> fhc_hit;
        std::atomic<bool> expiring;
        std::atomic<bool> expiry_broadcast;
        std::atomic<bool> expired;
        std::atomic<bool> ip_nat;
        std::atomic<bool> soft_dissector;
    } flags;

    struct {
        std::atomic<uint8_t> fin_ack;
        std::atomic<uint32_t> last_seq;
    } tcp;

#if defined(_ND_ENABLE_CONNTRACK) && \
  defined(_ND_ENABLE_CONNTRACK_MDATA)
    struct {
        uint32_t id = { 0 };
        uint32_t mark = { 0 };
    } conntrack;
#endif

    struct {
        uint8_t version = { 0xFF };
        uint8_t ip_version = { 0 };
        uint32_t lower_teid = { 0 };
        uint32_t upper_teid = { 0 };
        ndAddr::Type lower_type;
        ndAddr::Type upper_type;
        ndAddr lower_addr;
        ndAddr upper_addr;
        LowerMap lower_map = { LowerMap::UNKNOWN };
        OtherType other_type = { OtherType::UNKNOWN };
    } gtp;

    std::string dns_host_name;
    std::string host_server_name;

    ndProto::Id detected_protocol = { ndProto::Id::UNKNOWN };
    std::string detected_protocol_name;

    nd_app_id_t detected_application = { ND_APP_UNKNOWN };
    std::string detected_application_name;

    struct {
        nd_cat_id_t application = { ND_CAT_UNKNOWN };
        nd_cat_id_t protocol = { ND_CAT_UNKNOWN };
        nd_cat_id_t domain = { ND_CAT_UNKNOWN };
        nd_cat_id_t network = { ND_CAT_UNKNOWN };
    } category;

    struct {
        std::string user_agent;
        std::string url;
    } http;

    struct {
        std::string fingerprint;
        std::string class_ident;
    } dhcp;

    struct {
        std::string client_agent;
        std::string server_agent;
    } ssh;

    struct {
        uint16_t version = { 0 };
        uint16_t cipher_suite = { 0 };

        std::string subject_dn;
        std::string issuer_dn;
        std::string server_cn;
        std::string client_ja3;
        std::string server_ja3;
        std::vector<uint8_t> cert_fingerprint;
        std::vector<std::string> alpn, alpn_server;

        struct {
            uint16_t version = { 0 };
        } ech;

        struct {
            uint16_t cipher_suite = { 0 };
            std::string esni;
        } esni;

        std::atomic<bool> proc_hello;
        std::atomic<bool> proc_certificate;
    } tls;

    struct {
        bool tls = { false };
    } smtp;

    struct {
        ndDigestDynamic info_hash;
    } bt;

    struct {
        std::string domain_name;
    } mdns;

    struct {
        uint16_t ndpi_score = { 0 };
        uint16_t ndpi_score_client = { 0 };
        uint16_t ndpi_score_server = { 0 };

        typedef std::set<ndRisk::Id> Risks;
        Risks risks;
    } risk;

    ndFlowStats stats;

    mutable std::recursive_mutex lock;

    uint8_t dpi_queued = { 0 };
    int16_t dpi_thread_id = { -1 };

    struct ndpi_flow_struct *ndpi_flow = { nullptr };

    ndFlow(nd_iface_ptr &iface);
    ndFlow(const ndFlow &flow);
    virtual ~ndFlow();

    void Hash(const std::string &device, bool hash_mdata = false,
      const uint8_t *key = nullptr, size_t key_length = 0);

    inline void Reset(void) { stats.Reset(); }

    void Release(void);

    ndProto::Id GetMasterProtocol(void) const;

    bool HasDhcpFingerprint(void) const;
    bool HasDhcpClassIdent(void) const;
    bool HasHttpUserAgent(void) const;
    bool HasHttpURL(void) const;
    bool HasSSHClientAgent(void) const;
    bool HasSSHServerAgent(void) const;
    bool HasTLSClientSNI(void) const;
    bool HasTLSEncryptedCH(void) const;
    bool HasTLSEncryptedSNI(void) const;
    bool HasTLSServerCN(void) const;
    bool HasTLSIssuerDN(void) const;
    bool HasTLSSubjectDN(void) const;
    bool HasTLSClientJA3(void) const;
    bool HasTLSServerJA3(void) const;
    bool HasBTInfoHash(void) const;
    bool HasSSDPUserAgent(void) const;
    bool HasMDNSDomainName(void) const;

    enum class PrintFlags : uint8_t {
        NONE = 0,
        HASHES = (1 << 0),
        MACS = (1 << 1),
        METADATA = (1 << 2),
        STATS = (1 << 3),
        STATS_FULL = (1 << 4),
        RISKS = (1 << 5),
        ALL = (HASHES | MACS | METADATA | STATS | STATS_FULL | RISKS)
    };

    void Print(ndFlags<PrintFlags> pflags = PrintFlags::METADATA,
      const std::string &prefix = "") const;

    void UpdateLowerMaps(void);
    void GetLowerMap(ndAddr::Type lt, ndAddr::Type ut,
      LowerMap &lm, OtherType &ot);

    enum class EncodeFlags : uint8_t {
        NONE = 0,
        METADATA = (1 << 0),
        TUNNELS = (1 << 1),
        STATS = (1 << 2),
        ALL = (METADATA | TUNNELS | STATS)
    };

    template <class T>
    void Encode(T &output, const ndFlowStats &stats,
      ndFlags<EncodeFlags> encode_flags = EncodeFlags::ALL) const {
        std::lock_guard<std::recursive_mutex> lg(lock);

        std::string _other_type = "unknown";
        std::string _lower_mac = "local_mac",
                    _upper_mac = "other_mac";
        std::string _lower_ip = "local_ip",
                    _upper_ip = "other_ip";
        std::string _lower_gtp_ip = "local_ip",
                    _upper_gtp_ip = "other_ip";
        std::string _lower_port = "local_port",
                    _upper_port = "other_port";
        std::string _lower_gtp_port = "local_port",
                    _upper_gtp_port = "other_port";
        std::string _lower_bytes = "local_bytes",
                    _upper_bytes = "other_bytes";
        std::string _lower_packets = "local_packets",
                    _upper_packets = "other_packets";
#ifdef _ND_ENABLE_EXTENDED_STATS
        std::string _lower_rate = "local_rate";
        std::string _upper_rate = "other_rate";
#endif
        std::string digest;
        std::vector<std::string> digests;

        if (! digest_mdata.empty()) {
            auto i = digest_mdata.rbegin();
            nd_sha1_to_string((*i), digest);
            serialize(output, { "digest" }, digest);

            for (++i; i != digest_mdata.rend(); i++) {
                nd_sha1_to_string((*i), digest);
                digests.push_back(digest);
            }
        }
        serialize(output, { "digest_prev" }, digests);

        serialize(output, { "last_seen_at" }, ts_last_seen.load());

        switch (lower_map) {
        case LowerMap::LOCAL:
            _lower_mac = "local_mac";
            _lower_ip = "local_ip";
            _lower_port = "local_port";
            _lower_bytes = "local_bytes";
            _lower_packets = "local_packets";
            _upper_mac = "other_mac";
            _upper_ip = "other_ip";
            _upper_port = "other_port";
            _upper_bytes = "other_bytes";
            _upper_packets = "other_packets";
#ifdef _ND_ENABLE_EXTENDED_STATS
            _lower_rate = "local_rate";
            _upper_rate = "other_rate";
#endif
            break;
        case LowerMap::OTHER:
            _lower_mac = "other_mac";
            _lower_ip = "other_ip";
            _lower_port = "other_port";
            _lower_bytes = "other_bytes";
            _lower_packets = "other_packets";
            _upper_mac = "local_mac";
            _upper_ip = "local_ip";
            _upper_port = "local_port";
            _upper_bytes = "local_bytes";
            _upper_packets = "local_packets";
#ifdef _ND_ENABLE_EXTENDED_STATS
            _lower_rate = "other_rate";
            _upper_rate = "local_rate";
#endif
            break;
        default: break;
        }

        switch (other_type) {
        case OtherType::LOCAL: _other_type = "local"; break;
        case OtherType::MULTICAST:
            _other_type = "multicast";
            break;
        case OtherType::BROADCAST:
            _other_type = "broadcast";
            break;
        case OtherType::REMOTE:
            _other_type = "remote";
            break;
        case OtherType::UNSUPPORTED:
            _other_type = "unsupported";
            break;
        case OtherType::ERROR: _other_type = "error"; break;
        default: break;
        }

        if (ndFlagBoolean(encode_flags, EncodeFlags::METADATA))
        {
            serialize(output, { "ip_nat" },
              (bool)flags.ip_nat.load());
            if (ndGC_USE_DHC) {
                serialize(output, { "dhc_hit" },
                  (bool)flags.dhc_hit.load());
            }
            if (ndGC_USE_FHC) {
                serialize(output, { "fhc_hit" },
                  (bool)flags.fhc_hit.load());
            }
            serialize(output, { "soft_dissector" },
              (bool)flags.soft_dissector.load());
#if defined(_ND_ENABLE_CONNTRACK) && \
  defined(_ND_ENABLE_CONNTRACK_MDATA)
            serialize(output, { "ct_id" }, conntrack.id);
            serialize(output, { "ct_mark" }, conntrack.mark);
#endif
            serialize(output, { "ip_version" }, (unsigned)ip_version);
            serialize(output, { "ip_protocol" },
              (unsigned)ip_protocol);
            serialize(output, { "vlan_id" }, (unsigned)vlan_id);
            serialize(output, { "other_type" }, _other_type);

            switch (origin) {
            case Origin::UPPER:
                serialize(output, { "local_origin" },
                  (_lower_ip == "local_ip") ? false : true);
                break;
            case Origin::LOWER:
            default:
                serialize(output, { "local_origin" },
                  (_lower_ip == "local_ip") ? true : false);
                break;
            }

            // 00-52-14 to 00-52-FF: Unserialized (small
            // allocations)
            serialize(output, { _lower_mac },
              ndFlagBoolean(privacy_mask, PrivacyMask::LOWER_MAC) ?
                "00:52:14:00:00:00" :
                (lower_mac.IsValid()) ?
                lower_mac.GetString() :
                "00:00:00:00:00:00");
            serialize(output, { _upper_mac },
              ndFlagBoolean(privacy_mask, PrivacyMask::UPPER_MAC) ?
                "00:52:ff:00:00:00" :
                (upper_mac.IsValid()) ?
                upper_mac.GetString() :
                "00:00:00:00:00:00");

            if (ndFlagBoolean(privacy_mask, PrivacyMask::LOWER_IP))
            {
                if (ip_version == 4)
                    serialize(output, { _lower_ip },
                      ND_PRIVATE_IPV4 "253");
                else
                    serialize(output, { _lower_ip },
                      ND_PRIVATE_IPV6 "fd");
            }
            else
                serialize(output, { _lower_ip },
                  lower_addr.GetString());

            if (ndFlagBoolean(privacy_mask, PrivacyMask::UPPER_IP))
            {
                if (ip_version == 4)
                    serialize(output, { _upper_ip },
                      ND_PRIVATE_IPV4 "254");
                else
                    serialize(output, { _upper_ip },
                      ND_PRIVATE_IPV6 "fe");
            }
            else
                serialize(output, { _upper_ip },
                  upper_addr.GetString());

            serialize(output, { _lower_port },
              (unsigned)lower_addr.GetPort());
            serialize(output, { _upper_port },
              (unsigned)upper_addr.GetPort());

            serialize(output, { "detected_protocol" },
              (unsigned)detected_protocol);
            serialize(output, { "detected_protocol_name" },
              (detected_protocol_name.empty()) ?
                "Unknown" :
                detected_protocol_name);

            serialize(output, { "detected_application" },
              (unsigned)detected_application);
            serialize(output, { "detected_application_name" },
              (detected_application_name.empty()) ?
                "Unknown" :
                detected_application_name);

            serialize(output, { "detection_guessed" },
              flags.detection_guessed.load());
            serialize(output, { "detection_updated" },
              flags.detection_updated.load());

            serialize(output, { "category", "application" },
              category.application);
            serialize(output, { "category", "protocol" },
              category.protocol);
            serialize(output, { "category", "domain" },
              category.domain);
            serialize(output, { "category", "network" },
              category.network);

            if (! dns_host_name.empty())
                serialize(output, { "dns_host_name" }, dns_host_name);

            if (! host_server_name.empty())
                serialize(output, { "host_server_name" },
                  host_server_name);

            if (HasHttpUserAgent() || HasHttpURL()) {
                if (HasHttpUserAgent())
                    serialize(output,
                      { "http", "user_agent" }, http.user_agent);
                if (HasHttpURL())
                    serialize(output, { "http", "url" },
                      http.url);
            }

            if (HasDhcpFingerprint() || HasDhcpClassIdent()) {
                if (HasDhcpFingerprint())
                    serialize(output,
                      { "dhcp", "fingerprint" }, dhcp.fingerprint);

                if (HasDhcpClassIdent())
                    serialize(output,
                      { "dhcp", "class_ident" }, dhcp.class_ident);
            }

            if (HasSSHClientAgent() || HasSSHServerAgent()) {
                if (HasSSHClientAgent())
                    serialize(output, { "ssh", "client" },
                      ssh.client_agent);

                if (HasSSHServerAgent())
                    serialize(output, { "ssh", "server" },
                      ssh.server_agent);
            }

            if (GetMasterProtocol() == ndProto::Id::TLS ||
              detected_protocol == ndProto::Id::QUIC)
            {
                char tohex[7];

                sprintf(tohex, "0x%04hx", tls.version);
                serialize(output, { "ssl", "version" }, tohex);

                sprintf(tohex, "0x%04hx", tls.cipher_suite);
                serialize(output, { "ssl", "cipher_suite" }, tohex);

                if (HasTLSClientSNI())
                    serialize(output,
                      { "ssl", "client_sni" }, host_server_name);

                if (HasTLSEncryptedCH())
                    serialize(output,
                      { "ssl", "encrypted_ch_version" },
                      tls.ech.version);

                if (HasTLSEncryptedSNI()) {
                    serialize(output,
                      { "ssl", "encrypted_sni" },
                      tls.esni.esni);
                    serialize(output,
                      { "ssl", "esni_cipher_suite" },
                      tls.esni.cipher_suite);
                }

                if (HasTLSServerCN())
                    serialize(output,
                      { "ssl", "server_cn" }, tls.server_cn);

                if (HasTLSIssuerDN())
                    serialize(output,
                      { "ssl", "issuer_dn" }, tls.issuer_dn);

                if (HasTLSSubjectDN())
                    serialize(output,
                      { "ssl", "subject_dn" }, tls.subject_dn);

                if (HasTLSClientJA3())
                    serialize(output,
                      { "ssl", "client_ja3" }, tls.client_ja3);

                if (HasTLSServerJA3())
                    serialize(output,
                      { "ssl", "server_ja3" }, tls.server_ja3);

                if (! tls.cert_fingerprint.empty()) {
                    nd_sha1_to_string(tls.cert_fingerprint, digest);
                    serialize(output,
                      { "ssl", "fingerprint" }, digest);
                }

                if (! tls.alpn.empty())
                    serialize(output, { "ssl", "alpn" }, tls.alpn);
                if (! tls.alpn_server.empty())
                    serialize(output,
                      { "ssl", "alpn_server" }, tls.alpn_server);
            }

            if (HasBTInfoHash()) {
                nd_sha1_to_string(bt.info_hash, digest);
                serialize(output, { "bt", "info_hash" }, digest);
            }

            if (HasSSDPUserAgent()) {
                if (HasSSDPUserAgent()) {
                    serialize(output,
                      { "ssdp", "user_agent" }, http.user_agent);
                }
            }

            if (HasMDNSDomainName()) {
                serialize(output, { "mdns", "answer" },
                  mdns.domain_name);
            }

            serialize(output, { "first_seen_at" }, ts_first_seen);

            serialize(output, { "risks", "risks" }, risk.risks);
            serialize(output, { "risks", "ndpi_risk_score" },
              risk.ndpi_score);
            serialize(output,
              { "risks", "ndpi_risk_score_client" },
              risk.ndpi_score_client);
            serialize(output,
              { "risks", "ndpi_risk_score_server" },
              risk.ndpi_score_server);
        }

        if (ndFlagBoolean(encode_flags, EncodeFlags::TUNNELS))
        {
            std::string _lower_teid = "local_teid",
                        _upper_teid = "other_teid";

            switch (tunnel_type) {
            case TunnelType::GTP:
                switch (gtp.lower_map) {
                case LowerMap::LOCAL:
                    _lower_ip = "local_ip";
                    _lower_port = "local_port";
                    _lower_teid = "local_teid";
                    _upper_ip = "other_ip";
                    _upper_port = "other_port";
                    _upper_teid = "other_teid";
                    break;
                case LowerMap::OTHER:
                    _lower_ip = "other_ip";
                    _lower_port = "other_port";
                    _lower_teid = "other_teid";
                    _upper_ip = "local_ip";
                    _upper_port = "local_port";
                    _upper_teid = "local_teid";
                    break;
                default: break;
                }

                switch (gtp.other_type) {
                case OtherType::LOCAL:
                    _other_type = "local";
                    break;
                case OtherType::REMOTE:
                    _other_type = "remote";
                    break;
                case OtherType::ERROR:
                    _other_type = "error";
                    break;
                case OtherType::UNSUPPORTED:
                default: _other_type = "unsupported"; break;
                }

                serialize(output, { "gtp", "version" }, gtp.version);
                serialize(output, { "gtp", "ip_version" },
                  gtp.ip_version);
                serialize(output, { "gtp", _lower_ip },
                  gtp.lower_addr.GetString());
                serialize(output, { "gtp", _upper_ip },
                  gtp.upper_addr.GetString());
                serialize(output, { "gtp", _lower_port },
                  (unsigned)gtp.lower_addr.GetPort());
                serialize(output, { "gtp", _upper_port },
                  (unsigned)gtp.upper_addr.GetPort());
                serialize(output, { "gtp", _lower_teid },
                  htonl(gtp.lower_teid));
                serialize(output, { "gtp", _upper_teid },
                  htonl(gtp.upper_teid));
                serialize(output, { "gtp", "other_type" },
                  _other_type);

                break;
            default: break;
            }
        }

        if (ndFlagBoolean(encode_flags, EncodeFlags::STATS)) {
            serialize(output, { _lower_bytes },
              stats.lower_bytes.load());
            serialize(output, { _upper_bytes },
              stats.upper_bytes.load());
            serialize(output, { _lower_packets },
              stats.lower_packets.load());
            serialize(output, { _upper_packets },
              stats.upper_packets.load());
            serialize(output, { "total_packets" },
              stats.total_packets.load());
            serialize(output, { "total_bytes" },
              stats.total_bytes.load());
            serialize(output, { "detection_packets" },
              stats.detection_packets.load());

#ifdef _ND_ENABLE_EXTENDED_STATS
            serialize(output, { _lower_rate },
              stats.lower_rate.load());
            serialize(output, { _upper_rate },
              stats.upper_rate.load());

            if (ip_protocol == IPPROTO_TCP) {
                serialize(output,
                  { "tcp", "seq_errors" },
                  stats.tcp_seq_errors.load());
                serialize(output, { "tcp", "resets" },
                  stats.tcp_resets.load());
                serialize(output, { "tcp", "retrans" },
                  stats.tcp_retrans.load());
            }
#endif
        }
    }
};

typedef std::shared_ptr<ndFlow> nd_flow_ptr;
typedef std::unordered_map<std::string, nd_flow_ptr> nd_flow_map;
typedef std::map<std::string, nd_flow_map *> nd_flows;
typedef std::pair<std::string, nd_flow_ptr> nd_flow_pair;
typedef std::pair<nd_flow_map::iterator, bool> nd_flow_insert;
