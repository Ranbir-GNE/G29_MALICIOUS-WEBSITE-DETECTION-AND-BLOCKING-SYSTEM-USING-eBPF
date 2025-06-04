// Auto-generated, update with ./util/generate-alpn-include.sh

#pragma once

#include "nd-protos.hpp"

typedef std::unordered_map<const char *, ndProto::Id> nd_alpn_proto_map;

const nd_alpn_proto_map nd_alpn_protos = {
    { "http/0.9" /* HTTP/0.9 */, ndProto::Id::HTTPS },
    { "http/1.0" /* HTTP/1.0 */, ndProto::Id::HTTPS },
    { "http/1.1" /* HTTP/1.1 */, ndProto::Id::HTTPS },
    { "spdy/1" /* SPDY/1 */, ndProto::Id::QUIC },
    { "spdy/2" /* SPDY/2 */, ndProto::Id::QUIC },
    { "spdy/3" /* SPDY/3 */, ndProto::Id::QUIC },
    { "stun.turn" /* Traversal Using Relays around NAT (TURN) */,
      ndProto::Id::STUN },
    { "stun.nat-discovery" /* NAT discovery using Session Traversal Utilities for NAT (STUN) */,
      ndProto::Id::STUN },
    { "h2" /* HTTP/2 over TLS */, ndProto::Id::HTTPS },
    { "h2c" /* HTTP/2 over TCP */, ndProto::Id::HTTPS },
    { "webrtc" /* WebRTC Media and Data */, ndProto::Id::TLS },
    { "c-webrtc" /* Confidential WebRTC Media and Data */, ndProto::Id::TLS },
    { "ftp" /* FTP */, ndProto::Id::FTPS },
    { "imap" /* IMAP */, ndProto::Id::MAIL_IMAPS },
    { "pop3" /* POP3 */, ndProto::Id::MAIL_POPS },
    { "managesieve" /* ManageSieve */, ndProto::Id::TLS },
    { "coap" /* CoAP */, ndProto::Id::COAP },
    { "xmpp-client" /* XMPP jabber:client namespace */, ndProto::Id::XMPPS },
    { "xmpp-server" /* XMPP jabber:server namespace */, ndProto::Id::XMPPS },
    { "acme-tls/1" /* acme-tls/1 */, ndProto::Id::TLS },
    { "mqtt" /* OASIS Message Queuing Telemetry Transport (MQTT) */,
      ndProto::Id::MQTTS },
    { "dot" /* DNS-over-TLS */, ndProto::Id::DOT },
    { "ntske/1" /* Network Time Security Key Establishment, version 1 */,
      ndProto::Id::TLS },
    { "sunrpc" /* SunRPC */, ndProto::Id::TLS },
    { "h3" /* HTTP/3 */, ndProto::Id::HTTPS },
    { "smb" /* SMB2 */, ndProto::Id::SMBV23 },
    { "irc" /* IRC */, ndProto::Id::IRCS },
    { "nntp" /* NNTP (reading) */, ndProto::Id::NNTPS },
    { "nnsp" /* NNTP (transit) */, ndProto::Id::NNTPS },
    { "doq" /* DoQ */, ndProto::Id::DOQ },
    { "sip/2" /* SIP */, ndProto::Id::SIPS },
    { "tds/8.0" /* TDS/8.0 */, ndProto::Id::MSSQL_TDS },
    { "dicom" /* DICOM */, ndProto::Id::TLS },
};

// vi: ei=all
