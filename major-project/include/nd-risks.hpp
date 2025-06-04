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

#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>

#include <ndpi_typedefs.h>

#include "nd-ndpi.hpp"
#include "nd-util.hpp"

namespace ndRisk {

enum class Id : uint32_t {
    NONE = 0,
    ANONYMOUS_SUBSCRIBER = 1,
    BINARY_APPLICATION_TRANSFER = 2,
    CLEAR_TEXT_CREDENTIALS = 3,
    DESKTOP_OR_FILE_SHARING_SESSION = 4,
    DNS_FRAGMENTED = 5,
    DNS_LARGE_PACKET = 6,
    DNS_SUSPICIOUS_TRAFFIC = 7,
    ERROR_CODE_DETECTED = 8,
    HTTP_CRAWLER_BOT = 9,
    NUMERIC_IP_HOST = 10,
    HTTP_SUSPICIOUS_CONTENT = 11,
    HTTP_SUSPICIOUS_HEADER = 12,
    HTTP_SUSPICIOUS_URL = 13,
    HTTP_SUSPICIOUS_USER_AGENT = 14,
    INVALID_CHARACTERS = 15,
    KNOWN_PROTOCOL_ON_NON_STANDARD_PORT = 16,
    MALFORMED_PACKET = 17,
    MALICIOUS_JA3 = 18,
    MALICIOUS_SHA1_CERTIFICATE = 19,
    POSSIBLE_EXPLOIT = 20,
    PUNYCODE_IDN = 21,
    RISKY_ASN = 22,
    RISKY_DOMAIN = 23,
    SMB_INSECURE_VERSION = 24,
    SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER = 25,
    SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER = 26,
    SUSPICIOUS_DGA_DOMAIN = 27,
    SUSPICIOUS_ENTROPY = 28,
    TLS_CERTIFICATE_ABOUT_TO_EXPIRE = 29,
    TLS_CERTIFICATE_EXPIRED = 30,
    TLS_CERTIFICATE_MISMATCH = 31,
    TLS_CERT_VALIDITY_TOO_LONG = 32,
    TLS_FATAL_ALERT = 33,
    DEPR_TLS_MISSING_ALPN = 34,
    TLS_MISSING_SNI = 35,
    TLS_OBSOLETE_VERSION = 36,
    TLS_SELFSIGNED_CERTIFICATE = 37,
    TLS_SUSPICIOUS_ESNI_USAGE = 38,
    TLS_SUSPICIOUS_EXTENSION = 39,
    TLS_UNCOMMON_ALPN = 40,
    TLS_WEAK_CIPHER = 41,
    UNSAFE_PROTOCOL = 42,
    URL_POSSIBLE_RCE_INJECTION = 43,
    URL_POSSIBLE_SQL_INJECTION = 44,
    URL_POSSIBLE_XSS = 45,
    UNIDIRECTIONAL_TRAFFIC = 46,
    TLS_ALPN_NOT_FOUND = 47,
    HTTP_OBSOLETE_SERVER = 48,
    PERIODIC_FLOW = 49,
    MINOR_ISSUES = 50,
    TCP_ISSUES = 51,
    FULLY_ENCRYPTED = 52,
    TLS_ALPN_SNI_MISMATCH = 53,
    MALWARE_HOST_CONTACTED = 54,

    MAX,
    TODO = 0xffffffff
};

const std::unordered_map<Id, const char *, ndEnumHasher> Tags = {
    { Id::NONE, "None" },

    { Id::ANONYMOUS_SUBSCRIBER, "Anonymous Subscriber" },
    { Id::BINARY_APPLICATION_TRANSFER,
      "Binary Application Transfer" },
    { Id::CLEAR_TEXT_CREDENTIALS, "Clear-Text Credentials" },
    { Id::DESKTOP_OR_FILE_SHARING_SESSION,
      "Desktop/File Sharing" },
    { Id::DNS_FRAGMENTED, "Fragmented DNS Message" },
    { Id::DNS_LARGE_PACKET,
      "Large DNS Packet (512+ bytes)" },
    { Id::DNS_SUSPICIOUS_TRAFFIC, "Suspicious DNS Traffic" },
    { Id::ERROR_CODE_DETECTED, "Error Code" },
    { Id::FULLY_ENCRYPTED, "Fully Encrypted Flow" },
    { Id::HTTP_CRAWLER_BOT, "Crawler/Bot" },
    { Id::HTTP_OBSOLETE_SERVER, "HTTP Obsolete Server" },
    { Id::HTTP_SUSPICIOUS_CONTENT,
      "HTTP Suspicious Content" },
    { Id::HTTP_SUSPICIOUS_HEADER, "HTTP Suspicious Header" },
    { Id::HTTP_SUSPICIOUS_URL, "HTTP Suspicious URL" },
    { Id::HTTP_SUSPICIOUS_USER_AGENT,
      "HTTP Suspicious User-Agent" },
    { Id::INVALID_CHARACTERS,
      "Text With Non-Printable Characters" },
    { Id::KNOWN_PROTOCOL_ON_NON_STANDARD_PORT,
      "Known Protocol on Non-standard Port" },
    { Id::MALFORMED_PACKET, "Malformed Packet" },
    { Id::MALICIOUS_JA3, "Malicious JA3 Fingerprint" },
    { Id::MALICIOUS_SHA1_CERTIFICATE,
      "Malicious SSL Cert/SHA1 Fingerprint" },
    { Id::MINOR_ISSUES, "Minor Issues" },
    { Id::NUMERIC_IP_HOST, "Numeric IP Address" },
    { Id::PERIODIC_FLOW, "Periodic Flow" },
    { Id::POSSIBLE_EXPLOIT, "Possible Exploit" },
    { Id::PUNYCODE_IDN, "IDN Domain Name" },
    { Id::RISKY_ASN, "Risky ASN" },
    { Id::RISKY_DOMAIN, "Risky Domain Name" },
    { Id::SMB_INSECURE_VERSION, "SMB Insecure Version" },
    { Id::SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER,
      "SSH Obsolete Client Version/Cipher" },
    { Id::SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER,
      "SSH Obsolete Server Version/Cipher" },
    { Id::SUSPICIOUS_DGA_DOMAIN,
      "Suspicious DGA Domain name" },
    { Id::SUSPICIOUS_ENTROPY, "Suspicious Entropy" },
    { Id::TCP_ISSUES, "TCP Connection Issues" },
    { Id::TLS_ALPN_SNI_MISMATCH, "TLS ALPN/SNI Mismatch" },
    { Id::TLS_CERTIFICATE_ABOUT_TO_EXPIRE,
      "TLS Certificate About To Expire" },
    { Id::TLS_CERTIFICATE_EXPIRED,
      "TLS Certificate Expired" },
    { Id::TLS_CERTIFICATE_MISMATCH,
      "TLS Certificate Mismatch" },
    { Id::TLS_CERT_VALIDITY_TOO_LONG,
      "TLS Certificate Validity Too Long" },
    { Id::TLS_FATAL_ALERT, "TLS Fatal Alert" },
    { Id::TLS_MISSING_SNI, "TLS SNI Extension Not Found" },
    { Id::TLS_ALPN_NOT_FOUND, "TLS ALPN Not Found" },
    { Id::TLS_OBSOLETE_VERSION,
      "Obsolete TLS (v1.1 or older)" },
    { Id::TLS_SELFSIGNED_CERTIFICATE,
      "Self-signed Certificate" },
    { Id::TLS_SUSPICIOUS_ESNI_USAGE,
      "TLS Suspicious ESNI Usage" },
    { Id::TLS_SUSPICIOUS_EXTENSION,
      "TLS Suspicious Extension" },
    { Id::TLS_UNCOMMON_ALPN, "Uncommon TLS ALPN" },
    { Id::TLS_WEAK_CIPHER, "Weak TLS Cipher" },
    { Id::UNIDIRECTIONAL_TRAFFIC, "Unidirectional Traffic" },
    { Id::UNSAFE_PROTOCOL, "Unsafe Protocol" },
    { Id::URL_POSSIBLE_RCE_INJECTION, "RCE Injection" },
    { Id::URL_POSSIBLE_SQL_INJECTION, "SQL Injection" },
    { Id::URL_POSSIBLE_XSS, "XSS Attack" },

    { Id::TODO, "TODO Add Risk" },
};

inline const char *GetName(Id id) {
    auto it = Tags.find(id);
    if (it == Tags.end()) return "None";
    return it->second;
}

inline Id GetId(const std::string &name) {
    for (auto &i : Tags) {
        if (strcasecmp(name.c_str(), i.second)) continue;
        return i.first;
    }
    return Id::MAX;
}

namespace nDPI {

const std::unordered_map<uint16_t, Id> Risks = {
    { NDPI_ANONYMOUS_SUBSCRIBER, Id::ANONYMOUS_SUBSCRIBER },
    { NDPI_BINARY_APPLICATION_TRANSFER, Id::BINARY_APPLICATION_TRANSFER },
    { NDPI_CLEAR_TEXT_CREDENTIALS, Id::CLEAR_TEXT_CREDENTIALS },
    { NDPI_DESKTOP_OR_FILE_SHARING_SESSION,
      Id::DESKTOP_OR_FILE_SHARING_SESSION },
    { NDPI_DNS_FRAGMENTED, Id::DNS_FRAGMENTED },
    { NDPI_DNS_LARGE_PACKET, Id::DNS_LARGE_PACKET },
    { NDPI_DNS_SUSPICIOUS_TRAFFIC, Id::DNS_SUSPICIOUS_TRAFFIC },
    { NDPI_ERROR_CODE_DETECTED, Id::ERROR_CODE_DETECTED },
    { NDPI_FULLY_ENCRYPTED, Id::FULLY_ENCRYPTED },
    { NDPI_HTTP_CRAWLER_BOT, Id::HTTP_CRAWLER_BOT },
    { NDPI_HTTP_OBSOLETE_SERVER, Id::HTTP_OBSOLETE_SERVER },
    { NDPI_HTTP_SUSPICIOUS_CONTENT, Id::HTTP_SUSPICIOUS_CONTENT },
    { NDPI_HTTP_SUSPICIOUS_HEADER, Id::HTTP_SUSPICIOUS_HEADER },
    { NDPI_HTTP_SUSPICIOUS_URL, Id::HTTP_SUSPICIOUS_URL },
    { NDPI_HTTP_SUSPICIOUS_USER_AGENT, Id::HTTP_SUSPICIOUS_USER_AGENT },
    { NDPI_INVALID_CHARACTERS, Id::INVALID_CHARACTERS },
    { NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT,
      Id::KNOWN_PROTOCOL_ON_NON_STANDARD_PORT },
    { NDPI_MALFORMED_PACKET, Id::MALFORMED_PACKET },
    { NDPI_MALICIOUS_JA3, Id::MALICIOUS_JA3 },
    { NDPI_MALICIOUS_SHA1_CERTIFICATE, Id::MALICIOUS_SHA1_CERTIFICATE },
    { NDPI_MALWARE_HOST_CONTACTED, Id::MALWARE_HOST_CONTACTED },
    { NDPI_MINOR_ISSUES, Id::MINOR_ISSUES },
    { NDPI_NO_RISK, Id::NONE },
    { NDPI_NUMERIC_IP_HOST, Id::NUMERIC_IP_HOST },
    { NDPI_PERIODIC_FLOW, Id::PERIODIC_FLOW },
    { NDPI_POSSIBLE_EXPLOIT, Id::POSSIBLE_EXPLOIT },
    { NDPI_PUNYCODE_IDN, Id::PUNYCODE_IDN },
    { NDPI_RISKY_ASN, Id::RISKY_ASN },
    { NDPI_RISKY_DOMAIN, Id::RISKY_DOMAIN },
    { NDPI_SMB_INSECURE_VERSION, Id::SMB_INSECURE_VERSION },
    { NDPI_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER,
      Id::SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER },
    { NDPI_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER,
      Id::SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER },
    { NDPI_SUSPICIOUS_DGA_DOMAIN, Id::SUSPICIOUS_DGA_DOMAIN },
    { NDPI_SUSPICIOUS_ENTROPY, Id::SUSPICIOUS_ENTROPY },
    { NDPI_TCP_ISSUES, Id::TCP_ISSUES },
    { NDPI_TLS_ALPN_SNI_MISMATCH, Id::TLS_ALPN_SNI_MISMATCH },
    { NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE,
      Id::TLS_CERTIFICATE_ABOUT_TO_EXPIRE },
    { NDPI_TLS_CERTIFICATE_EXPIRED, Id::TLS_CERTIFICATE_EXPIRED },
    { NDPI_TLS_CERTIFICATE_MISMATCH, Id::TLS_CERTIFICATE_MISMATCH },
    { NDPI_TLS_CERT_VALIDITY_TOO_LONG, Id::TLS_CERT_VALIDITY_TOO_LONG },
    { NDPI_TLS_FATAL_ALERT, Id::TLS_FATAL_ALERT },
    { NDPI_TLS_MISSING_SNI, Id::TLS_MISSING_SNI },
    { NDPI_TLS_NOT_CARRYING_HTTPS, Id::TLS_ALPN_NOT_FOUND },
    { NDPI_TLS_OBSOLETE_VERSION, Id::TLS_OBSOLETE_VERSION },
    { NDPI_TLS_SELFSIGNED_CERTIFICATE, Id::TLS_SELFSIGNED_CERTIFICATE },
    { NDPI_TLS_SUSPICIOUS_ESNI_USAGE, Id::TLS_SUSPICIOUS_ESNI_USAGE },
    { NDPI_TLS_SUSPICIOUS_EXTENSION, Id::TLS_SUSPICIOUS_EXTENSION },
    { NDPI_TLS_UNCOMMON_ALPN, Id::TLS_UNCOMMON_ALPN },
    { NDPI_TLS_WEAK_CIPHER, Id::TLS_WEAK_CIPHER },
    { NDPI_UNIDIRECTIONAL_TRAFFIC, Id::UNIDIRECTIONAL_TRAFFIC },
    { NDPI_UNSAFE_PROTOCOL, Id::UNSAFE_PROTOCOL },
    { NDPI_URL_POSSIBLE_RCE_INJECTION, Id::URL_POSSIBLE_RCE_INJECTION },
    { NDPI_URL_POSSIBLE_SQL_INJECTION, Id::URL_POSSIBLE_SQL_INJECTION },
    { NDPI_URL_POSSIBLE_XSS, Id::URL_POSSIBLE_XSS },
};

inline Id Find(uint16_t id) {
    auto it = Risks.find(id);
    if (it == Risks.end()) return Id::TODO;
    return it->second;
}

}  // namespace nDPI
}  // namespace ndRisk
