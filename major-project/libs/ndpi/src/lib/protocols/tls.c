/*
 * tls.c - TLS/TLS/DTLS dissector
 *
 * Copyright (C) 2016-22 - ntop.org
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TLS

#include "ndpi_api.h"
#include "ndpi_md5.h"
#include "ndpi_sha1.h"
#include "ndpi_encryption.h"

extern char *strptime(const char *s, const char *format, struct tm *tm);
extern int processClientServerHello(struct ndpi_detection_module_struct *ndpi_struct,
				    struct ndpi_flow_struct *flow, uint32_t quic_version);
static void ndpi_search_tls_wrapper(struct ndpi_detection_module_struct *ndpi_struct,
				    struct ndpi_flow_struct *flow);
extern int http_process_user_agent(struct ndpi_detection_module_struct *ndpi_struct,
                                   struct ndpi_flow_struct *flow,
                                   const u_int8_t *ua_ptr, u_int16_t ua_ptr_len);
extern int ookla_search_into_cache(struct ndpi_detection_module_struct* ndpi_struct,
                                   struct ndpi_flow_struct* flow);
/* QUIC/GQUIC stuff */
extern int quic_len(const uint8_t *buf, uint64_t *value);
extern int quic_len_buffer_still_required(uint8_t value);
extern int is_version_with_var_int_transport_params(uint32_t version);

// #define DEBUG_TLS_MEMORY       1
// #define DEBUG_TLS              1
// #define DEBUG_TLS_BLOCKS       1
// #define DEBUG_CERTIFICATE_HASH

// #define DEBUG_HEURISTIC

// #define DEBUG_JA3C 1

/* #define DEBUG_FINGERPRINT      1 */
/* #define DEBUG_ENCRYPTED_SNI    1 */

/* **************************************** */

/* https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967 */

#define JA3_STR_LEN        1024
#define MAX_NUM_JA3         512
#define MAX_JA3_STRLEN      256

union ja3_info {
  struct {
    u_int16_t tls_handshake_version;
    u_int16_t num_cipher, cipher[MAX_NUM_JA3];
    u_int16_t num_tls_extension, tls_extension[MAX_NUM_JA3];
    u_int16_t num_elliptic_curve, elliptic_curve[MAX_NUM_JA3];
    u_int16_t num_elliptic_curve_point_format, elliptic_curve_point_format[MAX_NUM_JA3];
    char signature_algorithms[MAX_JA3_STRLEN], supported_versions[MAX_JA3_STRLEN], alpn[MAX_JA3_STRLEN];
  } client;

  struct {
    u_int16_t tls_handshake_version;
    u_int16_t num_cipher, cipher[MAX_NUM_JA3];
    u_int16_t num_tls_extension, tls_extension[MAX_NUM_JA3];
    u_int16_t tls_supported_version;
    u_int16_t num_elliptic_curve_point_format, elliptic_curve_point_format[MAX_NUM_JA3];
    char alpn[MAX_JA3_STRLEN];
  } server; /* Used for JA3+ */
};

/*
  NOTE

  How to view the certificate fingerprint
  1. Using wireshark save the certificate on certificate.bin file as explained
  in https://security.stackexchange.com/questions/123851/how-can-i-extract-the-certificate-from-this-pcap-file

  2. openssl x509 -inform der -in certificate.bin -text > certificate.der
  3. openssl x509 -noout -fingerprint -sha1 -inform pem -in certificate.der
  SHA1 Fingerprint=15:9A:76....

  $ shasum -a 1 www.grc.com.bin
  159a76.....
*/

#define NDPI_MAX_TLS_REQUEST_SIZE 10000
#define TLS_THRESHOLD             34387200 /* Threshold for certificate validity                                */
#define TLS_LIMIT_DATE            1598918400 /* From 01/09/2020 TLS certificates lifespan is limited to 13 months */


static void ndpi_int_tls_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					struct ndpi_flow_struct *flow);

/* **************************************** */

static u_int32_t ndpi_tls_refine_master_protocol(struct ndpi_detection_module_struct *ndpi_struct,
						 struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int32_t protocol;

  if(packet->tcp != NULL) {
    /*
      In case of TLS there are probably sub-protocols
      such as IMAPS that can be otherwise detected
    */
    u_int16_t sport = ntohs(packet->tcp->source);
    u_int16_t dport = ntohs(packet->tcp->dest);

    if((sport == 465) || (dport == 465) || (sport == 587) || (dport == 587))
      protocol = NDPI_PROTOCOL_MAIL_SMTPS;
    else if((sport == 993) || (dport == 993) || (flow->l4.tcp.mail_imap_starttls))
      protocol = NDPI_PROTOCOL_MAIL_IMAPS;
    else if((sport == 995) || (dport == 995))
      protocol = NDPI_PROTOCOL_MAIL_POPS;
    else
      protocol = NDPI_PROTOCOL_TLS;
  } else {
      protocol = NDPI_PROTOCOL_DTLS;
  }

  return protocol;
}

/* **************************************** */

static u_int32_t __get_master(struct ndpi_detection_module_struct *ndpi_struct,
			      struct ndpi_flow_struct *flow) {

  if(flow->detected_protocol_stack[1] != NDPI_PROTOCOL_UNKNOWN)
    return flow->detected_protocol_stack[1];
  if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN)
    return flow->detected_protocol_stack[0];

  return ndpi_tls_refine_master_protocol(ndpi_struct, flow);
}

/* **************************************** */

static int ndpi_search_tls_memory(struct ndpi_detection_module_struct *ndpi_struct,
				  struct ndpi_flow_struct *flow,
				  const u_int8_t *payload,
				  u_int16_t payload_len,
				  u_int32_t seq,
				  message_t *message) {
  u_int avail_bytes;

#ifdef DEBUG_TLS_MEMORY
  printf("[TLS Mem] Handling TLS flow [payload_len: %u][buffer_len: %u]\n",
	 payload_len,
	 message->buffer_len);
#endif

  if(message->buffer == NULL) {
    /* Allocate buffer */
    message->buffer_len = 2048, message->buffer_used = 0;
    message->buffer = (u_int8_t*)ndpi_malloc(message->buffer_len);

    if(message->buffer == NULL)
      return -1;

#ifdef DEBUG_TLS_MEMORY
    printf("[TLS Mem] Allocating %u buffer\n", message->buffer_len);
#endif
  }

  avail_bytes = message->buffer_len - message->buffer_used;

  if(avail_bytes < payload_len) {
    u_int new_len = message->buffer_len + payload_len - avail_bytes + 1;
    void *newbuf  = ndpi_realloc(message->buffer,
				 message->buffer_len, new_len);
    if(!newbuf) return -1;

#ifdef DEBUG_TLS_MEMORY
    printf("[TLS Mem] Enlarging %u -> %u buffer\n", message->buffer_len, new_len);
#endif

    message->buffer = (u_int8_t*)newbuf;
    message->buffer_len = new_len;
    avail_bytes = message->buffer_len - message->buffer_used;
  }

  if(payload_len > 0 && avail_bytes >= payload_len) {
    u_int8_t ok = 0;

    if(message->next_seq != 0) {
      if(seq == message->next_seq)
	ok = 1;
    } else
      ok = 1;

    if(ok) {
      memcpy(&message->buffer[message->buffer_used],
	     payload, payload_len);

      message->buffer_used += payload_len;
#ifdef DEBUG_TLS_MEMORY
      printf("[TLS Mem] Copied data to buffer [%u/%u bytes][tcp_seq: %u][next: %u]\n",
	     message->buffer_used, message->buffer_len,
	     seq,
	     seq + payload_len);
#endif

      message->next_seq = seq + payload_len;
    } else {
#ifdef DEBUG_TLS_MEMORY
      printf("[TLS Mem] Skipping packet [%u bytes][tcp_seq: %u][expected next: %u]\n",
	     message->buffer_len,
	     seq,
	     message->next_seq);
#endif
    }
  }
  return 0;
}

/* **************************************** */

static void cleanupServerName(char *buffer, u_int buffer_len) {
  u_int i;

  /* Now all lowecase */
  for(i=0; i<buffer_len; i++)
    buffer[i] = tolower(buffer[i]);
}

/* **************************************** */

/*
  Return code
  -1: error (buffer too short)
  0: OK but buffer is not human readeable (so something went wrong)
  1: OK
*/
static int extractRDNSequence(struct ndpi_packet_struct *packet,
			      u_int offset, char *buffer, u_int buffer_len,
			      char *rdnSeqBuf, u_int *rdnSeqBuf_offset,
			      u_int rdnSeqBuf_len,
			      const char *label) {
  u_int8_t str_len, is_printable = 1;
  char *str;
  u_int len;

  if(*rdnSeqBuf_offset >= rdnSeqBuf_len) {
#ifdef DEBUG_TLS
    printf("[TLS] %s() [buffer capacity reached][%u]\n",
           __FUNCTION__, rdnSeqBuf_len);
#endif
    return -1;
  }
  if((offset+4) >= packet->payload_packet_len)
    return(-1);

  str_len = packet->payload[offset+4];

  // packet is truncated... further inspection is not needed
  if((offset+4+str_len) >= packet->payload_packet_len)
    return(-1);

  str = (char*)&packet->payload[offset+5];

  len = (u_int)ndpi_min(str_len, buffer_len-1);
  strncpy(buffer, str, len);
  buffer[len] = '\0';

  // check string is printable
  is_printable = ndpi_normalize_printable_string(buffer, len);

  if(is_printable) {
    int rc = ndpi_snprintf(&rdnSeqBuf[*rdnSeqBuf_offset],
			   rdnSeqBuf_len-(*rdnSeqBuf_offset),
			   "%s%s=%s", (*rdnSeqBuf_offset > 0) ? ", " : "",
			   label, buffer);

    if(rc > 0 && ((u_int)rc > rdnSeqBuf_len-(*rdnSeqBuf_offset)))
      return -1; /* Truncated; not enough buffer */
    if(rc > 0)
      (*rdnSeqBuf_offset) += rc;
  }

  return(is_printable);
}

/* **************************************** */

static u_int32_t make_tls_cert_key(struct ndpi_packet_struct *packet, int is_from_client)
{
  u_int32_t key;

  /* Server ip/port */
  if(packet->iphv6 == NULL) {
    if(packet->tcp) {
      if(is_from_client)
        key = packet->iph->daddr + packet->tcp->dest;
      else
        key = packet->iph->saddr + packet->tcp->source;
    } else {
      if(is_from_client)
        key = packet->iph->daddr + packet->udp->dest;
      else
        key = packet->iph->saddr + packet->udp->source;
    }
  } else {
    if(packet->tcp) {
      if(is_from_client)
        key = ndpi_quick_hash((unsigned char *)&packet->iphv6->ip6_dst, 16) + packet->tcp->dest;
      else
        key = ndpi_quick_hash((unsigned char *)&packet->iphv6->ip6_src, 16) + packet->tcp->source;
    } else {
      if(is_from_client)
        key = ndpi_quick_hash((unsigned char *)&packet->iphv6->ip6_dst, 16) + packet->udp->dest;
      else
        key = ndpi_quick_hash((unsigned char *)&packet->iphv6->ip6_src, 16) + packet->udp->source;
    }
  }

  return key;
}

/* **************************************** */

static void checkTLSSubprotocol(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow,
				int is_from_client) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  if(flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN) {
    /* Subprotocol not yet set */

    if(ndpi_struct->tls_cert_cache) {
      u_int16_t cached_proto;
      u_int32_t key;

      key = make_tls_cert_key(packet, is_from_client);

      if(ndpi_lru_find_cache(ndpi_struct->tls_cert_cache, key,
			     &cached_proto, 0 /* Don't remove it as it can be used for other connections */,
			     ndpi_get_current_time(flow))) {
	ndpi_protocol ret = { __get_master(ndpi_struct, flow), cached_proto, NDPI_PROTOCOL_UNKNOWN /* unused */, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, NULL};

	ndpi_set_detected_protocol(ndpi_struct, flow, cached_proto, __get_master(ndpi_struct, flow), NDPI_CONFIDENCE_DPI_CACHE);
	flow->category = ndpi_get_proto_category(ndpi_struct, ret);
	ndpi_check_subprotocol_risk(ndpi_struct, flow, cached_proto);
	ndpi_unset_risk(ndpi_struct, flow, NDPI_NUMERIC_IP_HOST);
      }
    }
  }
}

/* **************************************** */

/* See https://blog.catchpoint.com/2017/05/12/dissecting-tls-using-wireshark/ */
void processCertificateElements(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow,
				u_int16_t p_offset, u_int16_t certificate_len) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t num_found = 0;
  int32_t i;
  char buffer[64] = { '\0' }, rdnSeqBuf[2048];
  u_int rdn_len = 0;

  rdnSeqBuf[0] = '\0';

#ifdef DEBUG_TLS
  printf("[TLS] %s() [offset: %u][certificate_len: %u]\n", __FUNCTION__, p_offset, certificate_len);
#endif

  /* Check after handshake protocol header (5 bytes) and message header (4 bytes) */
  for(i = p_offset; i < certificate_len - 2; i++) {
    /*
      See https://www.ibm.com/support/knowledgecenter/SSFKSJ_7.5.0/com.ibm.mq.sec.doc/q009860_.htm
      for X.509 certificate labels
    */
    if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x03)) {
      /* Common Name */
      int rc = extractRDNSequence(packet, i, buffer, sizeof(buffer), rdnSeqBuf, &rdn_len, sizeof(rdnSeqBuf), "CN");
      if(rc == -1) break;

      if(num_found == 1 && flow->protos.tls_quic.serverCN == NULL)
        flow->protos.tls_quic.serverCN = ndpi_strdup(buffer);
#ifdef DEBUG_TLS
      printf("[TLS] %s() [%s][%s: %s]\n", __FUNCTION__, (num_found == 0) ? "Subject" : "Issuer", "Common Name", buffer);
#endif
    } else if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x06)) {
      /* Country */
      int rc = extractRDNSequence(packet, i, buffer, sizeof(buffer), rdnSeqBuf, &rdn_len, sizeof(rdnSeqBuf), "C");
      if(rc == -1) break;

#ifdef DEBUG_TLS
      printf("[TLS] %s() [%s][%s: %s]\n", __FUNCTION__, (num_found == 0) ? "Subject" : "Issuer", "Country", buffer);
#endif
    } else if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x07)) {
      /* Locality */
      int rc = extractRDNSequence(packet, i, buffer, sizeof(buffer), rdnSeqBuf, &rdn_len, sizeof(rdnSeqBuf), "L");
      if(rc == -1) break;

#ifdef DEBUG_TLS
      printf("[TLS] %s() [%s][%s: %s]\n", __FUNCTION__, (num_found == 0) ? "Subject" : "Issuer", "Locality", buffer);
#endif
    } else if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x08)) {
      /* State or Province */
      int rc = extractRDNSequence(packet, i, buffer, sizeof(buffer), rdnSeqBuf, &rdn_len, sizeof(rdnSeqBuf), "ST");
      if(rc == -1) break;

#ifdef DEBUG_TLS
      printf("[TLS] %s() [%s][%s: %s]\n", __FUNCTION__, (num_found == 0) ? "Subject" : "Issuer", "State or Province", buffer);
#endif
    } else if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x0a)) {
      /* Organization Name */
      int rc = extractRDNSequence(packet, i, buffer, sizeof(buffer), rdnSeqBuf, &rdn_len, sizeof(rdnSeqBuf), "O");
      if(rc == -1) break;

#ifdef DEBUG_TLS
      printf("[TLS] %s() [%s][%s: %s]\n", __FUNCTION__, (num_found == 0) ? "Subject" : "Issuer", "Organization Name", buffer);
#endif

    } else if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x0b)) {
      /* Organization Unit */
      int rc = extractRDNSequence(packet, i, buffer, sizeof(buffer), rdnSeqBuf, &rdn_len, sizeof(rdnSeqBuf), "OU");
      if(rc == -1) break;

#ifdef DEBUG_TLS
      printf("[TLS] %s() [%s][%s: %s]\n", __FUNCTION__, (num_found == 0) ? "Subject" : "Issuer", "Organization Unit", buffer);
#endif
    } else if((packet->payload[i] == 0x30) && (packet->payload[i+1] == 0x1e) && (packet->payload[i+2] == 0x17)) {
      /* Certificate Validity */
      u_int offset = i+4;

      if(num_found == 0) {
	num_found++;

#ifdef DEBUG_TLS
	printf("[TLS] %s() IssuerDN [%s]\n", __FUNCTION__, rdnSeqBuf);
#endif

	if(rdn_len && (flow->protos.tls_quic.issuerDN == NULL)) {
	  flow->protos.tls_quic.issuerDN = ndpi_strdup(rdnSeqBuf);
	  if(ndpi_normalize_printable_string(rdnSeqBuf, rdn_len) == 0) {
	    char str[64];

	    snprintf(str, sizeof(str), "Invalid issuerDN %s", flow->protos.tls_quic.issuerDN);
	    ndpi_set_risk(ndpi_struct, flow, NDPI_INVALID_CHARACTERS, str);
	  }
	}

	rdn_len = 0; /* Reset buffer */
      }

      if(i + 3 < certificate_len &&
	 (offset+packet->payload[i+3]) < packet->payload_packet_len) {
	char utcDate[32];
        u_int8_t len = packet->payload[i+3];

#ifdef DEBUG_TLS
	u_int j;

	printf("[CERTIFICATE] notBefore [len: %u][", len);
	for(j=0; j<len; j++) printf("%c", packet->payload[i+4+j]);
	printf("]\n");
#endif

	if(len < (sizeof(utcDate)-1)) {
	  struct tm utc;
	  utc.tm_isdst = -1; /* Not set by strptime */

	  strncpy(utcDate, (const char*)&packet->payload[i+4], len);
	  utcDate[len] = '\0';

	  /* 141021000000Z */
	  if(strptime(utcDate, "%y%m%d%H%M%SZ", &utc) != NULL) {
	    flow->protos.tls_quic.notBefore = timegm(&utc);
#ifdef DEBUG_TLS
	    printf("[CERTIFICATE] notBefore %u [%s]\n",
		   flow->protos.tls_quic.notBefore, utcDate);
#endif
	  }
	}

	offset += len;

	if((offset+1) < packet->payload_packet_len) {
	  len = packet->payload[offset+1];

	  offset += 2;

	  if((offset+len) < packet->payload_packet_len) {
	    u_int32_t time_sec = packet->current_time_ms / 1000;
#ifdef DEBUG_TLS
	    u_int j;

	    printf("[CERTIFICATE] notAfter [len: %u][", len);
	    for(j=0; j<len; j++) printf("%c", packet->payload[offset+j]);
	    printf("]\n");
#endif

	    if(len < (sizeof(utcDate)-1)) {
	      struct tm utc;
	      utc.tm_isdst = -1; /* Not set by strptime */

	      strncpy(utcDate, (const char*)&packet->payload[offset], len);
	      utcDate[len] = '\0';

	      /* 141021000000Z */
	      if(strptime(utcDate, "%y%m%d%H%M%SZ", &utc) != NULL) {
		flow->protos.tls_quic.notAfter = timegm(&utc);
#ifdef DEBUG_TLS
		printf("[CERTIFICATE] notAfter %u [%s]\n",
		       flow->protos.tls_quic.notAfter, utcDate);
#endif
	      }
	    }

	    if(flow->protos.tls_quic.notBefore > TLS_LIMIT_DATE)
	      if((flow->protos.tls_quic.notAfter-flow->protos.tls_quic.notBefore) > TLS_THRESHOLD) {
		char str[64];
		
		snprintf(str, sizeof(str), "TLS Cert lasts %u days",
			  (flow->protos.tls_quic.notAfter-flow->protos.tls_quic.notBefore) / 86400);

		ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_CERT_VALIDITY_TOO_LONG, str); /* Certificate validity longer than 13 months */
	      }
	    
	    if((time_sec < flow->protos.tls_quic.notBefore) || (time_sec > flow->protos.tls_quic.notAfter)) {
	      char str[96], b[32], e[32];
	      struct tm result;	      
	      time_t theTime;

	      theTime = flow->protos.tls_quic.notBefore;
	      strftime(b, sizeof(b), "%d/%b/%Y %H:%M:%S", ndpi_gmtime_r(&theTime, &result));

	      theTime = flow->protos.tls_quic.notAfter;
	      strftime(e, sizeof(e), "%d/%b/%Y %H:%M:%S", ndpi_gmtime_r(&theTime, &result));
	      	      
	      snprintf(str, sizeof(str), "%s - %s", b, e);
	      ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_CERTIFICATE_EXPIRED, str); /* Certificate expired */
	    } else if((time_sec > flow->protos.tls_quic.notBefore)
		      && (time_sec > (flow->protos.tls_quic.notAfter - (ndpi_struct->tls_certificate_expire_in_x_days * 86400)))) {
	      char str[96], b[32], e[32];
	      struct tm result;	      
	      time_t theTime;

	      theTime = flow->protos.tls_quic.notBefore;
	      strftime(b, sizeof(b), "%d/%b/%Y %H:%M:%S", ndpi_gmtime_r(&theTime, &result));

	      theTime = flow->protos.tls_quic.notAfter;
	      strftime(e, sizeof(e), "%d/%b/%Y %H:%M:%S", ndpi_gmtime_r(&theTime, &result));

	      snprintf(str, sizeof(str), "%s - %s", b, e);
	      ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE, str); /* Certificate almost expired */
	    }
	  }
	}
      }
    } else if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x1d) && (packet->payload[i+2] == 0x11)) {
      /* Organization OID: 2.5.29.17 (subjectAltName) */
      u_int8_t matched_name = 0;

      /* If the client hello was not observed or the requested name was missing, there is no need to trigger an alert */
      if(flow->host_server_name[0] == '\0')
	matched_name = 1;

#ifdef DEBUG_TLS
      printf("******* [TLS] Found subjectAltName\n");
#endif

      i += 3 /* skip the initial patten 55 1D 11 */;

      /* skip the first type, 0x04 == BIT STRING, and jump to it's length */
      if(i < packet->payload_packet_len && packet->payload[i] == 0x04) i++; else i += 4; /* 4 bytes, with the last byte set to 04 */

      if(i < packet->payload_packet_len) {
	i += (packet->payload[i] & 0x80) ? (packet->payload[i] & 0x7F) : 0; /* skip BIT STRING length */
	if(i < packet->payload_packet_len) {
	  i += 2; /* skip the second type, 0x30 == SEQUENCE, and jump to it's length */
	  if(i < packet->payload_packet_len) {
	    i += (packet->payload[i] & 0x80) ? (packet->payload[i] & 0x7F) : 0; /* skip SEQUENCE length */
	    i++;

	    while(i < packet->payload_packet_len) {
	      u_int8_t general_name_type = packet->payload[i];

	      if((general_name_type == 0x81)    /* rfc822Name */
		 || (general_name_type == 0x82) /* dNSName    */
		 || (general_name_type == 0x87) /* ipAddress  */
		 )
		{
		  if((i < (packet->payload_packet_len - 1))
		     && ((i + packet->payload[i + 1] + 2) < packet->payload_packet_len)) {
		    u_int8_t len = packet->payload[i + 1];
		    char dNSName[256];
		    u_int16_t dNSName_len;

		    i += 2;

		    /* The check "len > sizeof(dNSName) - 1" will be always false. If we add it,
		       the compiler is smart enough to detect it and throws a warning */
		    if((len == 0 /* Looks something went wrong */)
		       || ((i+len) > packet->payload_packet_len))
		      break;

		    if(general_name_type == 0x87) {
		      if(len == 4 /* IPv4 */) {
			ndpi_snprintf(dNSName, sizeof(dNSName), "%u.%u.%u.%u",
				      packet->payload[i] & 0xFF,
				      packet->payload[i+1] & 0xFF,
				      packet->payload[i+2] & 0xFF,
				      packet->payload[i+3] & 0xFF);
		      } else if(len == 16 /* IPv6 */) {
			struct in6_addr addr = *(struct in6_addr *)&packet->payload[i];
			inet_ntop(AF_INET6, &addr, dNSName, sizeof(dNSName));
		      } else {
			/* Is that possibile? Better safe than sorry */
			dNSName[0] = '\0';
		      }
		    } else {
		      strncpy(dNSName, (const char*)&packet->payload[i], len);
		      dNSName[len] = '\0';
		    }

		    dNSName_len = strlen(dNSName);
		    cleanupServerName(dNSName, dNSName_len);

#if DEBUG_TLS
		    printf("[TLS] dNSName %s [%s][len: %u][leftover: %d]\n", dNSName,
			   flow->host_server_name, len,
			   packet->payload_packet_len-i-len);
#endif

		    /*
		      We cannot use ndpi_is_valid_hostname() as we can have wildcards
		      here that will create false positives
		    */
		    if(ndpi_normalize_printable_string(dNSName, dNSName_len) == 0) {
		      ndpi_set_risk(ndpi_struct, flow, NDPI_INVALID_CHARACTERS, dNSName);

		      /* This looks like an attack */
		      ndpi_set_risk(ndpi_struct, flow, NDPI_POSSIBLE_EXPLOIT, NULL);
		    }

		    if(matched_name == 0) {
#if DEBUG_TLS
		      printf("[TLS] Trying to match '%s' with '%s'\n",
			     flow->host_server_name,
			     dNSName);
#endif

		      if(dNSName[0] == '*') {
			char * label = strstr(flow->host_server_name, &dNSName[1]);

			if(label != NULL) {
			  char * first_dot = strchr(flow->host_server_name, '.');

			  if((first_dot == NULL) || (first_dot <= label)) {
			    matched_name = 1;
			  }
			}
		      }
		      else if(strcmp(flow->host_server_name, dNSName) == 0) {
			matched_name = 1;
		      }
		    }

		    if(flow->protos.tls_quic.server_names == NULL)
		      flow->protos.tls_quic.server_names = ndpi_strdup(dNSName),
			flow->protos.tls_quic.server_names_len = strlen(dNSName);
		    else if((u_int16_t)(flow->protos.tls_quic.server_names_len + dNSName_len + 1) > flow->protos.tls_quic.server_names_len) {
		      u_int16_t newstr_len = flow->protos.tls_quic.server_names_len + dNSName_len + 1;
		      char *newstr = (char*)ndpi_realloc(flow->protos.tls_quic.server_names,
							 flow->protos.tls_quic.server_names_len+1, newstr_len+1);

		      if(newstr) {
			flow->protos.tls_quic.server_names = newstr;
			flow->protos.tls_quic.server_names[flow->protos.tls_quic.server_names_len] = ',';
			strncpy(&flow->protos.tls_quic.server_names[flow->protos.tls_quic.server_names_len+1],
				dNSName, dNSName_len+1);
			flow->protos.tls_quic.server_names[newstr_len] = '\0';
			flow->protos.tls_quic.server_names_len = newstr_len;
		      }
		    }

		    if(!flow->protos.tls_quic.subprotocol_detected)
		      if(ndpi_match_hostname_protocol(ndpi_struct, flow, __get_master(ndpi_struct, flow), dNSName, dNSName_len)) {
			flow->protos.tls_quic.subprotocol_detected = 1;
		        ndpi_unset_risk(ndpi_struct, flow, NDPI_NUMERIC_IP_HOST);
		      }

		    i += len;
		  } else {
#if DEBUG_TLS
		    printf("[TLS] Leftover %u bytes", packet->payload_packet_len - i);
#endif
		    ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_SUSPICIOUS_EXTENSION, NULL);
		    break;
		  }
		} else {
		break;
	      }
	    } /* while */

	    if(!matched_name) {
	      char str[128];

	      snprintf(str, sizeof(str), "%s vs %s", flow->host_server_name, flow->protos.tls_quic.server_names);
	      ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_CERTIFICATE_MISMATCH, str); /* Certificate mismatch */
	    }
	  }
	}
      }
    }
  } /* for */

  if(rdn_len && (flow->protos.tls_quic.subjectDN == NULL)) {
    flow->protos.tls_quic.subjectDN = ndpi_strdup(rdnSeqBuf);

    if(flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN) {
      /* No idea what is happening behind the scenes: let's check the certificate */
      u_int32_t val;
      int rc = ndpi_match_string_value(ndpi_struct->tls_cert_subject_automa.ac_automa,
				       rdnSeqBuf, strlen(rdnSeqBuf), &val);

      if(rc == 0) {
	/* Match found */
	u_int16_t proto_id = (u_int16_t)val;
	ndpi_protocol ret = { __get_master(ndpi_struct, flow), proto_id, NDPI_PROTOCOL_UNKNOWN /* unused */, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, NULL};

	ndpi_set_detected_protocol(ndpi_struct, flow, proto_id, __get_master(ndpi_struct, flow), NDPI_CONFIDENCE_DPI);
	flow->category = ndpi_get_proto_category(ndpi_struct, ret);
	ndpi_check_subprotocol_risk(ndpi_struct, flow, proto_id);
	ndpi_unset_risk(ndpi_struct, flow, NDPI_NUMERIC_IP_HOST);

	if(ndpi_struct->tls_cert_cache) {
	  u_int32_t key = make_tls_cert_key(packet, 0 /* from the server */);

	  ndpi_lru_add_to_cache(ndpi_struct->tls_cert_cache, key, proto_id, ndpi_get_current_time(flow));
	}
      }
    }
  }

  if(flow->protos.tls_quic.subjectDN && flow->protos.tls_quic.issuerDN
     && (!strcmp(flow->protos.tls_quic.subjectDN, flow->protos.tls_quic.issuerDN))) {
    /* Last resort: we check if this is a trusted issuerDN */
    if(ndpi_check_issuerdn_risk_exception(ndpi_struct, flow->protos.tls_quic.issuerDN))
      return; /* This is a trusted DN */
    
    ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_SELFSIGNED_CERTIFICATE, flow->protos.tls_quic.subjectDN);
  }
  
#if DEBUG_TLS
  printf("[TLS] %s() SubjectDN [%s]\n", __FUNCTION__, rdnSeqBuf);
#endif
}

/* **************************************** */

/* See https://blog.catchpoint.com/2017/05/12/dissecting-tls-using-wireshark/ */
int processCertificate(struct ndpi_detection_module_struct *ndpi_struct,
		       struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  int is_dtls = packet->udp ? 1 : 0;
  u_int32_t certificates_length, length = (packet->payload[1] << 16) + (packet->payload[2] << 8) + packet->payload[3];
  u_int32_t certificates_offset = 7 + (is_dtls ? 8 : 0);
  u_int8_t num_certificates_found = 0;
  SHA1_CTX srv_cert_fingerprint_ctx ;

#ifdef DEBUG_TLS
  printf("[TLS] %s() [payload_packet_len=%u][direction: %u][%02X %02X %02X %02X %02X %02X...]\n",
	 __FUNCTION__, packet->payload_packet_len,
	 packet->packet_direction,
	 packet->payload[0], packet->payload[1], packet->payload[2],
	 packet->payload[3], packet->payload[4], packet->payload[5]);
#endif

  if((packet->payload_packet_len != (length + 4 + (is_dtls ? 8 : 0))) || (packet->payload[1] != 0x0) ||
     certificates_offset >= packet->payload_packet_len) {
    ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET, NULL);
    return(-1); /* Invalid length */
  }

  certificates_length = (packet->payload[certificates_offset - 3] << 16) +
    (packet->payload[certificates_offset - 2] << 8) +
    packet->payload[certificates_offset - 1];

  if((packet->payload[certificates_offset - 3] != 0x0) || ((certificates_length+3) != length)) {
    ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET, NULL);
    return(-2); /* Invalid length */
  }

  /* Now let's process each individual certificates */
  while(certificates_offset < certificates_length) {
    u_int32_t certificate_len = (packet->payload[certificates_offset] << 16) + (packet->payload[certificates_offset+1] << 8) + packet->payload[certificates_offset+2];

    /* Invalid lenght */
    if((certificate_len == 0)
       || (packet->payload[certificates_offset] != 0x0)
       || ((certificates_offset+certificate_len) > (4+certificates_length+(is_dtls ? 8 : 0)))) {
#ifdef DEBUG_TLS
      printf("[TLS] Invalid length [certificate_len: %u][certificates_offset: %u][%u vs %u]\n",
	     certificate_len, certificates_offset,
	     (certificates_offset+certificate_len),
	     certificates_length);
#endif
      break;
    }

    certificates_offset += 3;
#ifdef DEBUG_TLS
    printf("[TLS] Processing %u bytes certificate [%02X %02X %02X]\n",
	   certificate_len,
	   packet->payload[certificates_offset],
	   packet->payload[certificates_offset+1],
	   packet->payload[certificates_offset+2]);
#endif

    if(num_certificates_found++ == 0) /* Dissect only the first certificate that is the one we care */ {
      /* For SHA-1 we take into account only the first certificate and not all of them */

      SHA1Init(&srv_cert_fingerprint_ctx);

#ifdef DEBUG_CERTIFICATE_HASH
      {
	u_int32_t i;

	for(i=0;i<certificate_len;i++)
	  printf("%02X ", packet->payload[certificates_offset+i]);

	printf("\n");
      }
#endif

      SHA1Update(&srv_cert_fingerprint_ctx,
		 &packet->payload[certificates_offset],
		 certificate_len);

      SHA1Final(flow->protos.tls_quic.sha1_certificate_fingerprint, &srv_cert_fingerprint_ctx);

      flow->protos.tls_quic.fingerprint_set = 1;

      uint8_t * sha1 = flow->protos.tls_quic.sha1_certificate_fingerprint;
      const size_t sha1_siz = sizeof(flow->protos.tls_quic.sha1_certificate_fingerprint);
      char sha1_str[20 /* sha1_siz */ * 2 + 1];
      static const char hexalnum[] = "0123456789ABCDEF";
      size_t i;
      for (i = 0; i < sha1_siz; ++i) {
        u_int8_t lower = (sha1[i] & 0x0F);
        u_int8_t upper = (sha1[i] & 0xF0) >> 4;
        sha1_str[i*2] = hexalnum[upper];
        sha1_str[i*2 + 1] = hexalnum[lower];
      }
      sha1_str[sha1_siz * 2] = '\0';

#ifdef DEBUG_TLS
      printf("[TLS] SHA-1: %s\n", sha1_str);
#endif

      if(ndpi_struct->malicious_sha1_hashmap != NULL) {
        u_int16_t rc1 = ndpi_hash_find_entry(ndpi_struct->malicious_sha1_hashmap, sha1_str, sha1_siz * 2, NULL);

        if(rc1 == 0)
          ndpi_set_risk(ndpi_struct, flow, NDPI_MALICIOUS_SHA1_CERTIFICATE, sha1_str);
      }

      processCertificateElements(ndpi_struct, flow, certificates_offset, certificate_len);
    }

    certificates_offset += certificate_len;
  }

  if((ndpi_struct->num_tls_blocks_to_follow != 0)
     && (flow->l4.tcp.tls.num_tls_blocks >= ndpi_struct->num_tls_blocks_to_follow)) {
#ifdef DEBUG_TLS_BLOCKS
    printf("*** [TLS Block] Enough blocks dissected\n");
#endif

    flow->extra_packets_func = NULL; /* We're good now */
  }

  return(1);
}

/* **************************************** */

static int processTLSBlock(struct ndpi_detection_module_struct *ndpi_struct,
                           struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  int ret;

#ifdef DEBUG_TLS
  printf("[TLS] Processing block %u\n", packet->payload[0]);
#endif

  switch(packet->payload[0] /* block type */) {
  case 0x01: /* Client Hello */
  case 0x02: /* Server Hello */
    processClientServerHello(ndpi_struct, flow, 0);
    flow->protos.tls_quic.hello_processed = 1;
    flow->protos.tls_quic.ch_direction = (packet->payload[0] == 0x01 ? packet->packet_direction : !packet->packet_direction);
    ndpi_int_tls_add_connection(ndpi_struct, flow);

#ifdef DEBUG_TLS
    printf("*** TLS [version: %02X][%s Hello]\n",
	   flow->protos.tls_quic.ssl_version,
	   (packet->payload[0] == 0x01) ? "Client" : "Server");
#endif

    /* Not support for DTLS 1.3 yet, then certificates are always visible in DTLS */
    if((packet->tcp && flow->protos.tls_quic.ssl_version >= 0x0304 /* TLS 1.3 */)
       && (packet->payload[0] == 0x02 /* Server Hello */)) {
      flow->tls_quic.certificate_processed = 1; /* No Certificate with TLS 1.3+ */
    }

    checkTLSSubprotocol(ndpi_struct, flow, packet->payload[0] == 0x01);
    break;

  case 0x0b: /* Certificate */
    /* Important: populate the tls union fields only after
     * ndpi_int_tls_add_connection has been called */
    if(flow->protos.tls_quic.hello_processed) {
      /* Only certificates from the server */
      if(flow->protos.tls_quic.ch_direction != packet->packet_direction) {
        ret = processCertificate(ndpi_struct, flow);
        if(ret != 1) {
#ifdef DEBUG_TLS
          printf("[TLS] Error processing certificate: %d\n", ret);
#endif
        }
      } else {
#ifdef DEBUG_TLS
        printf("[TLS] Certificate from client. Ignoring it\n");
#endif
      }
      flow->tls_quic.certificate_processed = 1;
    }
    break;

  default:
    return(-1);
  }

  return(0);
}

/* **************************************** */

static void ndpi_looks_like_tls(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow) {
  if(flow->guessed_protocol_id == NDPI_PROTOCOL_UNKNOWN)
    flow->guessed_protocol_id = __get_master(ndpi_struct, flow);
}

/* **************************************** */

static int ndpi_search_tls_tcp(struct ndpi_detection_module_struct *ndpi_struct,
			       struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int8_t something_went_wrong = 0;
  message_t *message;

#ifdef DEBUG_TLS_MEMORY
  printf("[TLS Mem] ndpi_search_tls_tcp() Processing new packet [payload_packet_len: %u][Dir: %u]\n",
	 packet->payload_packet_len, packet->packet_direction);
#endif

  /* This function is also called by "extra dissection" data path. Unfortunately,
     generic "extra function" code doesn't honour protocol bitmask.
     TODO: handle that in ndpi_main.c for all the protocols */
  if(packet->payload_packet_len == 0 ||
     packet->tcp_retransmission) {
#ifdef DEBUG_TLS_MEMORY
    printf("[TLS Mem] Ack or retransmission %d/%d. Skip\n",
           packet->payload_packet_len, packet->tcp_retransmission);
#endif
    return 1; /* Keep working */
  }

  message = &flow->tls_quic.message[packet->packet_direction];
  if(ndpi_search_tls_memory(ndpi_struct, flow, packet->payload,
			    packet->payload_packet_len, ntohl(packet->tcp->seq),
			    message) == -1)
    return 0; /* Error -> stop */

  /* Valid TLS Content Types:
     https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5 */
  if(!(message->buffer[0] >= 20 &&
       message->buffer[0] <= 26)) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    something_went_wrong = 1;
  }

  while(!something_went_wrong) {
    u_int32_t len;
    u_int16_t p_len;
    const u_int8_t *p;
    u_int8_t content_type;

    if(message->buffer_used < 5)
      break;

    len = (message->buffer[3] << 8) + message->buffer[4] + 5;

    if(len > message->buffer_used) {
#ifdef DEBUG_TLS_MEMORY
      printf("[TLS Mem] Not enough TLS data [%u < %u][%02X %02X %02X %02X %02X]\n",
	     len, message->buffer_used,
	     message->buffer[0],
	     message->buffer[1],
	     message->buffer[2],
	     message->buffer[3],
	     message->buffer[4]);
#endif
      break;
    }

    if(len == 0) {
      something_went_wrong = 1;
      break;
    }

#ifdef DEBUG_TLS_MEMORY
    printf("[TLS Mem] Processing %u bytes message\n", len);
#endif

    content_type = message->buffer[0];

    /* Overwriting packet payload */
    p = packet->payload;
    p_len = packet->payload_packet_len; /* Backup */

    if(content_type == 0x14 /* Change Cipher Spec */) {
      if(ndpi_struct->skip_tls_blocks_until_change_cipher) {
	/*
	  Ignore Application Data up until change cipher
	  so in this case we reset the number of observed
	  TLS blocks
	*/
	flow->l4.tcp.tls.num_tls_blocks = 0;
      }
    } else if(content_type == 0x15 /* Alert */) {
      /* https://techcommunity.microsoft.com/t5/iis-support-blog/ssl-tls-alert-protocol-and-the-alert-codes/ba-p/377132 */
#ifdef DEBUG_TLS
      printf("[TLS] *** TLS ALERT ***\n");
#endif

      if(len >= 7) {
	u_int8_t alert_level = message->buffer[5];

	if(alert_level == 2 /* Warning (1), Fatal (2) */)
	  ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_FATAL_ALERT, NULL);
      }

      u_int16_t const alert_len = ntohs(*(u_int16_t const *)&message->buffer[3]);
      if (message->buffer[1] == 0x03 &&
          message->buffer[2] <= 0x04 &&
          alert_len == (u_int32_t)message->buffer_used - 5)
	{
	  ndpi_int_tls_add_connection(ndpi_struct, flow);
	}
    }

    if((len > 9)
       && (content_type != 0x17 /* Application Data */)
       && (!flow->tls_quic.certificate_processed)) {
      /* Split the element in blocks */
      u_int32_t processed = 5;

      while((processed+4) <= len) {
	const u_int8_t *block = (const u_int8_t *)&message->buffer[processed];
	u_int32_t block_len   = (block[1] << 16) + (block[2] << 8) + block[3];

	if(/* (block_len == 0) || */ /* Note blocks can have zero lenght */
	   (block_len > len) || ((block[1] != 0x0))) {
	  something_went_wrong = 1;
	  break;
	}

	packet->payload = block;
	packet->payload_packet_len = ndpi_min(block_len+4, message->buffer_used);

	if((processed+packet->payload_packet_len) > len) {
	  something_went_wrong = 1;
	  break;
	}

	processTLSBlock(ndpi_struct, flow);
	ndpi_looks_like_tls(ndpi_struct, flow);

	processed += packet->payload_packet_len;
      }
    } else if(len > 5 /* Minimum block size */) {
      /* Process element as a whole */
      if(content_type == 0x17 /* Application Data */) {
	u_int32_t block_len   = (message->buffer[3] << 8) + (message->buffer[4]);

	/* Let's do a quick check to make sure this really looks like TLS */
	if(block_len < 16384 /* Max TLS block size */)
	  ndpi_looks_like_tls(ndpi_struct, flow);

	if (message->buffer[1] == 0x03 &&
	    message->buffer[2] <= 0x04 &&
	    block_len == (u_int32_t)message->buffer_used - 5)
	  {
	    ndpi_int_tls_add_connection(ndpi_struct, flow);
	  }

	/* If we have seen Application Data blocks in both directions, it means
	   we are after the handshake. Stop extra processing */
	flow->l4.tcp.tls.app_data_seen[packet->packet_direction] = 1;
	if(flow->l4.tcp.tls.app_data_seen[!packet->packet_direction] == 1)
	  flow->tls_quic.certificate_processed = 1;

	if(flow->tls_quic.certificate_processed) {
	  if(flow->l4.tcp.tls.num_tls_blocks < ndpi_struct->num_tls_blocks_to_follow) {
	    int16_t blen = len-5;

	    /* Use positive values for c->s e negative for s->c */
	    if(packet->packet_direction != 0) blen = -blen;
	    
	    flow->l4.tcp.tls.tls_application_blocks_len[flow->l4.tcp.tls.num_tls_blocks++] = blen;
	  }
	  
#ifdef DEBUG_TLS_BLOCKS
	  printf("*** [TLS Block] [len: %u][num_tls_blocks: %u/%u]\n",
		 len-5, flow->l4.tcp.tls.num_tls_blocks, ndpi_struct->num_tls_blocks_to_follow);
#endif
	}
      }
    }

    packet->payload = p;
    packet->payload_packet_len = p_len; /* Restore */
    message->buffer_used -= len;

    if(message->buffer_used > 0)
      memmove(message->buffer, &message->buffer[len], message->buffer_used);
    else
      break;

#ifdef DEBUG_TLS_MEMORY
    printf("[TLS Mem] Left memory buffer %u bytes\n", message->buffer_used);
#endif
  }

  if(something_went_wrong
     || ((ndpi_struct->num_tls_blocks_to_follow > 0)
	 && (flow->l4.tcp.tls.num_tls_blocks == ndpi_struct->num_tls_blocks_to_follow))
     || ((ndpi_struct->num_tls_blocks_to_follow == 0)
	 && (flow->tls_quic.certificate_processed == 1))
     ) {
#ifdef DEBUG_TLS_BLOCKS
    printf("*** [TLS Block] No more blocks\n");
#endif
    /* An ookla flow? */
    if((ndpi_struct->aggressiveness_ookla & NDPI_AGGRESSIVENESS_OOKLA_TLS) && /* Feature enabled */
       (!something_went_wrong &&
        flow->tls_quic.certificate_processed == 1 &&
        flow->protos.tls_quic.hello_processed == 1) && /* TLS handshake found without errors */
       flow->detected_protocol_stack[0] == NDPI_PROTOCOL_TLS && /* No IMAPS/FTPS/... */
       flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN && /* No sub-classification */
       ntohs(flow->s_port) == 8080 && /* Ookla port */
       ookla_search_into_cache(ndpi_struct, flow)) {
      NDPI_LOG_INFO(ndpi_struct, "found ookla (cache over TLS)\n");
      /* Even if a LRU cache is involved, NDPI_CONFIDENCE_DPI_AGGRESSIVE seems more
         suited than NDPI_CONFIDENCE_DPI_CACHE */
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OOKLA, NDPI_PROTOCOL_TLS, NDPI_CONFIDENCE_DPI_AGGRESSIVE);
      /* TLS over port 8080 usually triggers that risk; clear it */
      ndpi_unset_risk(ndpi_struct, flow, NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT);
      flow->extra_packets_func = NULL;
      return(0); /* That's all */
    } else {
      flow->extra_packets_func = NULL;
      return(0); /* That's all */
    }
  } else
    return(1);
}

/* **************************************** */

int is_dtls(const u_int8_t *buf, u_int32_t buf_len, u_int32_t *block_len) {
  if(buf_len <= 13)
    return 0;

  if((buf[0] != 0x16 && buf[0] != 0x14 && buf[0] != 0x17) || /* Handshake, change-cipher-spec, Application-Data */
     !((buf[1] == 0xfe && buf[2] == 0xff) || /* Versions */
       (buf[1] == 0xfe && buf[2] == 0xfd) ||
       (buf[1] == 0x01 && buf[2] == 0x00))) {
#ifdef DEBUG_TLS
    printf("[TLS] DTLS invalid block 0x%x or old version 0x%x-0x%x-0x%x\n",
           buf[0], buf[1], buf[2], buf[3]);
#endif
    return 0;
  }
  *block_len = ntohs(*((u_int16_t*)&buf[11]));
#ifdef DEBUG_TLS
  printf("[TLS] DTLS block len: %d\n", *block_len);
#endif
  if(*block_len == 0 || (*block_len + 12 >= buf_len)) { /* We might have multiple DTLS records */
#ifdef DEBUG_TLS
    printf("[TLS] DTLS invalid block len %d (buf_len %d)\n",
           *block_len, buf_len);
#endif
    return 0;
  }
  return 1;
}

/* **************************************** */

static int ndpi_search_tls_udp(struct ndpi_detection_module_struct *ndpi_struct,
			       struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int32_t handshake_len, handshake_frag_off, handshake_frag_len;
  u_int16_t p_len, processed;
  const u_int8_t *p;
  u_int8_t no_dtls = 0, change_cipher_found = 0;
  message_t *message = NULL;

#ifdef DEBUG_TLS
  printf("[TLS] %s()\n", __FUNCTION__);
#endif

  /* Overwriting packet payload */
  p = packet->payload, p_len = packet->payload_packet_len; /* Backup */

  /* Split the element in blocks */
  processed = 0;
  while(processed + 13 < p_len) {
    u_int32_t block_len;
    const u_int8_t *block = (const u_int8_t *)&p[processed];

    if(!is_dtls(block, p_len, &block_len)) {
      if(processed == 0 && /* First block */
         flow->stun.maybe_dtls == 1) {
	/* Sometimes STUN packets are interleaved with TLS ones. Ignore STUN ones
	   since we already are after STUN dissection and we are interested only on
	   TLS stuff right now */
#ifdef DEBUG_TLS
        printf("Probably a stun packet. Keep going with TLS on next packets\n");
#endif
        /* Note that we can immediately "return" because, being the first block,
	   we don't need to restore packet->payload and packet->payload_packet_len */
        return(1); /* Keep working */
      }
      no_dtls = 1;
      break;
    }

    /* We process only handshake msgs */
    if(block[0] == 0x16) {
      if(processed + block_len + 13 > p_len) {
#ifdef DEBUG_TLS
        printf("[TLS] DTLS invalid len %d %d %d\n", processed, block_len, p_len);
#endif
        no_dtls = 1;
        break;
      }
      /* TODO: handle (certificate) fragments */
      if(block_len > 24) {
        handshake_len = (block[14] << 16) + (block[15] << 8) + block[16];
        handshake_frag_off = (block[19] << 16) + (block[20] << 8) + block[21];
        handshake_frag_len = (block[22] << 16) + (block[23] << 8) + block[24];
        message = &flow->tls_quic.message[packet->packet_direction];


#ifdef DEBUG_TLS
        printf("[TLS] DTLS frag off %d len %d\n", handshake_frag_off, handshake_frag_len);
#endif

	if((handshake_len + 12) == block_len) {
          packet->payload = &block[13];
          packet->payload_packet_len = block_len;
          processTLSBlock(ndpi_struct, flow);
	} else if(handshake_len + 12 > block_len) {
	  int rc;

#ifdef DEBUG_TLS
          printf("[TLS] DTLS fragment off %d len %d\n", handshake_frag_off, handshake_frag_len);
#endif
          if(handshake_frag_len + 12 > block_len) {
#ifdef DEBUG_TLS
            printf("[TLS] DTLS fragment invalid len %d + 12 > %d\n", handshake_frag_len, block_len);
#endif
            no_dtls = 1;
            break;
	  }

          if(handshake_frag_off == 0) {
            rc = ndpi_search_tls_memory(ndpi_struct, flow,  &block[13],
					handshake_frag_len + 12,
					handshake_frag_off, message);
	  } else {
            rc = ndpi_search_tls_memory(ndpi_struct, flow,  &block[13 + 12],
					handshake_frag_len,
					handshake_frag_off + 12, message);
	  }
	  if(rc == -1) {
            no_dtls = 1;
            break;
	  }
#ifdef DEBUG_TLS
          printf("[TLS] DTLS reassembled len %d vs %d\n",
                 message->buffer_used, handshake_len + 12);
#endif

          if(handshake_len + 12 == message->buffer_used) {
            packet->payload = message->buffer;
            packet->payload_packet_len = message->buffer_used;
            processTLSBlock(ndpi_struct, flow);

            ndpi_free(message->buffer);
            memset(message, '\0', sizeof(*message));
            message = NULL;
          } else {
            /* No break, next fragments might be in the same packet */
          }

        } else {
#ifdef DEBUG_TLS
          printf("[TLS] DTLS invalid handshake_len %d, %d\n",
                 handshake_len, block_len);
#endif
          no_dtls = 1;
          break;
        }
      }
    } else if(block[0] == 0x14) {
      /* Change-cipher-spec: any subsequent block might be encrypted */
#ifdef DEBUG_TLS
      printf("[TLS] Change-cipher-spec\n");
#endif
      change_cipher_found = 1;
      processed += block_len + 13;
      break;
    } else {
#ifdef DEBUG_TLS
      printf("[TLS] Appllication Data\n");
#endif
      processed += block_len + 13;
      /* DTLS mid session: no need to further inspect the flow */
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_DTLS, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      flow->tls_quic.certificate_processed = 1; /* Fake, to avoid extra dissection */
      break;
    }

    processed += block_len + 13;
  }
  if(processed != p_len && message == NULL /* No pending reassembler */) {
#ifdef DEBUG_TLS
    printf("[TLS] DTLS invalid processed len %d/%d (%d)\n", processed, p_len, change_cipher_found);
#endif
    if(!change_cipher_found)
      no_dtls = 1;
  }

  packet->payload = p;
  packet->payload_packet_len = p_len; /* Restore */

  if(no_dtls || change_cipher_found || flow->tls_quic.certificate_processed) {
    NDPI_EXCLUDE_PROTO_EXT(ndpi_struct, flow, NDPI_PROTOCOL_DTLS);
    flow->extra_packets_func = NULL;
    return(0); /* That's all */
  } else {
    return(1); /* Keep working */
  }
}

/* **************************************** */

static void tlsInitExtraPacketProcessing(struct ndpi_detection_module_struct *ndpi_struct,
					 struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  /* At most 12 packets should almost always be enough to find the server certificate if it's there.
     Exception: DTLS traffic with fragments, retransmissions and STUN packets */
  flow->max_extra_packets_to_check = ((packet->udp != NULL) ? 20 : 12) + (ndpi_struct->num_tls_blocks_to_follow*4);
  flow->extra_packets_func = (packet->udp != NULL) ? ndpi_search_tls_udp : ndpi_search_tls_tcp;
}

/* **************************************** */

void switch_extra_dissection_to_tls(struct ndpi_detection_module_struct *ndpi_struct,
				    struct ndpi_flow_struct *flow)
{
#ifdef DEBUG_TLS
  printf("Switching to TLS extra dissection\n");
#endif

  /* Reset reassemblers */
  if(flow->tls_quic.message[0].buffer)
    ndpi_free(flow->tls_quic.message[0].buffer);
  memset(&flow->tls_quic.message[0], '\0', sizeof(flow->tls_quic.message[0]));
  if(flow->tls_quic.message[1].buffer)
    ndpi_free(flow->tls_quic.message[1].buffer);
  memset(&flow->tls_quic.message[1], '\0', sizeof(flow->tls_quic.message[1]));

  tlsInitExtraPacketProcessing(ndpi_struct, flow);
}

/* **************************************** */

void switch_to_tls(struct ndpi_detection_module_struct *ndpi_struct,
		   struct ndpi_flow_struct *flow)
{
#ifdef DEBUG_TLS
  printf("Switching to TLS\n");
#endif

  /* Reset reassemblers */
  if(flow->tls_quic.message[0].buffer)
    ndpi_free(flow->tls_quic.message[0].buffer);
  memset(&flow->tls_quic.message[0], '\0', sizeof(flow->tls_quic.message[0]));
  if(flow->tls_quic.message[1].buffer)
    ndpi_free(flow->tls_quic.message[1].buffer);
  memset(&flow->tls_quic.message[1], '\0', sizeof(flow->tls_quic.message[1]));

  ndpi_search_tls_wrapper(ndpi_struct, flow);
}

/* **************************************** */

static void tls_subclassify_by_alpn(struct ndpi_detection_module_struct *ndpi_struct,
				    struct ndpi_flow_struct *flow) {
  /* Right now we have only one rule so we can keep it trivial */

  if (!flow->protos.tls_quic.advertised_alpns)
    return;

  if(strlen(flow->protos.tls_quic.advertised_alpns) > NDPI_STATICSTRING_LEN("anydesk/") &&
     strncmp(flow->protos.tls_quic.advertised_alpns, "anydesk/", NDPI_STATICSTRING_LEN("anydesk/")) == 0) {
#ifdef DEBUG_TLS
    printf("Matching ANYDESK via alpn\n");
#endif
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ANYDESK,
			       __get_master(ndpi_struct, flow), NDPI_CONFIDENCE_DPI);
    flow->protos.tls_quic.subprotocol_detected = 1;
  }
}

/* **************************************** */

static void tlsCheckUncommonALPN(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow,
				 char *alpn_start) {
  char * comma_or_nul = alpn_start;

  do {
    size_t alpn_len;

    comma_or_nul = strchr(comma_or_nul, ',');

    if(comma_or_nul == NULL)
      comma_or_nul = alpn_start + strlen(alpn_start);

    alpn_len = comma_or_nul - alpn_start;

    if(!is_a_common_alpn(ndpi_struct, alpn_start, alpn_len)) {
      char str[64];
      size_t str_len;
      
#ifdef DEBUG_TLS
      printf("TLS uncommon ALPN found: %.*s\n", (int)alpn_len, alpn_start);
#endif

      str[0] = '\0';
      str_len = ndpi_min(alpn_len, sizeof(str));
      if(str_len > 0) {
        strncpy(str, alpn_start, str_len);
        str[str_len - 1] = '\0';
      }

      ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_UNCOMMON_ALPN, str);
      break;
    }

    alpn_start = comma_or_nul + 1;
  } while (*(comma_or_nul++) != '\0');
}

/* **************************************** */

static void ndpi_int_tls_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					struct ndpi_flow_struct *flow) {
  u_int32_t protocol;

#if DEBUG_TLS
  printf("[TLS] %s()\n", __FUNCTION__);
#endif

  if((flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN) ||
     (flow->detected_protocol_stack[1] != NDPI_PROTOCOL_UNKNOWN)) {
    if(!flow->extra_packets_func)
      tlsInitExtraPacketProcessing(ndpi_struct, flow);
    return;
  }

  protocol = __get_master(ndpi_struct, flow);

  ndpi_set_detected_protocol(ndpi_struct, flow, protocol, protocol, NDPI_CONFIDENCE_DPI);

  tlsInitExtraPacketProcessing(ndpi_struct, flow);
}

/* **************************************** */

static void checkExtensions(struct ndpi_detection_module_struct *ndpi_struct,
			    struct ndpi_flow_struct * const flow, int is_dtls,
                            u_int16_t extension_id, u_int16_t extension_len,
			    u_int16_t extension_payload_offset) {
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  if((extension_payload_offset + extension_len) > packet->payload_packet_len) {
#ifdef DEBUG_TLS
      printf("[TLS] extension length exceeds remaining packet length: %u > %u.\n",
	     extension_len, packet->payload_packet_len - extension_payload_offset);
#endif
      ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_SUSPICIOUS_EXTENSION, NULL);
      return;
    }

  /* see: https://www.wireshark.org/docs/wsar_html/packet-tls-utils_8h_source.html */
  static u_int16_t const allowed_non_iana_extensions[] = {
    65486 /* ESNI */, 13172 /* NPN - Next Proto Neg */, 17513 /* ALPS */,
    30032 /* Channel ID */, 65445 /* QUIC transport params */,
    /* GREASE extensions */
    2570, 6682, 10794, 14906, 19018, 23130, 27242,
    31354, 35466, 39578, 43690, 47802, 51914, 56026,
    60138, 64250,
    /* Groups */
    1035, 10794, 16696, 23130, 31354, 35466, 51914,
    /* Ciphers */
    102, 129, 52243, 52244, 57363, 65279, 65413,
    /* ECH */
    65037
  };
  size_t const allowed_non_iana_extensions_size = sizeof(allowed_non_iana_extensions) /
    sizeof(allowed_non_iana_extensions[0]);

  /* see: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml */
  if(extension_id > 59 && extension_id != 65281)
    {
      u_int8_t extension_found = 0;
      size_t i;

      for (i = 0; i < allowed_non_iana_extensions_size; ++i) {
	if(allowed_non_iana_extensions[i] == extension_id) {
	  extension_found = 1;
	  break;
	}
      }
      
      if(extension_found == 0) {
	char str[64];

	snprintf(str, sizeof(str), "Extn id %u", extension_id);
#ifdef DEBUG_TLS
	  printf("[TLS] suspicious extension id: %u\n", extension_id);
#endif
	  ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_SUSPICIOUS_EXTENSION, str);
	  return;
	}
    }

  /* Check for DTLS-only extensions. */
  if(is_dtls == 0)
    {
      if(extension_id == 53 || extension_id == 54)
	{
	  char str[64];
	  
	  snprintf(str, sizeof(str), "Extn id %u", extension_id);
	  
#ifdef DEBUG_TLS
	  printf("[TLS] suspicious DTLS-only extension id: %u\n", extension_id);
#endif
	  ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_SUSPICIOUS_EXTENSION, str);
	  return;
	}
    }
}

/* **************************************** */

static int check_sni_is_numeric_ip(char *sni) {
  unsigned char buf[sizeof(struct in6_addr)];

  if(inet_pton(AF_INET, sni, buf) == 1)
    return 1;
  if(inet_pton(AF_INET6, sni, buf) == 1)
    return 1;
  return 0;
}


/* **************************************** */

int processClientServerHello(struct ndpi_detection_module_struct *ndpi_struct,
			     struct ndpi_flow_struct *flow, uint32_t quic_version) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  union ja3_info ja3;
  u_int8_t invalid_ja3 = 0;
  u_int16_t tls_version, ja3_str_len;
  char ja3_str[JA3_STR_LEN];
  ndpi_MD5_CTX ctx;
  u_char md5_hash[16];
  u_int32_t i, j;
  u_int16_t total_len;
  u_int8_t handshake_type;
  int is_quic = (quic_version != 0);
  int is_dtls = packet->udp && (!is_quic);

#ifdef DEBUG_TLS
  printf("TLS %s() called\n", __FUNCTION__);
#endif


  handshake_type = packet->payload[0];
  total_len = (packet->payload[1] << 16) +  (packet->payload[2] << 8) + packet->payload[3];

  if((total_len > packet->payload_packet_len) || (packet->payload[1] != 0x0))
    return(0); /* Not found */

  total_len = packet->payload_packet_len;

  /* At least "magic" 3 bytes, null for string end, otherwise no need to waste cpu cycles */
  if(total_len > 4) {
    u_int16_t base_offset    = (!is_dtls) ? 38 : 46;
    u_int16_t version_offset = (!is_dtls) ? 4 : 12;
    u_int16_t offset = (!is_dtls) ? 38 : 46;
    u_int32_t tot_extension_len;
    u_int8_t  session_id_len =  0;

    if((base_offset >= total_len) ||
       (version_offset + 1) >= total_len)
      return 0; /* Not found */

    session_id_len = packet->payload[base_offset];

#ifdef DEBUG_TLS
    printf("TLS [len: %u][handshake_type: %02X]\n", packet->payload_packet_len, handshake_type);
#endif

    tls_version = ntohs(*((u_int16_t*)&packet->payload[version_offset]));

    if(handshake_type == 0x02 /* Server Hello */) {
      int rc;

      ja3.server.num_cipher = 0;
      ja3.server.num_tls_extension = 0;
      ja3.server.num_elliptic_curve_point_format = 0;
      ja3.server.alpn[0] = '\0';

      ja3.server.tls_handshake_version = tls_version;

#ifdef DEBUG_TLS
      printf("TLS Server Hello [version: 0x%04X]\n", tls_version);
#endif

      /*
	The server hello decides about the TLS version of this flow
	https://networkengineering.stackexchange.com/questions/55752/why-does-wireshark-show-version-tls-1-2-here-instead-of-tls-1-3
      */
      if(packet->udp)
	offset += session_id_len + 1;
      else {
	if(tls_version < 0x7F15 /* TLS 1.3 lacks of session id */)
	  offset += session_id_len+1;
      }

      if((offset+3) > packet->payload_packet_len)
	return(0); /* Not found */

      ja3.server.num_cipher = 1, ja3.server.cipher[0] = ntohs(*((u_int16_t*)&packet->payload[offset]));
      if((flow->protos.tls_quic.server_unsafe_cipher = ndpi_is_safe_ssl_cipher(ja3.server.cipher[0])) == 1) {
	char str[64];
	char unknown_cipher[8];

	snprintf(str, sizeof(str), "Cipher %s", ndpi_cipher2str(ja3.server.cipher[0], unknown_cipher));
	ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_WEAK_CIPHER, str);
      }
      
      flow->protos.tls_quic.server_cipher = ja3.server.cipher[0];

#ifdef DEBUG_TLS
      printf("TLS [server][session_id_len: %u][cipher: %04X]\n", session_id_len, ja3.server.cipher[0]);
#endif

      offset += 2 + 1;

      if((offset + 1) < packet->payload_packet_len) /* +1 because we are goint to read 2 bytes */
	tot_extension_len = ntohs(*((u_int16_t*)&packet->payload[offset]));
      else
	tot_extension_len = 0;

#ifdef DEBUG_TLS
      printf("TLS [server][tot_extension_len: %u]\n", tot_extension_len);
#endif
      offset += 2;

      for(i=0; i<tot_extension_len; ) {
        u_int16_t extension_id;
        u_int32_t extension_len;

	if((offset+4) > packet->payload_packet_len) break;

	extension_id  = ntohs(*((u_int16_t*)&packet->payload[offset]));
	extension_len = ntohs(*((u_int16_t*)&packet->payload[offset+2]));
	if(offset+4+extension_len > packet->payload_packet_len) {
	  break;
	}

	if(ja3.server.num_tls_extension < MAX_NUM_JA3)
	  ja3.server.tls_extension[ja3.server.num_tls_extension++] = extension_id;

#ifdef DEBUG_TLS
	printf("TLS [server][extension_id: %u/0x%04X][len: %u]\n",
	       extension_id, extension_id, extension_len);
#endif
	checkExtensions(ndpi_struct, flow, is_dtls, extension_id, extension_len, offset + 4);

	if(extension_id == 43 /* supported versions */) {
	  if(extension_len >= 2) {
	    u_int16_t tls_version = ntohs(*((u_int16_t*)&packet->payload[offset+4]));

#ifdef DEBUG_TLS
	    printf("TLS [server] [TLS version: 0x%04X]\n", tls_version);
#endif

	    flow->protos.tls_quic.ssl_version = ja3.server.tls_supported_version = tls_version;
	  }
	} else if(extension_id == 16 /* application_layer_protocol_negotiation (ALPN) */ &&
	          offset + 6 < packet->payload_packet_len) {
	  u_int16_t s_offset = offset+4;
	  u_int16_t tot_alpn_len = ntohs(*((u_int16_t*)&packet->payload[s_offset]));
	  char alpn_str[256];
	  u_int16_t alpn_str_len = 0, i;

#ifdef DEBUG_TLS
	  printf("Server TLS [ALPN: block_len=%u/len=%u]\n", extension_len, tot_alpn_len);
#endif
	  s_offset += 2;
	  tot_alpn_len += s_offset;

	  if(tot_alpn_len > packet->payload_packet_len)
	    return 0;

	  while(s_offset < tot_alpn_len && s_offset < total_len) {
	    u_int8_t alpn_i, alpn_len = packet->payload[s_offset++];

	    if((s_offset + alpn_len) <= tot_alpn_len) {
#ifdef DEBUG_TLS
	      printf("Server TLS [ALPN: %u]\n", alpn_len);
#endif

	      if(((uint32_t)alpn_str_len+alpn_len+1) < (sizeof(alpn_str)-1)) {
	        if(alpn_str_len > 0) {
	          alpn_str[alpn_str_len] = ',';
	          alpn_str_len++;
	        }

	        for(alpn_i=0; alpn_i<alpn_len; alpn_i++) {
		    alpn_str[alpn_str_len+alpn_i] = packet->payload[s_offset+alpn_i];
		  }

	        s_offset += alpn_len, alpn_str_len += alpn_len;;
	      } else {
	        alpn_str[alpn_str_len] = '\0';
	        ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_UNCOMMON_ALPN, alpn_str);
	        break;
	      }
	    } else {
	      alpn_str[alpn_str_len] = '\0';
	      ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_UNCOMMON_ALPN, alpn_str);
	      break;
	    }
	  } /* while */

	  alpn_str[alpn_str_len] = '\0';

#ifdef DEBUG_TLS
	  printf("Server TLS [ALPN: %s][len: %u]\n", alpn_str, alpn_str_len);
#endif
	  if(ndpi_normalize_printable_string(alpn_str, alpn_str_len) == 0)
	    ndpi_set_risk(ndpi_struct, flow, NDPI_INVALID_CHARACTERS, alpn_str);

	  if(flow->protos.tls_quic.negotiated_alpn == NULL)
	    flow->protos.tls_quic.negotiated_alpn = ndpi_strdup(alpn_str);

	  /* Check ALPN only if not already checked (client-side) */
	  if(flow->protos.tls_quic.negotiated_alpn != NULL &&
	     flow->protos.tls_quic.advertised_alpns == NULL)
	    tlsCheckUncommonALPN(ndpi_struct, flow, flow->protos.tls_quic.negotiated_alpn);

	  alpn_str_len = ndpi_min(sizeof(ja3.server.alpn), (size_t)alpn_str_len);
	  memcpy(ja3.server.alpn, alpn_str, alpn_str_len);
	  if(alpn_str_len > 0)
	    ja3.server.alpn[alpn_str_len - 1] = '\0';

	  /* Replace , with - as in JA3 */
	  for(i=0; ja3.server.alpn[i] != '\0'; i++)
	    if(ja3.server.alpn[i] == ',') ja3.server.alpn[i] = '-';
	} else if(extension_id == 11 /* ec_point_formats groups */) {
	  u_int16_t s_offset = offset+4 + 1;

#ifdef DEBUG_TLS
	  printf("Server TLS [EllipticCurveFormat: len=%u]\n", extension_len);
#endif
	  if((s_offset+extension_len-1) <= total_len) {
	    for(i=0; i<extension_len-1 && s_offset+i<packet->payload_packet_len; i++) {
	      u_int8_t s_group = packet->payload[s_offset+i];

#ifdef DEBUG_TLS
	      printf("Server TLS [EllipticCurveFormat: %u]\n", s_group);
#endif

	      if(ja3.server.num_elliptic_curve_point_format < MAX_NUM_JA3)
		ja3.server.elliptic_curve_point_format[ja3.server.num_elliptic_curve_point_format++] = s_group;
	      else {
		invalid_ja3 = 1;
#ifdef DEBUG_TLS
		printf("Server TLS Invalid num elliptic %u\n", ja3.server.num_elliptic_curve_point_format);
#endif
	      }
	    }
	  } else {
	    invalid_ja3 = 1;
#ifdef DEBUG_TLS
	    printf("Server TLS Invalid len %u vs %u\n", s_offset+extension_len, total_len);
#endif
	  }
	}

	i += 4 + extension_len, offset += 4 + extension_len;
      } /* for */

      /* If the CH is not available and if "supported_versions" extension is not present in the SH
         (i.e. (D)TLS <= 1.2), use the version field present in the record layer */
      if(flow->protos.tls_quic.ssl_version == 0)
        flow->protos.tls_quic.ssl_version = tls_version;

      ja3_str_len = ndpi_snprintf(ja3_str, JA3_STR_LEN, "%u,", ja3.server.tls_handshake_version);

      for(i=0; (i<ja3.server.num_cipher) && (JA3_STR_LEN > ja3_str_len); i++) {
	rc = ndpi_snprintf(&ja3_str[ja3_str_len], JA3_STR_LEN-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.server.cipher[i]);

	if(rc <= 0) break; else ja3_str_len += rc;
      }

      if(JA3_STR_LEN > ja3_str_len) {
	rc = ndpi_snprintf(&ja3_str[ja3_str_len], JA3_STR_LEN-ja3_str_len, ",");
	if(rc > 0 && ja3_str_len + rc < JA3_STR_LEN) ja3_str_len += rc;
      }

      /* ********** */

      for(i=0; (i<ja3.server.num_tls_extension) && (JA3_STR_LEN > ja3_str_len); i++) {
	int rc = ndpi_snprintf(&ja3_str[ja3_str_len], JA3_STR_LEN-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.server.tls_extension[i]);

	if(rc <= 0) break; else ja3_str_len += rc;
      }

      if(ndpi_struct->enable_ja3_plus) {
	for(i=0; (i<ja3.server.num_elliptic_curve_point_format) && (JA3_STR_LEN > ja3_str_len); i++) {
	  rc = ndpi_snprintf(&ja3_str[ja3_str_len], JA3_STR_LEN-ja3_str_len, "%s%u",
			     (i > 0) ? "-" : "", ja3.server.elliptic_curve_point_format[i]);
	  if((rc > 0) && (ja3_str_len + rc < JA3_STR_LEN)) ja3_str_len += rc; else break;
	}

	if((ja3.server.alpn[0] != '\0') && (JA3_STR_LEN > ja3_str_len)) {
	  rc = ndpi_snprintf(&ja3_str[ja3_str_len], JA3_STR_LEN-ja3_str_len, ",%s", ja3.server.alpn);
	  if((rc > 0) && (ja3_str_len + rc < JA3_STR_LEN)) ja3_str_len += rc;
	}

#ifdef DEBUG_TLS
	printf("[JA3+] Server: %s \n", ja3_str);
#endif
      } else {
#ifdef DEBUG_TLS
	printf("[JA3] Server: %s \n", ja3_str);
#endif
      }

      ndpi_MD5Init(&ctx);
      ndpi_MD5Update(&ctx, (const unsigned char *)ja3_str, strlen(ja3_str));
      ndpi_MD5Final(md5_hash, &ctx);

      for(i=0, j=0; i<16; i++) {
	int rc = ndpi_snprintf(&flow->protos.tls_quic.ja3_server[j],
			       sizeof(flow->protos.tls_quic.ja3_server)-j, "%02x", md5_hash[i]);
	if(rc <= 0) break; else j += rc;
      }

#ifdef DEBUG_TLS
      printf("[JA3] Server: %s \n", flow->protos.tls_quic.ja3_server);
#endif
    } else if(handshake_type == 0x01 /* Client Hello */) {
      u_int16_t cipher_len, cipher_offset;
      u_int8_t cookie_len = 0;

      ja3.client.num_cipher = 0;
      ja3.client.num_tls_extension = 0;
      ja3.client.num_elliptic_curve = 0;
      ja3.client.num_elliptic_curve_point_format = 0;
      ja3.client.signature_algorithms[0] = '\0';
      ja3.client.supported_versions[0] = '\0';
      ja3.client.alpn[0] = '\0';

      flow->protos.tls_quic.ssl_version = ja3.client.tls_handshake_version = tls_version;
      if(flow->protos.tls_quic.ssl_version < 0x0303) /* < TLSv1.2 */ {
	char str[32], buf[32];
	u_int8_t unknown_tls_version;
	
	snprintf(str, sizeof(str), "%s", ndpi_ssl_version2str(buf, sizeof(buf),
							      flow->protos.tls_quic.ssl_version,
							      &unknown_tls_version));
	ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_OBSOLETE_VERSION, str);
      }
      
      if((session_id_len+base_offset+3) > packet->payload_packet_len)
	return(0); /* Not found */

      if(!is_dtls) {
	cipher_len = packet->payload[session_id_len+base_offset+2] + (packet->payload[session_id_len+base_offset+1] << 8);
	cipher_offset = base_offset + session_id_len + 3;
      } else {
	cookie_len = packet->payload[base_offset+session_id_len+1];
#ifdef DEBUG_TLS
	printf("[JA3] Client: DTLS cookie len %d\n", cookie_len);
#endif
	if((session_id_len+base_offset+cookie_len+4) > packet->payload_packet_len)
	  return(0); /* Not found */
	cipher_len = ntohs(*((u_int16_t*)&packet->payload[base_offset+session_id_len+cookie_len+2]));
	cipher_offset = base_offset + session_id_len + cookie_len + 4;
      }

#ifdef DEBUG_TLS
      printf("Client TLS [client cipher_len: %u][tls_version: 0x%04X]\n", cipher_len, tls_version);
#endif

      if((cipher_offset+cipher_len) <= total_len - 1) { /* -1 because variable "id" is a u_int16_t */
	u_int8_t safari_ciphers = 0, chrome_ciphers = 0, this_is_not_safari = 0, looks_like_safari_on_big_sur = 0;

	for(i=0; i<cipher_len;) {
	  u_int16_t *id = (u_int16_t*)&packet->payload[cipher_offset+i];
	  u_int16_t cipher_id = ntohs(*id);

	  if(cipher_offset+i+1 < packet->payload_packet_len &&
	     ((packet->payload[cipher_offset+i] != packet->payload[cipher_offset+i+1]) ||
	      ((packet->payload[cipher_offset+i] & 0xF) != 0xA)) /* Skip Grease */) {
	    /*
	      Skip GREASE [https://tools.ietf.org/id/draft-ietf-tls-grease-01.html]
	      https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967
	    */

#if defined(DEBUG_TLS) || defined(DEBUG_HEURISTIC)
	    printf("Client TLS [non-GREASE cipher suite: %u/0x%04X] [%d/%u]\n", cipher_id, cipher_id, i, cipher_len);
#endif

	    if(ja3.client.num_cipher < MAX_NUM_JA3)
	      ja3.client.cipher[ja3.client.num_cipher++] = cipher_id;
	    else {
	      invalid_ja3 = 1;
#ifdef DEBUG_TLS
	      printf("Client TLS Invalid cipher %u\n", ja3.client.num_cipher);
#endif
	    }

#if defined(DEBUG_TLS) || defined(DEBUG_HEURISTIC)
	    printf("Client TLS [cipher suite: %u/0x%04X] [%d/%u]\n", cipher_id, cipher_id, i, cipher_len);
#endif

	    switch(cipher_id) {
	    case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
	    case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
	      safari_ciphers++;
	      break;

	    case TLS_AES_128_GCM_SHA256:
	    case TLS_AES_256_GCM_SHA384:
	    case TLS_CHACHA20_POLY1305_SHA256:
	      chrome_ciphers++;
	      break;

	    case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
	    case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
	    case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
	    case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
	    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
	    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
	    case TLS_RSA_WITH_AES_128_CBC_SHA:
	    case TLS_RSA_WITH_AES_256_CBC_SHA:
	    case TLS_RSA_WITH_AES_128_GCM_SHA256:
	    case TLS_RSA_WITH_AES_256_GCM_SHA384:
	      safari_ciphers++, chrome_ciphers++;
	      break;

	    case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
	      looks_like_safari_on_big_sur = 1;
	      break;
	    }
	  } else {
#if defined(DEBUG_TLS) || defined(DEBUG_HEURISTIC)
	    printf("Client TLS [GREASE cipher suite: %u/0x%04X] [%d/%u]\n", cipher_id, cipher_id, i, cipher_len);
#endif

	    this_is_not_safari = 1; /* NOTE: BugSur and up have grease support */
	  }

	  i += 2;
	} /* for */

	/* NOTE:
	   we do not check for duplicates as with signatures because
	   this is time consuming and we want to avoid overhead whem possible
	*/
	if(this_is_not_safari)
	  flow->protos.tls_quic.browser_heuristics.is_safari_tls = 0;
	else if((safari_ciphers == 12) || (this_is_not_safari && looks_like_safari_on_big_sur))
	  flow->protos.tls_quic.browser_heuristics.is_safari_tls = 1;

	if(chrome_ciphers == 13)
	  flow->protos.tls_quic.browser_heuristics.is_chrome_tls = 1;

	/* Note that both Safari and Chrome can overlap */
#ifdef DEBUG_HEURISTIC
	printf("[CIPHERS] [is_chrome_tls: %u (%u)][is_safari_tls: %u (%u)][this_is_not_safari: %u]\n",
	       flow->protos.tls_quic.browser_heuristics.is_chrome_tls,
	       chrome_ciphers,
	       flow->protos.tls_quic.browser_heuristics.is_safari_tls,
	       safari_ciphers,
	       this_is_not_safari);
#endif
      } else {
	invalid_ja3 = 1;
#ifdef DEBUG_TLS
	printf("Client TLS Invalid len %u vs %u\n", (cipher_offset+cipher_len), total_len);
#endif
      }

      offset = base_offset + session_id_len + cookie_len + cipher_len + 2;
      offset += (!is_dtls) ? 1 : 2;

      if(offset < total_len) {
	u_int16_t compression_len;
	u_int16_t extensions_len;

	compression_len = packet->payload[offset];
	offset++;

#ifdef DEBUG_TLS
	printf("Client TLS [compression_len: %u]\n", compression_len);
#endif

	// offset += compression_len + 3;
	offset += compression_len;

	if(offset+1 < total_len) {
	  extensions_len = ntohs(*((u_int16_t*)&packet->payload[offset]));
	  offset += 2;

#ifdef DEBUG_TLS
	  printf("Client TLS [extensions_len: %u]\n", extensions_len);
#endif

	  if((extensions_len+offset) <= total_len) {
	    /* Move to the first extension
	       Type is u_int to avoid possible overflow on extension_len addition */
	    u_int extension_offset = 0;

	    while(extension_offset < extensions_len &&
		  offset+extension_offset+4 <= total_len) {
	      u_int16_t extension_id, extension_len, extn_off = offset+extension_offset;


	      extension_id = ntohs(*((u_int16_t*)&packet->payload[offset+extension_offset]));
	      extension_offset += 2;

	      extension_len = ntohs(*((u_int16_t*)&packet->payload[offset+extension_offset]));
	      extension_offset += 2;

#ifdef DEBUG_TLS
	      printf("Client TLS [extension_id: %u][extension_len: %u]\n", extension_id, extension_len);
#endif
	      checkExtensions(ndpi_struct, flow, is_dtls,
			      extension_id, extension_len, offset + extension_offset);

	      if(offset + 4 + extension_len > total_len) {
#ifdef DEBUG_TLS
	        printf("[TLS] extension length %u too long (%u, offset %u)\n",
	               extension_len, total_len, offset);
#endif
	        break;
	      }

	      if((extension_id == 0) || (packet->payload[extn_off] != packet->payload[extn_off+1]) ||
		 ((packet->payload[extn_off] & 0xF) != 0xA)) {
		/* Skip GREASE */

		if(ja3.client.num_tls_extension < MAX_NUM_JA3)
		  ja3.client.tls_extension[ja3.client.num_tls_extension++] = extension_id;
		else {
		  invalid_ja3 = 1;
#ifdef DEBUG_TLS
		  printf("Client TLS Invalid extensions %u\n", ja3.client.num_tls_extension);
#endif
		}
	      }

	      if(extension_id == 0 /* server name */) {
		u_int16_t len;

#ifdef DEBUG_TLS
		printf("[TLS] Extensions: found server name\n");
#endif
		if((offset+extension_offset+4) < packet->payload_packet_len) {
		  len = (packet->payload[offset+extension_offset+3] << 8) + packet->payload[offset+extension_offset+4];

		  if((offset+extension_offset+5+len) <= packet->payload_packet_len) {
		    char *sni = ndpi_hostname_sni_set(flow, &packet->payload[offset+extension_offset+5], len);
		    int sni_len = strlen(sni);
#ifdef DEBUG_TLS
		    printf("[TLS] SNI: [%s]\n", sni);
#endif
		    if(ndpi_is_valid_hostname(sni, sni_len) == 0) {
		      ndpi_set_risk(ndpi_struct, flow, NDPI_INVALID_CHARACTERS, sni);
		      
		      /* This looks like an attack */
		      ndpi_set_risk(ndpi_struct, flow, NDPI_POSSIBLE_EXPLOIT, NULL);
		    }
		    
		    if(!is_quic) {
		      if(ndpi_match_hostname_protocol(ndpi_struct, flow, __get_master(ndpi_struct, flow), sni, sni_len))
		        flow->protos.tls_quic.subprotocol_detected = 1;
		    } else {
		      if(ndpi_match_hostname_protocol(ndpi_struct, flow, NDPI_PROTOCOL_QUIC, sni, sni_len))
		        flow->protos.tls_quic.subprotocol_detected = 1;
		    }

		    if(flow->protos.tls_quic.subprotocol_detected == 0 &&
		       check_sni_is_numeric_ip(sni) == 1) {
		      ndpi_set_risk(ndpi_struct, flow, NDPI_NUMERIC_IP_HOST, sni);
		    }

		    if(ndpi_check_dga_name(ndpi_struct, flow,
					   sni, 1, 0)) {
#ifdef DEBUG_TLS
		      printf("[TLS] SNI: (DGA) [%s]\n", sni);
#endif

		      if((sni_len >= 4)
		         /* Check if it ends in .com or .net */
		         && ((strcmp(&sni[sni_len-4], ".com") == 0) || (strcmp(&sni[sni_len-4], ".net") == 0))
		         && (strncmp(sni, "www.", 4) == 0)) /* Not starting with www.... */
		        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TOR, __get_master(ndpi_struct, flow), NDPI_CONFIDENCE_DPI);
		    } else {
#ifdef DEBUG_TLS
		      printf("[TLS] SNI: (NO DGA) [%s]\n", sni);
#endif
		    }
		  } else {
#ifdef DEBUG_TLS
		    printf("[TLS] Extensions server len too short: %u vs %u\n",
			   offset+extension_offset+5+len,
			   packet->payload_packet_len);
#endif
		  }
		}
	      } else if(extension_id == 10 /* supported groups */) {
		u_int16_t s_offset = offset+extension_offset + 2;

#ifdef DEBUG_TLS
		printf("Client TLS [EllipticCurveGroups: len=%u]\n", extension_len);
#endif

		if((s_offset+extension_len-2) <= total_len) {
		  for(i=0; i<(u_int32_t)extension_len-2 && s_offset + i + 1 < total_len; i += 2) {
		    u_int16_t s_group = ntohs(*((u_int16_t*)&packet->payload[s_offset+i]));

#ifdef DEBUG_TLS
		    printf("Client TLS [EllipticCurve: %u/0x%04X]\n", s_group, s_group);
#endif
		    if((s_group == 0) || (packet->payload[s_offset+i] != packet->payload[s_offset+i+1])
		       || ((packet->payload[s_offset+i] & 0xF) != 0xA)) {
		      /* Skip GREASE */
		      if(ja3.client.num_elliptic_curve < MAX_NUM_JA3)
			ja3.client.elliptic_curve[ja3.client.num_elliptic_curve++] = s_group;
		      else {
			invalid_ja3 = 1;
#ifdef DEBUG_TLS
			printf("Client TLS Invalid num elliptic %u\n", ja3.client.num_elliptic_curve);
#endif
		      }
		    }
		  }
		} else {
		  invalid_ja3 = 1;
#ifdef DEBUG_TLS
		  printf("Client TLS Invalid len %u vs %u\n", (s_offset+extension_len-1), total_len);
#endif
		}
	      } else if(extension_id == 11 /* ec_point_formats groups */) {
		u_int16_t s_offset = offset+extension_offset + 1;

#ifdef DEBUG_TLS
		printf("Client TLS [EllipticCurveFormat: len=%u]\n", extension_len);
#endif
		if((s_offset+extension_len-1) <= total_len) {
		  for(i=0; i<(u_int32_t)extension_len-1 && s_offset+i < total_len; i++) {
		    u_int8_t s_group = packet->payload[s_offset+i];

#ifdef DEBUG_TLS
		    printf("Client TLS [EllipticCurveFormat: %u]\n", s_group);
#endif

		    if(ja3.client.num_elliptic_curve_point_format < MAX_NUM_JA3)
		      ja3.client.elliptic_curve_point_format[ja3.client.num_elliptic_curve_point_format++] = s_group;
		    else {
		      invalid_ja3 = 1;
#ifdef DEBUG_TLS
		      printf("Client TLS Invalid num elliptic %u\n", ja3.client.num_elliptic_curve_point_format);
#endif
		    }
		  }
		} else {
		  invalid_ja3 = 1;
#ifdef DEBUG_TLS
		  printf("Client TLS Invalid len %u vs %u\n", s_offset+extension_len, total_len);
#endif
		}
	      } else if(extension_id == 13 /* signature algorithms */ &&
	                offset+extension_offset+1 < total_len) {
		int s_offset = offset+extension_offset, safari_signature_algorithms = 0, chrome_signature_algorithms = 0,
		  duplicate_found = 0, last_signature = 0;
		u_int16_t tot_signature_algorithms_len = ntohs(*((u_int16_t*)&packet->payload[s_offset]));

#ifdef DEBUG_TLS
		printf("Client TLS [SIGNATURE_ALGORITHMS: block_len=%u/len=%u]\n", extension_len, tot_signature_algorithms_len);
#endif

		s_offset += 2;
		tot_signature_algorithms_len = ndpi_min((sizeof(ja3.client.signature_algorithms) / 2) - 1, tot_signature_algorithms_len);

#ifdef TLS_HANDLE_SIGNATURE_ALGORITMS
		size_t size = ndpi_min(tot_signature_algorithms_len / 2, MAX_NUM_TLS_SIGNATURE_ALGORITHMS);

		if (s_offset + 2 * size <= packet->payload_packet_len) {
			flow->protos.tls_quic.num_tls_signature_algorithms = size;
			memcpy(flow->protos.tls_quic.client_signature_algorithms,
			       &packet->payload[s_offset], 2 /* 16 bit */ * size);
		}
#endif

		for(i=0; i<tot_signature_algorithms_len && s_offset+i<total_len; i++) {
		  int rc = ndpi_snprintf(&ja3.client.signature_algorithms[i*2], sizeof(ja3.client.signature_algorithms)-i*2, "%02X", packet->payload[s_offset+i]);

		  if(rc < 0) break;
		}

		for(i=0; i<tot_signature_algorithms_len && s_offset + (int)i + 2 < packet->payload_packet_len; i+=2) {
		  u_int16_t signature_algo = (u_int16_t)ntohs(*((u_int16_t*)&packet->payload[s_offset+i]));

		  if(last_signature == signature_algo) {
		    /* Consecutive duplication */
		    duplicate_found = 1;
		    continue;
		  } else {
		    /* Check for other duplications */
		    u_int all_ok = 1;

		    for(j=0; j<tot_signature_algorithms_len; j+=2) {
		      if(j != i && s_offset + (int)j + 2 < packet->payload_packet_len) {
			u_int16_t j_signature_algo = (u_int16_t)ntohs(*((u_int16_t*)&packet->payload[s_offset+j]));

			if((signature_algo == j_signature_algo)
			   && (i < j) /* Don't skip both of them */) {
#ifdef DEBUG_HEURISTIC
			  printf("[SIGNATURE] [TLS Signature Algorithm] Skipping duplicate 0x%04X\n", signature_algo);
#endif

			  duplicate_found = 1, all_ok = 0;
			  break;
			}
		      }
		    }

		    if(!all_ok)
		      continue;
		  }

		  last_signature = signature_algo;

#ifdef DEBUG_HEURISTIC
		  printf("[SIGNATURE] [TLS Signature Algorithm] 0x%04X\n", signature_algo);
#endif
		  switch(signature_algo) {
		  case ECDSA_SECP521R1_SHA512:
		    flow->protos.tls_quic.browser_heuristics.is_firefox_tls = 1;
		    break;

		  case ECDSA_SECP256R1_SHA256:
		  case ECDSA_SECP384R1_SHA384:
		  case RSA_PKCS1_SHA256:
		  case RSA_PKCS1_SHA384:
		  case RSA_PKCS1_SHA512:
		  case RSA_PSS_RSAE_SHA256:
		  case RSA_PSS_RSAE_SHA384:
		  case RSA_PSS_RSAE_SHA512:
		    chrome_signature_algorithms++, safari_signature_algorithms++;
#ifdef DEBUG_HEURISTIC
		    printf("[SIGNATURE] [Chrome/Safari] Found 0x%04X [chrome: %u][safari: %u]\n",
			   signature_algo, chrome_signature_algorithms, safari_signature_algorithms);
#endif

		    break;
		  }
		}

#ifdef DEBUG_HEURISTIC
		printf("[SIGNATURE] [safari_signature_algorithms: %u][chrome_signature_algorithms: %u]\n",
		       safari_signature_algorithms, chrome_signature_algorithms);
#endif

		if(flow->protos.tls_quic.browser_heuristics.is_firefox_tls)
		  flow->protos.tls_quic.browser_heuristics.is_safari_tls = 0,
		    flow->protos.tls_quic.browser_heuristics.is_chrome_tls = 0;

		if(safari_signature_algorithms != 8)
		  flow->protos.tls_quic.browser_heuristics.is_safari_tls = 0;

		if((chrome_signature_algorithms != 8) || duplicate_found)
		  flow->protos.tls_quic.browser_heuristics.is_chrome_tls = 0;

		/* Avoid Chrome and Safari overlaps, thing that cannot happen with Firefox */
		if(flow->protos.tls_quic.browser_heuristics.is_safari_tls)
		  flow->protos.tls_quic.browser_heuristics.is_chrome_tls = 0;

		if((flow->protos.tls_quic.browser_heuristics.is_chrome_tls == 0)
		   && duplicate_found)
		  flow->protos.tls_quic.browser_heuristics.is_safari_tls = 1; /* Safari */

#ifdef DEBUG_HEURISTIC
		printf("[SIGNATURE] [is_firefox_tls: %u][is_chrome_tls: %u][is_safari_tls: %u][duplicate_found: %u]\n",
		       flow->protos.tls_quic.browser_heuristics.is_firefox_tls,
		       flow->protos.tls_quic.browser_heuristics.is_chrome_tls,
		       flow->protos.tls_quic.browser_heuristics.is_safari_tls,
		       duplicate_found);
#endif

		if(i > 0 && i >= tot_signature_algorithms_len) {
		  ja3.client.signature_algorithms[i*2 - 1] = '\0';
		} else {
		  ja3.client.signature_algorithms[i*2] = '\0';
		}

#ifdef DEBUG_TLS
		printf("Client TLS [SIGNATURE_ALGORITHMS: %s]\n", ja3.client.signature_algorithms);
#endif
	      } else if(extension_id == 16 /* application_layer_protocol_negotiation */ &&
	                offset+extension_offset+1 < total_len) {
		u_int16_t s_offset = offset+extension_offset;
		u_int16_t tot_alpn_len = ntohs(*((u_int16_t*)&packet->payload[s_offset]));
		char alpn_str[256];
		u_int16_t alpn_str_len = 0, i;

#ifdef DEBUG_TLS
		printf("Client TLS [ALPN: block_len=%u/len=%u]\n", extension_len, tot_alpn_len);
#endif
		s_offset += 2;
		tot_alpn_len += s_offset;

		while(s_offset < tot_alpn_len && s_offset < total_len) {
		  u_int8_t alpn_i, alpn_len = packet->payload[s_offset++];

		  if((s_offset + alpn_len) <= tot_alpn_len &&
		     (s_offset + alpn_len) <= total_len) {
#ifdef DEBUG_TLS
		    printf("Client TLS [ALPN: %u]\n", alpn_len);
#endif

		    if(((uint32_t)alpn_str_len+alpn_len+1) < (sizeof(alpn_str)-1)) {
		      if(alpn_str_len > 0) {
			alpn_str[alpn_str_len] = ',';
			alpn_str_len++;
		      }

		      for(alpn_i=0; alpn_i<alpn_len; alpn_i++)
			alpn_str[alpn_str_len+alpn_i] = packet->payload[s_offset+alpn_i];

		      s_offset += alpn_len, alpn_str_len += alpn_len;;
		    } else
		      break;
		  } else
		    break;
		} /* while */

		alpn_str[alpn_str_len] = '\0';

#ifdef DEBUG_TLS
		printf("Client TLS [ALPN: %s][len: %u]\n", alpn_str, alpn_str_len);
#endif
		if(flow->protos.tls_quic.advertised_alpns == NULL) {
		  flow->protos.tls_quic.advertised_alpns = ndpi_strdup(alpn_str);
		  if(flow->protos.tls_quic.advertised_alpns) {
		    tlsCheckUncommonALPN(ndpi_struct, flow, flow->protos.tls_quic.advertised_alpns);

		    /* Without SNI matching we can try to sub-classify the flow via ALPN.
		       Note that this happens only on very rare cases, not the common ones
		       ("h2", "http/1.1", ...). Usefull for asymmetric traffic */
		    if(!flow->protos.tls_quic.subprotocol_detected)
	              tls_subclassify_by_alpn(ndpi_struct, flow);
		  }
		}

                alpn_str_len = ndpi_min(sizeof(ja3.client.alpn), (size_t)alpn_str_len);
		memcpy(ja3.client.alpn, alpn_str, alpn_str_len);
		if(alpn_str_len > 0)
		  ja3.client.alpn[alpn_str_len - 1] = '\0';

		/* Replace , with - as in JA3 */
		for(i=0; ja3.client.alpn[i] != '\0'; i++)
		  if(ja3.client.alpn[i] == ',') ja3.client.alpn[i] = '-';

	      } else if(extension_id == 43 /* supported versions */ &&
	                offset+extension_offset < total_len) {
		u_int16_t s_offset = offset+extension_offset;
		u_int8_t version_len = packet->payload[s_offset];
		char version_str[256];
		char buf_ver_tmp[16];
		size_t version_str_len = 0;
		version_str[0] = 0;
#ifdef DEBUG_TLS
		printf("Client TLS [TLS version len: %u]\n", version_len);
#endif

		if(version_len == (extension_len-1)) {
		  u_int8_t j;
		  u_int16_t supported_versions_offset = 0;

		  s_offset++;

		  // careful not to overflow and loop forever with u_int8_t
		  for(j=0; j+1<version_len && s_offset + j + 1 < packet->payload_packet_len; j += 2) {
		    u_int16_t tls_version = ntohs(*((u_int16_t*)&packet->payload[s_offset+j]));
		    u_int8_t unknown_tls_version;

#ifdef DEBUG_TLS
		    printf("Client TLS [TLS version: %s/0x%04X]\n",
			   ndpi_ssl_version2str(buf_ver_tmp, sizeof(buf_ver_tmp), tls_version, &unknown_tls_version), tls_version);
#endif

		    if((version_str_len+8) < sizeof(version_str)) {
		      int rc = ndpi_snprintf(&version_str[version_str_len],
					     sizeof(version_str) - version_str_len, "%s%s",
					     (version_str_len > 0) ? "," : "",
					     ndpi_ssl_version2str(buf_ver_tmp, sizeof(buf_ver_tmp), tls_version, &unknown_tls_version));
		      if(rc <= 0)
			break;
		      else
			version_str_len += rc;

		      rc = ndpi_snprintf(&ja3.client.supported_versions[supported_versions_offset],
					 sizeof(ja3.client.supported_versions)-supported_versions_offset,
					 "%s%04X", (j > 0) ? "-" : "", tls_version);

		      if(rc > 0)
			supported_versions_offset += rc;
		    }
		  }

#ifdef DEBUG_TLS
		  printf("Client TLS [SUPPORTED_VERSIONS: %s]\n", ja3.client.supported_versions);
#endif

		  if(flow->protos.tls_quic.tls_supported_versions == NULL)
		    flow->protos.tls_quic.tls_supported_versions = ndpi_strdup(version_str);
		}
	      } else if(extension_id == 65486 /* encrypted server name */ &&
	                offset+extension_offset+1 < total_len) {
		/*
		  - https://tools.ietf.org/html/draft-ietf-tls-esni-06
		  - https://blog.cloudflare.com/encrypted-sni/
		*/
		int e_offset = offset+extension_offset;
		int e_sni_len;
		int initial_offset = e_offset;
		u_int16_t cipher_suite = ntohs(*((u_int16_t*)&packet->payload[e_offset]));

		flow->protos.tls_quic.encrypted_sni.cipher_suite = cipher_suite;

		e_offset += 2; /* Cipher suite len */

		/* Key Share Entry */
		e_offset += 2; /* Group */
		if(e_offset + 2 < packet->payload_packet_len) {
		  e_offset += ntohs(*((u_int16_t*)&packet->payload[e_offset])) + 2; /* Lenght */

		  if((e_offset+4) < packet->payload_packet_len) {
		    /* Record Digest */
		    e_offset +=  ntohs(*((u_int16_t*)&packet->payload[e_offset])) + 2; /* Lenght */

		    if((e_offset+4) < packet->payload_packet_len) {
		      e_sni_len = ntohs(*((u_int16_t*)&packet->payload[e_offset]));
		      e_offset += 2;

		      if((e_offset+e_sni_len-(int)extension_len-initial_offset) >= 0 &&
			 e_offset+e_sni_len < packet->payload_packet_len) {
#ifdef DEBUG_ENCRYPTED_SNI
			printf("Client TLS [Encrypted Server Name len: %u]\n", e_sni_len);
#endif

			if(flow->protos.tls_quic.encrypted_sni.esni == NULL) {
			  flow->protos.tls_quic.encrypted_sni.esni = (char*)ndpi_malloc(e_sni_len*2+1);

			  if(flow->protos.tls_quic.encrypted_sni.esni) {
			    u_int16_t off;
			    int i;

			    for(i=e_offset, off=0; i<(e_offset+e_sni_len); i++) {
			      int rc = sprintf(&flow->protos.tls_quic.encrypted_sni.esni[off], "%02X", packet->payload[i] & 0XFF);

			      if(rc <= 0) {
				break;
			      } else
				off += rc;
			    }
			    flow->protos.tls_quic.encrypted_sni.esni[off] = '\0';
			  }
			}
		      }
		    }
		  }
		}
	      } else if(extension_id == 65037 /* ECH: latest drafts */) {
#ifdef DEBUG_TLS
		printf("Client TLS: ECH version 0x%x\n", extension_id);
#endif
		/* Beginning with draft-08, the version is the same as the code point
		   for the "encrypted_client_hello" extension. */
		flow->protos.tls_quic.encrypted_ch.version = extension_id;
	      } else if(extension_id == 65445 || /* QUIC transport parameters (drafts version) */
		        extension_id == 57) { /* QUIC transport parameters (final version) */
		u_int16_t s_offset = offset+extension_offset;
		uint16_t final_offset;
		int using_var_int = is_version_with_var_int_transport_params(quic_version);

		if(!using_var_int) {
		  if(s_offset+1 >= total_len) {
		    final_offset = 0; /* Force skipping extension */
		  } else {
		    u_int16_t seq_len = ntohs(*((u_int16_t*)&packet->payload[s_offset]));
		    s_offset += 2;
	            final_offset = ndpi_min(total_len, s_offset + seq_len);
		  }
		} else {
	          final_offset = ndpi_min(total_len, s_offset + extension_len);
		}

		while(s_offset < final_offset) {
		  u_int64_t param_type, param_len;

                  if(!using_var_int) {
		    if(s_offset+3 >= final_offset)
		      break;
		    param_type = ntohs(*((u_int16_t*)&packet->payload[s_offset]));
		    param_len = ntohs(*((u_int16_t*)&packet->payload[s_offset + 2]));
		    s_offset += 4;
		  } else {
		    if(s_offset >= final_offset ||
		       (s_offset + quic_len_buffer_still_required(packet->payload[s_offset])) >= final_offset)
		      break;
		    s_offset += quic_len(&packet->payload[s_offset], &param_type);

		    if(s_offset >= final_offset ||
		       (s_offset + quic_len_buffer_still_required(packet->payload[s_offset])) >= final_offset)
		      break;
		    s_offset += quic_len(&packet->payload[s_offset], &param_len);
		  }

#ifdef DEBUG_TLS
		  printf("Client TLS [QUIC TP: Param 0x%x Len %d]\n", (int)param_type, (int)param_len);
#endif
		  if(s_offset+param_len > final_offset)
		    break;

		  if(param_type==0x3129) {
#ifdef DEBUG_TLS
		    printf("UA [%.*s]\n", (int)param_len, &packet->payload[s_offset]);
#endif
		    http_process_user_agent(ndpi_struct, flow,
					    &packet->payload[s_offset], param_len);
		    break;
		  }
		  s_offset += param_len;
		}
	      }

	      extension_offset += extension_len; /* Move to the next extension */

#ifdef DEBUG_TLS
	      printf("Client TLS [extension_offset/len: %u/%u]\n", extension_offset, extension_len);
#endif
	    } /* while */

	    if(!invalid_ja3) {
	      int rc;

	    compute_ja3c:
	      ja3_str_len = ndpi_snprintf(ja3_str, JA3_STR_LEN, "%u,", ja3.client.tls_handshake_version);

	      for(i=0; i<ja3.client.num_cipher; i++) {
		rc = ndpi_snprintf(&ja3_str[ja3_str_len], JA3_STR_LEN-ja3_str_len, "%s%u",
				   (i > 0) ? "-" : "", ja3.client.cipher[i]);
		if((rc > 0) && (ja3_str_len + rc < JA3_STR_LEN)) ja3_str_len += rc; else break;
	      }

	      rc = ndpi_snprintf(&ja3_str[ja3_str_len], JA3_STR_LEN-ja3_str_len, ",");
	      if((rc > 0) && (ja3_str_len + rc < JA3_STR_LEN)) ja3_str_len += rc;

	      /* ********** */

	      for(i=0; i<ja3.client.num_tls_extension; i++) {
		rc = ndpi_snprintf(&ja3_str[ja3_str_len], JA3_STR_LEN-ja3_str_len, "%s%u",
				   (i > 0) ? "-" : "", ja3.client.tls_extension[i]);
		if((rc > 0) && (ja3_str_len + rc < JA3_STR_LEN)) ja3_str_len += rc; else break;
	      }

	      rc = ndpi_snprintf(&ja3_str[ja3_str_len], JA3_STR_LEN-ja3_str_len, ",");
	      if((rc > 0) && (ja3_str_len + rc < JA3_STR_LEN)) ja3_str_len += rc;

	      /* ********** */

	      for(i=0; i<ja3.client.num_elliptic_curve; i++) {
		rc = ndpi_snprintf(&ja3_str[ja3_str_len], JA3_STR_LEN-ja3_str_len, "%s%u",
				   (i > 0) ? "-" : "", ja3.client.elliptic_curve[i]);
		if((rc > 0) && (ja3_str_len + rc < JA3_STR_LEN)) ja3_str_len += rc; else break;
	      }

	      rc = ndpi_snprintf(&ja3_str[ja3_str_len], JA3_STR_LEN-ja3_str_len, ",");
	      if((rc > 0) && (ja3_str_len + rc < JA3_STR_LEN)) ja3_str_len += rc;

	      for(i=0; i<ja3.client.num_elliptic_curve_point_format; i++) {
		rc = ndpi_snprintf(&ja3_str[ja3_str_len], JA3_STR_LEN-ja3_str_len, "%s%u",
				   (i > 0) ? "-" : "", ja3.client.elliptic_curve_point_format[i]);
		if((rc > 0) && (ja3_str_len + rc < JA3_STR_LEN)) ja3_str_len += rc; else break;
	      }

	      if(ndpi_struct->enable_ja3_plus) {
		rc = ndpi_snprintf(&ja3_str[ja3_str_len], JA3_STR_LEN-ja3_str_len,
				   ",%s,%s,%s", ja3.client.signature_algorithms, ja3.client.supported_versions, ja3.client.alpn);
		if((rc > 0) && (ja3_str_len + rc < JA3_STR_LEN)) ja3_str_len += rc;
	      }

#ifdef DEBUG_JA3C
	      printf("[JA3+] Client: %s \n", ja3_str);
#endif

	      ndpi_MD5Init(&ctx);
	      ndpi_MD5Update(&ctx, (const unsigned char *)ja3_str, strlen(ja3_str));
	      ndpi_MD5Final(md5_hash, &ctx);

	      for(i=0, j=0; i<16; i++) {
		rc = ndpi_snprintf(&flow->protos.tls_quic.ja3_client[j],
				   sizeof(flow->protos.tls_quic.ja3_client)-j, "%02x",
				   md5_hash[i]);
		if(rc > 0) j += rc; else break;
	      }

#ifdef DEBUG_JA3C
	      printf("[JA3] Client: %s \n", flow->protos.tls_quic.ja3_client);
#endif

	      if(ndpi_struct->malicious_ja3_hashmap != NULL) {
	        u_int16_t rc1 = ndpi_hash_find_entry(ndpi_struct->malicious_ja3_hashmap,
	                                             flow->protos.tls_quic.ja3_client,
	                                             NDPI_ARRAY_LENGTH(flow->protos.tls_quic.ja3_client) - 1,
	                                             NULL);

	      if(rc1 == 0)
	        ndpi_set_risk(ndpi_struct, flow, NDPI_MALICIOUS_JA3, flow->protos.tls_quic.ja3_client);
	      }
	    }

	    /* Before returning to the caller we need to make a final check */
	    if((flow->protos.tls_quic.ssl_version >= 0x0303) /* >= TLSv1.2 */
	       && (flow->protos.tls_quic.advertised_alpns == NULL) /* No ALPN */) {
	      ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_NOT_CARRYING_HTTPS, "No ALPN");
	    }

	    /* Suspicious Domain Fronting:
	       https://github.com/SixGenInc/Noctilucent/blob/master/docs/ */
	    if(flow->protos.tls_quic.encrypted_sni.esni &&
	       flow->host_server_name[0] != '\0') {
	      ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_SUSPICIOUS_ESNI_USAGE, "Found ESNI w/o SNI");
	    }

	    /* Add check for missing SNI */
	    if(flow->host_server_name[0] == '\0'
	       && (flow->protos.tls_quic.ssl_version >= 0x0302) /* TLSv1.1 */
	       && (flow->protos.tls_quic.encrypted_sni.esni == NULL) /* No ESNI */
	       ) {
	      /* This is a bit suspicious */
	      ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_MISSING_SNI, NULL);
	      
	      if(flow->protos.tls_quic.advertised_alpns != NULL) {
		char buf[256], *tmp, *item;

		snprintf(buf, sizeof(buf), "%s", flow->protos.tls_quic.advertised_alpns);

		item = strtok_r(buf, ",", &tmp);
		
		while(item != NULL) {
		  if(item[0] == 'h') {
		    /* Example 'h2' */
		    ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_ALPN_SNI_MISMATCH, NULL);
		    break;
		  } else
		    item = strtok_r(NULL, ",", &tmp);
		}
	      }
	    }
	    
	    return(2 /* Client Certificate */);
	  } else {
#ifdef DEBUG_TLS
	    printf("[TLS] Client: too short [%u vs %u]\n",
		   (extensions_len+offset), total_len);
#endif
	  }
	} else if(offset == total_len) {
	  /* TLS does not have extensions etc */
	  goto compute_ja3c;
	}
      } else {
#ifdef DEBUG_TLS
	printf("[JA3] Client: invalid length detected\n");
#endif
      }
    }
  }

  return(0); /* Not found */
}

/* **************************************** */

static void ndpi_search_tls_wrapper(struct ndpi_detection_module_struct *ndpi_struct,
				    struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

#ifdef DEBUG_TLS
  printf("==>> %s() %u [len: %u][version: %u]\n",
	 __FUNCTION__,
	 flow->guessed_protocol_id_by_ip,
	 packet->payload_packet_len,
	 flow->protos.tls_quic.ssl_version);
#endif

  if(packet->udp != NULL)
    ndpi_search_tls_udp(ndpi_struct, flow);
  else
    ndpi_search_tls_tcp(ndpi_struct, flow);
}

/* **************************************** */

void init_tls_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			u_int32_t *id) {
  ndpi_set_bitmask_protocol_detection("TLS", ndpi_struct, *id,
				      NDPI_PROTOCOL_TLS,
				      ndpi_search_tls_wrapper,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;

  /* *************************************************** */

  ndpi_set_bitmask_protocol_detection("DTLS", ndpi_struct, *id,
				      NDPI_PROTOCOL_DTLS,
				      ndpi_search_tls_wrapper,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
