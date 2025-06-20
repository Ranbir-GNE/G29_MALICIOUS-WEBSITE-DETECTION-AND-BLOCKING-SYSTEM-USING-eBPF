/*
 * ndpiReader.c
 *
 * Copyright (C) 2011-23 - ntop.org
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

#include "ndpi_config.h"

#ifdef __linux__
#include <sched.h>
#endif

#include "ndpi_api.h"
#include "../src/lib/third_party/include/uthash.h"
#include "../src/lib/third_party/include/ahocorasick.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <float.h> /* FLT_EPSILON */
#ifdef WIN32
#include <winsock2.h> /* winsock.h is included automatically */
#include <windows.h>
#include <ws2tcpip.h>
#include <process.h>
#include <io.h>
#else
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/mman.h>
#endif
#include <string.h>
#include <stdarg.h>
#include <search.h>
#include <pcap.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <assert.h>
#include <math.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifndef _MSC_BUILD
#include <libgen.h>
#endif
#include <errno.h>

#include "reader_util.h"

#define ntohl64(x) ( ( (uint64_t)(ntohl( (uint32_t)((x << 32) >> 32) )) << 32) | ntohl( ((uint32_t)(x >> 32)) ) )
#define htonl64(x) ntohl64(x)

#define HEURISTICS_CODE 1

/** Client parameters **/

static char *_pcap_file[MAX_NUM_READER_THREADS]; /**< Ingress pcap file/interfaces */
#ifndef USE_DPDK
static FILE *playlist_fp[MAX_NUM_READER_THREADS] = { NULL }; /**< Ingress playlist */
#endif
static FILE *results_file           = NULL;
static char *results_path           = NULL;
static char * bpfFilter             = NULL; /**< bpf filter  */
static char *_protoFilePath         = NULL; /**< Protocol file path */
static char *_customCategoryFilePath= NULL; /**< Custom categories file path  */
static char *_maliciousJA3Path      = NULL; /**< Malicious JA3 signatures */
static char *_maliciousSHA1Path     = NULL; /**< Malicious SSL certificate SHA1 fingerprints */
static char *_riskyDomainFilePath   = NULL; /**< Risky domain files */
static char *_categoriesDirPath     = NULL; /**< Directory containing domain files */
static u_int8_t live_capture = 0;
static u_int8_t undetected_flows_deleted = 0;
static FILE *csv_fp                 = NULL; /**< for CSV export */
static FILE *serialization_fp       = NULL; /**< for TLV,CSV,JSON export */
static ndpi_serialization_format serialization_format = ndpi_serialization_format_unknown;
static char* domain_to_check = NULL;
static char* ip_port_to_check = NULL;
static u_int8_t ignore_vlanid = 0;
/** User preferences **/
u_int8_t enable_protocol_guess = 1, enable_payload_analyzer = 0, num_bin_clusters = 0, extcap_exit = 0;
u_int8_t verbose = 0, enable_flow_stats = 0;
int stun_monitoring_pkts_to_process = -1; /* Default */
int stun_monitoring_flags = -1; /* Default */
int nDPI_LogLevel = 0;
char *_debug_protocols = NULL;
char *_disabled_protocols = NULL;
int aggressiveness[NDPI_MAX_SUPPORTED_PROTOCOLS];
static u_int8_t stats_flag = 0;
ndpi_init_prefs init_prefs = ndpi_no_prefs | ndpi_enable_tcp_ack_payload_heuristic;
u_int8_t human_readeable_string_len = 5;
u_int8_t max_num_udp_dissected_pkts = 24 /* 8 is enough for most protocols, Signal and SnapchatCall require more */, max_num_tcp_dissected_pkts = 80 /* due to telnet */;
static u_int32_t pcap_analysis_duration = (u_int32_t)-1;
static u_int32_t risk_stats[NDPI_MAX_RISK] = { 0 }, risks_found = 0, flows_with_risks = 0;
static struct ndpi_stats cumulative_stats;
static u_int16_t decode_tunnels = 0;
static u_int16_t num_loops = 1;
static u_int8_t shutdown_app = 0, quiet_mode = 0;
static u_int8_t num_threads = 1;
static struct timeval startup_time, begin, end;
#ifdef __linux__
static int core_affinity[MAX_NUM_READER_THREADS];
#endif
static struct timeval pcap_start = { 0, 0}, pcap_end = { 0, 0 };
#ifndef USE_DPDK
static struct bpf_program bpf_code;
#endif
static struct bpf_program *bpf_cfilter = NULL;
/** Detection parameters **/
static time_t capture_for = 0;
static time_t capture_until = 0;
static u_int32_t num_flows;
static struct ndpi_detection_module_struct *ndpi_info_mod = NULL;

extern u_int8_t enable_doh_dot_detection;
extern u_int32_t max_num_packets_per_flow, max_packet_payload_dissection, max_num_reported_top_payloads;
extern u_int16_t min_pattern_len, max_pattern_len;
u_int8_t dump_internal_stats;

struct ndpi_bin malloc_bins;
int enable_malloc_bins = 0;
int max_malloc_bins = 14;
int malloc_size_stats = 0;

static int lru_cache_sizes[NDPI_LRUCACHE_MAX];
static int lru_cache_ttls[NDPI_LRUCACHE_MAX];

struct flow_info {
  struct ndpi_flow_info *flow;
  u_int16_t thread_id;
};

static struct flow_info *all_flows;

struct info_pair {
  u_int32_t addr;
  u_int8_t version; /* IP version */
  char proto[16]; /*app level protocol*/
  int count;
};

typedef struct node_a {
  u_int32_t addr;
  u_int8_t version; /* IP version */
  char proto[16]; /*app level protocol*/
  int count;
  struct node_a *left, *right;
}addr_node;

// struct to add more statitcs in function printFlowStats
typedef struct hash_stats{
  char* domain_name;
  int occurency;       /* how many time domain name occury in the flow */
  UT_hash_handle hh;   /* hashtable to collect the stats */
}hash_stats;


struct port_stats {
  u_int32_t port; /* we'll use this field as the key */
  u_int32_t num_pkts, num_bytes;
  u_int32_t num_flows;
  u_int32_t num_addr; /*number of distinct IP addresses */
  u_int32_t cumulative_addr; /*cumulative some of IP addresses */
  addr_node *addr_tree; /* tree of distinct IP addresses */
  struct info_pair top_ip_addrs[MAX_NUM_IP_ADDRESS];
  u_int8_t hasTopHost; /* as boolean flag */
  u_int32_t top_host;  /* host that is contributed to > 95% of traffic */
  u_int8_t version;    /* top host's ip version */
  char proto[16];      /* application level protocol of top host */
  UT_hash_handle hh;   /* makes this structure hashable */
};

struct port_stats *srcStats = NULL, *dstStats = NULL;

// struct to hold count of flows received by destination ports
struct port_flow_info {
  u_int32_t port; /* key */
  u_int32_t num_flows;
  UT_hash_handle hh;
};

// struct to hold single packet tcp flows sent by source ip address
struct single_flow_info {
  u_int32_t saddr; /* key */
  u_int8_t version; /* IP version */
  struct port_flow_info *ports;
  u_int32_t tot_flows;
  UT_hash_handle hh;
};

struct single_flow_info *scannerHosts = NULL;

// struct to hold top receiver hosts
struct receiver {
  u_int32_t addr; /* key */
  u_int8_t version; /* IP version */
  u_int32_t num_pkts;
  UT_hash_handle hh;
};

struct receiver *receivers = NULL, *topReceivers = NULL;

#define WIRESHARK_NTOP_MAGIC 0x19680924

PACK_ON
struct ndpi_packet_trailer {
  u_int32_t magic; /* WIRESHARK_NTOP_MAGIC */
  u_int16_t master_protocol /* e.g. HTTP */, app_protocol /* e.g. FaceBook */;
  ndpi_risk flow_risk;
  u_int16_t flow_score;
  char name[16];
} PACK_OFF;

static pcap_dumper_t *extcap_dumper = NULL;
static pcap_t *extcap_fifo_h = NULL;
static char extcap_buf[16384];
static char *extcap_capture_fifo    = NULL;
static u_int16_t extcap_packet_filter = (u_int16_t)-1;

// struct associated to a workflow for a thread
struct reader_thread {
  struct ndpi_workflow *workflow;
  pthread_t pthread;
  u_int64_t last_idle_scan_time;
  u_int32_t idle_scan_idx;
  u_int32_t num_idle_flows;
  struct ndpi_flow_info *idle_flows[IDLE_SCAN_BUDGET];
};

// array for every thread created for a flow
static struct reader_thread ndpi_thread_info[MAX_NUM_READER_THREADS];

// ID tracking
typedef struct ndpi_id {
  u_int8_t ip[4];                   // Ip address
  struct ndpi_id_struct *ndpi_id;  // nDpi worker structure
} ndpi_id_t;

// used memory counters
u_int32_t current_ndpi_memory = 0, max_ndpi_memory = 0;
#ifdef USE_DPDK
static int dpdk_port_id = 0, dpdk_run_capture = 1;
#endif

void test_lib(); /* Forward */

extern void ndpi_report_payload_stats(FILE *out);
extern int parse_proto_name_list(char *str, NDPI_PROTOCOL_BITMASK *bitmask, int inverted_logic);

/* ********************************** */

// #define DEBUG_TRACE

#ifdef DEBUG_TRACE
FILE *trace = NULL;
#endif

/* ********************************** */

#define NUM_DOH_BINS 2

static struct ndpi_bin doh_ndpi_bins[NUM_DOH_BINS];

static u_int8_t doh_centroids[NUM_DOH_BINS][PLEN_NUM_BINS] = {
  { 23,25,3,0,26,0,0,0,0,0,0,0,0,0,2,0,0,15,3,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
  { 35,30,21,0,0,0,2,4,0,0,5,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }
};

static float doh_max_distance = 35.5;

static void init_doh_bins() {
  u_int i;

  for(i=0; i<NUM_DOH_BINS; i++) {
    ndpi_init_bin(&doh_ndpi_bins[i], ndpi_bin_family8, PLEN_NUM_BINS);
    ndpi_free_bin(&doh_ndpi_bins[i]); /* Hack: we use static bins (see below), so we need to free the dynamic ones just allocated */
    doh_ndpi_bins[i].u.bins8 = doh_centroids[i];
  }
}

/* *********************************************** */

static u_int check_bin_doh_similarity(struct ndpi_bin *bin, float *similarity) {
  u_int i;
  float lowest_similarity = 9999999999.0f;

  for(i=0; i<NUM_DOH_BINS; i++) {
    *similarity = ndpi_bin_similarity(&doh_ndpi_bins[i], bin, 0, 0);

    if(*similarity < 0) /* Error */
      return(0);

    if(*similarity <= doh_max_distance)
      return(1);

    if(*similarity < lowest_similarity) lowest_similarity = *similarity;
  }

  *similarity = lowest_similarity;

  return(0);
}

/* *********************************************** */

void ndpiCheckHostStringMatch(char *testChar) {
  ndpi_protocol_match_result match = { NDPI_PROTOCOL_UNKNOWN,
    NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, NDPI_PROTOCOL_UNRATED };
  int  testRes;
  char appBufStr[64];
  ndpi_protocol detected_protocol;
  struct ndpi_detection_module_struct *ndpi_str;

  if(!testChar)
    return;

  ndpi_str = ndpi_init_detection_module(init_prefs);
  ndpi_finalize_initialization(ndpi_str);

  testRes =  ndpi_match_string_subprotocol(ndpi_str,
                                           testChar, strlen(testChar), &match);

  if(testRes) {
    memset( &detected_protocol, 0, sizeof(ndpi_protocol) );

    detected_protocol.app_protocol    = match.protocol_id;
    detected_protocol.master_protocol = 0;
    detected_protocol.category        = match.protocol_category;

    ndpi_protocol2name( ndpi_str, detected_protocol, appBufStr,
                        sizeof(appBufStr));

    printf("Match Found for string [%s] -> P(%d) B(%d) C(%d) => %s %s %s\n",
	   testChar, match.protocol_id, match.protocol_breed,
	   match.protocol_category,
	   appBufStr,
	   ndpi_get_proto_breed_name( ndpi_str, match.protocol_breed ),
	   ndpi_category_get_name( ndpi_str, match.protocol_category));
  } else
    printf("Match NOT Found for string: %s\n\n", testChar );

  ndpi_exit_detection_module(ndpi_str);
}

/* *********************************************** */

static void ndpiCheckIPMatch(char *testChar) {
  struct ndpi_detection_module_struct *ndpi_str;
  u_int16_t ret = NDPI_PROTOCOL_UNKNOWN;
  u_int16_t port = 0;
  char *saveptr, *ip_str, *port_str;
  struct in_addr addr;
  char appBufStr[64];
  ndpi_protocol detected_protocol;
  NDPI_PROTOCOL_BITMASK all;

  if(!testChar)
    return;

  ndpi_str = ndpi_init_detection_module(init_prefs);
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);

  if(_protoFilePath != NULL)
    ndpi_load_protocols_file(ndpi_str, _protoFilePath);

  ndpi_finalize_initialization(ndpi_str);

  ip_str = strtok_r(testChar, ":", &saveptr);
  if(!ip_str)
    return;

  addr.s_addr = inet_addr(ip_str);
  port_str = strtok_r(NULL, "\n", &saveptr);
  if(port_str)
    port = atoi(port_str);
  ret = ndpi_network_port_ptree_match(ndpi_str, &addr, htons(port));

  if(ret != NDPI_PROTOCOL_UNKNOWN) {
    memset(&detected_protocol, 0, sizeof(ndpi_protocol));
    detected_protocol.app_protocol = ndpi_map_ndpi_id_to_user_proto_id(ndpi_str, ret);

    ndpi_protocol2name(ndpi_str, detected_protocol, appBufStr,
                       sizeof(appBufStr));

    printf("Match Found for IP %s, port %d -> %s (%d)\n",
	   ip_str, port, appBufStr, detected_protocol.app_protocol);
  } else {
    printf("Match NOT Found for IP: %s\n", testChar);
  }

  ndpi_exit_detection_module(ndpi_str);
}

/********************** FUNCTIONS ********************* */

static double ndpi_flow_get_byte_count_entropy(const uint32_t byte_count[256],
					       unsigned int num_bytes)
{
  int i;
  double sum = 0.0;

  for(i=0; i<256; i++) {
    double tmp = (double) byte_count[i] / (double) num_bytes;

    if(tmp > FLT_EPSILON) {
      sum -= tmp * logf(tmp);
    }
  }
  return(sum / log(2.0));
}

/**
 * @brief Set main components necessary to the detection
 */
static void setupDetection(u_int16_t thread_id, pcap_t * pcap_handle);

/**
 * @brief Get flow byte distribution mean and variance
 */
static void
flowGetBDMeanandVariance(struct ndpi_flow_info* flow) {
  FILE *out = results_file ? results_file : stdout;
  const uint32_t *array = NULL;
  uint32_t tmp[256], i;
  unsigned int num_bytes;
  double mean = 0.0, variance = 0.0;
  struct ndpi_entropy *last_entropy = flow->last_entropy;

  fflush(out);

  if(!last_entropy)
    return;

  /*
   * Sum up the byte_count array for outbound and inbound flows,
   * if this flow is bidirectional
   */
  /* TODO: we could probably use ndpi_data_* generic functions to simplify the code and
     to get rid of `ndpi_flow_get_byte_count_entropy()` */
  if (!flow->bidirectional) {
    array = last_entropy->src2dst_byte_count;
    num_bytes = last_entropy->src2dst_l4_bytes;
    for(i=0; i<256; i++) {
      tmp[i] = last_entropy->src2dst_byte_count[i];
    }

    if (last_entropy->src2dst_num_bytes != 0) {
      mean = last_entropy->src2dst_bd_mean;
      variance = last_entropy->src2dst_bd_variance/(last_entropy->src2dst_num_bytes - 1);
      variance = sqrt(variance);

      if (last_entropy->src2dst_num_bytes == 1) {
        variance = 0.0;
      }
    }
  } else {
    for(i=0; i<256; i++) {
      tmp[i] = last_entropy->src2dst_byte_count[i] + last_entropy->dst2src_byte_count[i];
    }
    array = tmp;
    num_bytes = last_entropy->src2dst_l4_bytes + last_entropy->dst2src_l4_bytes;

    if (last_entropy->src2dst_num_bytes + last_entropy->dst2src_num_bytes != 0) {
      mean = ((double)last_entropy->src2dst_num_bytes)/((double)(last_entropy->src2dst_num_bytes+last_entropy->dst2src_num_bytes))*last_entropy->src2dst_bd_mean +
	((double)last_entropy->dst2src_num_bytes)/((double)(last_entropy->dst2src_num_bytes+last_entropy->src2dst_num_bytes))*last_entropy->dst2src_bd_mean;

      variance = ((double)last_entropy->src2dst_num_bytes)/((double)(last_entropy->src2dst_num_bytes+last_entropy->dst2src_num_bytes))*last_entropy->src2dst_bd_variance +
	((double)last_entropy->dst2src_num_bytes)/((double)(last_entropy->dst2src_num_bytes+last_entropy->src2dst_num_bytes))*last_entropy->dst2src_bd_variance;

      variance = variance/((double)(last_entropy->src2dst_num_bytes + last_entropy->dst2src_num_bytes - 1));
      variance = sqrt(variance);
      if (last_entropy->src2dst_num_bytes + last_entropy->dst2src_num_bytes == 1) {
        variance = 0.0;
      }
    }
  }

  if(enable_flow_stats) {
    /* Output the mean */
    if(num_bytes != 0) {
      double entropy = ndpi_flow_get_byte_count_entropy(array, num_bytes);

      if(csv_fp) {
        fprintf(csv_fp, ",%.3f,%.3f,%.3f,%.3f", mean, variance, entropy, entropy * num_bytes);
      } else {
        fprintf(out, "[byte_dist_mean: %.3f", mean);
        fprintf(out, "][byte_dist_std: %.3f]", variance);
        fprintf(out, "[entropy: %.3f]", entropy);
        fprintf(out, "[total_entropy: %.3f]", entropy * num_bytes);
      }
    } else {
      if(csv_fp)
        fprintf(csv_fp, ",%.3f,%.3f,%.3f,%.3f", 0.0, 0.0, 0.0, 0.0);
    }
  }
}

/**
 * @brief Print help instructions
 */
static void help(u_int long_help) {
  printf("Welcome to nDPI %s\n\n", ndpi_revision());

  printf("ndpiReader "
#ifndef USE_DPDK
         "-i <file|device> "
#endif
         "[-f <filter>][-s <duration>][-m <duration>][-b <num bin clusters>]\n"
         "          [-p <protos>][-l <loops> [-q][-d][-h][-H][-D][-e <len>][-E][-t][-v <level>]\n"
         "          [-n <threads>][-w <file>][-c <file>][-C <file>][-j <file>][-x <file>]\n"
         "          [-r <file>][-j <file>][-S <file>][-T <num>][-U <num>] [-x <domain>][-z]\n"
         "          [-a <mode>][-B proto_list]\n\n"
         "Usage:\n"
         "  -i <file.pcap|device>     | Specify a pcap file/playlist to read packets from or a\n"
         "                            | device for live capture (comma-separated list)\n"
         "  -f <BPF filter>           | Specify a BPF filter for filtering selected traffic\n"
         "  -s <duration>             | Maximum capture duration in seconds (live traffic capture only)\n"
         "  -m <duration>             | Split analysis duration in <duration> max seconds\n"
         "  -p <file>.protos          | Specify a protocol file (eg. protos.txt)\n"
         "  -l <num loops>            | Number of detection loops (test only)\n"
         "  -n <num threads>          | Number of threads. Default: number of interfaces in -i.\n"
         "                            | Ignored with pcap files.\n"
         "  -b <num bin clusters>     | Number of bin clusters\n"
         "  -k <file>                 | Specify a file to write serialized detection results\n"
         "  -K <format>               | Specify the serialization format for `-k'\n"
         "                            | Valid formats are tlv, csv or json (default)\n"
#ifdef __linux__
         "  -g <id:id...>             | Thread affinity mask (one core id per thread)\n"
#endif
         "  -a <mode>                 | Generates option values for GUIs\n"
         "                            | 0 - List known protocols\n"
         "                            | 1 - List known categories\n"
         "                            | 2 - List known risks\n"
         "  -d                        | Disable protocol guess and use only DPI\n"
         "  -e <len>                  | Min human readeable string match len. Default %u\n"
	 "  -E                        | Track flow payload\n"
         "  -q                        | Quiet mode\n"
         "  -F                        | Enable flow stats\n"
         "  -t                        | Dissect GTP/TZSP tunnels\n"
         "  -P <a>:<b>:<c>:<d>:<e>    | Enable payload analysis:\n"
         "                            | <a> = min pattern len to search\n"
         "                            | <b> = max pattern len to search\n"
         "                            | <c> = max num packets per flow\n"
         "                            | <d> = max packet payload dissection\n"
         "                            | <d> = max num reported payloads\n"
         "                            | Default: %u:%u:%u:%u:%u\n"
         "  -c <path>                 | Load custom categories from the specified file\n"
         "  -C <path>                 | Write output in CSV format on the specified file\n"
         "  -r <path>                 | Load risky domain file\n"
         "  -j <path>                 | Load malicious JA3 fingeprints\n"
         "  -S <path>                 | Load malicious SSL certificate SHA1 fingerprints\n"
	 "  -G <dir>                  | Bind domain names to categories loading files from <dir>\n"
         "  -w <path>                 | Write test output on the specified file. This is useful for\n"
         "                            | testing purposes in order to compare results across runs\n"
         "  -h                        | This help\n"
         "  -H                        | This help plus some information about supported protocols/risks\n"
         "  -v <1|2|3|4>              | Verbose 'unknown protocol' packet print.\n"
         "                            | 1 = verbose\n"
         "                            | 2 = very verbose\n"
         "                            | 3 = port stats\n"
	   "                            | 4 = hash stats\n"
         "  -V <1-4>                  | nDPI logging level\n"
         "                            | 1 - trace, 2 - debug, 3 - full debug\n"
         "                            | >3 - full debug + log enabled for all protocols (i.e. '-u all')\n"
         "  -u all|proto|num[,...]    | Enable logging only for such protocol(s)\n"
         "                            | If this flag is present multiple times (directly, or via '-V'),\n"
         "                            | only the last instance will be considered\n"
         "  -B all|proto|num[,...]    | Disable such protocol(s). By defaul all protocols are enabled\n"
         "  -T <num>                  | Max number of TCP processed packets before giving up [default: %u]\n"
         "  -U <num>                  | Max number of UDP processed packets before giving up [default: %u]\n"
         "  -D                        | Enable DoH traffic analysis based on content (no DPI)\n"
         "  -x <domain>               | Check domain name [Test only]\n"
         "  -I                        | Ignore VLAN id for flow hash calculation\n"
         "  -z                        | Enable JA3+\n"
         "  -A                        | Dump internal statistics (LRU caches / Patricia trees / Ahocarasick automas / ...\n"
         "  -M                        | Memory allocation stats on data-path (only by the library). It works only on single-thread configuration\n"
         "  -Z proto:value            | Set this value of aggressiveness for this protocol (0 to disable it). This flag can be used multiple times\n"
         "  --lru-cache-size=NAME:size       | Specify the size for this LRU cache (0 to disable it). This flag can be used multiple times\n"
         "  --lru-cache-ttl=NAME:size        | Specify the TTL [in seconds] for this LRU cache (0 to disable it). This flag can be used multiple times\n"
         "  --stun-monitoring=<pkts>:<flags> | Configure STUN monitoring: keep monitoring STUN session for <pkts> more pkts looking for RTP\n"
         "                                   | (0:0 to disable the feature); set the specified features in <flags>\n"
         ,
         human_readeable_string_len,
         min_pattern_len, max_pattern_len, max_num_packets_per_flow, max_packet_payload_dissection,
         max_num_reported_top_payloads, max_num_tcp_dissected_pkts, max_num_udp_dissected_pkts);

  printf("\nLRU Cache names: ookla, bittorrent, zoom, stun, tls_cert, mining, msteams, stun_zoom\n");

#ifndef WIN32
  printf("\nExcap (wireshark) options:\n"
         "  --extcap-interfaces\n"
         "  --extcap-version\n"
         "  --extcap-dlts\n"
         "  --extcap-interface <name>\n"
         "  --extcap-config\n"
         "  --capture\n"
         "  --extcap-capture-filter <filter>\n"
         "  --fifo <path to file or pipe>\n"
         "  --ndpi-proto-filter <protocol>\n"
	 );
#endif

  if(long_help) {
    printf("\n\nSize of nDPI Flow structure: %u\n"
           "Sizeof of nDPI Flow protocol union: %zu\n",
           ndpi_detection_get_sizeof_ndpi_flow_struct(),
           sizeof(((struct ndpi_flow_struct *)0)->protos));

    NDPI_PROTOCOL_BITMASK all;

    ndpi_info_mod = ndpi_init_detection_module(init_prefs);
    printf("\n\nnDPI supported protocols:\n");
    printf("%3s %-22s %-10s %-8s %-12s %s\n",
	   "Id", "Protocol", "Layer_4", "Nw_Proto", "Breed", "Category");
    num_threads = 1;

    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_info_mod, &all);

    ndpi_dump_protocols(ndpi_info_mod, stdout);

    printf("\n\nnDPI supported risks:\n");
    ndpi_dump_risks_score(stdout);

    ndpi_exit_detection_module(ndpi_info_mod);
  }

  exit(!long_help);
}


#define OPTLONG_VALUE_LRU_CACHE_SIZE	1000
#define OPTLONG_VALUE_LRU_CACHE_TTL	1001

#define OPTLONG_VALUE_STUN_MONITORING	2000

static struct option longopts[] = {
  /* mandatory extcap options */
  { "extcap-interfaces", no_argument, NULL, '0'},
  { "extcap-version", optional_argument, NULL, '1'},
  { "extcap-dlts", no_argument, NULL, '2'},
  { "extcap-interface", required_argument, NULL, '3'},
  { "extcap-config", no_argument, NULL, '4'},
  { "capture", no_argument, NULL, '5'},
  { "extcap-capture-filter", required_argument, NULL, '6'},
  { "fifo", required_argument, NULL, '7'},
  { "ndpi-proto-filter", required_argument, NULL, '9'},

  /* ndpiReader options */
  { "enable-protocol-guess", no_argument, NULL, 'd'},
  { "categories", required_argument, NULL, 'c'},
  { "csv-dump", required_argument, NULL, 'C'},
  { "interface", required_argument, NULL, 'i'},
  { "filter", required_argument, NULL, 'f'},
  { "flow-stats", required_argument, NULL, 'F'},
  { "cpu-bind", required_argument, NULL, 'g'},
  { "load-categories", required_argument, NULL, 'G'},
  { "loops", required_argument, NULL, 'l'},
  { "num-threads", required_argument, NULL, 'n'},
  { "ignore-vlanid", no_argument, NULL, 'I'},

  { "protos", required_argument, NULL, 'p'},
  { "capture-duration", required_argument, NULL, 's'},
  { "decode-tunnels", no_argument, NULL, 't'},
  { "revision", no_argument, NULL, 'r'},
  { "verbose", required_argument, NULL, 'v'},
  { "version", no_argument, NULL, 'r'},
  { "ndpi-log-level", required_argument, NULL, 'V'},
  { "dbg-proto", required_argument, NULL, 'u'},
  { "help", no_argument, NULL, 'h'},
  { "long-help", no_argument, NULL, 'H'},
  { "serialization-outfile", required_argument, NULL, 'k'},
  { "serialization-format", required_argument, NULL, 'K'},
  { "payload-analysis", required_argument, NULL, 'P'},
  { "result-path", required_argument, NULL, 'w'},
  { "quiet", no_argument, NULL, 'q'},

  { "lru-cache-size", required_argument, NULL, OPTLONG_VALUE_LRU_CACHE_SIZE},
  { "lru-cache-ttl", required_argument, NULL, OPTLONG_VALUE_LRU_CACHE_TTL},
  { "stun-monitoring", required_argument, NULL, OPTLONG_VALUE_STUN_MONITORING},

  {0, 0, 0, 0}
};

/* ********************************** */

void extcap_interfaces() {
  printf("extcap {version=%s}{help=https://github.com/ntop/nDPI/tree/dev/wireshark}\n", ndpi_revision());
  printf("interface {value=ndpi}{display=nDPI interface}\n");

  extcap_exit = 1;
}

/* ********************************** */

void extcap_dlts() {
  u_int dlts_number = DLT_EN10MB;

  printf("dlt {number=%u}{name=%s}{display=%s}\n", dlts_number, "ndpi", "nDPI Interface");
  extcap_exit = 1;
}

/* ********************************** */

struct ndpi_proto_sorter {
  int id;
  char name[16];
};

/* ********************************** */

int cmpProto(const void *_a, const void *_b) {
  struct ndpi_proto_sorter *a = (struct ndpi_proto_sorter*)_a;
  struct ndpi_proto_sorter *b = (struct ndpi_proto_sorter*)_b;

  return(strcmp(a->name, b->name));
}

/* ********************************** */

int cmpFlows(const void *_a, const void *_b) {
  struct ndpi_flow_info *fa = ((struct flow_info*)_a)->flow;
  struct ndpi_flow_info *fb = ((struct flow_info*)_b)->flow;
  uint64_t a_size = fa->src2dst_bytes + fa->dst2src_bytes;
  uint64_t b_size = fb->src2dst_bytes + fb->dst2src_bytes;
  if(a_size != b_size)
    return a_size < b_size ? 1 : -1;

  // copy from ndpi_workflow_node_cmp();

  if(fa->ip_version < fb->ip_version ) return(-1); else { if(fa->ip_version > fb->ip_version ) return(1); }
  if(fa->protocol   < fb->protocol   ) return(-1); else { if(fa->protocol   > fb->protocol   ) return(1); }
  if(htonl(fa->src_ip)   < htonl(fb->src_ip)  ) return(-1); else { if(htonl(fa->src_ip)   > htonl(fb->src_ip)  ) return(1); }
  if(htons(fa->src_port) < htons(fb->src_port)) return(-1); else { if(htons(fa->src_port) > htons(fb->src_port)) return(1); }
  if(htonl(fa->dst_ip)   < htonl(fb->dst_ip)  ) return(-1); else { if(htonl(fa->dst_ip)   > htonl(fb->dst_ip)  ) return(1); }
  if(htons(fa->dst_port) < htons(fb->dst_port)) return(-1); else { if(htons(fa->dst_port) > htons(fb->dst_port)) return(1); }
  if(fa->vlan_id < fb->vlan_id) return(-1); else { if(fa->vlan_id > fb->vlan_id) return(1); }
  return(0);
}

/* ********************************** */

void extcap_config() {
  int argidx = 0;
#if 0
  struct ndpi_proto_sorter *protos;
  u_int ndpi_num_supported_protocols;
  int i;
  ndpi_proto_defaults_t *proto_defaults;
#endif

  ndpi_info_mod = ndpi_init_detection_module(init_prefs);
#if 0
  ndpi_num_supported_protocols = ndpi_get_ndpi_num_supported_protocols(ndpi_info_mod);
  proto_defaults = ndpi_get_proto_defaults(ndpi_info_mod);
#endif

  /* -i <interface> */
  printf("arg {number=%d}{call=-i}{display=Capture Interface}{type=string}{group=Live Capture}"
         "{tooltip=The interface name}\n", argidx++);

  printf("arg {number=%d}{call=-i}{display=Pcap File to Analyze}{type=fileselect}{mustexist=true}{group=Pcap}"
         "{tooltip=The pcap file to analyze (if the interface is unspecified)}\n", argidx++);

#if 0
  /* Removed as it breaks! extcap */
  protos = (struct ndpi_proto_sorter*)ndpi_malloc(sizeof(struct ndpi_proto_sorter) * ndpi_num_supported_protocols);
  if(!protos) exit(0);

  printf("arg {number=%d}{call=--ndpi-proto-filter}{display=nDPI Protocol Filter}{type=selector}{group=Filter}"
         "{tooltip=nDPI Protocol to be filtered}\n", argidx);

  printf("value {arg=%d}{value=%d}{display=%s}{default=true}\n", argidx, 0, "No nDPI filtering");

  for(i=0; i<(int) ndpi_num_supported_protocols; i++) {
    protos[i].id = i;
    ndpi_snprintf(protos[i].name, sizeof(protos[i].name), "%s", proto_defaults[i].protoName);
  }

  qsort(protos, ndpi_num_supported_protocols, sizeof(struct ndpi_proto_sorter), cmpProto);

  for(i=0; i<(int)ndpi_num_supported_protocols; i++)
    printf("value {arg=%d}{value=%d}{display=%s (%d)}{default=false}{enabled=true}\n", argidx, protos[i].id,
           protos[i].name, protos[i].id);

  ndpi_free(protos);
#endif

  ndpi_exit_detection_module(ndpi_info_mod);

  extcap_exit = 1;
}

/* ********************************** */

void extcap_capture() {
#ifdef DEBUG_TRACE
  if(trace) fprintf(trace, " #### %s #### \n", __FUNCTION__);
#endif

  if((extcap_fifo_h = pcap_open_dead(DLT_EN10MB, 16384 /* MTU */)) == NULL) {
    fprintf(stderr, "Error pcap_open_dead");

#ifdef DEBUG_TRACE
    if(trace) fprintf(trace, "Error pcap_open_dead\n");
#endif
    return;
  }

  if((extcap_dumper = pcap_dump_open(extcap_fifo_h,
                                     extcap_capture_fifo)) == NULL) {
    fprintf(stderr, "Unable to open the pcap dumper on %s", extcap_capture_fifo);

#ifdef DEBUG_TRACE
    if(trace) fprintf(trace, "Unable to open the pcap dumper on %s\n",
                      extcap_capture_fifo);
#endif
    return;
  }

#ifdef DEBUG_TRACE
  if(trace) fprintf(trace, "Starting packet capture [%p]\n", extcap_dumper);
#endif
}

/* ********************************** */

void printCSVHeader() {
  if(!csv_fp) return;

  fprintf(csv_fp, "#flow_id,protocol,first_seen,last_seen,duration,src_ip,src_port,dst_ip,dst_port,ndpi_proto_num,ndpi_proto,proto_by_ip,server_name_sni,");
  fprintf(csv_fp, "c_to_s_pkts,c_to_s_bytes,c_to_s_goodput_bytes,s_to_c_pkts,s_to_c_bytes,s_to_c_goodput_bytes,");
  fprintf(csv_fp, "data_ratio,str_data_ratio,c_to_s_goodput_ratio,s_to_c_goodput_ratio,");

  /* IAT (Inter Arrival Time) */
  fprintf(csv_fp, "iat_flow_min,iat_flow_avg,iat_flow_max,iat_flow_stddev,");
  fprintf(csv_fp, "iat_c_to_s_min,iat_c_to_s_avg,iat_c_to_s_max,iat_c_to_s_stddev,");
  fprintf(csv_fp, "iat_s_to_c_min,iat_s_to_c_avg,iat_s_to_c_max,iat_s_to_c_stddev,");

  /* Packet Length */
  fprintf(csv_fp, "pktlen_c_to_s_min,pktlen_c_to_s_avg,pktlen_c_to_s_max,pktlen_c_to_s_stddev,");
  fprintf(csv_fp, "pktlen_s_to_c_min,pktlen_s_to_c_avg,pktlen_s_to_c_max,pktlen_s_to_c_stddev,");

  /* TCP flags */
  fprintf(csv_fp, "cwr,ece,urg,ack,psh,rst,syn,fin,");

  fprintf(csv_fp, "c_to_s_cwr,c_to_s_ece,c_to_s_urg,c_to_s_ack,c_to_s_psh,c_to_s_rst,c_to_s_syn,c_to_s_fin,");

  fprintf(csv_fp, "s_to_c_cwr,s_to_c_ece,s_to_c_urg,s_to_c_ack,s_to_c_psh,s_to_c_rst,s_to_c_syn,s_to_c_fin,");

  /* TCP window */
  fprintf(csv_fp, "c_to_s_init_win,s_to_c_init_win,");

  /* Flow info */
  fprintf(csv_fp, "server_info,");
  fprintf(csv_fp, "tls_version,quic_version,ja3c,tls_client_unsafe,");
  fprintf(csv_fp, "ja3s,tls_server_unsafe,");
  fprintf(csv_fp, "advertised_alpns,negotiated_alpn,tls_supported_versions,");
#if 0
  fprintf(csv_fp, "tls_issuerDN,tls_subjectDN,");
#endif
  fprintf(csv_fp, "ssh_client_hassh,ssh_server_hassh,flow_info,plen_bins,http_user_agent");

  if(enable_flow_stats) {
    fprintf(csv_fp, ",byte_dist_mean,byte_dist_std,entropy,total_entropy");
  }

  fprintf(csv_fp, "\n");
}

static int cache_idx_from_name(const char *name)
{
  if(strcmp(name, "ookla") == 0)
    return NDPI_LRUCACHE_OOKLA;
  if(strcmp(name, "bittorrent") == 0)
    return NDPI_LRUCACHE_BITTORRENT;
  if(strcmp(name, "zoom") == 0)
    return NDPI_LRUCACHE_ZOOM;
  if(strcmp(name, "stun") == 0)
    return NDPI_LRUCACHE_STUN;
  if(strcmp(name, "tls_cert") == 0)
    return NDPI_LRUCACHE_TLS_CERT;
  if(strcmp(name, "mining") == 0)
    return NDPI_LRUCACHE_MINING;
  if(strcmp(name, "msteams") == 0)
    return NDPI_LRUCACHE_MSTEAMS;
  if(strcmp(name, "stun_zoom") == 0)
    return NDPI_LRUCACHE_STUN_ZOOM;
  return -1;
}

static int parse_cache_param(char *param, int *cache_idx, int *param_value)
{
  char *saveptr, *tmp_str, *cache_str, *param_str;
  int idx;

  tmp_str = ndpi_strdup(param);
  if(tmp_str) {
    cache_str = strtok_r(tmp_str, ":", &saveptr);
    if(cache_str) {
      param_str = strtok_r(NULL, ":", &saveptr);
      if(param_str) {
        idx = cache_idx_from_name(cache_str);
        if(idx >= 0) {
          *cache_idx = idx;
          *param_value = atoi(param_str);
          ndpi_free(tmp_str);
	  return 0;
	}
      }
    }
  }
  ndpi_free(tmp_str);
  return -1;
}

static int parse_two_unsigned_integer(char *param, u_int32_t *num1, u_int32_t *num2)
{
  char *saveptr, *tmp_str, *num1_str, *num2_str;

  tmp_str = ndpi_strdup(param);
  if(tmp_str) {
    num1_str = strtok_r(tmp_str, ":", &saveptr);
    if(num1_str) {
      num2_str = strtok_r(NULL, ":", &saveptr);
      if(num2_str) {
        *num1 = atoi(num1_str);
        *num2 = atoi(num2_str);
        ndpi_free(tmp_str);
	return 0;
      }
    }
  }
  ndpi_free(tmp_str);
  return -1;
}

/* ********************************** */

/**
 * @brief Option parser
 */
static void parseOptions(int argc, char **argv) {
  int option_idx = 0;
  int opt, i;
#ifndef USE_DPDK
  char *__pcap_file = NULL;
  int thread_id, do_capture = 0;
#ifdef __linux__
  char *bind_mask = NULL;
  u_int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
#endif
#endif
  int cache_idx, cache_size, cache_ttl;
  u_int32_t num_pkts, flags;

#ifdef USE_DPDK
  {
    int ret = rte_eal_init(argc, argv);

    if(ret < 0)
      rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret, argv += ret;
  }
#endif

  for(i = 0; i < NDPI_MAX_SUPPORTED_PROTOCOLS; i++)
    aggressiveness[i] = -1; /* Use the default value */

  for(i = 0; i < NDPI_LRUCACHE_MAX; i++) {
    lru_cache_sizes[i] = -1; /* Use the default value */
    lru_cache_ttls[i] = -1; /* Use the default value */
  }

  while((opt = getopt_long(argc, argv,
			   "a:Ab:B:e:Ec:C:dDFf:g:G:i:Ij:k:K:S:hHp:pP:l:r:s:tu:v:V:n:rp:x:X:w:zZ:q0123:456:7:89:m:MT:U:",
                           longopts, &option_idx)) != EOF) {
#ifdef DEBUG_TRACE
    if(trace) fprintf(trace, " #### Handling option -%c [%s] #### \n", opt, optarg ? optarg : "");
#endif

    switch (opt) {
    case 'a':
      ndpi_generate_options(atoi(optarg), stdout);
      exit(0);

    case 'A':
      dump_internal_stats = 1;
      break;

    case 'b':
      if((num_bin_clusters = atoi(optarg)) > 32)
        num_bin_clusters = 32;
      break;

    case 'd':
      enable_protocol_guess = 0;
      break;

    case 'D':
      enable_doh_dot_detection = 1;
      break;

    case 'e':
      human_readeable_string_len = atoi(optarg);
      break;

    case 'E':
      init_prefs |= ndpi_track_flow_payload;
      break;

    case 'i':
    case '3':
      _pcap_file[0] = optarg;
      break;

    case 'I':
      ignore_vlanid = 1;
      break;

    case 'j':
      _maliciousJA3Path = optarg;
      break;

    case 'S':
      _maliciousSHA1Path = optarg;
      break;

    case 'm':
      pcap_analysis_duration = atol(optarg);
      break;

    case 'f':
    case '6':
      bpfFilter = optarg;
      break;

#ifndef USE_DPDK
#ifdef __linux__
    case 'g':
      bind_mask = optarg;
      break;
#endif
#endif

    case 'G':
      _categoriesDirPath = optarg;
      break;

    case 'l':
      num_loops = atoi(optarg);
      break;

    case 'n':
      num_threads = atoi(optarg);
      break;

    case 'p':
      _protoFilePath = optarg;
      break;

    case 'c':
      _customCategoryFilePath = optarg;
      break;

    case 'C':
      errno = 0;
      if((csv_fp = fopen(optarg, "w")) == NULL)
      {
        printf("Unable to write on CSV file %s: %s\n", optarg, strerror(errno));
        exit(1);
      }
      break;

    case 'r':
      _riskyDomainFilePath = optarg;
      break;

    case 's':
      capture_for = atoi(optarg);
      capture_until = capture_for + time(NULL);
      break;

    case 't':
      decode_tunnels = 1;
      break;

    case 'v':
      verbose = atoi(optarg);
      break;

    case 'V':
      nDPI_LogLevel  = atoi(optarg);
      if(nDPI_LogLevel < NDPI_LOG_ERROR) nDPI_LogLevel = NDPI_LOG_ERROR;
      if(nDPI_LogLevel > NDPI_LOG_DEBUG_EXTRA) {
        nDPI_LogLevel = NDPI_LOG_DEBUG_EXTRA;
        ndpi_free(_debug_protocols);
        _debug_protocols = ndpi_strdup("all");
      }
      break;

    case 'u':
      ndpi_free(_debug_protocols);
      _debug_protocols = ndpi_strdup(optarg);
      break;

    case 'B':
      ndpi_free(_disabled_protocols);
      _disabled_protocols = ndpi_strdup(optarg);
      break;

    case 'Z': /* proto_name:aggr_value */
      {
        struct ndpi_detection_module_struct *module_tmp;
        NDPI_PROTOCOL_BITMASK all;
        char *saveptr, *tmp_str, *proto_str, *aggr_str;

        /* Use a temporary module with all protocols enabled */
        module_tmp = ndpi_init_detection_module(0);
        if(!module_tmp)
          break;
	
        NDPI_BITMASK_SET_ALL(all);
        ndpi_set_protocol_detection_bitmask2(module_tmp, &all);
        ndpi_finalize_initialization(module_tmp);

        tmp_str = ndpi_strdup(optarg);
        if(tmp_str) {
          proto_str = strtok_r(tmp_str, ":", &saveptr);
          if(proto_str) {
            aggr_str = strtok_r(NULL, ":", &saveptr);
            if(aggr_str) {
              aggressiveness[ndpi_get_protocol_id(module_tmp, proto_str)] = atoi(aggr_str);
            }
          }
        }
        ndpi_free(tmp_str);
        ndpi_exit_detection_module(module_tmp);
        break;
      }

    case 'h':
      help(0);
      break;

    case 'H':
      help(1);
      break;

    case 'F':
      enable_flow_stats = 1;
      break;

    case 'P':
      {
        int _min_pattern_len, _max_pattern_len,
          _max_num_packets_per_flow, _max_packet_payload_dissection,
          _max_num_reported_top_payloads;

        enable_payload_analyzer = 1;
        if(sscanf(optarg, "%d:%d:%d:%d:%d", &_min_pattern_len, &_max_pattern_len,
                  &_max_num_packets_per_flow,
                  &_max_packet_payload_dissection,
                  &_max_num_reported_top_payloads) == 5) {
          min_pattern_len = _min_pattern_len, max_pattern_len = _max_pattern_len;
          max_num_packets_per_flow = _max_num_packets_per_flow, max_packet_payload_dissection = _max_packet_payload_dissection;
          max_num_reported_top_payloads = _max_num_reported_top_payloads;
          if(min_pattern_len > max_pattern_len) min_pattern_len = max_pattern_len;
          if(min_pattern_len < 2)               min_pattern_len = 2;
          if(max_pattern_len > 16)              max_pattern_len = 16;
          if(max_num_packets_per_flow == 0)     max_num_packets_per_flow = 1;
          if(max_packet_payload_dissection < 4) max_packet_payload_dissection = 4;
          if(max_num_reported_top_payloads == 0) max_num_reported_top_payloads = 1;
        } else {
          printf("Invalid -P format. Ignored\n");
          help(0);
        }
      }
      break;

    case 'M':
      enable_malloc_bins = 1;
      ndpi_init_bin(&malloc_bins, ndpi_bin_family64, max_malloc_bins);
      break;

    case 'k':
      errno = 0;
      if((serialization_fp = fopen(optarg, "w")) == NULL)
      {
        printf("Unable to write on serialization file %s: %s\n", optarg, strerror(errno));
        exit(1);
      }
      break;

    case 'K':
      if (strcasecmp(optarg, "tlv") == 0 && strlen(optarg) == 3)
      {
        serialization_format = ndpi_serialization_format_tlv;
      } else if (strcasecmp(optarg, "csv") == 0 && strlen(optarg) == 3)
      {
        serialization_format = ndpi_serialization_format_csv;
      } else if (strcasecmp(optarg, "json") == 0 && strlen(optarg) == 4)
      {
        serialization_format = ndpi_serialization_format_json;
      } else {
        printf("Unknown serialization format. Valid values are: tlv,csv,json\n");
        exit(1);
      }
      break;

    case 'w':
      results_path = ndpi_strdup(optarg);
      if((results_file = fopen(results_path, "w")) == NULL) {
        printf("Unable to write in file %s: quitting\n", results_path);
        exit(1);
      }
      break;

    case 'q':
      quiet_mode = 1;
      nDPI_LogLevel = 0;
      break;

      /* Extcap */
    case '0':
      extcap_interfaces();
      break;

    case '1':
      printf("extcap {version=%s}\n", ndpi_revision());
      break;

    case '2':
      extcap_dlts();
      break;

    case '4':
      extcap_config();
      break;

#ifndef USE_DPDK
    case '5':
      do_capture = 1;
      break;
#endif

    case '7':
      extcap_capture_fifo = ndpi_strdup(optarg);
      break;

    case '9':
      extcap_packet_filter = ndpi_get_proto_by_name(ndpi_info_mod, optarg);
      if(extcap_packet_filter == NDPI_PROTOCOL_UNKNOWN) extcap_packet_filter = atoi(optarg);
      break;

    case 'T':
      max_num_tcp_dissected_pkts = atoi(optarg);
      if(max_num_tcp_dissected_pkts < 3) max_num_tcp_dissected_pkts = 3;
      break;

    case 'x':
      domain_to_check = optarg;
      break;

    case 'X':
      ip_port_to_check = optarg;
      break;

    case 'U':
      max_num_udp_dissected_pkts = atoi(optarg);
      if(max_num_udp_dissected_pkts < 3) max_num_udp_dissected_pkts = 3;
      break;

    case 'z':
      init_prefs |= ndpi_enable_ja3_plus;
      break;

    case OPTLONG_VALUE_LRU_CACHE_SIZE:
      if(parse_cache_param(optarg, &cache_idx, &cache_size) == -1) {
        printf("Invalid parameter [%s]\n", optarg);
        exit(1);
      }
      lru_cache_sizes[cache_idx] = cache_size;
      break;

    case OPTLONG_VALUE_LRU_CACHE_TTL:
      if(parse_cache_param(optarg, &cache_idx, &cache_ttl) == -1) {
        printf("Invalid parameter [%s]\n", optarg);
        exit(1);
      }
      lru_cache_ttls[cache_idx] = cache_ttl;
      break;

    case OPTLONG_VALUE_STUN_MONITORING:
      if(parse_two_unsigned_integer(optarg, &num_pkts, &flags) == -1) {
        printf("Invalid parameter [%s]\n", optarg);
        exit(1);
      }
      stun_monitoring_pkts_to_process = num_pkts;
      stun_monitoring_flags = flags;
      break;

    default:
#ifdef DEBUG_TRACE
      if(trace) fprintf(trace, " #### Unknown option -%c: skipping it #### \n", opt);
#endif

      help(0);
      break;
    }
  }

  if (serialization_fp == NULL && serialization_format != ndpi_serialization_format_unknown)
  {
    printf("Serializing detection results to a file requires command line arguments `-k'\n");
    exit(1);
  }
  if (serialization_fp != NULL && serialization_format == ndpi_serialization_format_unknown)
  {
    serialization_format = ndpi_serialization_format_json;
  }

  if(extcap_exit)
    exit(0);

  if(csv_fp)
    printCSVHeader();

#ifndef USE_DPDK
  if(do_capture) {
    quiet_mode = 1;
    extcap_capture();
  }

  if(!domain_to_check && !ip_port_to_check) {
    if(_pcap_file[0] == NULL)
      help(0);

    if(strchr(_pcap_file[0], ',')) { /* multiple ingress interfaces */
      num_threads = 0;               /* setting number of threads = number of interfaces */
      __pcap_file = strtok(_pcap_file[0], ",");
      while(__pcap_file != NULL && num_threads < MAX_NUM_READER_THREADS) {
        _pcap_file[num_threads++] = __pcap_file;
        __pcap_file = strtok(NULL, ",");
      }
    } else {
      if(num_threads > MAX_NUM_READER_THREADS) num_threads = MAX_NUM_READER_THREADS;
      for(thread_id = 1; thread_id < num_threads; thread_id++)
        _pcap_file[thread_id] = _pcap_file[0];
    }

    if(num_threads > 1 && enable_malloc_bins == 1)
    {
      printf("Memory profiling ('-M') is incompatible with multi-thread enviroment");
      exit(1);
    }
  }

#ifdef __linux__
#ifndef USE_DPDK
  for(thread_id = 0; thread_id < num_threads; thread_id++)
    core_affinity[thread_id] = -1;

  if(num_cores > 1 && bind_mask != NULL) {
    char *core_id = strtok(bind_mask, ":");
    thread_id = 0;

    while(core_id != NULL && thread_id < num_threads) {
      core_affinity[thread_id++] = atoi(core_id) % num_cores;
      core_id = strtok(NULL, ":");
    }
  }
#endif
#endif
#endif
}

/* ********************************** */

#if 0
/**
 * @brief A faster replacement for inet_ntoa().
 */
char* intoaV4(u_int32_t addr, char* buf, u_int16_t bufLen) {
  char *cp;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    u_int byte = addr & 0xff;

    *--cp = byte % 10 + '0';
    byte /= 10;
    if(byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if(byte > 0)
        *--cp = byte + '0';
    }
    if(n > 1)
      *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  return(cp);
}
#endif

/* ********************************** */

static char* print_cipher(ndpi_cipher_weakness c) {
  switch(c) {
  case ndpi_cipher_insecure:
    return(" (INSECURE)");
    break;

  case ndpi_cipher_weak:
    return(" (WEAK)");
    break;

  default:
    return("");
  }
}

/* ********************************** */

static char* is_unsafe_cipher(ndpi_cipher_weakness c) {
  switch(c) {
  case ndpi_cipher_insecure:
    return("INSECURE");
    break;

  case ndpi_cipher_weak:
    return("WEAK");
    break;

  default:
    return("OK");
  }
}

/* ********************************** */

void print_bin(FILE *fout, const char *label, struct ndpi_bin *b) {
  u_int16_t i;
  const char *sep = label ? "," : ";";

  ndpi_normalize_bin(b);

  if(label) fprintf(fout, "[%s: ", label);

  for(i=0; i<b->num_bins; i++) {
    switch(b->family) {
    case ndpi_bin_family8:
      fprintf(fout, "%s%u", (i > 0) ? sep : "", b->u.bins8[i]);
      break;
    case ndpi_bin_family16:
      fprintf(fout, "%s%u", (i > 0) ? sep : "", b->u.bins16[i]);
      break;
    case ndpi_bin_family32:
      fprintf(fout, "%s%u", (i > 0) ? sep : "", b->u.bins32[i]);
      break;
    case ndpi_bin_family64:
      fprintf(fout, "%s%llu", (i > 0) ? sep : "", (unsigned long long)b->u.bins64[i]);
      break;
    }
  }

  if(label) fprintf(fout, "]");
}

/* ********************************** */

/**
 * @brief Print the flow
 */
static void printFlow(u_int32_t id, struct ndpi_flow_info *flow, u_int16_t thread_id) {
  FILE *out = results_file ? results_file : stdout;
  u_int8_t known_tls;
  char buf[32], buf1[64];
  char buf_ver[16];
  char buf2_ver[16];
  char l4_proto_name[32];
  u_int i;

  if(csv_fp != NULL) {
    float data_ratio = ndpi_data_ratio(flow->src2dst_bytes, flow->dst2src_bytes);
    double f = (double)flow->first_seen_ms, l = (double)flow->last_seen_ms;

    fprintf(csv_fp, "%u,%u,%.3f,%.3f,%.3f,%s,%u,%s,%u,",
            flow->flow_id,
            flow->protocol,
            f/1000.0, l/1000.0,
            (l-f)/1000.0,
            flow->src_name, ntohs(flow->src_port),
            flow->dst_name, ntohs(flow->dst_port)
            );

    fprintf(csv_fp, "%s,",
            ndpi_protocol2id(ndpi_thread_info[thread_id].workflow->ndpi_struct,
                             flow->detected_protocol, buf, sizeof(buf)));

    fprintf(csv_fp, "%s,%s,%s,",
            ndpi_protocol2name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
                               flow->detected_protocol, buf, sizeof(buf)),
            ndpi_get_proto_name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
                                flow->detected_protocol.protocol_by_ip),
            flow->host_server_name);

    fprintf(csv_fp, "%u,%llu,%llu,", flow->src2dst_packets,
            (long long unsigned int) flow->src2dst_bytes, (long long unsigned int) flow->src2dst_goodput_bytes);
    fprintf(csv_fp, "%u,%llu,%llu,", flow->dst2src_packets,
            (long long unsigned int) flow->dst2src_bytes, (long long unsigned int) flow->dst2src_goodput_bytes);
    fprintf(csv_fp, "%.3f,%s,", data_ratio, ndpi_data_ratio2str(data_ratio));
    fprintf(csv_fp, "%.1f,%.1f,", 100.0*((float)flow->src2dst_goodput_bytes / (float)(flow->src2dst_bytes+1)),
            100.0*((float)flow->dst2src_goodput_bytes / (float)(flow->dst2src_bytes+1)));

    /* IAT (Inter Arrival Time) */
    fprintf(csv_fp, "%u,%.1f,%u,%.1f,",
            ndpi_data_min(flow->iat_flow), ndpi_data_average(flow->iat_flow), ndpi_data_max(flow->iat_flow), ndpi_data_stddev(flow->iat_flow));

    fprintf(csv_fp, "%u,%.1f,%u,%.1f,%u,%.1f,%u,%.1f,",
	    ndpi_data_min(flow->iat_c_to_s), ndpi_data_average(flow->iat_c_to_s), ndpi_data_max(flow->iat_c_to_s), ndpi_data_stddev(flow->iat_c_to_s),
	    ndpi_data_min(flow->iat_s_to_c), ndpi_data_average(flow->iat_s_to_c), ndpi_data_max(flow->iat_s_to_c), ndpi_data_stddev(flow->iat_s_to_c));

    /* Packet Length */
    fprintf(csv_fp, "%u,%.1f,%u,%.1f,%u,%.1f,%u,%.1f,",
	    ndpi_data_min(flow->pktlen_c_to_s), ndpi_data_average(flow->pktlen_c_to_s), ndpi_data_max(flow->pktlen_c_to_s), ndpi_data_stddev(flow->pktlen_c_to_s),
	    ndpi_data_min(flow->pktlen_s_to_c), ndpi_data_average(flow->pktlen_s_to_c), ndpi_data_max(flow->pktlen_s_to_c), ndpi_data_stddev(flow->pktlen_s_to_c));

    /* TCP flags */
    fprintf(csv_fp, "%d,%d,%d,%d,%d,%d,%d,%d,", flow->cwr_count, flow->ece_count, flow->urg_count, flow->ack_count, flow->psh_count, flow->rst_count, flow->syn_count, flow->fin_count);

    fprintf(csv_fp, "%d,%d,%d,%d,%d,%d,%d,%d,", flow->src2dst_cwr_count, flow->src2dst_ece_count, flow->src2dst_urg_count, flow->src2dst_ack_count,
	    flow->src2dst_psh_count, flow->src2dst_rst_count, flow->src2dst_syn_count, flow->src2dst_fin_count);

    fprintf(csv_fp, "%d,%d,%d,%d,%d,%d,%d,%d,", flow->dst2src_cwr_count, flow->dst2src_ece_count, flow->dst2src_urg_count, flow->dst2src_ack_count,
	    flow->dst2src_psh_count, flow->dst2src_rst_count, flow->dst2src_syn_count, flow->dst2src_fin_count);

    /* TCP window */
    fprintf(csv_fp, "%u,%u,", flow->c_to_s_init_win, flow->s_to_c_init_win);

    fprintf(csv_fp, "%s,",
            (flow->ssh_tls.server_info[0] != '\0')  ? flow->ssh_tls.server_info : "");

    fprintf(csv_fp, "%s,%s,%s,%s,%s,%s,",
            (flow->ssh_tls.ssl_version != 0)        ? ndpi_ssl_version2str(buf_ver, sizeof(buf_ver), flow->ssh_tls.ssl_version, &known_tls) : "0",
            (flow->ssh_tls.quic_version != 0)       ? ndpi_quic_version2str(buf2_ver, sizeof(buf2_ver), flow->ssh_tls.quic_version) : "0",
            (flow->ssh_tls.ja3_client[0] != '\0')   ? flow->ssh_tls.ja3_client : "",
            (flow->ssh_tls.ja3_client[0] != '\0')   ? is_unsafe_cipher(flow->ssh_tls.client_unsafe_cipher) : "0",
            (flow->ssh_tls.ja3_server[0] != '\0')   ? flow->ssh_tls.ja3_server : "",
            (flow->ssh_tls.ja3_server[0] != '\0')   ? is_unsafe_cipher(flow->ssh_tls.server_unsafe_cipher) : "0");

    fprintf(csv_fp, "%s,%s,%s,",
            flow->ssh_tls.advertised_alpns          ? flow->ssh_tls.advertised_alpns : "",
            flow->ssh_tls.negotiated_alpn           ? flow->ssh_tls.negotiated_alpn : "",
            flow->ssh_tls.tls_supported_versions    ? flow->ssh_tls.tls_supported_versions : ""
            );

#if 0
    fprintf(csv_fp, "%s,%s,",
            flow->ssh_tls.tls_issuerDN              ? flow->ssh_tls.tls_issuerDN : "",
            flow->ssh_tls.tls_subjectDN             ? flow->ssh_tls.tls_subjectDN : ""
            );
#endif

    fprintf(csv_fp, "%s,%s",
            (flow->ssh_tls.client_hassh[0] != '\0') ? flow->ssh_tls.client_hassh : "",
            (flow->ssh_tls.server_hassh[0] != '\0') ? flow->ssh_tls.server_hassh : ""
            );

    fprintf(csv_fp, ",%s,", flow->info);

#ifndef DIRECTION_BINS
    print_bin(csv_fp, NULL, &flow->payload_len_bin);
#endif

    fprintf(csv_fp, ",%s", flow->http.user_agent);

    if((verbose != 1) && (verbose != 2)) {
      if(csv_fp && enable_flow_stats) {
	flowGetBDMeanandVariance(flow);
      }

      if(csv_fp)
	fprintf(csv_fp, "\n");
      //  return;
    }
  }

  if(csv_fp || (verbose > 1)) {
#if 1
    fprintf(out, "\t%u", id);
#else
    fprintf(out, "\t%u(%u)", id, flow->flow_id);
#endif

    fprintf(out, "\t%s ", ndpi_get_ip_proto_name(flow->protocol, l4_proto_name, sizeof(l4_proto_name)));

    fprintf(out, "%s%s%s:%u %s %s%s%s:%u ",
	    (flow->ip_version == 6) ? "[" : "",
	    flow->src_name, (flow->ip_version == 6) ? "]" : "", ntohs(flow->src_port),
	    flow->bidirectional ? "<->" : "->",
	    (flow->ip_version == 6) ? "[" : "",
	    flow->dst_name, (flow->ip_version == 6) ? "]" : "", ntohs(flow->dst_port)
	    );

    if(flow->vlan_id > 0) fprintf(out, "[VLAN: %u]", flow->vlan_id);
    if(enable_payload_analyzer) fprintf(out, "[flowId: %u]", flow->flow_id);

    if(enable_flow_stats) {
      /* Print entropy values for monitored flows. */
      flowGetBDMeanandVariance(flow);
      fflush(out);
      fprintf(out, "[score: %.4f]", flow->entropy->score);
    }

    if(csv_fp) fprintf(csv_fp, "\n");

    fprintf(out, "[proto: ");
    if(flow->tunnel_type != ndpi_no_tunnel)
      fprintf(out, "%s:", ndpi_tunnel2str(flow->tunnel_type));

    fprintf(out, "%s/%s][IP: %u/%s]",
	    ndpi_protocol2id(ndpi_thread_info[thread_id].workflow->ndpi_struct,
			     flow->detected_protocol, buf, sizeof(buf)),
	    ndpi_protocol2name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
			       flow->detected_protocol, buf1, sizeof(buf1)),
	    flow->detected_protocol.protocol_by_ip,
	    ndpi_get_proto_name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
				flow->detected_protocol.protocol_by_ip));

    if(flow->multimedia_flow_type != ndpi_multimedia_unknown_flow) {
      const char *content;

      switch(flow->multimedia_flow_type) {
      case ndpi_multimedia_audio_flow:
	content = "Audio";
	break;

      case ndpi_multimedia_video_flow:
	content = "Video";
	break;

      case ndpi_multimedia_screen_sharing_flow:
	content = "Screen Sharing";
	break;

      default:
	content = "???";
	break;
      }

      fprintf(out, "[Stream Content: %s]", content);
    }

    fprintf(out, "[%s]",
	    ndpi_is_encrypted_proto(ndpi_thread_info[thread_id].workflow->ndpi_struct,
				    flow->detected_protocol) ? "Encrypted" : "ClearText");

    fprintf(out, "[Confidence: %s]", ndpi_confidence_get_name(flow->confidence));
    /* If someone wants to have the num_dissector_calls variable per flow, he can print it here.
       Disabled by default to avoid too many diffs in the unit tests...
    */
#if 0
    fprintf(out, "[Num calls: %d]", flow->num_dissector_calls);
#endif
    fprintf(out, "[DPI packets: %d]", flow->dpi_packets);

    if(flow->detected_protocol.category != 0)
      fprintf(out, "[cat: %s/%u]",
	      ndpi_category_get_name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
				     flow->detected_protocol.category),
	      (unsigned int)flow->detected_protocol.category);

    fprintf(out, "[%u pkts/%llu bytes ", flow->src2dst_packets, (long long unsigned int) flow->src2dst_bytes);
    fprintf(out, "%s %u pkts/%llu bytes]",
	    (flow->dst2src_packets > 0) ? "<->" : "->",
	    flow->dst2src_packets, (long long unsigned int) flow->dst2src_bytes);

    fprintf(out, "[Goodput ratio: %.0f/%.0f]",
	    100.0*((float)flow->src2dst_goodput_bytes / (float)(flow->src2dst_bytes+1)),
	    100.0*((float)flow->dst2src_goodput_bytes / (float)(flow->dst2src_bytes+1)));

    if(flow->last_seen_ms > flow->first_seen_ms)
      fprintf(out, "[%.2f sec]", ((float)(flow->last_seen_ms - flow->first_seen_ms))/(float)1000);
    else
      fprintf(out, "[< 1 sec]");

    if(flow->telnet.username)  fprintf(out, "[Username: %s]", flow->telnet.username);
    if(flow->telnet.password)  fprintf(out, "[Password: %s]", flow->telnet.password);

    if(flow->host_server_name[0] != '\0') fprintf(out, "[Hostname/SNI: %s]", flow->host_server_name);

    switch (flow->info_type)
    {
      case INFO_INVALID:
        break;

      case INFO_GENERIC:
        if (flow->info[0] != '\0')
        {
          fprintf(out, "[%s]", flow->info);
        }
        break;

      case INFO_KERBEROS:
        if (flow->kerberos.domain[0] != '\0' ||
            flow->kerberos.hostname[0] != '\0' ||
            flow->kerberos.username[0] != '\0')
        {
          fprintf(out, "[%s%s%s%s]",
                  flow->kerberos.domain,
                  (flow->kerberos.hostname[0] != '\0' ||
                   flow->kerberos.username[0] != '\0' ? "\\" : ""),
                  flow->kerberos.hostname,
                  flow->kerberos.username);
        }
        break;

      case INFO_SOFTETHER:
        if (flow->softether.ip[0] != '\0')
        {
          fprintf(out, "[Client IP: %s]", flow->softether.ip);
        }
        if (flow->softether.port[0] != '\0')
        {
          fprintf(out, "[Client Port: %s]", flow->softether.port);
        }
        if (flow->softether.hostname[0] != '\0')
        {
          fprintf(out, "[Hostname: %s]", flow->softether.hostname);
        }
        if (flow->softether.fqdn[0] != '\0')
        {
          fprintf(out, "[FQDN: %s]", flow->softether.fqdn);
        }
        break;

      case INFO_TIVOCONNECT:
        if (flow->tivoconnect.identity_uuid[0] != '\0')
        {
          fprintf(out, "[UUID: %s]", flow->tivoconnect.identity_uuid);
        }
        if (flow->tivoconnect.machine[0] != '\0')
        {
          fprintf(out, "[Machine: %s]", flow->tivoconnect.machine);
        }
        if (flow->tivoconnect.platform[0] != '\0')
        {
          fprintf(out, "[Platform: %s]", flow->tivoconnect.platform);
        }
        if (flow->tivoconnect.services[0] != '\0')
        {
          fprintf(out, "[Services: %s]", flow->tivoconnect.services);
        }
        break;

      case INFO_NATPMP:
        if (flow->natpmp.internal_port != 0 && flow->natpmp.ip[0] != '\0')
        {
            fprintf(out, "[Result: %u][Internal Port: %u][External Port: %u][External Address: %s]",
                    flow->natpmp.result_code, flow->natpmp.internal_port, flow->natpmp.external_port,
                    flow->natpmp.ip);
        }
        break;

      case INFO_FTP_IMAP_POP_SMTP:
        if (flow->ftp_imap_pop_smtp.username[0] != '\0')
        {
          fprintf(out, "[User: %s][Pwd: %s]",
                  flow->ftp_imap_pop_smtp.username,
                  flow->ftp_imap_pop_smtp.password);
          if (flow->ftp_imap_pop_smtp.auth_failed != 0)
          {
            fprintf(out, "[%s]", "Auth Failed");
          }
        }
        break;
    }

    if(flow->ssh_tls.advertised_alpns)
        fprintf(out, "[(Advertised) ALPNs: %s]", flow->ssh_tls.advertised_alpns);

    if(flow->ssh_tls.negotiated_alpn)
        fprintf(out, "[(Negotiated) ALPN: %s]", flow->ssh_tls.negotiated_alpn);

    if(flow->ssh_tls.tls_supported_versions)
      fprintf(out, "[TLS Supported Versions: %s]", flow->ssh_tls.tls_supported_versions);

    if(flow->mining.currency[0] != '\0') fprintf(out, "[currency: %s]", flow->mining.currency);

    if(flow->dns.geolocation_iata_code[0] != '\0') fprintf(out, "[GeoLocation: %s]", flow->dns.geolocation_iata_code);

    if((flow->src2dst_packets+flow->dst2src_packets) > 5) {
      if(flow->iat_c_to_s && flow->iat_s_to_c) {
	float data_ratio = ndpi_data_ratio(flow->src2dst_bytes, flow->dst2src_bytes);

	fprintf(out, "[bytes ratio: %.3f (%s)]", data_ratio, ndpi_data_ratio2str(data_ratio));

	/* IAT (Inter Arrival Time) */
	fprintf(out, "[IAT c2s/s2c min/avg/max/stddev: %u/%u %.0f/%.0f %u/%u %.0f/%.0f]",
		ndpi_data_min(flow->iat_c_to_s),     ndpi_data_min(flow->iat_s_to_c),
		(float)ndpi_data_average(flow->iat_c_to_s), (float)ndpi_data_average(flow->iat_s_to_c),
		ndpi_data_max(flow->iat_c_to_s),     ndpi_data_max(flow->iat_s_to_c),
		(float)ndpi_data_stddev(flow->iat_c_to_s),  (float)ndpi_data_stddev(flow->iat_s_to_c));

	/* Packet Length */
	fprintf(out, "[Pkt Len c2s/s2c min/avg/max/stddev: %u/%u %.0f/%.0f %u/%u %.0f/%.0f]",
		ndpi_data_min(flow->pktlen_c_to_s), ndpi_data_min(flow->pktlen_s_to_c),
		ndpi_data_average(flow->pktlen_c_to_s), ndpi_data_average(flow->pktlen_s_to_c),
		ndpi_data_max(flow->pktlen_c_to_s), ndpi_data_max(flow->pktlen_s_to_c),
		ndpi_data_stddev(flow->pktlen_c_to_s),  ndpi_data_stddev(flow->pktlen_s_to_c));
      }
    }

    if(flow->http.url[0] != '\0') {
      ndpi_risk_enum risk = ndpi_validate_url(flow->http.url);

      if(risk != NDPI_NO_RISK)
	NDPI_SET_BIT(flow->risk, risk);

      fprintf(out, "[URL: %s]", flow->http.url);
    }

    if(flow->http.response_status_code)
      fprintf(out, "[StatusCode: %u]", flow->http.response_status_code);

    if(flow->http.request_content_type[0] != '\0')
      fprintf(out, "[Req Content-Type: %s]", flow->http.request_content_type);

    if(flow->http.content_type[0] != '\0')
      fprintf(out, "[Content-Type: %s]", flow->http.content_type);

    if(flow->http.nat_ip[0] != '\0')
      fprintf(out, "[Nat-IP: %s]", flow->http.nat_ip);

    if(flow->http.server[0] != '\0')
      fprintf(out, "[Server: %s]", flow->http.server);

    if(flow->http.user_agent[0] != '\0')
      fprintf(out, "[User-Agent: %s]", flow->http.user_agent);

    if(flow->http.filename[0] != '\0')
      fprintf(out, "[Filename: %s]", flow->http.filename);

    if(flow->risk) {
      u_int i;
      u_int16_t cli_score, srv_score;
      fprintf(out, "[Risk: ");

      for(i=0; i<NDPI_MAX_RISK; i++)
	if(NDPI_ISSET_BIT(flow->risk, i))
	  fprintf(out, "** %s **", ndpi_risk2str(i));

      fprintf(out, "]");

      fprintf(out, "[Risk Score: %u]", ndpi_risk2score(flow->risk, &cli_score, &srv_score));

      if(flow->risk_str)
	fprintf(out, "[Risk Info: %s]", flow->risk_str);
    }

    if(flow->ssh_tls.ssl_version != 0) fprintf(out, "[%s]", ndpi_ssl_version2str(buf_ver, sizeof(buf_ver),
										 flow->ssh_tls.ssl_version, &known_tls));

    if(flow->ssh_tls.quic_version != 0) fprintf(out, "[QUIC ver: %s]", ndpi_quic_version2str(buf_ver, sizeof(buf_ver),
										 flow->ssh_tls.quic_version));

    if(flow->ssh_tls.client_hassh[0] != '\0') fprintf(out, "[HASSH-C: %s]", flow->ssh_tls.client_hassh);

    if(flow->ssh_tls.ja3_client[0] != '\0') fprintf(out, "[JA3C: %s%s]", flow->ssh_tls.ja3_client,
						    print_cipher(flow->ssh_tls.client_unsafe_cipher));

    if(flow->ssh_tls.server_info[0] != '\0') fprintf(out, "[Server: %s]", flow->ssh_tls.server_info);

    if(flow->ssh_tls.server_names) fprintf(out, "[ServerNames: %s]", flow->ssh_tls.server_names);
    if(flow->ssh_tls.server_hassh[0] != '\0') fprintf(out, "[HASSH-S: %s]", flow->ssh_tls.server_hassh);

    if(flow->ssh_tls.ja3_server[0] != '\0') fprintf(out, "[JA3S: %s%s]", flow->ssh_tls.ja3_server,
						    print_cipher(flow->ssh_tls.server_unsafe_cipher));

    if(flow->ssh_tls.tls_issuerDN)  fprintf(out, "[Issuer: %s]", flow->ssh_tls.tls_issuerDN);
    if(flow->ssh_tls.tls_subjectDN) fprintf(out, "[Subject: %s]", flow->ssh_tls.tls_subjectDN);

    if(flow->ssh_tls.encrypted_sni.esni) {
      char unknown_cipher[8];
      fprintf(out, "[ESNI: %s]", flow->ssh_tls.encrypted_sni.esni);
      fprintf(out, "[ESNI Cipher: %s]",
              ndpi_cipher2str(flow->ssh_tls.encrypted_sni.cipher_suite, unknown_cipher));
    }

    if(flow->ssh_tls.encrypted_ch.version != 0) {
      fprintf(out, "[ECH: version 0x%x]", flow->ssh_tls.encrypted_ch.version);
    }

    if(flow->ssh_tls.sha1_cert_fingerprint_set) {
      fprintf(out, "[Certificate SHA-1: ");
      for(i=0; i<20; i++)
        fprintf(out, "%s%02X", (i > 0) ? ":" : "",
                flow->ssh_tls.sha1_cert_fingerprint[i] & 0xFF);
      fprintf(out, "]");
    }

#ifdef HEURISTICS_CODE
    if(flow->ssh_tls.browser_heuristics.is_safari_tls)  fprintf(out, "[Safari]");
    if(flow->ssh_tls.browser_heuristics.is_firefox_tls) fprintf(out, "[Firefox]");
    if(flow->ssh_tls.browser_heuristics.is_chrome_tls)  fprintf(out, "[Chrome]");
#endif

    if(flow->ssh_tls.notBefore && flow->ssh_tls.notAfter) {
      char notBefore[32], notAfter[32];
      struct tm a, b;
      struct tm *before = ndpi_gmtime_r(&flow->ssh_tls.notBefore, &a);
      struct tm *after  = ndpi_gmtime_r(&flow->ssh_tls.notAfter, &b);

      strftime(notBefore, sizeof(notBefore), "%Y-%m-%d %H:%M:%S", before);
      strftime(notAfter, sizeof(notAfter), "%Y-%m-%d %H:%M:%S", after);

      fprintf(out, "[Validity: %s - %s]", notBefore, notAfter);
    }

    char unknown_cipher[8];
    if(flow->ssh_tls.server_cipher != '\0')
    {
      fprintf(out, "[Cipher: %s]", ndpi_cipher2str(flow->ssh_tls.server_cipher, unknown_cipher));
    }
    if(flow->bittorent_hash != NULL) fprintf(out, "[BT Hash: %s]", flow->bittorent_hash);
    if(flow->dhcp_fingerprint != NULL) fprintf(out, "[DHCP Fingerprint: %s]", flow->dhcp_fingerprint);
    if(flow->dhcp_class_ident) fprintf(out, "[DHCP Class Ident: %s]",
				       flow->dhcp_class_ident);

    if(flow->has_human_readeable_strings) fprintf(out, "[PLAIN TEXT (%s)]",
						  flow->human_readeable_string_buffer);

#ifdef DIRECTION_BINS
    print_bin(out, "Plen c2s", &flow->payload_len_bin_src2dst);
    print_bin(out, "Plen s2c", &flow->payload_len_bin_dst2src);
#else
    print_bin(out, "Plen Bins", &flow->payload_len_bin);
#endif

    if(flow->flow_payload && (flow->flow_payload_len > 0)) {
      u_int i;

      fprintf(out, "[Payload: ");

      for(i=0; i<flow->flow_payload_len; i++)
	fprintf(out, "%c", isspace(flow->flow_payload[i]) ? '.' : flow->flow_payload[i]);

      fprintf(out, "]");
    }

    fprintf(out, "\n");
  }
}

static void printFlowSerialized(u_int16_t thread_id,
                                struct ndpi_flow_info *flow)
{
  char *json_str = NULL;
  u_int32_t json_str_len = 0;
  ndpi_serializer * const serializer = &flow->ndpi_flow_serializer;
  //float data_ratio = ndpi_data_ratio(flow->src2dst_bytes, flow->dst2src_bytes);
  double f = (double)flow->first_seen_ms, l = (double)flow->last_seen_ms;
  float data_ratio = ndpi_data_ratio(flow->src2dst_bytes, flow->dst2src_bytes);

  ndpi_serialize_string_uint32(serializer, "flow_id", flow->flow_id);
  ndpi_serialize_string_double(serializer, "first_seen", f / 1000., "%.3f");
  ndpi_serialize_string_double(serializer, "last_seen", l / 1000., "%.3f");
  ndpi_serialize_string_double(serializer, "duration", (l-f)/1000.0, "%.3f");
  ndpi_serialize_string_uint32(serializer, "vlan_id", flow->vlan_id);
  ndpi_serialize_string_uint32(serializer, "bidirectional", flow->bidirectional);

  /* XFER Packets/Bytes */
  ndpi_serialize_start_of_block(serializer, "xfer");
  ndpi_serialize_string_float(serializer, "data_ratio", data_ratio, "%.3f");
  ndpi_serialize_string_string(serializer, "data_ratio_str", ndpi_data_ratio2str(data_ratio));
  ndpi_serialize_string_uint32(serializer, "src2dst_packets", flow->src2dst_packets);
  ndpi_serialize_string_uint64(serializer, "src2dst_bytes",
                               (u_int64_t)flow->src2dst_bytes);
  ndpi_serialize_string_uint64(serializer, "src2dst_goodput_bytes",
                               (u_int64_t)flow->src2dst_goodput_bytes);
  ndpi_serialize_string_uint32(serializer, "dst2src_packets", flow->dst2src_packets);
  ndpi_serialize_string_uint64(serializer, "dst2src_bytes",
                               (u_int64_t)flow->dst2src_bytes);
  ndpi_serialize_string_uint64(serializer, "dst2src_goodput_bytes",
                               (u_int64_t)flow->dst2src_goodput_bytes);
  ndpi_serialize_end_of_block(serializer);

  /* IAT (Inter Arrival Time) */
  ndpi_serialize_start_of_block(serializer, "iat");
  ndpi_serialize_string_uint32(serializer, "flow_min", ndpi_data_min(flow->iat_flow));
  ndpi_serialize_string_float(serializer, "flow_avg",
                              ndpi_data_average(flow->iat_flow), "%.1f");
  ndpi_serialize_string_uint32(serializer, "flow_max", ndpi_data_max(flow->iat_flow));
  ndpi_serialize_string_float(serializer, "flow_stddev",
                              ndpi_data_stddev(flow->iat_flow), "%.1f");

  ndpi_serialize_string_uint32(serializer, "c_to_s_min",
                               ndpi_data_min(flow->iat_c_to_s));
  ndpi_serialize_string_float(serializer, "c_to_s_avg",
                              ndpi_data_average(flow->iat_c_to_s), "%.1f");
  ndpi_serialize_string_uint32(serializer, "c_to_s_max",
                               ndpi_data_max(flow->iat_c_to_s));
  ndpi_serialize_string_float(serializer, "c_to_s_stddev",
                              ndpi_data_stddev(flow->iat_c_to_s), "%.1f");

  ndpi_serialize_string_uint32(serializer, "s_to_c_min",
                               ndpi_data_min(flow->iat_s_to_c));
  ndpi_serialize_string_float(serializer, "s_to_c_avg",
                              ndpi_data_average(flow->iat_s_to_c), "%.1f");
  ndpi_serialize_string_uint32(serializer, "s_to_c_max",
                               ndpi_data_max(flow->iat_s_to_c));
  ndpi_serialize_string_float(serializer, "s_to_c_stddev",
                              ndpi_data_stddev(flow->iat_s_to_c), "%.1f");
  ndpi_serialize_end_of_block(serializer);

  /* Packet Length */
  ndpi_serialize_start_of_block(serializer, "pktlen");
  ndpi_serialize_string_uint32(serializer, "c_to_s_min",
                               ndpi_data_min(flow->pktlen_c_to_s));
  ndpi_serialize_string_float(serializer, "c_to_s_avg",
                              ndpi_data_average(flow->pktlen_c_to_s), "%.1f");
  ndpi_serialize_string_uint32(serializer, "c_to_s_max",
                               ndpi_data_max(flow->pktlen_c_to_s));
  ndpi_serialize_string_float(serializer, "c_to_s_stddev",
                              ndpi_data_stddev(flow->pktlen_c_to_s), "%.1f");

  ndpi_serialize_string_uint32(serializer, "s_to_c_min",
                               ndpi_data_min(flow->pktlen_s_to_c));
  ndpi_serialize_string_float(serializer, "s_to_c_avg",
                              ndpi_data_average(flow->pktlen_s_to_c), "%.1f");
  ndpi_serialize_string_uint32(serializer, "s_to_c_max",
                               ndpi_data_max(flow->pktlen_s_to_c));
  ndpi_serialize_string_float(serializer, "s_to_c_stddev",
                              ndpi_data_stddev(flow->pktlen_s_to_c), "%.1f");
  ndpi_serialize_end_of_block(serializer);

  /* TCP flags */
  ndpi_serialize_start_of_block(serializer, "tcp_flags");
  ndpi_serialize_string_int32(serializer, "cwr_count", flow->cwr_count);
  ndpi_serialize_string_int32(serializer, "ece_count", flow->ece_count);
  ndpi_serialize_string_int32(serializer, "urg_count", flow->urg_count);
  ndpi_serialize_string_int32(serializer, "ack_count", flow->ack_count);
  ndpi_serialize_string_int32(serializer, "psh_count", flow->psh_count);
  ndpi_serialize_string_int32(serializer, "rst_count", flow->rst_count);
  ndpi_serialize_string_int32(serializer, "syn_count", flow->syn_count);
  ndpi_serialize_string_int32(serializer, "fin_count", flow->fin_count);

  ndpi_serialize_string_int32(serializer, "src2dst_cwr_count", flow->src2dst_cwr_count);
  ndpi_serialize_string_int32(serializer, "src2dst_ece_count", flow->src2dst_ece_count);
  ndpi_serialize_string_int32(serializer, "src2dst_urg_count", flow->src2dst_urg_count);
  ndpi_serialize_string_int32(serializer, "src2dst_ack_count", flow->src2dst_ack_count);
  ndpi_serialize_string_int32(serializer, "src2dst_psh_count", flow->src2dst_psh_count);
  ndpi_serialize_string_int32(serializer, "src2dst_rst_count", flow->src2dst_rst_count);
  ndpi_serialize_string_int32(serializer, "src2dst_syn_count", flow->src2dst_syn_count);
  ndpi_serialize_string_int32(serializer, "src2dst_fin_count", flow->src2dst_fin_count);

  ndpi_serialize_string_int32(serializer, "dst2src_cwr_count", flow->dst2src_cwr_count);
  ndpi_serialize_string_int32(serializer, "dst2src_ece_count", flow->dst2src_ece_count);
  ndpi_serialize_string_int32(serializer, "dst2src_urg_count", flow->dst2src_urg_count);
  ndpi_serialize_string_int32(serializer, "dst2src_ack_count", flow->dst2src_ack_count);
  ndpi_serialize_string_int32(serializer, "dst2src_psh_count", flow->dst2src_psh_count);
  ndpi_serialize_string_int32(serializer, "dst2src_rst_count", flow->dst2src_rst_count);
  ndpi_serialize_string_int32(serializer, "dst2src_syn_count", flow->dst2src_syn_count);
  ndpi_serialize_string_int32(serializer, "dst2src_fin_count", flow->dst2src_fin_count);
  ndpi_serialize_end_of_block(serializer);

  /* TCP window */
  ndpi_serialize_string_uint32(serializer, "c_to_s_init_win", flow->c_to_s_init_win);
  ndpi_serialize_string_uint32(serializer, "s_to_c_init_win", flow->s_to_c_init_win);

  json_str = ndpi_serializer_get_buffer(serializer, &json_str_len);
  if (json_str == NULL || json_str_len == 0)
  {
    printf("ERROR: nDPI serialization failed\n");
    exit(-1);
  }

  fprintf(serialization_fp, "%.*s\n", (int)json_str_len, json_str);
}

/* ********************************** */

/**
 * @brief Unknown Proto Walker
 */
static void node_print_unknown_proto_walker(const void *node,
                                            ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow_info *flow = *(struct ndpi_flow_info**)node;
  u_int16_t thread_id = *((u_int16_t*)user_data);

  if((flow->detected_protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN)
     || (flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN))
    return;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) {
    /* Avoid walking the same node multiple times */
    all_flows[num_flows].thread_id = thread_id, all_flows[num_flows].flow = flow;
    num_flows++;
  }
}

/* ********************************** */

/**
 * @brief Known Proto Walker
 */
static void node_print_known_proto_walker(const void *node,
                                          ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow_info *flow = *(struct ndpi_flow_info**)node;
  u_int16_t thread_id = *((u_int16_t*)user_data);

  if((flow->detected_protocol.master_protocol == NDPI_PROTOCOL_UNKNOWN)
     && (flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN))
    return;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) {
    /* Avoid walking the same node multiple times */
    all_flows[num_flows].thread_id = thread_id, all_flows[num_flows].flow = flow;
    num_flows++;
  }
}

/* ********************************** */

/**
 * @brief Proto Guess Walker
 */
static void node_proto_guess_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;
  u_int16_t thread_id = *((u_int16_t *) user_data), proto;

  if(flow == NULL) return;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
    if((!flow->detection_completed) && flow->ndpi_flow) {
      u_int8_t proto_guessed;

      malloc_size_stats = 1;
      flow->detected_protocol = ndpi_detection_giveup(ndpi_thread_info[0].workflow->ndpi_struct,
                                                      flow->ndpi_flow, enable_protocol_guess, &proto_guessed);
      malloc_size_stats = 0;

      if(enable_protocol_guess) ndpi_thread_info[thread_id].workflow->stats.guessed_flow_protocols++;
    }

    process_ndpi_collected_info(ndpi_thread_info[thread_id].workflow, flow);

    proto = flow->detected_protocol.app_protocol ? flow->detected_protocol.app_protocol : flow->detected_protocol.master_protocol;

    proto = ndpi_map_user_proto_id_to_ndpi_id(ndpi_thread_info[thread_id].workflow->ndpi_struct, proto);

    ndpi_thread_info[thread_id].workflow->stats.protocol_counter[proto]       += flow->src2dst_packets + flow->dst2src_packets;
    ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes[proto] += flow->src2dst_bytes + flow->dst2src_bytes;
    ndpi_thread_info[thread_id].workflow->stats.protocol_flows[proto]++;
    ndpi_thread_info[thread_id].workflow->stats.flow_confidence[flow->confidence]++;
    ndpi_thread_info[thread_id].workflow->stats.num_dissector_calls += flow->num_dissector_calls;
  }
}

/* *********************************************** */

void updateScanners(struct single_flow_info **scanners, u_int32_t saddr,
                    u_int8_t version, u_int32_t dport) {
  struct single_flow_info *f;
  struct port_flow_info *p;

  HASH_FIND_INT(*scanners, (int *)&saddr, f);

  if(f == NULL) {
    f = (struct single_flow_info*)ndpi_malloc(sizeof(struct single_flow_info));
    if(!f) return;
    f->saddr = saddr;
    f->version = version;
    f->tot_flows = 1;
    f->ports = NULL;

    p = (struct port_flow_info*)ndpi_malloc(sizeof(struct port_flow_info));

    if(!p) {
      ndpi_free(f);
      return;
    } else
      p->port = dport, p->num_flows = 1;

    HASH_ADD_INT(f->ports, port, p);
    HASH_ADD_INT(*scanners, saddr, f);
  } else{
    struct port_flow_info *pp;
    f->tot_flows++;

    HASH_FIND_INT(f->ports, (int *)&dport, pp);

    if(pp == NULL) {
      pp = (struct port_flow_info*)ndpi_malloc(sizeof(struct port_flow_info));
      if(!pp) return;
      pp->port = dport, pp->num_flows = 1;

      HASH_ADD_INT(f->ports, port, pp);
    } else
      pp->num_flows++;
  }
}

/* *********************************************** */

int updateIpTree(u_int32_t key, u_int8_t version,
                 addr_node **vrootp, const char *proto) {
  addr_node *q;
  addr_node **rootp = vrootp;

  if(rootp == (addr_node **)0)
    return 0;

  while(*rootp != (addr_node *)0) {
    /* Knuth's T1: */
    if((version == (*rootp)->version) && (key == (*rootp)->addr)) {
      /* T2: */
      return ++((*rootp)->count);
    }

    rootp = (key < (*rootp)->addr) ?
      &(*rootp)->left :                /* T3: follow left branch */
      &(*rootp)->right;                /* T4: follow right branch */
  }

  q = (addr_node *) ndpi_malloc(sizeof(addr_node));        /* T5: key not found */
  if(q != (addr_node *)0) {                        /* make new node */
    *rootp = q;                                        /* link new node to old */

    q->addr = key;
    q->version = version;
    strncpy(q->proto, proto, sizeof(q->proto) - 1);
    q->proto[sizeof(q->proto) - 1] = '\0';
    q->count = UPDATED_TREE;
    q->left = q->right = (addr_node *)0;

    return q->count;
  }

  return(0);
}
/* *********************************************** */

void freeIpTree(addr_node *root) {
  if(root == NULL)
    return;

  freeIpTree(root->left);
  freeIpTree(root->right);
  ndpi_free(root);
}

/* *********************************************** */

void updateTopIpAddress(u_int32_t addr, u_int8_t version, const char *proto,
                        int count, struct info_pair top[], int size) {
  struct info_pair pair;
  int min = count;
  int update = 0;
  int min_i = 0;
  int i;

  if(count == 0) return;

  pair.addr = addr;
  pair.version = version;
  pair.count = count;
  strncpy(pair.proto, proto, sizeof(pair.proto) - 1);
  pair.proto[sizeof(pair.proto) - 1] = '\0';

  for(i=0; i<size; i++) {
    /* if the same ip with a bigger
       count just update it     */
    if(top[i].addr == addr) {
      top[i].count = count;
      return;
    }
    /* if array is not full yet
       add it to the first empty place */
    if(top[i].count == 0) {
      top[i] = pair;
      return;
    }
  }

  /* if bigger than the smallest one, replace it */
  for(i=0; i<size; i++) {
    if(top[i].count < count && top[i].count < min) {
      min = top[i].count;
      min_i = i;
      update = 1;
    }
  }

  if(update)
    top[min_i] = pair;
}

/* *********************************************** */

static void updatePortStats(struct port_stats **stats, u_int32_t port,
                            u_int32_t addr, u_int8_t version,
                            u_int32_t num_pkts, u_int32_t num_bytes,
                            const char *proto) {

  struct port_stats *s = NULL;
  int count = 0;

  HASH_FIND_INT(*stats, &port, s);
  if(s == NULL) {
    s = (struct port_stats*)ndpi_calloc(1, sizeof(struct port_stats));
    if(!s) return;

    s->port = port, s->num_pkts = num_pkts, s->num_bytes = num_bytes;
    s->num_addr = 1, s->cumulative_addr = 1; s->num_flows = 1;

    updateTopIpAddress(addr, version, proto, 1, s->top_ip_addrs, MAX_NUM_IP_ADDRESS);

    s->addr_tree = (addr_node *) ndpi_malloc(sizeof(addr_node));
    if(!s->addr_tree) {
      ndpi_free(s);
      return;
    }

    s->addr_tree->addr = addr;
    s->addr_tree->version = version;
    strncpy(s->addr_tree->proto, proto, sizeof(s->addr_tree->proto) - 1);
    s->addr_tree->proto[sizeof(s->addr_tree->proto) - 1] = '\0';
    s->addr_tree->count = 1;
    s->addr_tree->left = NULL;
    s->addr_tree->right = NULL;

    HASH_ADD_INT(*stats, port, s);
  }
  else{
    count = updateIpTree(addr, version, &(*s).addr_tree, proto);

    if(count == UPDATED_TREE) s->num_addr++;

    if(count) {
      s->cumulative_addr++;
      updateTopIpAddress(addr, version, proto, count, s->top_ip_addrs, MAX_NUM_IP_ADDRESS);
    }

    s->num_pkts += num_pkts, s->num_bytes += num_bytes, s->num_flows++;
  }
}

/* *********************************************** */

/* @brief heuristic choice for receiver stats */
static int acceptable(u_int32_t num_pkts) {
  return num_pkts > 5;
}

/* *********************************************** */

static int receivers_sort(void *_a, void *_b) {
  struct receiver *a = (struct receiver *)_a;
  struct receiver *b = (struct receiver *)_b;

  return(b->num_pkts - a->num_pkts);
}

/* *********************************************** */

static int receivers_sort_asc(void *_a, void *_b) {
  struct receiver *a = (struct receiver *)_a;
  struct receiver *b = (struct receiver *)_b;

  return(a->num_pkts - b->num_pkts);
}

/* ***************************************************** */
/*@brief removes first (size - max) elements from hash table.
 * hash table is ordered in ascending order.
 */
static struct receiver *cutBackTo(struct receiver **rcvrs, u_int32_t size, u_int32_t max) {
  struct receiver *r, *tmp;
  int i=0;
  int count;

  if(size < max) //return the original table
    return *rcvrs;

  count = size - max;

  HASH_ITER(hh, *rcvrs, r, tmp) {
    if(i++ == count)
      return r;
    HASH_DEL(*rcvrs, r);
    ndpi_free(r);
  }

  return(NULL);

}

/* *********************************************** */
/*@brief merge first table to the second table.
 * if element already in the second table
 *  then updates its value
 * else adds it to the second table
 */
static void mergeTables(struct receiver **primary, struct receiver **secondary) {
  struct receiver *r, *s, *tmp;

  HASH_ITER(hh, *primary, r, tmp) {
    HASH_FIND_INT(*secondary, (int *)&(r->addr), s);
    if(s == NULL) {
      s = (struct receiver *)ndpi_malloc(sizeof(struct receiver));
      if(!s) return;

      s->addr = r->addr;
      s->version = r->version;
      s->num_pkts = r->num_pkts;

      HASH_ADD_INT(*secondary, addr, s);
    }
    else
      s->num_pkts += r->num_pkts;

    HASH_DEL(*primary, r);
    ndpi_free(r);
  }
}
/* *********************************************** */

static void deleteReceivers(struct receiver *rcvrs) {
  struct receiver *current, *tmp;

  HASH_ITER(hh, rcvrs, current, tmp) {
    HASH_DEL(rcvrs, current);
    ndpi_free(current);
  }
}

/* *********************************************** */
/* implementation of: https://jeroen.massar.ch/presentations/files/FloCon2010-TopK.pdf
 *
 * if(table1.size < max1 || acceptable) {
 *    create new element and add to the table1
 *    if(table1.size > max2) {
 *      cut table1 back to max1
 *      merge table 1 to table2
 *      if(table2.size > max1)
 *        cut table2 back to max1
 *    }
 * }
 * else
 *   update table1
 */
static void updateReceivers(struct receiver **rcvrs, u_int32_t dst_addr,
                            u_int8_t version, u_int32_t num_pkts,
                            struct receiver **topRcvrs) {
  struct receiver *r;
  u_int32_t size;
  int a;

  HASH_FIND_INT(*rcvrs, (int *)&dst_addr, r);
  if(r == NULL) {
    if(((size = HASH_COUNT(*rcvrs)) < MAX_TABLE_SIZE_1)
       || ((a = acceptable(num_pkts)) != 0)) {
      r = (struct receiver *)ndpi_malloc(sizeof(struct receiver));
      if(!r) return;

      r->addr = dst_addr;
      r->version = version;
      r->num_pkts = num_pkts;

      HASH_ADD_INT(*rcvrs, addr, r);

      if((size = HASH_COUNT(*rcvrs)) > MAX_TABLE_SIZE_2) {

        HASH_SORT(*rcvrs, receivers_sort_asc);
        *rcvrs = cutBackTo(rcvrs, size, MAX_TABLE_SIZE_1);
        mergeTables(rcvrs, topRcvrs);

        if((size = HASH_COUNT(*topRcvrs)) > MAX_TABLE_SIZE_1) {
          HASH_SORT(*topRcvrs, receivers_sort_asc);
          *topRcvrs = cutBackTo(topRcvrs, size, MAX_TABLE_SIZE_1);
        }

        *rcvrs = NULL;
      }
    }
  }
  else
    r->num_pkts += num_pkts;
}

/* *********************************************** */

static void deleteScanners(struct single_flow_info *scanners) {
  struct single_flow_info *s, *tmp;
  struct port_flow_info *p, *tmp2;

  HASH_ITER(hh, scanners, s, tmp) {
    HASH_ITER(hh, s->ports, p, tmp2) {
      if(s->ports) HASH_DEL(s->ports, p);
      ndpi_free(p);
    }
    HASH_DEL(scanners, s);
    ndpi_free(s);
  }
}

/* *********************************************** */

static void deletePortsStats(struct port_stats *stats) {
  struct port_stats *current_port, *tmp;

  HASH_ITER(hh, stats, current_port, tmp) {
    HASH_DEL(stats, current_port);
    freeIpTree(current_port->addr_tree);
    ndpi_free(current_port);
  }
}

/* *********************************************** */

/**
 * @brief Ports stats
 */
static void port_stats_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
    struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;
    u_int16_t thread_id = *(int *)user_data;
    u_int16_t sport, dport;
    char proto[16];

    sport = ntohs(flow->src_port), dport = ntohs(flow->dst_port);

    /* get app level protocol */
    if(flow->detected_protocol.master_protocol) {
      ndpi_protocol2name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
                         flow->detected_protocol, proto, sizeof(proto));
    } else {
      strncpy(proto, ndpi_get_proto_name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
                                         flow->detected_protocol.app_protocol),sizeof(proto) - 1);
      proto[sizeof(proto) - 1] = '\0';
    }

    if(flow->protocol == IPPROTO_TCP
       && (flow->src2dst_packets == 1) && (flow->dst2src_packets == 0)) {
      updateScanners(&scannerHosts, flow->src_ip, flow->ip_version, dport);
    }

    updateReceivers(&receivers, flow->dst_ip, flow->ip_version,
                    flow->src2dst_packets, &topReceivers);

    updatePortStats(&srcStats, sport, flow->src_ip, flow->ip_version,
                    flow->src2dst_packets, flow->src2dst_bytes, proto);

    updatePortStats(&dstStats, dport, flow->dst_ip, flow->ip_version,
                    flow->dst2src_packets, flow->dst2src_bytes, proto);
  }
}

/* *********************************************** */

/**
 * @brief Idle Scan Walker
 */
static void node_idle_scan_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;
  u_int16_t thread_id = *((u_int16_t *) user_data);

  if(ndpi_thread_info[thread_id].num_idle_flows == IDLE_SCAN_BUDGET) /* TODO optimise with a budget-based walk */
    return;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
    if(flow->last_seen_ms + MAX_IDLE_TIME < ndpi_thread_info[thread_id].workflow->last_time) {

      /* update stats */
      node_proto_guess_walker(node, which, depth, user_data);
      if(verbose == 3)
        port_stats_walker(node, which, depth, user_data);

      if((flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) && !undetected_flows_deleted)
        undetected_flows_deleted = 1;

      ndpi_flow_info_free_data(flow);
      ndpi_thread_info[thread_id].workflow->stats.ndpi_flow_count--;

      /* adding to a queue (we can't delete it from the tree inline ) */
      ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows++] = flow;
    }
  }
}

/* *********************************************** */

#if 0
/**
 * @brief Print debug
 */
static void debug_printf(u_int32_t protocol, void *id_struct,
                         ndpi_log_level_t log_level,
                         const char *format, ...) {
  va_list va_ap;
  struct tm result;

  if(log_level <= nDPI_LogLevel) {
    char buf[8192], out_buf[8192];
    char theDate[32];
    const char *extra_msg = "";
    time_t theTime = time(NULL);

    va_start (va_ap, format);

    if(log_level == NDPI_LOG_ERROR)
      extra_msg = "ERROR: ";
    else if(log_level == NDPI_LOG_TRACE)
      extra_msg = "TRACE: ";
    else
      extra_msg = "DEBUG: ";

    memset(buf, 0, sizeof(buf));
    strftime(theDate, 32, "%d/%b/%Y %H:%M:%S", localtime_r(&theTime,&result));
    ndpi_snprintf(buf, sizeof(buf)-1, format, va_ap);

    ndpi_snprintf(out_buf, sizeof(out_buf), "%s %s%s", theDate, extra_msg, buf);
    printf("%s", out_buf);
    fflush(stdout);
  }

  va_end(va_ap);
}
#endif

/* *********************************************** */

/**
 * @brief Setup for detection begin
 */
static void setupDetection(u_int16_t thread_id, pcap_t * pcap_handle) {
  NDPI_PROTOCOL_BITMASK enabled_bitmask;
  struct ndpi_workflow_prefs prefs;
  int i;

  memset(&prefs, 0, sizeof(prefs));
  prefs.decode_tunnels = decode_tunnels;
  prefs.num_roots = NUM_ROOTS;
  prefs.max_ndpi_flows = MAX_NDPI_FLOWS;
  prefs.quiet_mode = quiet_mode;
  prefs.ignore_vlanid = ignore_vlanid;

  memset(&ndpi_thread_info[thread_id], 0, sizeof(ndpi_thread_info[thread_id]));
  ndpi_thread_info[thread_id].workflow = ndpi_workflow_init(&prefs, pcap_handle, 1,
                                                            serialization_format);

  /* Protocols to enable/disable. Default: everything is enabled */
  NDPI_BITMASK_SET_ALL(enabled_bitmask);
  if(_disabled_protocols != NULL) {
    if(parse_proto_name_list(_disabled_protocols, &enabled_bitmask, 1))
      exit(-1);
  }

  if(_categoriesDirPath) {
    int failed_files = ndpi_load_categories_dir(ndpi_thread_info[thread_id].workflow->ndpi_struct, _categoriesDirPath);
    if (failed_files < 0) {
      fprintf(stderr, "Failed to parse all *.list files in: %s\n", _categoriesDirPath);
      exit(-1);
    }
  }
  
  if(_riskyDomainFilePath)
    ndpi_load_risk_domain_file(ndpi_thread_info[thread_id].workflow->ndpi_struct, _riskyDomainFilePath);

  if(_maliciousJA3Path)
    ndpi_load_malicious_ja3_file(ndpi_thread_info[thread_id].workflow->ndpi_struct, _maliciousJA3Path);

  if(_maliciousSHA1Path)
    ndpi_load_malicious_sha1_file(ndpi_thread_info[thread_id].workflow->ndpi_struct, _maliciousSHA1Path);
  
  if(_customCategoryFilePath) {
    char *label = strrchr(_customCategoryFilePath, '/');

    if(label != NULL)
      label = &label[1];
    else
      label = _customCategoryFilePath;

    int failed_lines = ndpi_load_categories_file(ndpi_thread_info[thread_id].workflow->ndpi_struct, _customCategoryFilePath, label);
    if (failed_lines < 0) {
      fprintf(stderr, "Failed to parse custom categories file: %s\n", _customCategoryFilePath);
      exit(-1);
    }
  }

  /* Make sure to load lists before finalizing the initialization */
  ndpi_set_protocol_detection_bitmask2(ndpi_thread_info[thread_id].workflow->ndpi_struct, &enabled_bitmask);

  // clear memory for results
  memset(ndpi_thread_info[thread_id].workflow->stats.protocol_counter, 0,
         sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_counter));
  memset(ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes, 0,
         sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes));
  memset(ndpi_thread_info[thread_id].workflow->stats.protocol_flows, 0,
         sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_flows));
  memset(ndpi_thread_info[thread_id].workflow->stats.flow_confidence, 0,
         sizeof(ndpi_thread_info[thread_id].workflow->stats.flow_confidence));

  if(_protoFilePath != NULL)
    ndpi_load_protocols_file(ndpi_thread_info[thread_id].workflow->ndpi_struct, _protoFilePath);

  /* Enable/disable/configure LRU caches size here */
  for(i = 0; i < NDPI_LRUCACHE_MAX; i++) {
    if(lru_cache_sizes[i] != -1)
      ndpi_set_lru_cache_size(ndpi_thread_info[thread_id].workflow->ndpi_struct,
			      i, lru_cache_sizes[i]);
  }

  /* Enable/disable LRU caches TTL here */
  for(i = 0; i < NDPI_LRUCACHE_MAX; i++) {
    if(lru_cache_ttls[i] != -1)
      ndpi_set_lru_cache_ttl(ndpi_thread_info[thread_id].workflow->ndpi_struct,
			     i, lru_cache_ttls[i]);
  }

  /* Set aggressiviness here */
  for(i = 0; i < NDPI_MAX_SUPPORTED_PROTOCOLS; i++) {
    if(aggressiveness[i] != -1)
      ndpi_set_protocol_aggressiveness(ndpi_thread_info[thread_id].workflow->ndpi_struct, i, aggressiveness[i]);
  }

  if(stun_monitoring_pkts_to_process != -1 &&
     stun_monitoring_flags != -1)
    ndpi_set_monitoring_state(ndpi_thread_info[thread_id].workflow->ndpi_struct, NDPI_PROTOCOL_STUN,
                              stun_monitoring_pkts_to_process, stun_monitoring_flags);

  ndpi_finalize_initialization(ndpi_thread_info[thread_id].workflow->ndpi_struct);

  if(enable_doh_dot_detection)
    ndpi_set_detection_preferences(ndpi_thread_info[thread_id].workflow->ndpi_struct, ndpi_pref_enable_tls_block_dissection, 1);
}

/* *********************************************** */

/**
 * @brief End of detection and free flow
 */
static void terminateDetection(u_int16_t thread_id) {
  ndpi_workflow_free(ndpi_thread_info[thread_id].workflow);
  ndpi_thread_info[thread_id].workflow = NULL;
}

/* *********************************************** */

/**
 * @brief Traffic stats format
 */
char* formatTraffic(float numBits, int bits, char *buf) {
  char unit;

  if(bits)
    unit = 'b';
  else
    unit = 'B';

  if(numBits < 1024) {
    ndpi_snprintf(buf, 32, "%lu %c", (unsigned long)numBits, unit);
  } else if(numBits < (1024*1024)) {
    ndpi_snprintf(buf, 32, "%.2f K%c", (float)(numBits)/1024, unit);
  } else {
    float tmpMBits = ((float)numBits)/(1024*1024);

    if(tmpMBits < 1024) {
      ndpi_snprintf(buf, 32, "%.2f M%c", tmpMBits, unit);
    } else {
      tmpMBits /= 1024;

      if(tmpMBits < 1024) {
        ndpi_snprintf(buf, 32, "%.2f G%c", tmpMBits, unit);
      } else {
        ndpi_snprintf(buf, 32, "%.2f T%c", (float)(tmpMBits)/1024, unit);
      }
    }
  }

  return(buf);
}

/* *********************************************** */

/**
 * @brief Packets stats format
 */
char* formatPackets(float numPkts, char *buf) {

  if(numPkts < 1000) {
    ndpi_snprintf(buf, 32, "%.2f", numPkts);
  } else if(numPkts < (1000*1000)) {
    ndpi_snprintf(buf, 32, "%.2f K", numPkts/1000);
  } else {
    numPkts /= (1000*1000);
    ndpi_snprintf(buf, 32, "%.2f M", numPkts);
  }

  return(buf);
}

/* *********************************************** */

/**
 * @brief Bytes stats format
 */
char* formatBytes(u_int32_t howMuch, char *buf, u_int buf_len) {
  char unit = 'B';

  if(howMuch < 1024) {
    ndpi_snprintf(buf, buf_len, "%lu %c", (unsigned long)howMuch, unit);
  } else if(howMuch < (1024*1024)) {
    ndpi_snprintf(buf, buf_len, "%.2f K%c", (float)(howMuch)/1024, unit);
  } else {
    float tmpGB = ((float)howMuch)/(1024*1024);

    if(tmpGB < 1024) {
      ndpi_snprintf(buf, buf_len, "%.2f M%c", tmpGB, unit);
    } else {
      tmpGB /= 1024;

      ndpi_snprintf(buf, buf_len, "%.2f G%c", tmpGB, unit);
    }
  }

  return(buf);
}

/* *********************************************** */

static int port_stats_sort(void *_a, void *_b) {
  struct port_stats *a = (struct port_stats*)_a;
  struct port_stats *b = (struct port_stats*)_b;

  if(b->num_pkts == 0 && a->num_pkts == 0)
    return(b->num_flows - a->num_flows);

  return(b->num_pkts - a->num_pkts);
}

/* *********************************************** */

static int info_pair_cmp (const void *_a, const void *_b)
{
  struct info_pair *a = (struct info_pair *)_a;
  struct info_pair *b = (struct info_pair *)_b;

  return b->count - a->count;
}

/* *********************************************** */

void printPortStats(struct port_stats *stats) {
  struct port_stats *s, *tmp;
  char addr_name[48];
  int i = 0, j = 0;

  HASH_ITER(hh, stats, s, tmp) {
    i++;
    printf("\t%2d\tPort %5u\t[%u IP address(es)/%u flows/%u pkts/%u bytes]\n\t\tTop IP Stats:\n",
           i, s->port, s->num_addr, s->num_flows, s->num_pkts, s->num_bytes);

    qsort(&s->top_ip_addrs[0], MAX_NUM_IP_ADDRESS, sizeof(struct info_pair), info_pair_cmp);

    for(j=0; j<MAX_NUM_IP_ADDRESS; j++) {
      if(s->top_ip_addrs[j].count != 0) {
        if(s->top_ip_addrs[j].version == IPVERSION) {
          inet_ntop(AF_INET, &(s->top_ip_addrs[j].addr), addr_name, sizeof(addr_name));
        } else {
          inet_ntop(AF_INET6, &(s->top_ip_addrs[j].addr),  addr_name, sizeof(addr_name));
        }

        printf("\t\t%-36s ~ %.2f%%\n", addr_name,
               ((s->top_ip_addrs[j].count) * 100.0) / s->cumulative_addr);
      }
    }

    printf("\n");
    if(i >= 10) break;
  }
}

/* *********************************************** */

static void node_flow_risk_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow_info *f = *(struct ndpi_flow_info**)node;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
    if(f->risk) {
      u_int j;

      flows_with_risks++;

      for(j = 0; j < NDPI_MAX_RISK; j++) {
        ndpi_risk_enum r = (ndpi_risk_enum)j;

        if(NDPI_ISSET_BIT(f->risk, r))
          risks_found++, risk_stats[r]++;
      }
    }
  }
}

/* *********************************************** */

static void printRiskStats() {
  if(!quiet_mode) {
    u_int thread_id, i;

    for(thread_id = 0; thread_id < num_threads; thread_id++) {
      for(i=0; i<NUM_ROOTS; i++)
        ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
		   node_flow_risk_walker, &thread_id);
    }

    if(risks_found) {
      printf("\nRisk stats [found %u (%.1f %%) flows with risks]:\n",
             flows_with_risks,
             (100.*flows_with_risks)/(float)cumulative_stats.ndpi_flow_count);

      for(i = 0; i < NDPI_MAX_RISK; i++) {
        ndpi_risk_enum r = (ndpi_risk_enum)i;

        if(risk_stats[r] != 0)
          printf("\t%-40s %5u [%4.01f %%]\n", ndpi_risk2str(r), risk_stats[r],
                 (float)(risk_stats[r]*100)/(float)risks_found);
      }

      printf("\n\tNOTE: as one flow can have multiple risks set, the sum of the\n"
             "\t      last column can exceed the number of flows with risks.\n");
      printf("\n\n");
    }
  }
}

/* *********************************************** */

/*function to use in HASH_SORT function in verbose == 4 to order in creasing order to delete host with the leatest occurency*/
static int hash_stats_sort_to_order(void *_a, void *_b) {
  struct hash_stats *a = (struct hash_stats*)_a;
  struct hash_stats *b = (struct hash_stats*)_b;

  return (a->occurency - b->occurency);
}

/* *********************************************** */

/*function to use in HASH_SORT function in verbose == 4 to print in decreasing order*/
static int hash_stats_sort_to_print(void *_a, void *_b) {
  struct hash_stats *a = (struct hash_stats*)_a;
  struct hash_stats *b = (struct hash_stats*)_b;

  return (b->occurency - a->occurency);
}

/* *********************************************** */

static void printFlowsStats() {
  int thread_id;
  u_int32_t total_flows = 0;
  FILE *out = results_file ? results_file : stdout;

  if(enable_payload_analyzer)
    ndpi_report_payload_stats(out);

  for(thread_id = 0; thread_id < num_threads; thread_id++)
    total_flows += ndpi_thread_info[thread_id].workflow->num_allocated_flows;

  if((all_flows = (struct flow_info*)ndpi_malloc(sizeof(struct flow_info)*total_flows)) == NULL) {
    fprintf(out, "Fatal error: not enough memory\n");
    exit(-1);
  }

  if(verbose) {
    ndpi_host_ja3_fingerprints *ja3ByHostsHashT = NULL; // outer hash table
    ndpi_ja3_fingerprints_host *hostByJA3C_ht = NULL;   // for client
    ndpi_ja3_fingerprints_host *hostByJA3S_ht = NULL;   // for server
    unsigned int i;
    ndpi_host_ja3_fingerprints *ja3ByHost_element = NULL;
    ndpi_ja3_info *info_of_element = NULL;
    ndpi_host_ja3_fingerprints *tmp = NULL;
    ndpi_ja3_info *tmp2 = NULL;
    unsigned int num_ja3_client;
    unsigned int num_ja3_server;

    fprintf(out, "\n");

    num_flows = 0;
    for(thread_id = 0; thread_id < num_threads; thread_id++) {
      for(i=0; i<NUM_ROOTS; i++)
        ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
                   node_print_known_proto_walker, &thread_id);
    }

    if((verbose == 2) || (verbose == 3)) {
      for(i = 0; i < num_flows; i++) {
        ndpi_host_ja3_fingerprints *ja3ByHostFound = NULL;
        ndpi_ja3_fingerprints_host *hostByJA3Found = NULL;

        //check if this is a ssh-ssl flow
        if(all_flows[i].flow->ssh_tls.ja3_client[0] != '\0') {
          //looking if the host is already in the hash table
          HASH_FIND_INT(ja3ByHostsHashT, &(all_flows[i].flow->src_ip), ja3ByHostFound);

          //host ip -> ja3
          if(ja3ByHostFound == NULL) {
            //adding the new host
            ndpi_host_ja3_fingerprints *newHost = ndpi_malloc(sizeof(ndpi_host_ja3_fingerprints));
            newHost->host_client_info_hasht = NULL;
            newHost->host_server_info_hasht = NULL;
            newHost->ip_string = all_flows[i].flow->src_name;
            newHost->ip = all_flows[i].flow->src_ip;
            newHost->dns_name = all_flows[i].flow->host_server_name;

            ndpi_ja3_info *newJA3 = ndpi_malloc(sizeof(ndpi_ja3_info));
            newJA3->ja3 = all_flows[i].flow->ssh_tls.ja3_client;
            newJA3->unsafe_cipher = all_flows[i].flow->ssh_tls.client_unsafe_cipher;
            //adding the new ja3 fingerprint
            HASH_ADD_KEYPTR(hh, newHost->host_client_info_hasht,
                            newJA3->ja3, strlen(newJA3->ja3), newJA3);
            //adding the new host
            HASH_ADD_INT(ja3ByHostsHashT, ip, newHost);
          } else {
            //host already in the hash table
            ndpi_ja3_info *infoFound = NULL;

            HASH_FIND_STR(ja3ByHostFound->host_client_info_hasht,
                          all_flows[i].flow->ssh_tls.ja3_client, infoFound);

            if(infoFound == NULL) {
              ndpi_ja3_info *newJA3 = ndpi_malloc(sizeof(ndpi_ja3_info));
              newJA3->ja3 = all_flows[i].flow->ssh_tls.ja3_client;
              newJA3->unsafe_cipher = all_flows[i].flow->ssh_tls.client_unsafe_cipher;
              HASH_ADD_KEYPTR(hh, ja3ByHostFound->host_client_info_hasht,
                              newJA3->ja3, strlen(newJA3->ja3), newJA3);
            }
          }

          //ja3 -> host ip
          HASH_FIND_STR(hostByJA3C_ht, all_flows[i].flow->ssh_tls.ja3_client, hostByJA3Found);
          if(hostByJA3Found == NULL) {
            ndpi_ip_dns *newHost = ndpi_malloc(sizeof(ndpi_ip_dns));

            newHost->ip = all_flows[i].flow->src_ip;
            newHost->ip_string = all_flows[i].flow->src_name;
            newHost->dns_name = all_flows[i].flow->host_server_name;

            ndpi_ja3_fingerprints_host *newElement = ndpi_malloc(sizeof(ndpi_ja3_fingerprints_host));
            newElement->ja3 = all_flows[i].flow->ssh_tls.ja3_client;
            newElement->unsafe_cipher = all_flows[i].flow->ssh_tls.client_unsafe_cipher;
            newElement->ipToDNS_ht = NULL;

            HASH_ADD_INT(newElement->ipToDNS_ht, ip, newHost);
            HASH_ADD_KEYPTR(hh, hostByJA3C_ht, newElement->ja3, strlen(newElement->ja3),
                            newElement);
          } else {
            ndpi_ip_dns *innerElement = NULL;
            HASH_FIND_INT(hostByJA3Found->ipToDNS_ht, &(all_flows[i].flow->src_ip), innerElement);
            if(innerElement == NULL) {
              ndpi_ip_dns *newInnerElement = ndpi_malloc(sizeof(ndpi_ip_dns));
              newInnerElement->ip = all_flows[i].flow->src_ip;
              newInnerElement->ip_string = all_flows[i].flow->src_name;
              newInnerElement->dns_name = all_flows[i].flow->host_server_name;
              HASH_ADD_INT(hostByJA3Found->ipToDNS_ht, ip, newInnerElement);
            }
          }
        }

        if(all_flows[i].flow->ssh_tls.ja3_server[0] != '\0') {
          //looking if the host is already in the hash table
          HASH_FIND_INT(ja3ByHostsHashT, &(all_flows[i].flow->dst_ip), ja3ByHostFound);
          if(ja3ByHostFound == NULL) {
            //adding the new host in the hash table
            ndpi_host_ja3_fingerprints *newHost = ndpi_malloc(sizeof(ndpi_host_ja3_fingerprints));
            newHost->host_client_info_hasht = NULL;
            newHost->host_server_info_hasht = NULL;
            newHost->ip_string = all_flows[i].flow->dst_name;
            newHost->ip = all_flows[i].flow->dst_ip;
            newHost->dns_name = all_flows[i].flow->ssh_tls.server_info;

            ndpi_ja3_info *newJA3 = ndpi_malloc(sizeof(ndpi_ja3_info));
            newJA3->ja3 = all_flows[i].flow->ssh_tls.ja3_server;
            newJA3->unsafe_cipher = all_flows[i].flow->ssh_tls.server_unsafe_cipher;
            //adding the new ja3 fingerprint
            HASH_ADD_KEYPTR(hh, newHost->host_server_info_hasht, newJA3->ja3,
                            strlen(newJA3->ja3), newJA3);
            //adding the new host
            HASH_ADD_INT(ja3ByHostsHashT, ip, newHost);
          } else {
            //host already in the hashtable
            ndpi_ja3_info *infoFound = NULL;
            HASH_FIND_STR(ja3ByHostFound->host_server_info_hasht,
                          all_flows[i].flow->ssh_tls.ja3_server, infoFound);
            if(infoFound == NULL) {
              ndpi_ja3_info *newJA3 = ndpi_malloc(sizeof(ndpi_ja3_info));
              newJA3->ja3 = all_flows[i].flow->ssh_tls.ja3_server;
              newJA3->unsafe_cipher = all_flows[i].flow->ssh_tls.server_unsafe_cipher;
              HASH_ADD_KEYPTR(hh, ja3ByHostFound->host_server_info_hasht,
                              newJA3->ja3, strlen(newJA3->ja3), newJA3);
            }
          }

          HASH_FIND_STR(hostByJA3S_ht, all_flows[i].flow->ssh_tls.ja3_server, hostByJA3Found);
          if(hostByJA3Found == NULL) {
            ndpi_ip_dns *newHost = ndpi_malloc(sizeof(ndpi_ip_dns));

            newHost->ip = all_flows[i].flow->dst_ip;
            newHost->ip_string = all_flows[i].flow->dst_name;
            newHost->dns_name = all_flows[i].flow->ssh_tls.server_info;;

            ndpi_ja3_fingerprints_host *newElement = ndpi_malloc(sizeof(ndpi_ja3_fingerprints_host));
            newElement->ja3 = all_flows[i].flow->ssh_tls.ja3_server;
            newElement->unsafe_cipher = all_flows[i].flow->ssh_tls.server_unsafe_cipher;
            newElement->ipToDNS_ht = NULL;

            HASH_ADD_INT(newElement->ipToDNS_ht, ip, newHost);
            HASH_ADD_KEYPTR(hh, hostByJA3S_ht, newElement->ja3, strlen(newElement->ja3),
                            newElement);
          } else {
            ndpi_ip_dns *innerElement = NULL;

            HASH_FIND_INT(hostByJA3Found->ipToDNS_ht, &(all_flows[i].flow->dst_ip), innerElement);
            if(innerElement == NULL) {
              ndpi_ip_dns *newInnerElement = ndpi_malloc(sizeof(ndpi_ip_dns));
              newInnerElement->ip = all_flows[i].flow->dst_ip;
              newInnerElement->ip_string = all_flows[i].flow->dst_name;
              newInnerElement->dns_name = all_flows[i].flow->ssh_tls.server_info;
              HASH_ADD_INT(hostByJA3Found->ipToDNS_ht, ip, newInnerElement);
            }
          }
        }
      }

      if(ja3ByHostsHashT) {
        ndpi_ja3_fingerprints_host *hostByJA3Element = NULL;
        ndpi_ja3_fingerprints_host *tmp3 = NULL;
        ndpi_ip_dns *innerHashEl = NULL;
        ndpi_ip_dns *tmp4 = NULL;

        if(verbose == 2) {
          /* for each host the number of flow with a ja3 fingerprint is printed */
          i = 1;

          fprintf(out, "JA3 Host Stats: \n");
          fprintf(out, "\t\t IP %-24s \t %-10s \n", "Address", "# JA3C");

          for(ja3ByHost_element = ja3ByHostsHashT; ja3ByHost_element != NULL;
              ja3ByHost_element = ja3ByHost_element->hh.next) {
            num_ja3_client = HASH_COUNT(ja3ByHost_element->host_client_info_hasht);
            num_ja3_server = HASH_COUNT(ja3ByHost_element->host_server_info_hasht);

            if(num_ja3_client > 0) {
              fprintf(out, "\t%d\t %-24s \t %-7u\n",
                      i,
                      ja3ByHost_element->ip_string,
                      num_ja3_client
                      );
              i++;
            }

          }
        } else if(verbose == 3) {
          int i = 1;
          int againstRepeat;
          ndpi_ja3_fingerprints_host *hostByJA3Element = NULL;
          ndpi_ja3_fingerprints_host *tmp3 = NULL;
          ndpi_ip_dns *innerHashEl = NULL;
          ndpi_ip_dns *tmp4 = NULL;

          //for each host it is printted the JA3C and JA3S, along the server name (if any)
          //and the security status

          fprintf(out, "JA3C/JA3S Host Stats: \n");
          fprintf(out, "\t%-7s %-24s %-34s %s\n", "", "IP", "JA3C", "JA3S");

          //reminder
          //ja3ByHostsHashT: hash table <ip, (ja3, ht_client, ht_server)>
          //ja3ByHost_element: element of ja3ByHostsHashT
          //info_of_element: element of the inner hash table of ja3ByHost_element
          HASH_ITER(hh, ja3ByHostsHashT, ja3ByHost_element, tmp) {
            num_ja3_client = HASH_COUNT(ja3ByHost_element->host_client_info_hasht);
            num_ja3_server = HASH_COUNT(ja3ByHost_element->host_server_info_hasht);
            againstRepeat = 0;
            if(num_ja3_client > 0) {
              HASH_ITER(hh, ja3ByHost_element->host_client_info_hasht, info_of_element, tmp2) {
                fprintf(out, "\t%-7d %-24s %s %s\n",
                        i,
                        ja3ByHost_element->ip_string,
                        info_of_element->ja3,
                        print_cipher(info_of_element->unsafe_cipher)
                        );
                againstRepeat = 1;
                i++;
              }
            }

            if(num_ja3_server > 0) {
              HASH_ITER(hh, ja3ByHost_element->host_server_info_hasht, info_of_element, tmp2) {
                fprintf(out, "\t%-7d %-24s %-34s %s %s %s%s%s\n",
                        i,
                        ja3ByHost_element->ip_string,
                        "",
                        info_of_element->ja3,
                        print_cipher(info_of_element->unsafe_cipher),
                        ja3ByHost_element->dns_name[0] ? "[" : "",
                        ja3ByHost_element->dns_name,
                        ja3ByHost_element->dns_name[0] ? "]" : ""
                        );
                i++;
              }
            }
          }

          i = 1;

          fprintf(out, "\nIP/JA3 Distribution:\n");
          fprintf(out, "%-15s %-39s %-26s\n", "", "JA3", "IP");
          HASH_ITER(hh, hostByJA3C_ht, hostByJA3Element, tmp3) {
            againstRepeat = 0;
            HASH_ITER(hh, hostByJA3Element->ipToDNS_ht, innerHashEl, tmp4) {
              if(againstRepeat == 0) {
                fprintf(out, "\t%-7d JA3C %s",
                        i,
                        hostByJA3Element->ja3
                        );
                fprintf(out, "   %-15s %s\n",
                        innerHashEl->ip_string,
                        print_cipher(hostByJA3Element->unsafe_cipher)
                        );
                againstRepeat = 1;
                i++;
              } else {
                fprintf(out, "\t%45s", "");
                fprintf(out, "   %-15s %s\n",
                        innerHashEl->ip_string,
                        print_cipher(hostByJA3Element->unsafe_cipher)
                        );
              }
            }
          }
          HASH_ITER(hh, hostByJA3S_ht, hostByJA3Element, tmp3) {
            againstRepeat = 0;
            HASH_ITER(hh, hostByJA3Element->ipToDNS_ht, innerHashEl, tmp4) {
              if(againstRepeat == 0) {
                fprintf(out, "\t%-7d JA3S %s",
                        i,
                        hostByJA3Element->ja3
                        );
                fprintf(out, "   %-15s %-10s %s%s%s\n",
                        innerHashEl->ip_string,
                        print_cipher(hostByJA3Element->unsafe_cipher),
                        innerHashEl->dns_name[0] ? "[" : "",
                        innerHashEl->dns_name,
                        innerHashEl->dns_name[0] ? "]" : ""
                        );
                againstRepeat = 1;
                i++;
              } else {
                fprintf(out, "\t%45s", "");
                fprintf(out, "   %-15s %-10s %s%s%s\n",
                        innerHashEl->ip_string,
                        print_cipher(hostByJA3Element->unsafe_cipher),
                        innerHashEl->dns_name[0] ? "[" : "",
                        innerHashEl->dns_name,
                        innerHashEl->dns_name[0] ? "]" : ""
                        );
              }
            }
          }
        }
        fprintf(out, "\n\n");

        //freeing the hash table
        HASH_ITER(hh, ja3ByHostsHashT, ja3ByHost_element, tmp) {
          HASH_ITER(hh, ja3ByHost_element->host_client_info_hasht, info_of_element, tmp2) {
            if(ja3ByHost_element->host_client_info_hasht)
              HASH_DEL(ja3ByHost_element->host_client_info_hasht, info_of_element);
            ndpi_free(info_of_element);
          }
          HASH_ITER(hh, ja3ByHost_element->host_server_info_hasht, info_of_element, tmp2) {
            if(ja3ByHost_element->host_server_info_hasht)
              HASH_DEL(ja3ByHost_element->host_server_info_hasht, info_of_element);
            ndpi_free(info_of_element);
          }
          HASH_DEL(ja3ByHostsHashT, ja3ByHost_element);
          ndpi_free(ja3ByHost_element);
        }

        HASH_ITER(hh, hostByJA3C_ht, hostByJA3Element, tmp3) {
          HASH_ITER(hh, hostByJA3C_ht->ipToDNS_ht, innerHashEl, tmp4) {
            if(hostByJA3Element->ipToDNS_ht)
              HASH_DEL(hostByJA3Element->ipToDNS_ht, innerHashEl);
            ndpi_free(innerHashEl);
          }
          HASH_DEL(hostByJA3C_ht, hostByJA3Element);
          ndpi_free(hostByJA3Element);
        }

        hostByJA3Element = NULL;
        HASH_ITER(hh, hostByJA3S_ht, hostByJA3Element, tmp3) {
          HASH_ITER(hh, hostByJA3S_ht->ipToDNS_ht, innerHashEl, tmp4) {
            if(hostByJA3Element->ipToDNS_ht)
              HASH_DEL(hostByJA3Element->ipToDNS_ht, innerHashEl);
            ndpi_free(innerHashEl);
          }
          HASH_DEL(hostByJA3S_ht, hostByJA3Element);
          ndpi_free(hostByJA3Element);
        }
      }
    }

    if (verbose == 4) {
		//how long the table could be
		unsigned int len_table_max = 1000;
	      	//number of element to delete when the table is full
		int toDelete = 10;
		struct hash_stats *hostsHashT = NULL;
		struct hash_stats *host_iter = NULL;
		struct hash_stats *tmp = NULL;
		int len_max = 0;

	      	for (i = 0; i<num_flows; i++) {

		if(all_flows[i].flow->host_server_name[0] != '\0') {

			int len = strlen(all_flows[i].flow->host_server_name);
			len_max = ndpi_max(len,len_max);

			struct hash_stats *hostFound;
			HASH_FIND_STR(hostsHashT, all_flows[i].flow->host_server_name, hostFound);

			if(hostFound == NULL) {
				struct hash_stats *newHost = (struct hash_stats*)ndpi_malloc(sizeof(hash_stats));
			      	newHost->domain_name = all_flows[i].flow->host_server_name;
				newHost->occurency = 1;
				if (HASH_COUNT(hostsHashT) == len_table_max) {
				  int i=0;
				  while (i<=toDelete) {

				    HASH_ITER(hh, hostsHashT, host_iter, tmp) {
				      HASH_DEL(hostsHashT,host_iter);
				      free(host_iter);
				      i++;
				    }
				  }

				}
				HASH_ADD_KEYPTR(hh, hostsHashT, newHost->domain_name, strlen(newHost->domain_name), newHost);
			}
			else
			  hostFound->occurency++;


		}

		if(all_flows[i].flow->ssh_tls.server_info[0] != '\0') {

			int len = strlen(all_flows[i].flow->host_server_name);
			len_max = ndpi_max(len,len_max);

			struct hash_stats *hostFound;
		  	HASH_FIND_STR(hostsHashT, all_flows[i].flow->ssh_tls.server_info, hostFound);

		  	if(hostFound == NULL) {
		    		struct hash_stats *newHost = (struct hash_stats*)ndpi_malloc(sizeof(hash_stats));
	      	    		newHost->domain_name = all_flows[i].flow->ssh_tls.server_info;
		    		newHost->occurency = 1;

	    			if ((HASH_COUNT(hostsHashT)) == len_table_max) {
				  int i=0;
				  while (i<toDelete) {

				    HASH_ITER(hh, hostsHashT, host_iter, tmp) {
			 	     HASH_DEL(hostsHashT,host_iter);
			  	    ndpi_free(host_iter);
			   	   i++;
			 	   }
				  }


	    			}
				HASH_ADD_KEYPTR(hh, hostsHashT, newHost->domain_name, strlen(newHost->domain_name), newHost);
			}
			else
			  hostFound->occurency++;


		}

		//sort the table by the least occurency
		HASH_SORT(hostsHashT, hash_stats_sort_to_order);
	}

	//sort the table in decreasing order to print
      	HASH_SORT(hostsHashT, hash_stats_sort_to_print);

	//print the element of the hash table
   	int j;
	HASH_ITER(hh, hostsHashT, host_iter, tmp) {

		printf("\t%s", host_iter->domain_name);
		//to print the occurency in aligned column
		int diff = len_max-strlen(host_iter->domain_name);
	    	for (j = 0; j <= diff+5;j++)
	    		printf (" ");
	    	printf("%d\n",host_iter->occurency);
	}
	printf("%s", "\n\n");

	//freeing the hash table
	HASH_ITER(hh, hostsHashT, host_iter, tmp) {
	   HASH_DEL(hostsHashT, host_iter);
	   ndpi_free(host_iter);
	}

  }

    /* Print all flows stats */

    qsort(all_flows, num_flows, sizeof(struct flow_info), cmpFlows);

    if(verbose > 1) {
#ifndef DIRECTION_BINS
      struct ndpi_bin *bins   = (struct ndpi_bin*)ndpi_malloc(sizeof(struct ndpi_bin)*num_flows);
      u_int16_t *cluster_ids  = (u_int16_t*)ndpi_malloc(sizeof(u_int16_t)*num_flows);
      u_int32_t num_flow_bins = 0;
#endif

      for(i=0; i<num_flows; i++) {
#ifndef DIRECTION_BINS
        if(enable_doh_dot_detection) {
          /* Discard flows with few packets per direction */
          if((all_flows[i].flow->src2dst_packets < 10)
             || (all_flows[i].flow->dst2src_packets < 10)
             /* Ignore flows for which we have not seen the beginning */
             )
            goto print_flow;

          if(all_flows[i].flow->protocol == 6 /* TCP */) {
            /* Discard flows with no SYN as we need to check ALPN */
            if((all_flows[i].flow->src2dst_syn_count == 0) || (all_flows[i].flow->dst2src_syn_count == 0))
              goto print_flow;

            if(all_flows[i].flow->detected_protocol.master_protocol == NDPI_PROTOCOL_TLS) {
              if((all_flows[i].flow->src2dst_packets+all_flows[i].flow->dst2src_packets) < 40)
                goto print_flow; /* Too few packets for TLS negotiation etc */
            }
          }
        }

        if(bins && cluster_ids) {
          u_int j;
          u_int8_t not_empty;

          if(enable_doh_dot_detection) {
            not_empty = 0;

            /* Check if bins are empty (and in this case discard it) */
            for(j=0; j<all_flows[i].flow->payload_len_bin.num_bins; j++)
              if(all_flows[i].flow->payload_len_bin.u.bins8[j] != 0) {
                not_empty = 1;
                break;
              }
          } else
            not_empty = 1;

          if(not_empty) {
            memcpy(&bins[num_flow_bins], &all_flows[i].flow->payload_len_bin, sizeof(struct ndpi_bin));
            ndpi_normalize_bin(&bins[num_flow_bins]);
            num_flow_bins++;
          }
        }
#endif

      print_flow:
        printFlow(i+1, all_flows[i].flow, all_flows[i].thread_id);
      }

#ifndef DIRECTION_BINS
      if(bins && cluster_ids && (num_bin_clusters > 0) && (num_flow_bins > 0)) {
        char buf[64];
        u_int j;
        struct ndpi_bin *centroids;

        if((centroids = (struct ndpi_bin*)ndpi_malloc(sizeof(struct ndpi_bin)*num_bin_clusters)) != NULL) {
          for(i=0; i<num_bin_clusters; i++)
            ndpi_init_bin(&centroids[i], ndpi_bin_family32 /* Use 32 bit to avoid overlaps */,
                          bins[0].num_bins);

          ndpi_cluster_bins(bins, num_flow_bins, num_bin_clusters, cluster_ids, centroids);

          fprintf(out, "\n"
                 "\tBin clusters\n"
                 "\t------------\n");

          for(j=0; j<num_bin_clusters; j++) {
            u_int16_t num_printed = 0;
            float max_similarity = 0;

            for(i=0; i<num_flow_bins; i++) {
              float similarity, s;

              if(cluster_ids[i] != j) continue;

              if(num_printed == 0) {
                fprintf(out, "\tCluster %u [", j);
                print_bin(out, NULL, &centroids[j]);
                fprintf(out, "]\n");
              }

              fprintf(out, "\t%u\t%-10s\t%s:%u <-> %s:%u\t[",
                      i,
                      ndpi_protocol2name(ndpi_thread_info[0].workflow->ndpi_struct,
                                         all_flows[i].flow->detected_protocol, buf, sizeof(buf)),
                      all_flows[i].flow->src_name,
                      ntohs(all_flows[i].flow->src_port),
                      all_flows[i].flow->dst_name,
                      ntohs(all_flows[i].flow->dst_port));

              print_bin(out, NULL, &bins[i]);
              fprintf(out, "][similarity: %f]",
                      (similarity = ndpi_bin_similarity(&centroids[j], &bins[i], 0, 0)));

              if(all_flows[i].flow->host_server_name[0] != '\0')
                fprintf(out, "[%s]", all_flows[i].flow->host_server_name);

              if(enable_doh_dot_detection) {
                if(((all_flows[i].flow->detected_protocol.master_protocol == NDPI_PROTOCOL_TLS)
                    || (all_flows[i].flow->detected_protocol.app_protocol == NDPI_PROTOCOL_TLS)
                    || (all_flows[i].flow->detected_protocol.app_protocol == NDPI_PROTOCOL_DOH_DOT)
                    )
                   && all_flows[i].flow->ssh_tls.advertised_alpns /* ALPN */
                   ) {
                  if(check_bin_doh_similarity(&bins[i], &s))
                    fprintf(out, "[DoH (%f distance)]", s);
                  else
                    fprintf(out, "[NO DoH (%f distance)]", s);
                } else {
                  if(all_flows[i].flow->ssh_tls.advertised_alpns == NULL)
                    fprintf(out, "[NO DoH check: missing ALPN]");
                }
              }

              fprintf(out, "\n");
              num_printed++;
              if(similarity > max_similarity) max_similarity = similarity;
            }

            if(num_printed) {
              fprintf(out, "\tMax similarity: %f\n", max_similarity);
              fprintf(out, "\n");
            }
          }

          for(i=0; i<num_bin_clusters; i++)
            ndpi_free_bin(&centroids[i]);

          ndpi_free(centroids);
        }
      }
      if(bins)
        ndpi_free(bins);
      if(cluster_ids)
        ndpi_free(cluster_ids);
#endif
    }

    for(thread_id = 0; thread_id < num_threads; thread_id++) {
      if(ndpi_thread_info[thread_id].workflow->stats.protocol_counter[0 /* 0 = Unknown */] > 0) {
        fprintf(out, "\n\nUndetected flows:%s\n",
                undetected_flows_deleted ? " (expired flows are not listed below)" : "");
        break;
      }
    }

    num_flows = 0;
    for(thread_id = 0; thread_id < num_threads; thread_id++) {
      if(ndpi_thread_info[thread_id].workflow->stats.protocol_counter[0] > 0) {
        for(i=0; i<NUM_ROOTS; i++)
          ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
                     node_print_unknown_proto_walker, &thread_id);
      }
    }

    qsort(all_flows, num_flows, sizeof(struct flow_info), cmpFlows);

    for(i=0; i<num_flows; i++)
      printFlow(i+1, all_flows[i].flow, all_flows[i].thread_id);
  } else if(csv_fp != NULL) {
    unsigned int i;

    num_flows = 0;
    for(thread_id = 0; thread_id < num_threads; thread_id++) {
      for(i=0; i<NUM_ROOTS; i++)
        ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
                   node_print_known_proto_walker, &thread_id);
    }

    for(i=0; i<num_flows; i++)
      printFlow(i+1, all_flows[i].flow, all_flows[i].thread_id);
  }

  if (serialization_fp != NULL &&
      serialization_format != ndpi_serialization_format_unknown)
  {
    unsigned int i;

    num_flows = 0;
    for(thread_id = 0; thread_id < num_threads; thread_id++) {
      for(i = 0; i < NUM_ROOTS; i++) {
        ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
                   node_print_known_proto_walker, &thread_id);
        ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
                   node_print_unknown_proto_walker, &thread_id);
      }
    }

    for(i=0; i<num_flows; i++)
    {
      printFlowSerialized(all_flows[i].thread_id, all_flows[i].flow);
    }
  }

  ndpi_free(all_flows);
}

/* *********************************************** */

/**
 * @brief Print result
 */
static void printResults(u_int64_t processing_time_usec, u_int64_t setup_time_usec) {
  u_int32_t i;
  u_int32_t avg_pkt_size = 0;
  int thread_id;
  char buf[32];
  long long unsigned int breed_stats[NUM_BREEDS] = { 0 };

  memset(&cumulative_stats, 0, sizeof(cumulative_stats));

  for(thread_id = 0; thread_id < num_threads; thread_id++) {
    if((ndpi_thread_info[thread_id].workflow->stats.total_wire_bytes == 0)
       && (ndpi_thread_info[thread_id].workflow->stats.raw_packet_count == 0))
      continue;

    for(i=0; i<NUM_ROOTS; i++) {
      ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
                 node_proto_guess_walker, &thread_id);
      if(verbose == 3 || stats_flag) ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
						port_stats_walker, &thread_id);
    }

    /* Stats aggregation */
    cumulative_stats.guessed_flow_protocols += ndpi_thread_info[thread_id].workflow->stats.guessed_flow_protocols;
    cumulative_stats.raw_packet_count += ndpi_thread_info[thread_id].workflow->stats.raw_packet_count;
    cumulative_stats.ip_packet_count += ndpi_thread_info[thread_id].workflow->stats.ip_packet_count;
    cumulative_stats.total_wire_bytes += ndpi_thread_info[thread_id].workflow->stats.total_wire_bytes;
    cumulative_stats.total_ip_bytes += ndpi_thread_info[thread_id].workflow->stats.total_ip_bytes;
    cumulative_stats.total_discarded_bytes += ndpi_thread_info[thread_id].workflow->stats.total_discarded_bytes;

    for(i = 0; i < ndpi_get_num_supported_protocols(ndpi_thread_info[0].workflow->ndpi_struct); i++) {
      cumulative_stats.protocol_counter[i] += ndpi_thread_info[thread_id].workflow->stats.protocol_counter[i];
      cumulative_stats.protocol_counter_bytes[i] += ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes[i];
      cumulative_stats.protocol_flows[i] += ndpi_thread_info[thread_id].workflow->stats.protocol_flows[i];
    }

    cumulative_stats.ndpi_flow_count += ndpi_thread_info[thread_id].workflow->stats.ndpi_flow_count;
    cumulative_stats.flow_count[0] += ndpi_thread_info[thread_id].workflow->stats.flow_count[0];
    cumulative_stats.flow_count[1] += ndpi_thread_info[thread_id].workflow->stats.flow_count[1];
    cumulative_stats.flow_count[2] += ndpi_thread_info[thread_id].workflow->stats.flow_count[2];
    cumulative_stats.tcp_count   += ndpi_thread_info[thread_id].workflow->stats.tcp_count;
    cumulative_stats.udp_count   += ndpi_thread_info[thread_id].workflow->stats.udp_count;
    cumulative_stats.mpls_count  += ndpi_thread_info[thread_id].workflow->stats.mpls_count;
    cumulative_stats.pppoe_count += ndpi_thread_info[thread_id].workflow->stats.pppoe_count;
    cumulative_stats.vlan_count  += ndpi_thread_info[thread_id].workflow->stats.vlan_count;
    cumulative_stats.fragmented_count += ndpi_thread_info[thread_id].workflow->stats.fragmented_count;
    for(i = 0; i < sizeof(cumulative_stats.packet_len)/sizeof(cumulative_stats.packet_len[0]); i++)
      cumulative_stats.packet_len[i] += ndpi_thread_info[thread_id].workflow->stats.packet_len[i];
    cumulative_stats.max_packet_len += ndpi_thread_info[thread_id].workflow->stats.max_packet_len;

    cumulative_stats.dpi_packet_count[0] += ndpi_thread_info[thread_id].workflow->stats.dpi_packet_count[0];
    cumulative_stats.dpi_packet_count[1] += ndpi_thread_info[thread_id].workflow->stats.dpi_packet_count[1];
    cumulative_stats.dpi_packet_count[2] += ndpi_thread_info[thread_id].workflow->stats.dpi_packet_count[2];

    for(i = 0; i < sizeof(cumulative_stats.flow_confidence)/sizeof(cumulative_stats.flow_confidence[0]); i++)
      cumulative_stats.flow_confidence[i] += ndpi_thread_info[thread_id].workflow->stats.flow_confidence[i];

    cumulative_stats.num_dissector_calls += ndpi_thread_info[thread_id].workflow->stats.num_dissector_calls;

    /* LRU caches */
    for(i = 0; i < NDPI_LRUCACHE_MAX; i++) {
      struct ndpi_lru_cache_stats s;
      ndpi_get_lru_cache_stats(ndpi_thread_info[thread_id].workflow->ndpi_struct, i, &s);
      cumulative_stats.lru_stats[i].n_insert += s.n_insert;
      cumulative_stats.lru_stats[i].n_search += s.n_search;
      cumulative_stats.lru_stats[i].n_found += s.n_found;
    }

    /* Automas */
    for(i = 0; i < NDPI_AUTOMA_MAX; i++) {
      struct ndpi_automa_stats s;
      ndpi_get_automa_stats(ndpi_thread_info[thread_id].workflow->ndpi_struct, i, &s);
      cumulative_stats.automa_stats[i].n_search += s.n_search;
      cumulative_stats.automa_stats[i].n_found += s.n_found;
    }

    /* Patricia trees */
    for(i = 0; i < NDPI_PTREE_MAX; i++) {
      struct ndpi_patricia_tree_stats s;
      ndpi_get_patricia_stats(ndpi_thread_info[thread_id].workflow->ndpi_struct, i, &s);
      cumulative_stats.patricia_stats[i].n_search += s.n_search;
      cumulative_stats.patricia_stats[i].n_found += s.n_found;
    }
  }

  if(cumulative_stats.total_wire_bytes == 0)
    goto free_stats;

  if(!quiet_mode) {
    printf("\nnDPI Memory statistics:\n");
    printf("\tnDPI Memory (once):      %-13s\n", formatBytes(ndpi_get_ndpi_detection_module_size(), buf, sizeof(buf)));
    printf("\tFlow Memory (per flow):  %-13s\n", formatBytes( ndpi_detection_get_sizeof_ndpi_flow_struct(), buf, sizeof(buf)));
    printf("\tActual Memory:           %-13s\n", formatBytes(current_ndpi_memory, buf, sizeof(buf)));
    printf("\tPeak Memory:             %-13s\n", formatBytes(max_ndpi_memory, buf, sizeof(buf)));
    printf("\tSetup Time:              %lu msec\n", (unsigned long)(setup_time_usec/1000));
    printf("\tPacket Processing Time:  %lu msec\n", (unsigned long)(processing_time_usec/1000));

    printf("\nTraffic statistics:\n");
    printf("\tEthernet bytes:        %-13llu (includes ethernet CRC/IFC/trailer)\n",
           (long long unsigned int)cumulative_stats.total_wire_bytes);
    printf("\tDiscarded bytes:       %-13llu\n",
           (long long unsigned int)cumulative_stats.total_discarded_bytes);
    printf("\tIP packets:            %-13llu of %llu packets total\n",
           (long long unsigned int)cumulative_stats.ip_packet_count,
           (long long unsigned int)cumulative_stats.raw_packet_count);
    /* In order to prevent Floating point exception in case of no traffic*/
    if(cumulative_stats.total_ip_bytes && cumulative_stats.raw_packet_count)
      {
	avg_pkt_size = (unsigned int)(cumulative_stats.total_ip_bytes/cumulative_stats.raw_packet_count);
      }
    printf("\tIP bytes:              %-13llu (avg pkt size %u bytes)\n",
           (long long unsigned int)cumulative_stats.total_ip_bytes,avg_pkt_size);
    printf("\tUnique flows:          %-13u\n", cumulative_stats.ndpi_flow_count);
    printf("\tTCP Packets:           %-13lu\n", (unsigned long)cumulative_stats.tcp_count);
    printf("\tUDP Packets:           %-13lu\n", (unsigned long)cumulative_stats.udp_count);
    printf("\tVLAN Packets:          %-13lu\n", (unsigned long)cumulative_stats.vlan_count);
    printf("\tMPLS Packets:          %-13lu\n", (unsigned long)cumulative_stats.mpls_count);
    printf("\tPPPoE Packets:         %-13lu\n", (unsigned long)cumulative_stats.pppoe_count);
    printf("\tFragmented Packets:    %-13lu\n", (unsigned long)cumulative_stats.fragmented_count);
    printf("\tMax Packet size:       %-13u\n",   cumulative_stats.max_packet_len);
    printf("\tPacket Len < 64:       %-13lu\n", (unsigned long)cumulative_stats.packet_len[0]);
    printf("\tPacket Len 64-128:     %-13lu\n", (unsigned long)cumulative_stats.packet_len[1]);
    printf("\tPacket Len 128-256:    %-13lu\n", (unsigned long)cumulative_stats.packet_len[2]);
    printf("\tPacket Len 256-1024:   %-13lu\n", (unsigned long)cumulative_stats.packet_len[3]);
    printf("\tPacket Len 1024-1500:  %-13lu\n", (unsigned long)cumulative_stats.packet_len[4]);
    printf("\tPacket Len > 1500:     %-13lu\n", (unsigned long)cumulative_stats.packet_len[5]);

    if(processing_time_usec > 0) {
      char buf[32], buf1[32], when[64];
      float t = (float)(cumulative_stats.ip_packet_count*1000000)/(float)processing_time_usec;
      float b = (float)(cumulative_stats.total_wire_bytes * 8 *1000000)/(float)processing_time_usec;
      float traffic_duration;
      struct tm result;
      
      if(live_capture) traffic_duration = processing_time_usec;
      else traffic_duration = ((u_int64_t)pcap_end.tv_sec*1000000 + pcap_end.tv_usec) - ((u_int64_t)pcap_start.tv_sec*1000000 + pcap_start.tv_usec);
      
      printf("\tnDPI throughput:       %s pps / %s/sec\n", formatPackets(t, buf), formatTraffic(b, 1, buf1));
      if(traffic_duration != 0) {
	t = (float)(cumulative_stats.ip_packet_count*1000000)/(float)traffic_duration;
	b = (float)(cumulative_stats.total_wire_bytes * 8 *1000000)/(float)traffic_duration;
      } else {
	t = 0;
	b = 0;
      }
#ifdef WIN32
      /* localtime() on Windows is thread-safe */
      time_t tv_sec = pcap_start.tv_sec;
      struct tm * tm_ptr = localtime(&tv_sec);
      result = *tm_ptr;
#else
      localtime_r(&pcap_start.tv_sec, &result);
#endif
      strftime(when, sizeof(when), "%d/%b/%Y %H:%M:%S", &result);
      printf("\tAnalysis begin:        %s\n", when);
#ifdef WIN32
      /* localtime() on Windows is thread-safe */
      tv_sec = pcap_end.tv_sec;
      tm_ptr = localtime(&tv_sec);
      result = *tm_ptr;
#else
      localtime_r(&pcap_end.tv_sec, &result);
#endif
      strftime(when, sizeof(when), "%d/%b/%Y %H:%M:%S", &result);
      printf("\tAnalysis end:          %s\n", when);
      printf("\tTraffic throughput:    %s pps / %s/sec\n", formatPackets(t, buf), formatTraffic(b, 1, buf1));
      printf("\tTraffic duration:      %.3f sec\n", traffic_duration/1000000);
    }

    if(enable_protocol_guess)
      printf("\tGuessed flow protos:   %-13u\n", cumulative_stats.guessed_flow_protocols);

    if(cumulative_stats.flow_count[0])
      printf("\tDPI Packets (TCP):     %-13llu (%.2f pkts/flow)\n",
	     (long long unsigned int)cumulative_stats.dpi_packet_count[0],
	     cumulative_stats.dpi_packet_count[0] / (float)cumulative_stats.flow_count[0]);
    if(cumulative_stats.flow_count[1])
      printf("\tDPI Packets (UDP):     %-13llu (%.2f pkts/flow)\n",
	     (long long unsigned int)cumulative_stats.dpi_packet_count[1],
	     cumulative_stats.dpi_packet_count[1] / (float)cumulative_stats.flow_count[1]);
    if(cumulative_stats.flow_count[2])
      printf("\tDPI Packets (other):   %-13llu (%.2f pkts/flow)\n",
	     (long long unsigned int)cumulative_stats.dpi_packet_count[2],
	     cumulative_stats.dpi_packet_count[2] / (float)cumulative_stats.flow_count[2]);

    for(i = 0; i < sizeof(cumulative_stats.flow_confidence)/sizeof(cumulative_stats.flow_confidence[0]); i++) {
      if(cumulative_stats.flow_confidence[i] != 0)
	printf("\tConfidence: %-10s %-13llu (flows)\n", ndpi_confidence_get_name(i),
	       (long long unsigned int)cumulative_stats.flow_confidence[i]);
    }

    if(dump_internal_stats) {
      char buf[1024];

      if(cumulative_stats.ndpi_flow_count)
	printf("\tNum dissector calls:   %-13llu (%.2f diss/flow)\n",
	       (long long unsigned int)cumulative_stats.num_dissector_calls,
	       cumulative_stats.num_dissector_calls / (float)cumulative_stats.ndpi_flow_count);

      printf("\tLRU cache ookla:      %llu/%llu/%llu (insert/search/found)\n",
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_OOKLA].n_insert,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_OOKLA].n_search,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_OOKLA].n_found);
      printf("\tLRU cache bittorrent: %llu/%llu/%llu (insert/search/found)\n",
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_BITTORRENT].n_insert,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_BITTORRENT].n_search,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_BITTORRENT].n_found);
      printf("\tLRU cache zoom:       %llu/%llu/%llu (insert/search/found)\n",
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_ZOOM].n_insert,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_ZOOM].n_search,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_ZOOM].n_found);
      printf("\tLRU cache stun:       %llu/%llu/%llu (insert/search/found)\n",
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN].n_insert,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN].n_search,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN].n_found);
      printf("\tLRU cache tls_cert:   %llu/%llu/%llu (insert/search/found)\n",
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_TLS_CERT].n_insert,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_TLS_CERT].n_search,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_TLS_CERT].n_found);
      printf("\tLRU cache mining:     %llu/%llu/%llu (insert/search/found)\n",
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MINING].n_insert,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MINING].n_search,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MINING].n_found);
      printf("\tLRU cache msteams:    %llu/%llu/%llu (insert/search/found)\n",
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MSTEAMS].n_insert,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MSTEAMS].n_search,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MSTEAMS].n_found);
      printf("\tLRU cache stun_zoom:  %llu/%llu/%llu (insert/search/found)\n",
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN_ZOOM].n_insert,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN_ZOOM].n_search,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN_ZOOM].n_found);

      printf("\tAutoma host:          %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_HOST].n_search,
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_HOST].n_found);
      printf("\tAutoma domain:        %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_DOMAIN].n_search,
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_DOMAIN].n_found);
      printf("\tAutoma tls cert:      %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_TLS_CERT].n_search,
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_TLS_CERT].n_found);
      printf("\tAutoma risk mask:     %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_RISK_MASK].n_search,
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_RISK_MASK].n_found);
      printf("\tAutoma common alpns:  %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_COMMON_ALPNS].n_search,
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_COMMON_ALPNS].n_found);

      printf("\tPatricia risk mask:   %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK].n_search,
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK].n_found);
      printf("\tPatricia risk mask IPv6: %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK6].n_search,
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK6].n_found);
      printf("\tPatricia risk:        %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK].n_search,
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK].n_found);
      printf("\tPatricia risk IPv6:   %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK6].n_search,
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK6].n_found);
      printf("\tPatricia protocols:   %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS].n_search,
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS].n_found);
      printf("\tPatricia protocols IPv6: %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS6].n_search,
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS6].n_found);

      if(enable_malloc_bins)
	printf("\tData-path malloc histogram: %s\n", ndpi_print_bin(&malloc_bins, 0, buf, sizeof(buf)));
    }
  }

  if(results_file) {
    if(enable_protocol_guess)
      fprintf(results_file, "Guessed flow protos:\t%u\n\n", cumulative_stats.guessed_flow_protocols);

    if(cumulative_stats.flow_count[0])
      fprintf(results_file, "DPI Packets (TCP):\t%llu\t(%.2f pkts/flow)\n",
	      (long long unsigned int)cumulative_stats.dpi_packet_count[0],
	      cumulative_stats.dpi_packet_count[0] / (float)cumulative_stats.flow_count[0]);
    if(cumulative_stats.flow_count[1])
      fprintf(results_file, "DPI Packets (UDP):\t%llu\t(%.2f pkts/flow)\n",
	      (long long unsigned int)cumulative_stats.dpi_packet_count[1],
	      cumulative_stats.dpi_packet_count[1] / (float)cumulative_stats.flow_count[1]);
    if(cumulative_stats.flow_count[2])
      fprintf(results_file, "DPI Packets (other):\t%llu\t(%.2f pkts/flow)\n",
	      (long long unsigned int)cumulative_stats.dpi_packet_count[2],
	      cumulative_stats.dpi_packet_count[2] / (float)cumulative_stats.flow_count[2]);

    for(i = 0; i < sizeof(cumulative_stats.flow_confidence)/sizeof(cumulative_stats.flow_confidence[0]); i++) {
      if(cumulative_stats.flow_confidence[i] != 0)
	fprintf(results_file, "Confidence %-17s: %llu (flows)\n",
		ndpi_confidence_get_name(i),
		(long long unsigned int)cumulative_stats.flow_confidence[i]);
    }

    if(dump_internal_stats) {
      char buf[1024];

      if(cumulative_stats.ndpi_flow_count)
	fprintf(results_file, "Num dissector calls: %llu (%.2f diss/flow)\n",
		(long long unsigned int)cumulative_stats.num_dissector_calls,
		cumulative_stats.num_dissector_calls / (float)cumulative_stats.ndpi_flow_count);

      fprintf(results_file, "LRU cache ookla:      %llu/%llu/%llu (insert/search/found)\n",
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_OOKLA].n_insert,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_OOKLA].n_search,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_OOKLA].n_found);
      fprintf(results_file, "LRU cache bittorrent: %llu/%llu/%llu (insert/search/found)\n",
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_BITTORRENT].n_insert,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_BITTORRENT].n_search,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_BITTORRENT].n_found);
      fprintf(results_file, "LRU cache zoom:       %llu/%llu/%llu (insert/search/found)\n",
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_ZOOM].n_insert,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_ZOOM].n_search,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_ZOOM].n_found);
      fprintf(results_file, "LRU cache stun:       %llu/%llu/%llu (insert/search/found)\n",
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN].n_insert,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN].n_search,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN].n_found);
      fprintf(results_file, "LRU cache tls_cert:   %llu/%llu/%llu (insert/search/found)\n",
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_TLS_CERT].n_insert,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_TLS_CERT].n_search,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_TLS_CERT].n_found);
      fprintf(results_file, "LRU cache mining:     %llu/%llu/%llu (insert/search/found)\n",
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MINING].n_insert,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MINING].n_search,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MINING].n_found);
      fprintf(results_file, "LRU cache msteams:    %llu/%llu/%llu (insert/search/found)\n",
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MSTEAMS].n_insert,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MSTEAMS].n_search,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MSTEAMS].n_found);
      fprintf(results_file, "LRU cache stun_zoom:  %llu/%llu/%llu (insert/search/found)\n",
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN_ZOOM].n_insert,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN_ZOOM].n_search,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN_ZOOM].n_found);

      fprintf(results_file, "Automa host:          %llu/%llu (search/found)\n",
	      (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_HOST].n_search,
	      (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_HOST].n_found);
      fprintf(results_file, "Automa domain:        %llu/%llu (search/found)\n",
	      (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_DOMAIN].n_search,
	      (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_DOMAIN].n_found);
      fprintf(results_file, "Automa tls cert:      %llu/%llu (search/found)\n",
	      (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_TLS_CERT].n_search,
	      (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_TLS_CERT].n_found);
      fprintf(results_file, "Automa risk mask:     %llu/%llu (search/found)\n",
	      (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_RISK_MASK].n_search,
	      (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_RISK_MASK].n_found);
      fprintf(results_file, "Automa common alpns:  %llu/%llu (search/found)\n",
	      (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_COMMON_ALPNS].n_search,
	      (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_COMMON_ALPNS].n_found);

      fprintf(results_file, "Patricia risk mask:   %llu/%llu (search/found)\n",
	      (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK].n_search,
	      (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK].n_found);
      fprintf(results_file, "Patricia risk mask IPv6: %llu/%llu (search/found)\n",
	      (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK6].n_search,
	      (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK6].n_found);
      fprintf(results_file, "Patricia risk:        %llu/%llu (search/found)\n",
	      (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK].n_search,
	      (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK].n_found);
      fprintf(results_file, "Patricia risk IPv6:   %llu/%llu (search/found)\n",
	      (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK6].n_search,
	      (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK6].n_found);
      fprintf(results_file, "Patricia protocols:   %llu/%llu (search/found)\n",
	      (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS].n_search,
	      (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS].n_found);
      fprintf(results_file, "Patricia protocols IPv6: %llu/%llu (search/found)\n",
	      (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS6].n_search,
	      (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS6].n_found);

      if(enable_malloc_bins)
	fprintf(results_file, "Data-path malloc histogram: %s\n", ndpi_print_bin(&malloc_bins, 0, buf, sizeof(buf)));
    }

    fprintf(results_file, "\n");
  }

  if(!quiet_mode) printf("\n\nDetected protocols:\n");
  for(i = 0; i <= ndpi_get_num_supported_protocols(ndpi_thread_info[0].workflow->ndpi_struct); i++) {
    ndpi_protocol_breed_t breed = ndpi_get_proto_breed(ndpi_thread_info[0].workflow->ndpi_struct, i);

    if(cumulative_stats.protocol_counter[i] > 0) {
      breed_stats[breed] += (long long unsigned int)cumulative_stats.protocol_counter_bytes[i];

      if(results_file)
	fprintf(results_file, "%s\t%llu\t%llu\t%u\n",
		ndpi_get_proto_name(ndpi_thread_info[0].workflow->ndpi_struct, i),
		(long long unsigned int)cumulative_stats.protocol_counter[i],
		(long long unsigned int)cumulative_stats.protocol_counter_bytes[i],
		cumulative_stats.protocol_flows[i]);

      if(!quiet_mode) {
	printf("\t%-20s packets: %-13llu bytes: %-13llu "
	       "flows: %-13u\n",
	       ndpi_get_proto_name(ndpi_thread_info[0].workflow->ndpi_struct,
				   ndpi_map_ndpi_id_to_user_proto_id(ndpi_thread_info[0].workflow->ndpi_struct, i)),
	       (long long unsigned int)cumulative_stats.protocol_counter[i],
	       (long long unsigned int)cumulative_stats.protocol_counter_bytes[i],
	       cumulative_stats.protocol_flows[i]);
      }
    }
  }

  if(!quiet_mode) {
    printf("\n\nProtocol statistics:\n");

    for(i=0; i < NUM_BREEDS; i++) {
      if(breed_stats[i] > 0) {
	printf("\t%-20s %13llu bytes\n",
	       ndpi_get_proto_breed_name(ndpi_thread_info[0].workflow->ndpi_struct, i),
	       breed_stats[i]);
      }
    }
  }

  printRiskStats();
  printFlowsStats();

  if(stats_flag || verbose == 3) {
    HASH_SORT(srcStats, port_stats_sort);
    HASH_SORT(dstStats, port_stats_sort);
  }

  if(verbose == 3) {
    printf("\n\nSource Ports Stats:\n");
    printPortStats(srcStats);

    printf("\nDestination Ports Stats:\n");
    printPortStats(dstStats);
  }

 free_stats:
  if(scannerHosts) {
    deleteScanners(scannerHosts);
    scannerHosts = NULL;
  }

  if(receivers) {
    deleteReceivers(receivers);
    receivers = NULL;
  }

  if(topReceivers) {
    deleteReceivers(topReceivers);
    topReceivers = NULL;
  }

  if(srcStats) {
    deletePortsStats(srcStats);
    srcStats = NULL;
  }

  if(dstStats) {
    deletePortsStats(dstStats);
    dstStats = NULL;
  }
}

/**
 * @brief Force a pcap_dispatch() or pcap_loop() call to return
 */
static void breakPcapLoop(u_int16_t thread_id) {
#ifdef USE_DPDK
  dpdk_run_capture = 0;
#else
  if(ndpi_thread_info[thread_id].workflow->pcap_handle != NULL) {
    pcap_breakloop(ndpi_thread_info[thread_id].workflow->pcap_handle);
  }
#endif
}

/**
 * @brief Sigproc is executed for each packet in the pcap file
 */
void sigproc(int sig) {

  static int called = 0;
  int thread_id;

  if(called) return; else called = 1;
  shutdown_app = 1;

  for(thread_id=0; thread_id<num_threads; thread_id++)
    breakPcapLoop(thread_id);
}


#ifndef USE_DPDK

/**
 * @brief Get the next pcap file from a passed playlist
 */
static int getNextPcapFileFromPlaylist(u_int16_t thread_id, char filename[], u_int32_t filename_len) {

  if(playlist_fp[thread_id] == NULL) {
    if((playlist_fp[thread_id] = fopen(_pcap_file[thread_id], "r")) == NULL)
      return -1;
  }

 next_line:
  if(fgets(filename, filename_len, playlist_fp[thread_id])) {
    int l = strlen(filename);
    if(filename[0] == '\0' || filename[0] == '#') goto next_line;
    if(filename[l-1] == '\n') filename[l-1] = '\0';
    return 0;
  } else {
    fclose(playlist_fp[thread_id]);
    playlist_fp[thread_id] = NULL;
    return -1;
  }
}

/**
 * @brief Configure the pcap handle
 */
static void configurePcapHandle(pcap_t * pcap_handle) {

  if(bpfFilter != NULL) {

    if(!bpf_cfilter) {
      if(pcap_compile(pcap_handle, &bpf_code, bpfFilter, 1, 0xFFFFFF00) < 0) {
	printf("pcap_compile error: '%s'\n", pcap_geterr(pcap_handle));
	return;
      }
      bpf_cfilter = &bpf_code;
    }
    if(pcap_setfilter(pcap_handle, bpf_cfilter) < 0) {
      printf("pcap_setfilter error: '%s'\n", pcap_geterr(pcap_handle));
    } else {
      printf("Successfully set BPF filter to '%s'\n", bpfFilter);
    }
  }
}

#endif

/**
 * @brief Open a pcap file or a specified device - Always returns a valid pcap_t
 */
static pcap_t * openPcapFileOrDevice(u_int16_t thread_id, const u_char * pcap_file) {
#ifndef USE_DPDK
  u_int snaplen = 1536;
  int promisc = 1;
  char pcap_error_buffer[PCAP_ERRBUF_SIZE];
#endif
  pcap_t * pcap_handle = NULL;

  /* trying to open a live interface */
#ifdef USE_DPDK
  struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
							  MBUF_CACHE_SIZE, 0,
							  RTE_MBUF_DEFAULT_BUF_SIZE,
							  rte_socket_id());

  if(mbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create mbuf pool: are hugepages ok?\n");

  if(dpdk_port_init(dpdk_port_id, mbuf_pool) != 0)
    rte_exit(EXIT_FAILURE, "DPDK: Cannot init port %u: please see README.dpdk\n", dpdk_port_id);
#else
  /* Trying to open the interface */
  if((pcap_handle = pcap_open_live((char*)pcap_file, snaplen,
				   promisc, 500, pcap_error_buffer)) == NULL) {
    capture_for = capture_until = 0;

    live_capture = 0;
    num_threads = 1; /* Open pcap files in single threads mode */

    /* Trying to open a pcap file */
    if((pcap_handle = pcap_open_offline((char*)pcap_file, pcap_error_buffer)) == NULL) {
      char filename[256] = { 0 };

      if(strstr((char*)pcap_file, (char*)".pcap"))
	printf("ERROR: could not open pcap file: %s\n", pcap_error_buffer);

      /* Trying to open as a playlist as last attempt */
      else if((getNextPcapFileFromPlaylist(thread_id, filename, sizeof(filename)) != 0)
	      || ((pcap_handle = pcap_open_offline(filename, pcap_error_buffer)) == NULL)) {
	/* This probably was a bad interface name, printing a generic error */
	printf("ERROR: could not open %s: %s\n", filename, pcap_error_buffer);
	exit(-1);
      } else {
	if(!quiet_mode)
	  printf("Reading packets from playlist %s...\n", pcap_file);
      }
    } else {
      if(!quiet_mode)
	printf("Reading packets from pcap file %s...\n", pcap_file);
    }
  } else {
    live_capture = 1;

    if(!quiet_mode) {
#ifdef USE_DPDK
      printf("Capturing from DPDK (port 0)...\n");
#else
      printf("Capturing live traffic from device %s...\n", pcap_file);
#endif
    }
  }

  configurePcapHandle(pcap_handle);
#endif /* !DPDK */

  if(capture_for > 0) {
    if(!quiet_mode)
      printf("Capturing traffic up to %u seconds\n", (unsigned int)capture_for);

#ifndef WIN32
    alarm(capture_for);
    signal(SIGALRM, sigproc);
#endif
  }

  return pcap_handle;
}

/**
 * @brief Check pcap packet
 */
static void ndpi_process_packet(u_char *args,
				const struct pcap_pkthdr *header,
				const u_char *packet) {
  struct ndpi_proto p;
  ndpi_risk flow_risk;
  u_int16_t thread_id = *((u_int16_t*)args);

  /* allocate an exact size buffer to check overflows */
  uint8_t *packet_checked = ndpi_malloc(header->caplen);

  if(packet_checked == NULL) {
    return ;
  }

  memcpy(packet_checked, packet, header->caplen);
  p = ndpi_workflow_process_packet(ndpi_thread_info[thread_id].workflow, header, packet_checked, &flow_risk);

  if(!pcap_start.tv_sec) pcap_start.tv_sec = header->ts.tv_sec, pcap_start.tv_usec = header->ts.tv_usec;
  pcap_end.tv_sec = header->ts.tv_sec, pcap_end.tv_usec = header->ts.tv_usec;

  /* Idle flows cleanup */
  if(live_capture) {
    if(ndpi_thread_info[thread_id].last_idle_scan_time + IDLE_SCAN_PERIOD < ndpi_thread_info[thread_id].workflow->last_time) {
      /* scan for idle flows */
      ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx],
		 node_idle_scan_walker, &thread_id);

      /* remove idle flows (unfortunately we cannot do this inline) */
      while(ndpi_thread_info[thread_id].num_idle_flows > 0) {
	/* search and delete the idle flow from the "ndpi_flow_root" (see struct reader thread) - here flows are the node of a b-tree */
	ndpi_tdelete(ndpi_thread_info[thread_id].idle_flows[--ndpi_thread_info[thread_id].num_idle_flows],
		     &ndpi_thread_info[thread_id].workflow->ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx],
		     ndpi_workflow_node_cmp);

	/* free the memory associated to idle flow in "idle_flows" - (see struct reader thread)*/
	ndpi_free_flow_info_half(ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows]);
	ndpi_free(ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows]);
      }

      if(++ndpi_thread_info[thread_id].idle_scan_idx == ndpi_thread_info[thread_id].workflow->prefs.num_roots)
	ndpi_thread_info[thread_id].idle_scan_idx = 0;

      ndpi_thread_info[thread_id].last_idle_scan_time = ndpi_thread_info[thread_id].workflow->last_time;
    }
  }

#ifdef DEBUG_TRACE
  if(trace) fprintf(trace, "Found %u bytes packet %u.%u\n", header->caplen, p.app_protocol, p.master_protocol);
#endif

  if(extcap_dumper
     && ((extcap_packet_filter == (u_int16_t)-1)
	 || (p.app_protocol == extcap_packet_filter)
	 || (p.master_protocol == extcap_packet_filter)
	 )
     ) {
    struct pcap_pkthdr h;
    u_int32_t *crc, delta = sizeof(struct ndpi_packet_trailer) + 4 /* ethernet trailer */;
    struct ndpi_packet_trailer *trailer;
    u_int16_t cli_score, srv_score;

    memcpy(&h, header, sizeof(h));

    if(h.caplen > (sizeof(extcap_buf)-sizeof(struct ndpi_packet_trailer) - 4)) {
      printf("INTERNAL ERROR: caplen=%u\n", h.caplen);
      h.caplen = sizeof(extcap_buf)-sizeof(struct ndpi_packet_trailer) - 4;
    }

    trailer = (struct ndpi_packet_trailer*)&extcap_buf[h.caplen];
    memcpy(extcap_buf, packet, h.caplen);
    memset(trailer, 0, sizeof(struct ndpi_packet_trailer));
    trailer->magic = htonl(WIRESHARK_NTOP_MAGIC);
    trailer->flow_risk = htonl64(flow_risk);
    trailer->flow_score = htons(ndpi_risk2score(flow_risk, &cli_score, &srv_score));
    trailer->master_protocol = htons(p.master_protocol), trailer->app_protocol = htons(p.app_protocol);
    ndpi_protocol2name(ndpi_thread_info[thread_id].workflow->ndpi_struct, p, trailer->name, sizeof(trailer->name));
    crc = (uint32_t*)&extcap_buf[h.caplen+sizeof(struct ndpi_packet_trailer)];
    *crc = ndpi_crc32((const void*)extcap_buf, h.caplen+sizeof(struct ndpi_packet_trailer));
    h.caplen += delta, h.len += delta;

#ifdef DEBUG_TRACE
    if(trace) fprintf(trace, "Dumping %u bytes packet\n", h.caplen);
#endif

    pcap_dump((u_char*)extcap_dumper, &h, (const u_char *)extcap_buf);
    pcap_dump_flush(extcap_dumper);
  }

  /* check for buffer changes */
  if(memcmp(packet, packet_checked, header->caplen) != 0)
    printf("INTERNAL ERROR: ingress packet was modified by nDPI: this should not happen [thread_id=%u, packetId=%lu, caplen=%u]\n",
	   thread_id, (unsigned long)ndpi_thread_info[thread_id].workflow->stats.raw_packet_count, header->caplen);

  if((u_int32_t)(pcap_end.tv_sec-pcap_start.tv_sec) > pcap_analysis_duration) {
    unsigned int i;
    u_int64_t processing_time_usec, setup_time_usec;

    gettimeofday(&end, NULL);
    processing_time_usec = (u_int64_t)end.tv_sec*1000000 + end.tv_usec - ((u_int64_t)begin.tv_sec*1000000 + begin.tv_usec);
    setup_time_usec = (u_int64_t)begin.tv_sec*1000000 + begin.tv_usec - ((u_int64_t)startup_time.tv_sec*1000000 + startup_time.tv_usec);

    printResults(processing_time_usec, setup_time_usec);

    for(i=0; i<ndpi_thread_info[thread_id].workflow->prefs.num_roots; i++) {
      ndpi_tdestroy(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i], ndpi_flow_info_freer);
      ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i] = NULL;

      memset(&ndpi_thread_info[thread_id].workflow->stats, 0, sizeof(struct ndpi_stats));
    }

    if(!quiet_mode)
      printf("\n-------------------------------------------\n\n");

    memcpy(&begin, &end, sizeof(begin));
    memcpy(&pcap_start, &pcap_end, sizeof(pcap_start));
  }

  /*
    Leave the free as last statement to avoid crashes when ndpi_detection_giveup()
    is called above by printResults()
  */
  if(packet_checked) {
    ndpi_free(packet_checked);
    packet_checked = NULL;
  }
}

#ifndef USE_DPDK
/**
 * @brief Call pcap_loop() to process packets from a live capture or savefile
 */
static void runPcapLoop(u_int16_t thread_id) {
  if((!shutdown_app) && (ndpi_thread_info[thread_id].workflow->pcap_handle != NULL)) {
    int datalink_type = pcap_datalink(ndpi_thread_info[thread_id].workflow->pcap_handle);
    if(!ndpi_is_datalink_supported(datalink_type)) {
      printf("Unsupported datalink %d. Skip pcap\n", datalink_type);
      return;
    }
    int ret = pcap_loop(ndpi_thread_info[thread_id].workflow->pcap_handle, -1, &ndpi_process_packet, (u_char*)&thread_id);
    if (ret == -1)
      printf("Error while reading pcap file: '%s'\n", pcap_geterr(ndpi_thread_info[thread_id].workflow->pcap_handle));
  }
}
#endif

/**
 * @brief Process a running thread
 */
void * processing_thread(void *_thread_id) {
#ifdef WIN64
  long long int thread_id = (long long int)_thread_id;
#else
  long int thread_id = (long int)_thread_id;
#endif
#ifndef USE_DPDK
  char pcap_error_buffer[PCAP_ERRBUF_SIZE];
#endif

#if defined(__linux__) && defined(HAVE_PTHREAD_SETAFFINITY_NP)
  if(core_affinity[thread_id] >= 0) {
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(core_affinity[thread_id], &cpuset);

    if(pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0)
      fprintf(stderr, "Error while binding thread %ld to core %d\n", thread_id, core_affinity[thread_id]);
    else {
      if(!quiet_mode) printf("Running thread %ld on core %d...\n", thread_id, core_affinity[thread_id]);
    }
  } else
#endif
    if((!quiet_mode)) {
#ifdef WIN64
      printf("Running thread %lld...\n", thread_id);
#else
      printf("Running thread %ld...\n", thread_id);
#endif
    }

#ifdef USE_DPDK
  while(dpdk_run_capture) {
    struct rte_mbuf *bufs[BURST_SIZE];
    u_int16_t num = rte_eth_rx_burst(dpdk_port_id, 0, bufs, BURST_SIZE);
    u_int i;

    if(num == 0) {
      usleep(1);
      continue;
    }

    for(i = 0; i < PREFETCH_OFFSET && i < num; i++)
      rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));

    for(i = 0; i < num; i++) {
      char *data = rte_pktmbuf_mtod(bufs[i], char *);
      int len = rte_pktmbuf_pkt_len(bufs[i]);
      struct pcap_pkthdr h;

      h.len = h.caplen = len;
      gettimeofday(&h.ts, NULL);

      ndpi_process_packet((u_char*)&thread_id, &h, (const u_char *)data);
      rte_pktmbuf_free(bufs[i]);
    }
  }
#else
 pcap_loop:
  runPcapLoop(thread_id);

  if(ndpi_thread_info[thread_id].workflow->pcap_handle)
    pcap_close(ndpi_thread_info[thread_id].workflow->pcap_handle);

  ndpi_thread_info[thread_id].workflow->pcap_handle = NULL;

  if(playlist_fp[thread_id] != NULL) { /* playlist: read next file */
    char filename[256];

    if(getNextPcapFileFromPlaylist(thread_id, filename, sizeof(filename)) == 0 &&
       (ndpi_thread_info[thread_id].workflow->pcap_handle = pcap_open_offline(filename, pcap_error_buffer)) != NULL) {
      configurePcapHandle(ndpi_thread_info[thread_id].workflow->pcap_handle);
      goto pcap_loop;
    }
  }
#endif
  if(bpf_cfilter) {
    pcap_freecode(bpf_cfilter);
    bpf_cfilter = NULL;
  }

  return NULL;
}


/**
 * @brief Begin, process, end detection process
 */
void test_lib() {
  u_int64_t processing_time_usec, setup_time_usec;
#ifdef WIN64
  long long int thread_id;
#else
  long thread_id;
#endif

#ifdef DEBUG_TRACE
  if(trace) fprintf(trace, "Num threads: %d\n", num_threads);
#endif

  for(thread_id = 0; thread_id < num_threads; thread_id++) {
    pcap_t *cap;

#ifdef DEBUG_TRACE
    if(trace) fprintf(trace, "Opening %s\n", (const u_char*)_pcap_file[thread_id]);
#endif

    cap = openPcapFileOrDevice(thread_id, (const u_char*)_pcap_file[thread_id]);
    setupDetection(thread_id, cap);
  }

  gettimeofday(&begin, NULL);

  int status;
  void * thd_res;

  /* Running processing threads */
  for(thread_id = 0; thread_id < num_threads; thread_id++) {
    status = pthread_create(&ndpi_thread_info[thread_id].pthread, NULL, processing_thread, (void *) thread_id);
    /* check pthreade_create return value */
    if(status != 0) {
#ifdef WIN64
      fprintf(stderr, "error on create %lld thread\n", thread_id);
#else
      fprintf(stderr, "error on create %ld thread\n", thread_id);
#endif
      exit(-1);
    }
  }
  /* Waiting for completion */
  for(thread_id = 0; thread_id < num_threads; thread_id++) {
    status = pthread_join(ndpi_thread_info[thread_id].pthread, &thd_res);
    /* check pthreade_join return value */
    if(status != 0) {
#ifdef WIN64
      fprintf(stderr, "error on join %lld thread\n", thread_id);
#else
      fprintf(stderr, "error on join %ld thread\n", thread_id);
#endif
      exit(-1);
    }
    if(thd_res != NULL) {
#ifdef WIN64
      fprintf(stderr, "error on returned value of %lld joined thread\n", thread_id);
#else
      fprintf(stderr, "error on returned value of %ld joined thread\n", thread_id);
#endif
      exit(-1);
    }
  }

#ifdef USE_DPDK
  dpdk_port_deinit(dpdk_port_id);
#endif

  gettimeofday(&end, NULL);
  processing_time_usec = (u_int64_t)end.tv_sec*1000000 + end.tv_usec - ((u_int64_t)begin.tv_sec*1000000 + begin.tv_usec);
  setup_time_usec = (u_int64_t)begin.tv_sec*1000000 + begin.tv_usec - ((u_int64_t)startup_time.tv_sec*1000000 + startup_time.tv_usec);

  /* Printing cumulative results */
  printResults(processing_time_usec, setup_time_usec);

  for(thread_id = 0; thread_id < num_threads; thread_id++) {
    if(ndpi_thread_info[thread_id].workflow->pcap_handle != NULL)
      pcap_close(ndpi_thread_info[thread_id].workflow->pcap_handle);

    terminateDetection(thread_id);
  }
}

/* *********************************************** */

#if 0
static void binUnitTest() {
  struct ndpi_bin *bins, b0, b1;
  u_int8_t num_bins = 32;
  u_int8_t num_points = 24;
  u_int32_t i, j;
  u_int8_t num_clusters = 3;
  u_int16_t cluster_ids[256];
  char out_buf[128];

  srand(time(NULL));

  assert((bins = (struct ndpi_bin*)ndpi_malloc(sizeof(struct ndpi_bin)*num_bins)) != NULL);

  for(i=0; i<num_bins; i++) {
    ndpi_init_bin(&bins[i], ndpi_bin_family8, num_points);

    for(j=0; j<num_points; j++)
      ndpi_set_bin(&bins[i], j, rand() % 0xFF);

    ndpi_normalize_bin(&bins[i]);
  }

  ndpi_cluster_bins(bins, num_bins, num_clusters, cluster_ids, NULL);

  for(j=0; j<num_clusters; j++) {
    if(verbose) printf("\n");

    for(i=0; i<num_bins; i++) {
      if(cluster_ids[i] == j) {
	if(verbose)
	  printf("[%u] %s\n", cluster_ids[i],
		 ndpi_print_bin(&bins[i], 0, out_buf, sizeof(out_buf)));
      }
    }
  }
  // printf("Similarity: %f\n\n", ndpi_bin_similarity(&b1, &b2, 1));

  for(i=0; i<num_bins; i++)
    ndpi_free_bin(&bins[i]);

  ndpi_free(bins);

  /* ************************ */

  ndpi_init_bin(&b0, ndpi_bin_family8, 16);
  ndpi_init_bin(&b1, ndpi_bin_family8, 16);

  ndpi_set_bin(&b0, 1, 100);
  ndpi_set_bin(&b1, 1, 100);

  printf("Similarity: %f\n\n", ndpi_bin_similarity(&b0, &b1, 1));

  ndpi_free_bin(&b0), ndpi_free_bin(&b1);

  // exit(0);
}
#endif

/* *********************************************** */

#ifndef DEBUG_TRACE

static void dgaUnitTest() {
  const char *dga[] = {
    //"www.lbjamwptxz.com",
    "www.l54c2e21e80ba5471be7a8402cffb98768.so",
    "www.wdd7ee574106a84807a601beb62dd851f0.hk",
    "www.jaa12148a5831a5af92aa1d8fe6059e276.ws",
    "www.e6r5p57kbafwrxj3plz.com",
    // "grdawgrcwegpjaoo.eu",
    "www.mcfpeqbotiwxfxqu.eu",
    "www.adgxwxhqsegnrsih.eu",
    NULL
  };

  const char *non_dga[] = {
    "mail.100x100design.com",
    "cdcvps.cloudapps.cisco.com",
    "vcsa.vmware.com",
    "mz.gov.pl",
    "zoomam104zc.zoom.us",
    "5CI_DOMBIN",
    "ALICEGATE",
    "BOWIE",
    "D002465",
    "DESKTOP-RB5T12G",
    "ECI_DOM",
    "ECI_DOMA",
    "ECI_DOMAIN",
    "ENDIAN-PC",
    "GFILE",
    "GIOVANNI-PC",
    "GUNNAR",
    "ISATAP",
    "LAB111",
    "LP-RKERUR-OSX",
    "LUCAS-IMAC",
    "LUCASMACBOOKPRO",
    "MACBOOKAIR-E1D0",
    //"MDJR98",
    "NASFILE",
    "SANJI-LIFEBOOK-",
    "SC.ARRANCAR.ORG",
    "WORKG",
    "WORKGROUP",
    "XSTREAM_HY",
    "__MSBROWSE__",
    "mqtt.facebook.com",
    NULL
  };
  int debug = 0, i;
  NDPI_PROTOCOL_BITMASK all;
  struct ndpi_detection_module_struct *ndpi_str = ndpi_init_detection_module(init_prefs);

  assert(ndpi_str != NULL);

  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);

  ndpi_finalize_initialization(ndpi_str);

  assert(ndpi_str != NULL);

  for(i=0; non_dga[i] != NULL; i++) {
    if(debug) printf("Checking non DGA %s\n", non_dga[i]);
    assert(ndpi_check_dga_name(ndpi_str, NULL, (char*)non_dga[i], 1, 1) == 0);
  }

  for(i=0; dga[i] != NULL; i++) {
    if(debug) printf("Checking DGA %s\n", non_dga[i]);
    assert(ndpi_check_dga_name(ndpi_str, NULL, (char*)dga[i], 1, 1) == 1);
  }

  ndpi_exit_detection_module(ndpi_str);
}

/* *********************************************** */

static void hllUnitTest() {
  struct ndpi_hll h;
  u_int8_t bits = 8; /* >= 4, <= 16 */
  u_int32_t i;

  assert(ndpi_hll_init(&h, bits) == 0);

  for(i=0; i<21320; i++)
    ndpi_hll_add_number(&h, i);

  /* printf("Count estimate: %f\n", ndpi_hll_count(&h)); */

  ndpi_hll_destroy(&h);
}

/* *********************************************** */

static void bitmapUnitTest() {
  u_int32_t val, i, j;
  u_int64_t val64;

  /* With a 32 bit integer */
  for(i=0; i<32; i++) {
    NDPI_ZERO_BIT(val);
    NDPI_SET_BIT(val, i);

    assert(NDPI_ISSET_BIT(val, i));

    for(j=0; j<32; j++) {
      if(j != i) {
	assert(!NDPI_ISSET_BIT(val, j));
      }
    }
  }

  /* With a 64 bit integer */
  for(i=0; i<64; i++) {
    NDPI_ZERO_BIT(val64);
    NDPI_SET_BIT(val64, i);

    assert(NDPI_ISSET_BIT(val64, i));

    for(j=0; j<64; j++) {
      if(j != i) {
	assert(!NDPI_ISSET_BIT(val64, j));
      }
    }
  }
}

/* *********************************************** */

void automataUnitTest() {
  void *automa = ndpi_init_automa();

  assert(automa);
  assert(ndpi_add_string_to_automa(automa, ndpi_strdup("hello")) == 0);
  assert(ndpi_add_string_to_automa(automa, ndpi_strdup("world")) == 0);
  ndpi_finalize_automa(automa);
  assert(ndpi_match_string(automa, "This is the wonderful world of nDPI") == 1);
  ndpi_free_automa(automa);
}

#endif

/* *********************************************** */

// #define RUN_DATA_ANALYSIS_THEN_QUIT 1

void analyzeUnitTest() {
  struct ndpi_analyze_struct *s = ndpi_alloc_data_analysis(32);
  u_int32_t i;

  for(i=0; i<256; i++) {
    ndpi_data_add_value(s, rand()*i);
    // ndpi_data_add_value(s, i+1);
  }

  // ndpi_data_print_window_values(s);

#ifdef RUN_DATA_ANALYSIS_THEN_QUIT
  printf("Average: [all: %f][window: %f]\n",
	 ndpi_data_average(s), ndpi_data_window_average(s));
  printf("Entropy: %f\n", ndpi_data_entropy(s));

  printf("Min/Max: %u/%u\n",
	 ndpi_data_min(s), ndpi_data_max(s));
#endif

  ndpi_free_data_analysis(s, 1);

#ifdef RUN_DATA_ANALYSIS_THEN_QUIT
  exit(0);
#endif
}

/* *********************************************** */

/**
 * @brief Initialize port array
 */

void bpf_filter_port_array_init(int array[], int size) {
  int i;
  for(i=0; i<size; i++)
    array[i] = INIT_VAL;
}

/* *********************************************** */
/**
 * @brief Initialize host array
 */

void bpf_filter_host_array_init(const char *array[48], int size) {
  int i;
  for(i=0; i<size; i++)
    array[i] = NULL;
}

/* *********************************************** */

/**
 * @brief Add host to host filter array
 */

void bpf_filter_host_array_add(const char *filter_array[48], int size, const char *host) {
  int i;
  int r;
  for(i=0; i<size; i++) {
    if((filter_array[i] != NULL) && (r = strcmp(filter_array[i], host)) == 0)
      return;
    if(filter_array[i] == NULL) {
      filter_array[i] = host;
      return;
    }
  }
  fprintf(stderr,"bpf_filter_host_array_add: max array size is reached!\n");
  exit(-1);
}


/* *********************************************** */

/**
 * @brief Add port to port filter array
 */

void bpf_filter_port_array_add(int filter_array[], int size, int port) {
  int i;
  for(i=0; i<size; i++) {
    if(filter_array[i] == port)
      return;
    if(filter_array[i] == INIT_VAL) {
      filter_array[i] = port;
      return;
    }
  }
  fprintf(stderr,"bpf_filter_port_array_add: max array size is reached!\n");
  exit(-1);
}

/* *********************************************** */

void analysisUnitTest() {
  struct ndpi_analyze_struct *s = ndpi_alloc_data_analysis(32);
  u_int32_t i;

  for(i=0; i<256; i++)
    ndpi_data_add_value(s, i);

  if(0) {
    ndpi_data_print_window_values(s);
    printf("Average: [all: %f][window: %f]\n", ndpi_data_average(s), ndpi_data_window_average(s));
    printf("Entropy: %f\n", ndpi_data_entropy(s));
    printf("StdDev:  %f\n", ndpi_data_stddev(s));
    printf("Min/Max: %u/%u\n", ndpi_data_min(s), ndpi_data_max(s));
  }

  ndpi_free_data_analysis(s, 1);
}

/* *********************************************** */

void rsiUnitTest() {
  struct ndpi_rsi_struct s;
  unsigned int v[] = {
    31,
    87,
    173,
    213,
    223,
    230,
    238,
    245,
    251,
    151,
    259,
    261,
    264,
    264,
    270,
    273,
    288,
    288,
    304,
    304,
    350,
    384,
    423,
    439,
    445,
    445,
    445,
    445
  };

  u_int i, n = sizeof(v) / sizeof(unsigned int);
  u_int debug = 0;

  assert(ndpi_alloc_rsi(&s, 8) == 0);

  for(i=0; i<n; i++) {
    float rsi = ndpi_rsi_add_value(&s, v[i]);


    if(debug)
      printf("%2d) RSI = %f\n", i, rsi);
  }

  ndpi_free_rsi(&s);
}

/* *********************************************** */

void hashUnitTest() {
  ndpi_str_hash *h;
  char * const dict[] = { "hello", "world", NULL };
  int i;

  assert(ndpi_hash_init(&h) == 0);
  assert(h == NULL);

  for(i=0; dict[i] != NULL; i++) {
    u_int8_t l = strlen(dict[i]);
    int * v;

    assert(ndpi_hash_add_entry(&h, dict[i], l, &i) == 0);
    assert(ndpi_hash_find_entry(h, dict[i], l, (void **)&v) == 0);
    assert(v == (void *)&i && *v == i);
  }

  ndpi_hash_free(&h, NULL);
  assert(h == NULL);
}

/* *********************************************** */

void hwUnitTest() {
  struct ndpi_hw_struct hw;
  double v[] = { 10, 14, 8, 25, 16, 22, 14, 35, 15, 27, 218, 40, 28, 40, 25, 65 };
  u_int i, j, num = sizeof(v) / sizeof(double);
  u_int num_learning_points = 2;
  u_int8_t trace = 0;

  for(j=0; j<2; j++) {
    assert(ndpi_hw_init(&hw, num_learning_points, j /* 0=multiplicative, 1=additive */, 0.9, 0.9, 0.1, 0.05) == 0);

    if(trace)
      printf("\nHolt-Winters %s method\n", (j == 0) ? "multiplicative" : "additive");

    for(i=0; i<num; i++) {
      double prediction, confidence_band;
      double lower, upper;
      int rc = ndpi_hw_add_value(&hw, v[i], &prediction, &confidence_band);

      lower = prediction - confidence_band, upper = prediction + confidence_band;

      if(trace)
	printf("%2u)\t%.3f\t%.3f\t%.3f\t%.3f\t %s [%.3f]\n", i, v[i], prediction, lower, upper,
	       ((rc == 0) || ((v[i] >= lower) && (v[i] <= upper))) ? "OK" : "ANOMALY",
	       confidence_band);
    }

    ndpi_hw_free(&hw);
  }
}

/* *********************************************** */

void hwUnitTest2() {
  struct ndpi_hw_struct hw;
  u_int8_t trace = 1;
  double v[] = {
    31.908466339111,
    87.339714050293,
    173.47660827637,
    213.92568969727,
    223.32124328613,
    230.60134887695,
    238.09457397461,
    245.8137512207,
    251.09228515625,
    251.09228515625,
    259.21997070312,
    261.98754882812,
    264.78540039062,
    264.78540039062,
    270.47451782227,
    173.3671875,
    288.34222412109,
    288.34222412109,
    304.24795532227,
    304.24795532227,
    350.92227172852,
    384.54431152344,
    423.25942993164,
    439.43322753906,
    445.05981445312,
    445.05981445312,
    445.05981445312,
    445.05981445312
  };
  u_int num_learning_points = 1;
  u_int i, num = sizeof(v) / sizeof(double);
  float alpha = 0.9, beta = 0.5, gamma = 1;
  FILE *fd = fopen("/tmp/result.csv", "w");

  assert(ndpi_hw_init(&hw, num_learning_points, 0 /* 0=multiplicative, 1=additive */,
		      alpha, beta, gamma, 0.05) == 0);

  if(trace) {
    printf("\nHolt-Winters [alpha: %.1f][beta: %.1f][gamma: %.1f]\n", alpha, beta, gamma);

    if(fd)
      fprintf(fd, "index;value;prediction;lower;upper;anomaly\n");
  }

  for(i=0; i<num; i++) {
    double prediction, confidence_band;
    double lower, upper;
    int rc = ndpi_hw_add_value(&hw, v[i], &prediction, &confidence_band);

    lower = prediction - confidence_band, upper = prediction + confidence_band;

    if(trace) {
      printf("%2u)\t%12.3f\t%.3f\t%12.3f\t%12.3f\t %s [%.3f]\n", i, v[i], prediction, lower, upper,
	     ((rc == 0) || ((v[i] >= lower) && (v[i] <= upper))) ? "OK" : "ANOMALY",
	     confidence_band);

      if(fd)
	fprintf(fd, "%u;%.0f;%.0f;%.0f;%.0f;%s\n",
		i, v[i], prediction, lower, upper,
		((rc == 0) || ((v[i] >= lower) && (v[i] <= upper))) ? "OK" : "ANOMALY");
    }
  }

  if(fd) fclose(fd);

  ndpi_hw_free(&hw);

  //exit(0);
}

/* *********************************************** */

void sesUnitTest() {
  struct ndpi_ses_struct ses;
  u_int8_t trace = 0;
  double v[] = {
    31.908466339111,
    87.339714050293,
    173.47660827637,
    213.92568969727,
    223.32124328613,
    230.60134887695,
    238.09457397461,
    245.8137512207,
    251.09228515625,
    251.09228515625,
    259.21997070312,
    261.98754882812,
    264.78540039062,
    264.78540039062,
    270.47451782227,
    173.3671875,
    288.34222412109,
    288.34222412109,
    304.24795532227,
    304.24795532227,
    350.92227172852,
    384.54431152344,
    423.25942993164,
    439.43322753906,
    445.05981445312,
    445.05981445312,
    445.05981445312,
    445.05981445312
  };
  u_int i, num = sizeof(v) / sizeof(double);
  float alpha = 0.9;
  FILE *fd = fopen("/tmp/ses_result.csv", "w");

  assert(ndpi_ses_init(&ses, alpha, 0.05) == 0);
  ndpi_ses_reset(&ses);

  if(trace) {
    printf("\nSingle Exponential Smoothing [alpha: %.1f]\n", alpha);

    if(fd)
      fprintf(fd, "index;value;prediction;lower;upper;anomaly\n");
  }

  for(i=0; i<num; i++) {
    double prediction, confidence_band;
    double lower, upper;
    int rc = ndpi_ses_add_value(&ses, v[i], &prediction, &confidence_band);

    lower = prediction - confidence_band, upper = prediction + confidence_band;

    if(trace) {
      printf("%2u)\t%12.3f\t%.3f\t%12.3f\t%12.3f\t %s [%.3f]\n", i, v[i], prediction, lower, upper,
	     ((rc == 0) || ((v[i] >= lower) && (v[i] <= upper))) ? "OK" : "ANOMALY",
	     confidence_band);

      if(fd)
	fprintf(fd, "%u;%.0f;%.0f;%.0f;%.0f;%s\n",
		i, v[i], prediction, lower, upper,
		((rc == 0) || ((v[i] >= lower) && (v[i] <= upper))) ? "OK" : "ANOMALY");
    }
  }

  if(fd) fclose(fd);

  ndpi_ses_fitting(v, num, &alpha); /* Compute the best alpha */
}

/* *********************************************** */

void desUnitTest() {
  struct ndpi_des_struct des;
  u_int8_t trace = 0;
  double v[] = {
    31.908466339111,
    87.339714050293,
    173.47660827637,
    213.92568969727,
    223.32124328613,
    230.60134887695,
    238.09457397461,
    245.8137512207,
    251.09228515625,
    251.09228515625,
    259.21997070312,
    261.98754882812,
    264.78540039062,
    264.78540039062,
    270.47451782227,
    173.3671875,
    288.34222412109,
    288.34222412109,
    304.24795532227,
    304.24795532227,
    350.92227172852,
    384.54431152344,
    423.25942993164,
    439.43322753906,
    445.05981445312,
    445.05981445312,
    445.05981445312,
    445.05981445312
  };
  u_int i, num = sizeof(v) / sizeof(double);
  float alpha = 0.9, beta = 0.5;
  FILE *fd = fopen("/tmp/des_result.csv", "w");

  assert(ndpi_des_init(&des, alpha, beta, 0.05) == 0);
  ndpi_des_reset(&des);

  if(trace) {
    printf("\nDouble Exponential Smoothing [alpha: %.1f][beta: %.1f]\n", alpha, beta);

    if(fd)
      fprintf(fd, "index;value;prediction;lower;upper;anomaly\n");
  }

  for(i=0; i<num; i++) {
    double prediction, confidence_band;
    double lower, upper;
    int rc = ndpi_des_add_value(&des, v[i], &prediction, &confidence_band);

    lower = prediction - confidence_band, upper = prediction + confidence_band;

    if(trace) {
      printf("%2u)\t%12.3f\t%.3f\t%12.3f\t%12.3f\t %s [%.3f]\n", i, v[i], prediction, lower, upper,
	     (rc == 0) ? "LEARNING" : (((v[i] >= lower) && (v[i] <= upper)) ? "OK" : "ANOMALY"),
	     confidence_band);

      if(fd)
	fprintf(fd, "%u;%.0f;%.0f;%.0f;%.0f;%s\n",
		i, v[i], prediction, lower, upper,
		((rc == 0) || ((v[i] >= lower) && (v[i] <= upper))) ? "OK" : "ANOMALY");
    }
  }

  if(fd) fclose(fd);

  ndpi_des_fitting(v, num, &alpha, &beta); /* Compute the best alpha/beta */
}

/* *********************************************** */

void desUnitStressTest() {
  struct ndpi_des_struct des;
  u_int8_t trace = 1;
  u_int i;
  float alpha = 0.9, beta = 0.5;
  double init_value = time(NULL) % 1000;

  assert(ndpi_des_init(&des, alpha, beta, 0.05) == 0);
  ndpi_des_reset(&des);

  if(trace) {
    printf("\nDouble Exponential Smoothing [alpha: %.1f][beta: %.1f]\n", alpha, beta);
  }

  for(i=0; i<512; i++) {
    double prediction, confidence_band;
    double lower, upper;
    double value = init_value + rand() % 25;
    int rc = ndpi_des_add_value(&des, value, &prediction, &confidence_band);

    lower = prediction - confidence_band, upper = prediction + confidence_band;

    if(trace) {
      printf("%2u)\t%12.3f\t%.3f\t%12.3f\t%12.3f\t %s [%.3f]\n", i, value, prediction, lower, upper,
	     ((rc == 0) || ((value >= lower) && (value <= upper))) ? "OK" : "ANOMALY",
	     confidence_band);
    }
  }
}

/* *********************************************** */

void hwUnitTest3() {
  struct ndpi_hw_struct hw;
  u_int num_learning_points = 3;
  u_int8_t trace = 1;
  double v[] = {
    10,
    14,
    8,
    25,
    16,
    22,
    14,
    35,
    15,
    27,
    18,
    40,
    28,
    40,
    25,
    65,
  };
  u_int i, num = sizeof(v) / sizeof(double);
  float alpha = 0.5, beta = 0.5, gamma = 0.1;
  assert(ndpi_hw_init(&hw, num_learning_points, 0 /* 0=multiplicative, 1=additive */, alpha, beta, gamma, 0.05) == 0);
  ndpi_hw_reset(&hw);

  if(trace)
    printf("\nHolt-Winters [alpha: %.1f][beta: %.1f][gamma: %.1f]\n", alpha, beta, gamma);

  for(i=0; i<num; i++) {
    double prediction, confidence_band;
    double lower, upper;
    int rc = ndpi_hw_add_value(&hw, v[i], &prediction, &confidence_band);

    lower = prediction - confidence_band, upper = prediction + confidence_band;

    if(trace)
      printf("%2u)\t%12.3f\t%.3f\t%12.3f\t%12.3f\t %s [%.3f]\n",
	     i, v[i], prediction, lower, upper,
	     ((rc == 0) || ((v[i] >= lower) && (v[i] <= upper))) ? "OK" : "ANOMALY",
	     confidence_band);
  }

  ndpi_hw_free(&hw);
}

/* *********************************************** */

void jitterUnitTest() {
  struct ndpi_jitter_struct jitter;
  float v[] = { 10, 14, 8, 25, 16, 22, 14, 35, 15, 27, 218, 40, 28, 40, 25, 65 };
  u_int i, num = sizeof(v) / sizeof(float);
  u_int num_learning_points = 4;
  u_int8_t trace = 0;

  assert(ndpi_jitter_init(&jitter, num_learning_points) == 0);

  for(i=0; i<num; i++) {
    float rc = ndpi_jitter_add_value(&jitter, v[i]);

    if(trace)
      printf("%2u)\t%.3f\t%.3f\n", i, v[i], rc);
  }

  ndpi_jitter_free(&jitter);
}

/* *********************************************** */

void compressedBitmapUnitTest() {
  ndpi_bitmap *b = ndpi_bitmap_alloc(), *b1;
  u_int i, trace = 0;
  size_t ser;
  char *buf;
  ndpi_bitmap_iterator *it;
  u_int32_t value;

  for(i=0; i<1000; i++) {
    u_int32_t v = rand();

    if(trace) printf("%u ", v);
    ndpi_bitmap_set(b, v);
    assert(ndpi_bitmap_isset(b, v));
  }

  if(trace) printf("\n");

  ser = ndpi_bitmap_serialize(b, &buf);
  assert(ser > 0);

  if(trace) printf("len: %u\n", (unsigned int)ser);
  b1 = ndpi_bitmap_deserialize(buf);
  assert(b1);

  assert((it = ndpi_bitmap_iterator_alloc(b)));
  while(ndpi_bitmap_iterator_next(it, &value)) {
    if(trace) printf("%u ", value);
  }

  if(trace) printf("\n");
  ndpi_bitmap_iterator_free(it);

  ndpi_free(buf);
  ndpi_bitmap_free(b);
  ndpi_bitmap_free(b1);
}

/* *********************************************** */

void filterUnitTest() {
  ndpi_filter* f = ndpi_filter_alloc();
  u_int32_t v, i;
  
  assert(f);

  srand(time(NULL));
  
  for(i=0; i<1000; i++)
    assert(ndpi_filter_add(f, v = rand()));

  assert(ndpi_filter_contains(f, v));
  
  ndpi_filter_free(f);
}

/* *********************************************** */

void zscoreUnitTest() {
  u_int32_t values[] = { 1, 3, 3, 4, 5, 2, 6, 7, 30, 16 };
  u_int32_t i;
  u_int32_t num_outliers;
  u_int32_t const num = NDPI_ARRAY_LENGTH(values);
  bool outliers[NDPI_ARRAY_LENGTH(values)], do_trace = false;

  num_outliers = ndpi_find_outliers(values, outliers, num);

  if(do_trace) {
    printf("outliers: %u\n", num_outliers);

    for(i=0; i<num; i++)
      printf("%u %s\n", values[i], outliers[i] ? "OUTLIER" : "OK");
  }
}

/* *********************************************** */

void linearUnitTest() {
  u_int32_t values[] = {15, 27, 38, 49, 68, 72, 90, 150, 175, 203};
  u_int32_t prediction;
  u_int32_t const num = NDPI_ARRAY_LENGTH(values);
  bool do_trace = false;
  int rc = ndpi_predict_linear(values, num, 2*num, &prediction);

  if(do_trace) {
    printf("[rc: %d][predicted value: %u]\n", rc, prediction);
  }
}

/* *********************************************** */

void sketchUnitTest() {
  struct ndpi_cm_sketch *sketch;

#if 0
  ndpi_cm_sketch_init(8);
  ndpi_cm_sketch_init(16);
  ndpi_cm_sketch_init(32);
  ndpi_cm_sketch_init(64);
  ndpi_cm_sketch_init(256);
  ndpi_cm_sketch_init(512);
  ndpi_cm_sketch_init(1024);
  ndpi_cm_sketch_init(2048);
  ndpi_cm_sketch_init(4096);
  ndpi_cm_sketch_init(8192);
  exit(0);
#endif

  sketch = ndpi_cm_sketch_init(32);
  
  if(sketch) {
    u_int32_t i, num_one = 0;
    bool do_trace = false;

    srand(time(NULL));

    for(i=0; i<10000; i++) {
      u_int32_t v = rand() % 1000;

      if(v == 1) num_one++;
      ndpi_cm_sketch_add(sketch, v);
    }

    if(do_trace)
      printf("The estimated count of 1 is %u [expectedl: %u]\n",
	     ndpi_cm_sketch_count(sketch, 1), num_one);

    ndpi_cm_sketch_destroy(sketch);

    if(do_trace)
      exit(0);
  }  
}

/* *********************************************** */

void binaryBitmapUnitTest() {
  ndpi_binary_bitmap *b = ndpi_binary_bitmap_alloc();
  u_int64_t hashval = 8149764909040470312;
  u_int8_t category = 33;
  
  ndpi_binary_bitmap_set(b, hashval, category);
  ndpi_binary_bitmap_set(b, hashval+1, category);
  category = 0;
  assert(ndpi_binary_bitmap_isset(b, hashval, &category));
  assert(category == 33);
  ndpi_binary_bitmap_free(b);
}

/* *********************************************** */

void domainSearchUnitTest() {
  ndpi_domain_classify *sc = ndpi_domain_classify_alloc();
  char *domain = "ntop.org";
  u_int8_t class_id;
  
  assert(sc);
    
  ndpi_domain_classify_add(sc, NDPI_PROTOCOL_NTOP, ".ntop.org");
  ndpi_domain_classify_add(sc, NDPI_PROTOCOL_NTOP, domain);
  assert(ndpi_domain_classify_contains(sc, &class_id, domain));

  ndpi_domain_classify_add(sc, NDPI_PROTOCOL_CATEGORY_GAMBLING, "123vc.club");
  assert(ndpi_domain_classify_contains(sc, &class_id, "123vc.club"));
  assert(class_id == NDPI_PROTOCOL_CATEGORY_GAMBLING);

  /* Subdomain check */
  assert(ndpi_domain_classify_contains(sc, &class_id, "blog.ntop.org"));
  assert(class_id == NDPI_PROTOCOL_NTOP);
  
#ifdef DEBUG_TRACE
  struct stat st;
  
  if(stat(fname, &st) == 0) {
    u_int32_t s = ndpi_domain_classify_size(sc);
    
    printf("Size: %u [%.1f %% of the original filename size]\n",
	   s, (float)(s * 100) / (float)st.st_size);
  }
#endif
  
  ndpi_domain_classify_free(sc);
}

/* *********************************************** */

void domainSearchUnitTest2() {
  ndpi_domain_classify *c = ndpi_domain_classify_alloc();
  u_int8_t class_id = 9;

  ndpi_domain_classify_add(c, class_id, "ntop.org");
  ndpi_domain_classify_add(c, class_id, "apple.com");

  assert(!ndpi_domain_classify_contains(c, &class_id, "ntop.com"));
  
  ndpi_domain_classify_free(c);
}

/* *********************************************** */

/**
   @brief MAIN FUNCTION
**/
int main(int argc, char **argv) {
  int i, skip_unit_tests = 0;

#ifdef DEBUG_TRACE
  trace = fopen("/tmp/ndpiReader.log", "a");

  if(trace) {
    int i;

    fprintf(trace, " #### %s #### \n", __FUNCTION__);
    fprintf(trace, " #### [argc: %u] #### \n", argc);

    for(i=0; i<argc; i++)
      fprintf(trace, " #### [%d] [%s]\n", i, argv[i]);
  }
#endif


  if(ndpi_get_api_version() != NDPI_API_VERSION) {
    printf("nDPI Library version mismatch: please make sure this code and the nDPI library are in sync\n");
    return(-1);
  }

  if(!skip_unit_tests) {
#ifndef DEBUG_TRACE
    /* Skip tests when debugging */

#ifdef HW_TEST
    hwUnitTest2();
#endif

#ifdef STRESS_TEST
    desUnitStressTest();
    exit(0);
#endif

    binaryBitmapUnitTest();
    domainSearchUnitTest();
    domainSearchUnitTest2();
    sketchUnitTest();
    linearUnitTest();
    zscoreUnitTest();
    sesUnitTest();
    desUnitTest();

    /* Internal checks */
    // binUnitTest();
    //hwUnitTest();
    jitterUnitTest();
    rsiUnitTest();
    hashUnitTest();
    dgaUnitTest();
    hllUnitTest();
    bitmapUnitTest();
    filterUnitTest();
    automataUnitTest();
    analyzeUnitTest();
    ndpi_self_check_host_match(stderr);
    analysisUnitTest();
    compressedBitmapUnitTest();
#endif
  }

  gettimeofday(&startup_time, NULL);
  memset(ndpi_thread_info, 0, sizeof(ndpi_thread_info));

  if(getenv("AHO_DEBUG"))
    ac_automata_enable_debug(1);
  parseOptions(argc, argv);

  ndpi_info_mod = ndpi_init_detection_module(init_prefs);

  if(ndpi_info_mod == NULL) return -1;

  if(domain_to_check) {
    ndpiCheckHostStringMatch(domain_to_check);
    exit(0);
  }
  if(ip_port_to_check) {
    ndpiCheckIPMatch(ip_port_to_check);
    exit(0);
  }

  if(enable_doh_dot_detection) {
    init_doh_bins();
    /* Clusters are not really used in DoH/DoT detection, but because of how
       the code has been written, we need to enable also clustering feature */
    if(num_bin_clusters == 0)
      num_bin_clusters = 1;
  }

  if(!quiet_mode) {
    printf("\n-----------------------------------------------------------\n"
	   "* NOTE: This is demo app to show *some* nDPI features.\n"
	   "* In this demo we have implemented only some basic features\n"
	   "* just to show you what you can do with the library. Feel \n"
	   "* free to extend it and send us the patches for inclusion\n"
	   "------------------------------------------------------------\n\n");

    printf("Using nDPI (%s) [%d thread(s)]\n", ndpi_revision(), num_threads);

    const char *gcrypt_ver = ndpi_get_gcrypt_version();
    if(gcrypt_ver)
      printf("Using libgcrypt version %s\n", gcrypt_ver);
  }

  signal(SIGINT, sigproc);
  
  for(i=0; i<num_loops; i++)
    test_lib();

  if(results_path)  ndpi_free(results_path);
  if(results_file)  fclose(results_file);
  if(extcap_dumper) pcap_dump_close(extcap_dumper);
  if(extcap_fifo_h) pcap_close(extcap_fifo_h);
  if(ndpi_info_mod) ndpi_exit_detection_module(ndpi_info_mod);
  if(enable_malloc_bins) ndpi_free_bin(&malloc_bins);
  if(csv_fp)        fclose(csv_fp);
  
  ndpi_free(_debug_protocols);
  ndpi_free(_disabled_protocols);

#ifdef DEBUG_TRACE
  if(trace) fclose(trace);
#endif

  return 0;
}

#ifdef _MSC_BUILD
int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  if (AttachConsole(ATTACH_PARENT_PROCESS)) {
    freopen("CONIN$", "r", stdin);
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
  }

  return main(__argc, __argv);
}
#endif

#if defined(WIN32) && !defined(_MSC_BUILD)
#ifndef __GNUC__
#define EPOCHFILETIME (116444736000000000i64)
#else
#define EPOCHFILETIME (116444736000000000LL)
#endif

  /**
     @brief Timezone
  **/
#ifndef __GNUC__
  struct timezone {
    int tz_minuteswest; /* minutes W of Greenwich */
    int tz_dsttime;     /* type of dst correction */
  };
#endif

  /**
     @brief Set time
  **/
  int gettimeofday(struct timeval *tv, struct timezone *tz) {
    FILETIME        ft;
    LARGE_INTEGER   li;
    __int64         t;
    static int      tzflag;

    if(tv) {
      GetSystemTimeAsFileTime(&ft);
      li.LowPart  = ft.dwLowDateTime;
      li.HighPart = ft.dwHighDateTime;
      t  = li.QuadPart;       /* In 100-nanosecond intervals */
      t -= EPOCHFILETIME;     /* Offset to the Epoch time */
      t /= 10;                /* In microseconds */
      tv->tv_sec  = (long)(t / 1000000);
      tv->tv_usec = (long)(t % 1000000);
    }

    if(tz) {
      if(!tzflag) {
	_tzset();
	tzflag++;
      }

      tz->tz_minuteswest = _timezone / 60;
      tz->tz_dsttime = _daylight;
    }

    return 0;
  }
#endif /* WIN32 */
