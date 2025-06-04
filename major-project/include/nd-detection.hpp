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

#include "nd-flow-parser.hpp"

//includes added by neb
#include <cppconn/driver.h>
#include <cppconn/connection.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>
#include <cppconn/exception.h>


class ndDetectionQueueEntry
{
public:
    ndDetectionQueueEntry(nd_flow_ptr &flow,
      const ndPacket *packet,
      const uint8_t *data,
      uint16_t length)
      : flow(flow), packet(packet), data(data), length(length) { }

    ndDetectionQueueEntry(nd_flow_ptr &flow)
      : flow(flow) { }

    virtual ~ndDetectionQueueEntry() {
        if (packet != nullptr) delete packet;
    }

    nd_flow_ptr flow;
    const ndPacket *packet = { nullptr };
    const uint8_t *data = { nullptr };
    uint16_t length = { 0 };
};

class ndDetectionThread : public ndThread, public ndInstanceClient
{
public:
    ndDetectionThread(int16_t cpu, const std::string &tag,
#ifdef _ND_ENABLE_NETLINK
      ndNetlink *netlink,
#endif
#ifdef _ND_ENABLE_CONNTRACK
      ndConntrackThread *thread_conntrack,
#endif
      ndDNSHintCache *dhc = NULL,
      ndFlowHashCache *fhc = NULL, uint8_t private_addr = 0);

    virtual ~ndDetectionThread();

    // XXX: Not thread-safe!  Lock before calling...
    virtual void Reload(void);

    void QueuePacket(nd_flow_ptr &flow,
      const ndPacket *packet = nullptr,
      const uint8_t *data = nullptr,
      uint16_t length = 0);

    struct ndpi_detection_module_struct *GetDetectionModule(void) {
        return ndpi;
    }

    virtual void *Entry(void);

protected:
#ifdef _ND_ENABLE_NETLINK
    ndNetlink *netlink;
#endif
#ifdef _ND_ENABLE_CONNTRACK
    ndConntrackThread *thread_conntrack;
#endif
    struct ndpi_detection_module_struct *ndpi;

    ndAddr::PrivatePair private_addrs;

    ndDNSHintCache *dhc;
    ndFlowHashCache *fhc;

    std::string flow_digest, flow_digest_mdata;

    std::queue<ndDetectionQueueEntry *> pkt_queue;
    pthread_cond_t pkt_queue_cond;
    pthread_mutex_t pkt_queue_cond_mutex;

    ndFlowParser parser;

    ndProto::Id
    ProtocolLookup(uint16_t id, ndDetectionQueueEntry *entry);

    void ProcessPacketQueue(void);
    void ProcessPacket(ndDetectionQueueEntry *entry);
    void ProcessFlow(ndDetectionQueueEntry *entry);
    bool ProcessALPN(ndDetectionQueueEntry *entry,
      bool client = true);
    void ProcessRisks(ndDetectionQueueEntry *entry);

    void SetHostServerName(ndDetectionQueueEntry *entry,
      const char *host_serer_name);
    void SetDetectedProtocol(ndDetectionQueueEntry *entry,
      ndProto::Id id);
    void SetDetectedApplication(ndDetectionQueueEntry *entry,
      nd_app_id_t id);

    void DispatchEvent(ndDetectionQueueEntry *entry);

    void DetectionUpdate(ndDetectionQueueEntry *entry);
    void DetectionGuess(ndDetectionQueueEntry *entry);
    void DetectionComplete(ndDetectionQueueEntry *entry);

#ifdef _ND_ENABLE_DEBUG_STATS
    uint64_t flows = { 0 };
    uint64_t pkts = { 0 };
    uint64_t queued_pkts = { 0 };
    uint64_t queued_size = { 0 };
    uint64_t max_queued_pkts = { 0 };
    uint64_t max_queued_size = { 0 };
#endif
};

void throwError(std::string error);
void loadBpfProgram();
void block_website(std::string local_ip, std::string other_ip, uint16_t local_port, uint16_t other_port);
__be32 convertIpToBe32(const std::string& ip);
__be16 convertPortToBe16(uint16_t port);
void remove_bpf_map_entry(__be32 index);

class DatabaseManager {
public:
    // Constructor
    /**
     * @brief Constructs a new DatabaseManager object.
     * 
     * This constructor initializes a DatabaseManager instance with the specified
     * database connection parameters and fetches initial data from the database.
     * 
     * @param host The hostname or IP address of the database server.
     * @param user The username to use for connecting to the database.
     * @param password The password to use for connecting to the database.
     * @param dbname The name of the database to connect to.
     * 
     * The constructor also fetches:
     * - User-to-IP mappings and stores them in `ip_user_mapping`
     * - Blocked applications per user in `blocked_applications`
     * - Blocked websites per user in `user_blocked_websites`
     */
    DatabaseManager(const std::string& host, const std::string& user, const std::string& password, const std::string& dbname);

    // Destructor
    /**
     * @brief Destroys the DatabaseManager object and releases database resources.
     */
    ~DatabaseManager();

    // Method to execute a prepared statement
    /**
     * @brief Executes a prepared SQL statement with the given query and parameters.
     *
     * This function takes a SQL query in the form of a std::string and a vector of tuples
     * containing the parameters to be bound to the query. Each tuple consists of 
     * six elements: two std::strings and four integers.
     *
     * @param query The SQL query to be executed.
     * @param params A vector of tuples where each tuple contains:
     *               - A std::string representing the first parameter.
     *               - A std::string representing the second parameter.
     *               - An integer representing the third parameter.
     *               - An integer representing the fourth parameter.
     *               - An integer representing the fifth parameter.
     *               - An integer representing the sixth parameter.
     */
    void executePreparedStatements();
        /**
     * @brief Fetches the user-to-IP mapping from the database.
     */
    void fetchUserIPMapping();

    /**
     * @brief Fetches blocked applications from the database.
     */
    void fetchBlockedApplications();

    /**
     * @brief Fetches blocked websites from the database.
     */
    void fetchBlockedWebsites();

private:
    sql::Driver *driver;
    sql::Connection *con;
    std::string host;
    std::string user;
    std::string password;
    std::string dbname;
};
