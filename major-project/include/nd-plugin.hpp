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

#include <queue>
#include <set>

#include "nd-config.hpp"
#include "nd-flow-map.hpp"
#include "nd-packet.hpp"
#include "nd-serializer.hpp"
#include "nd-thread.hpp"
#include "nd-util.hpp"

class ndInstanceStatus;

constexpr unsigned _ND_PLUGIN_VER = 0x20230309;

#define ndPluginInit(class_name) \
    extern "C" { \
    ndPlugin *ndPluginInit(const string &tag, \
      const ndPlugin::Params &params) { \
        class_name *p = new class_name(tag, params); \
        if (p->GetType() != ndPlugin::Type::PROC && \
          p->GetType() != ndPlugin::Type::SINK) \
        { \
            nd_printf("Invalid plugin type: %s [%u]\n", \
              tag.c_str(), p->GetType()); \
            delete p; \
            return nullptr; \
        } \
        return dynamic_cast<ndPlugin *>(p); \
    } \
    }

class ndPlugin : public ndThread, public ndSerializer
{
public:
    enum class Type : uint8_t {
        BASE,
        PROC,
        SINK,
    };

    typedef std::map<std::string, std::string> Params;
    typedef std::set<std::string> Channels;

    ndPlugin(Type type, const std::string &tag, const Params &params);
    virtual ~ndPlugin();

    virtual void *Entry(void) = 0;

    virtual void GetVersion(std::string &version) = 0;

    virtual void GetStatus(nlohmann::json &status) { }

    virtual void DisplayStatus(const nlohmann::json &status) { }

    inline const std::string &GetConfiguration(void) {
        return conf_filename;
    }

    enum class Event : uint8_t {
        RELOAD,
        STATUS_UPDATE,
    };

    virtual void
    DispatchEvent(Event event, void *param = nullptr){};

    static const std::map<ndPlugin::Type, std::string> types;

    Type GetType(void) { return type; };

    enum class DispatchFlags : uint8_t {
        NONE = 0,
        FORMAT_JSON = (1 << 0),
        FORMAT_MSGPACK = (1 << 1),
        ADD_CR = (1 << 2),
        ADD_HEADER = (1 << 3),
        GZ_DEFLATE = (1 << 4),
    };

protected:
    Type type;
    std::string conf_filename;
};

class ndPluginSinkPayload
{
public:
    static ndPluginSinkPayload *Create(size_t length,
      const uint8_t *data, const ndPlugin::Channels &channels,
      ndFlags<ndPlugin::DispatchFlags> flags = ndPlugin::DispatchFlags::NONE);

    inline static ndPluginSinkPayload *
    Create(const ndPluginSinkPayload &payload,
      ndFlags<ndPlugin::DispatchFlags> flags = ndPlugin::DispatchFlags::NONE) {
        return Create(payload.length, payload.data,
          payload.channels, flags);
    }

    inline static ndPluginSinkPayload *
    Create(const ndPluginSinkPayload *payload,
      ndFlags<ndPlugin::DispatchFlags> flags = ndPlugin::DispatchFlags::NONE) {
        return Create(payload->length, payload->data,
          payload->channels, flags);
    }

    inline static ndPluginSinkPayload *
    Create(const nlohmann::json &j,
      const ndPlugin::Channels &channels,
      ndFlags<ndPlugin::DispatchFlags> flags = ndPlugin::DispatchFlags::NONE) {
        std::string output;
        nd_json_to_string(j, output, ndGC_DEBUG);
        return Create(output.size(),
          (const uint8_t *)output.c_str(), channels, flags);
    }

    ndPluginSinkPayload()
      : length(0), data(nullptr),
        flags(ndPlugin::DispatchFlags::NONE) { }

    ndPluginSinkPayload(size_t length, const uint8_t *data,
      const ndPlugin::Channels &channels,
      ndFlags<ndPlugin::DispatchFlags> flags)
      : length(length), data(nullptr), channels(channels),
        flags(flags) {
        this->data = new uint8_t[length];
        memcpy(this->data, data, length);
    }

    virtual ~ndPluginSinkPayload() {
        if (data) {
            delete[] data;
            data = nullptr;
        }
        length = 0;
    }

    size_t length;
    uint8_t *data;
    ndPlugin::Channels channels;
    ndFlags<ndPlugin::DispatchFlags> flags;
};

class ndPluginProcessor : public ndPlugin
{
public:
    ndPluginProcessor(const std::string &tag,
      const ndPlugin::Params &params);
    virtual ~ndPluginProcessor();

    enum class Event : uint16_t {
        NONE,

        FLOW_MAP,  // ndFlowMap *
        FLOW_NEW,  // nd_flow_ptr
        FLOW_EXPIRING,  // nd_flow_ptr
        FLOW_EXPIRE,  // nd_flow_ptr
        DPI_NEW,  // nd_flow_ptr
        DPI_UPDATE,  // nd_flow_ptr
        DPI_COMPLETE,  // nd_flow_ptr
        INTERFACES,  // ndInterfaces
        PKT_CAPTURE_STATS,  // string, ndPacketStats *
        PKT_GLOBAL_STATS,  // ndPacketStats *
        UPDATE_INIT,  // ndInstanceStatus *
        UPDATE_COMPLETE,

        MAX
    };

    template <class T>
    void GetStatus(T &output) const {
        ndPlugin::GetStatus(output);
    }

    virtual void
    DispatchProcessorEvent(Event event, ndFlowMap *flow_map) { }
    virtual void
    DispatchProcessorEvent(Event event, nd_flow_ptr &flow) { }
    virtual void DispatchProcessorEvent(Event event,
      ndInterfaces *interfaces) { }
    virtual void DispatchProcessorEvent(Event event,
      const std::string &iface, ndPacketStats *stats) { }
    virtual void DispatchProcessorEvent(Event event,
      ndPacketStats *stats) { }
    virtual void DispatchProcessorEvent(Event event,
      ndInstanceStatus *status) { }
    virtual void DispatchProcessorEvent(Event event) { }

protected:
    virtual void DispatchSinkPayload(const std::string &target,
      const ndPlugin::Channels &channels, size_t length,
      const uint8_t *payload,
      ndFlags<ndPlugin::DispatchFlags> flags = DispatchFlags::NONE);

    inline void DispatchSinkPayload(const std::string &target,
      const ndPlugin::Channels &channels,
      const std::vector<uint8_t> &payload,
      ndFlags<ndPlugin::DispatchFlags> flags = DispatchFlags::NONE) {
        DispatchSinkPayload(target, channels,
          payload.size(), &payload[0], flags);
    }

    virtual void DispatchSinkPayload(const std::string &target,
      const ndPlugin::Channels &channels, const nlohmann::json &j,
      ndFlags<ndPlugin::DispatchFlags> flags = DispatchFlags::NONE);
};

#define _ND_PLQ_DEFAULT_MAX_SIZE 2097152

class ndPluginSink : public ndPlugin
{
public:
    ndPluginSink(const std::string &tag,
      const ndPlugin::Params &params);
    virtual ~ndPluginSink();

    template <class T>
    void GetStatus(T &output) const {
        ndPlugin::GetStatus(output);
    }

    virtual void QueuePayload(ndPluginSinkPayload *payload);

protected:
    size_t plq_size;
    size_t plq_size_max;
    std::queue<ndPluginSinkPayload *> plq_public;
    std::queue<ndPluginSinkPayload *> plq_private;
    pthread_cond_t plq_cond;
    pthread_mutex_t plq_cond_mutex;

    size_t PullPayloadQueue(void);
    size_t WaitOnPayloadQueue(unsigned timeout = 1);

    inline ndPluginSinkPayload *PopPayloadQueue(void) {
        if (! plq_private.size()) return nullptr;
        ndPluginSinkPayload *p = plq_private.front();
        plq_private.pop();
        plq_size -= p->length;
        return p;
    }
};

class ndPluginLoader
{
public:
    ndPluginLoader(const std::string &tag,
      const std::string &so_name, const ndPlugin::Params &params);
    virtual ~ndPluginLoader();

    inline ndPlugin *GetPlugin(void) { return plugin; };
    inline const std::string &GetTag(void) { return tag; };
    inline const std::string &GetObjectName(void) {
        return so_name;
    };

protected:
    std::string tag;
    std::string so_name;
    void *so_handle;
    ndPlugin *plugin;
};

class ndPluginManager : public ndSerializer
{
public:
    virtual ~ndPluginManager() { Destroy(); }

    void Load(ndPlugin::Type type = ndPlugin::Type::BASE,
      bool create = true);

    bool Create(ndPlugin::Type type = ndPlugin::Type::BASE);

    size_t Terminate(ndPlugin::Type type = ndPlugin::Type::BASE);

    void Destroy(ndPlugin::Type type = ndPlugin::Type::BASE);

    size_t Reap(ndPlugin::Type type = ndPlugin::Type::BASE);

    void BroadcastEvent(ndPlugin::Type type,
      ndPlugin::Event event,
      void *param = nullptr);

    void BroadcastSinkPayload(ndPluginSinkPayload *payload);
    bool DispatchSinkPayload(const std::string &target,
      ndPluginSinkPayload *payload);

    void BroadcastProcessorEvent(
      ndPluginProcessor::Event event, ndFlowMap *flow_map);
    void BroadcastProcessorEvent(
      ndPluginProcessor::Event event, nd_flow_ptr &flow);
    void BroadcastProcessorEvent(ndPluginProcessor::Event event,
      ndInterfaces *interfaces);
    void BroadcastProcessorEvent(ndPluginProcessor::Event event,
      const std::string &iface, ndPacketStats *stats);
    void BroadcastProcessorEvent(
      ndPluginProcessor::Event event, ndPacketStats *stats);
    void BroadcastProcessorEvent(ndPluginProcessor::Event event,
      ndInstanceStatus *status);
    void BroadcastProcessorEvent(ndPluginProcessor::Event event);

    void Encode(nlohmann::json &output) const;

    void DisplayStatus(const nlohmann::json &status) const;

    void DumpVersions(ndPlugin::Type type = ndPlugin::Type::BASE);

protected:
    std::mutex lock;

    typedef std::map<std::string, ndPluginLoader *> map_plugin;

    map_plugin processors;
    map_plugin sinks;
};
