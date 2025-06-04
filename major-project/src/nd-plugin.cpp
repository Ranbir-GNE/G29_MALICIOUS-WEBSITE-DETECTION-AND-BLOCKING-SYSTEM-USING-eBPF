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

#include <dlfcn.h>
#include <iostream>

#include <nlohmann/json.hpp>

#include "nd-except.hpp"
#include "nd-instance.hpp"
#include "nd-plugin.hpp"
#include "nd-util.hpp"

using namespace std;
using json = nlohmann::json;

// #define _ND_LOG_PLUGIN_DEBUG    1

const map<ndPlugin::Type, string> ndPlugin::types = {
    // XXX: Keep in sync with Type enum
    make_pair(ndPlugin::Type::PROC, "processor"),
    make_pair(ndPlugin::Type::SINK, "sink"),
};

ndPlugin::ndPlugin(Type type, const string &tag, const Params &params)
  : ndThread(tag, -1), type(type) {
    for (auto &param : params) {
        if (param.first == "conf_filename")
            conf_filename = param.second;
    }
#ifdef _ND_LOG_PLUGIN_DEBUG
    nd_dprintf("Plugin created: %s\n", tag.c_str());
#endif
}

ndPlugin::~ndPlugin() {
#ifdef _ND_LOG_PLUGIN_DEBUG
    nd_dprintf("Plugin destroyed: %s\n", tag.c_str());
#endif
}

ndPluginSink::ndPluginSink(const string &tag,
  const ndPlugin::Params &params)
  : ndPlugin(ndPlugin::Type::SINK, tag, params),
    plq_size(0), plq_size_max(_ND_PLQ_DEFAULT_MAX_SIZE) {
    int rc;

    pthread_condattr_t cond_attr;
    pthread_condattr_init(&cond_attr);

    pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC);

    if ((rc = pthread_cond_init(&plq_cond, &cond_attr)) != 0)
    {
        throw ndExceptionSystemErrno(__PRETTY_FUNCTION__,
          "pthread_cond_init", rc);
    }

    pthread_condattr_destroy(&cond_attr);

    if ((rc = pthread_mutex_init(&plq_cond_mutex, nullptr)) != 0)
    {
        throw ndExceptionSystemErrno(__PRETTY_FUNCTION__,
          "pthread_mutex_init", rc);
    }

#ifdef _ND_LOG_PLUGIN_DEBUG
    nd_dprintf("Sink plugin created: %s\n", tag.c_str());
#endif
}

ndPluginSink::~ndPluginSink() {
    pthread_cond_destroy(&plq_cond);
    pthread_mutex_destroy(&plq_cond_mutex);
#ifdef _ND_LOG_PLUGIN_DEBUG
    nd_dprintf("Sink plugin destroyed: %s\n", tag.c_str());
#endif
}

ndPluginSinkPayload *ndPluginSinkPayload::Create(size_t length,
  const uint8_t *data, const ndPlugin::Channels &channels,
  ndFlags<ndPlugin::DispatchFlags> flags) {
    ndPluginSinkPayload *p = nullptr;

    if (! ndFlagBoolean(flags, ndPlugin::DispatchFlags::GZ_DEFLATE))
        p = new ndPluginSinkPayload(length, data, channels, flags);
    else {
        vector<uint8_t> buffer;
        nd_gz_deflate(length, data, buffer);
        p = new ndPluginSinkPayload(buffer.size(),
          &buffer[0], channels, flags);
    }

    return p;
}

void ndPluginSink::QueuePayload(ndPluginSinkPayload *payload) {
    Lock();

    plq_public.push(payload);

    Unlock();

    int rc;

    if ((rc = pthread_cond_broadcast(&plq_cond)) != 0) {
        throw ndExceptionSystemErrno(__PRETTY_FUNCTION__,
          "pthread_cond_broadcast", rc);
    }
}

size_t ndPluginSink::PullPayloadQueue(void) {
    if (plq_public.size() == 0) return 0;

    ndPluginSinkPayload *p;

    do {
        while (plq_private.size() && plq_size > plq_size_max)
        {
            p = plq_private.front();
            plq_private.pop();

            plq_size -= p->length;
            delete p;
        }

        p = plq_public.front();
        plq_public.pop();

        plq_size += p->length;
        plq_private.push(p);
    }
    while (plq_public.size() > 0);

    return plq_private.size();
}

size_t ndPluginSink::WaitOnPayloadQueue(unsigned timeout) {
    Lock();

    size_t entries = PullPayloadQueue();

    if (timeout > 0 && entries == 0) {
        Unlock();

        int rc;
        if ((rc = pthread_mutex_lock(&plq_cond_mutex)) != 0) {
            throw ndExceptionSystemErrno(__PRETTY_FUNCTION__,
              "pthread_mutex_lock", rc);
        }

        struct timespec ts_cond;
        if (clock_gettime(CLOCK_MONOTONIC, &ts_cond) != 0) {
            throw ndExceptionSystemError(__PRETTY_FUNCTION__,
              "clock_gettime");
        }

        ts_cond.tv_sec += timeout;

        if ((rc = pthread_cond_timedwait(&plq_cond,
               &plq_cond_mutex, &ts_cond)) != 0 &&
          rc != ETIMEDOUT)
        {
            throw ndExceptionSystemErrno(__PRETTY_FUNCTION__,
              "pthread_cond_timedwait", rc);
        }

        if ((rc = pthread_mutex_unlock(&plq_cond_mutex)) != 0)
        {
            throw ndExceptionSystemErrno(__PRETTY_FUNCTION__,
              "pthread_mutex_unlock", rc);
        }

        Lock();

        entries = PullPayloadQueue();
    }

    Unlock();

    return entries;
}

ndPluginProcessor::ndPluginProcessor(const string &tag,
  const ndPlugin::Params &params)
  : ndPlugin(ndPlugin::Type::PROC, tag, params) {
#if 0
    for (auto &param : params) {
        if (param.first == "sink_targets") {
            stringstream ss(param.second);

            while (ss.good()) {
                string value;
                getline(ss, value, ',');

                nd_trim(value, ' ');

                if (value.empty()) continue;

                string target;
                string channel = "default";

                size_t p = value.find_first_of(":");

                if (p == string::npos)
                    target = value;
                else {
                    target = value.substr(0, p);
                    channel = value.substr(p + 1);
                }

                auto i = sink_targets.find(target);

                if (i != sink_targets.end()) {
                    if (! i->second.insert(channel).second) {
                        throw ndException("%s: duplicate channel: %s",
                          target.c_str(), channel.c_str());
                    }
                }
                else {
                    ndPlugin::Channels channels = { channel };

                    if (! sink_targets.insert(
                        make_pair(target, channels)).second) {
                            throw ndException("%s: error creating target",
                              target.c_str());
                    }
                }
            }
        }
    }
#endif
#ifdef _ND_LOG_PLUGIN_DEBUG
    nd_dprintf("Processor plugin created: %s\n", tag.c_str());
#endif
}

ndPluginProcessor::~ndPluginProcessor() {
#ifdef _ND_LOG_PLUGIN_DEBUG
    nd_dprintf("Processor plugin destroyed: %s\n", tag.c_str());
#endif
}

void ndPluginProcessor::DispatchSinkPayload(const string &target,
  const ndPlugin::Channels &channels, size_t length,
  const uint8_t *payload, ndFlags<ndPlugin::DispatchFlags> flags) {
    ndInstance &ndi = ndInstance::GetInstance();

    ndPluginSinkPayload *sp = ndPluginSinkPayload::Create(
      length, payload, channels, flags);

    if (ndi.plugins.DispatchSinkPayload(target, sp)) return;

    throw ndException("%s: sink target not found", target.c_str());
}

void ndPluginProcessor::DispatchSinkPayload(const string &target,
  const ndPlugin::Channels &channels, const json &j,
  ndFlags<ndPlugin::DispatchFlags> flags) {
    if (ndFlagBoolean(flags, ndPlugin::DispatchFlags::FORMAT_MSGPACK))
    {
        vector<uint8_t> output;
        output = json::to_msgpack(j);

        if (ndFlagBoolean(flags, ndPlugin::DispatchFlags::ADD_HEADER))
        {
            json jheader;
            jheader["length"] = output.size();

            vector<uint8_t> header;
            header = json::to_msgpack(jheader);

            output.insert(output.begin(), header.begin(),
              header.end());
        }

        DispatchSinkPayload(target, channels, output, flags);
    }
    else {
        string output;
        nd_json_to_string(j, output, ndGC_DEBUG);

        flags |= ndPlugin::DispatchFlags::FORMAT_JSON;

        if (ndFlagBoolean(flags, ndPlugin::DispatchFlags::ADD_CR))
            output.append("\n");
        if (ndFlagBoolean(flags, ndPlugin::DispatchFlags::ADD_HEADER))
        {
            json jheader;
            jheader["length"] = output.size();

            string header;
            nd_json_to_string(jheader, header, false);
            header.append("\n");

            output.insert(output.begin(), header.begin(),
              header.end());
        }

        DispatchSinkPayload(target, channels, output.size(),
          (const uint8_t *)output.c_str(), flags);
    }
}

ndPluginLoader::ndPluginLoader(const string &tag,
  const string &so_name, const ndPlugin::Params &params)
  : tag(tag), so_name(so_name), so_handle(nullptr) {
    so_handle = dlopen(so_name.c_str(), RTLD_NOW);
    if (so_handle == nullptr)
        throw ndException("%s: %s", tag.c_str(), dlerror());

    char *dlerror_string;
    ndPlugin *(*ndPluginInit)(const string &,
      const ndPlugin::Params &);

    dlerror();
    *(void **)(&ndPluginInit) = dlsym(so_handle,
      "ndPluginInit");

    if ((dlerror_string = dlerror()) != nullptr) {
        dlclose(so_handle);
        so_handle = nullptr;
        throw ndException("%s: %s", tag.c_str(), dlerror_string);
    }

    plugin = (*ndPluginInit)(tag, params);
    if (plugin == nullptr) {
        dlclose(so_handle);
        so_handle = nullptr;
        throw ndException("%s: %s", tag.c_str(),
          "ndPluginInit");
    }

    nd_dprintf("Plugin loaded: %s: %s\n", tag.c_str(),
      so_name.c_str());
}

ndPluginLoader::~ndPluginLoader() {
    if (so_handle != nullptr) {
        dlclose(so_handle);
#ifdef _ND_LOG_PLUGIN_DEBUG
        nd_dprintf("Plugin dereferenced: %s: %s\n",
          tag.c_str(), so_name.c_str());
#endif
    }
}

void ndPluginManager::Load(ndPlugin::Type type, bool create) {
    lock_guard<mutex> ul(lock);

    for (auto &t : ndPlugin::types) {
        if (type != ndPlugin::Type::BASE && type != t.first)
            continue;

        const ndGlobalConfig::Plugins *plugins = nullptr;

        switch (t.first) {
        case ndPlugin::Type::PROC:
            plugins = &ndGC.plugin_processors;
            break;
        case ndPlugin::Type::SINK:
            plugins = &ndGC.plugin_sinks;
            break;
        default: break;
        }

        if (plugins == nullptr) continue;

        for (auto &i : *plugins) {
            ndPluginLoader *loader = nullptr;

            loader = new ndPluginLoader(i.first,
              i.second.first, i.second.second);

            if (loader->GetPlugin()->GetType() != t.first) {
                throw ndException("%s: %s", i.first.c_str(),
                  "wrong type");
            }

            if (create) loader->GetPlugin()->Create();

            map_plugin *mp = nullptr;

            switch (t.first) {
            case ndPlugin::Type::PROC:
                mp = &processors;
                break;
            case ndPlugin::Type::SINK: mp = &sinks; break;
            default:
                throw ndException("%s: %s", i.first.c_str(),
                  "wrong type");
                break;
            }

            auto pl = mp->find(t.second);

            if (pl != mp->end()) {
                throw ndException("%s: %s", i.first.c_str(),
                  "duplicate plugin tag");
            }

            if (! mp->insert(make_pair(i.first, loader)).second)
            {
                throw ndException("%s: %s", i.first.c_str(),
                  "failed to insert plugin loader");
            }
        }
    }
}

bool ndPluginManager::Create(ndPlugin::Type type) {
    lock_guard<mutex> ul(lock);

    for (auto &t : ndPlugin::types) {
        if (type != ndPlugin::Type::BASE && type != t.first)
            continue;

        map_plugin *mp = nullptr;

        switch (t.first) {
        case ndPlugin::Type::PROC: mp = &processors; break;
        case ndPlugin::Type::SINK: mp = &sinks; break;
        default:
            throw ndException("%s: %s", t.second.c_str(),
              "invalid type");
            break;
        }

        auto pl = mp->find(t.second);

        if (pl == mp->end()) {
            throw ndException("%s: %s", t.second.c_str(),
              "plugin not found");
        }

        pl->second->GetPlugin()->Create();

        return true;
    }

    return false;
}

size_t ndPluginManager::Terminate(ndPlugin::Type type) {
    size_t count = 0;

    if (type == ndPlugin::Type::BASE || type == ndPlugin::Type::PROC)
    {
        for (auto &p : processors) {
            count++;
            p.second->GetPlugin()->Terminate();
        }
    }

    if (type == ndPlugin::Type::BASE || type == ndPlugin::Type::SINK)
    {
        for (auto &p : sinks) {
            count++;
            p.second->GetPlugin()->Terminate();
        }
    }

    return count;
}

void ndPluginManager::Destroy(ndPlugin::Type type) {
    lock_guard<mutex> ul(lock);

    if (type == ndPlugin::Type::BASE || type == ndPlugin::Type::PROC)
    {
        for (auto &p : processors)
            p.second->GetPlugin()->Terminate();

        for (auto &p : processors) {
            delete p.second->GetPlugin();
            delete p.second;
        }

        processors.clear();
    }

    if (type == ndPlugin::Type::BASE || type == ndPlugin::Type::SINK)
    {
        for (auto &p : sinks)
            p.second->GetPlugin()->Terminate();

        for (auto &p : sinks) {
            delete p.second->GetPlugin();
            delete p.second;
        }

        sinks.clear();
    }
}

size_t ndPluginManager::Reap(ndPlugin::Type type) {
    size_t count = 0;

    for (auto &t : ndPlugin::types) {
        if (type != ndPlugin::Type::BASE && type != t.first)
            continue;

        map_plugin *mp = nullptr;

        switch (t.first) {
        case ndPlugin::Type::PROC: mp = &processors; break;
        case ndPlugin::Type::SINK: mp = &sinks; break;
        default:
            throw ndException("%s: %s", t.second.c_str(),
              "invalid type");
            break;
        }

        for (map_plugin::iterator p = mp->begin(); p != mp->end();)
        {
            if (! p->second->GetPlugin()->HasTerminated()) {
                p++;
                continue;
            }

            nd_printf("Plugin has terminated: %s: %s\n",
              p->second->GetTag().c_str(),
              p->second->GetObjectName().c_str());

            lock_guard<mutex> ul(lock);

            delete p->second->GetPlugin();
            delete p->second;

            count++;
            p = mp->erase(p);
        }
    }

    return count;
}

void ndPluginManager::BroadcastEvent(ndPlugin::Type type,
  ndPlugin::Event event, void *param) {
    lock_guard<mutex> ul(lock);

    for (auto &t : ndPlugin::types) {
        if (type != ndPlugin::Type::BASE && type != t.first)
            continue;

        map_plugin *mp = nullptr;

        switch (t.first) {
        case ndPlugin::Type::PROC: mp = &processors; break;
        case ndPlugin::Type::SINK: mp = &sinks; break;
        default:
            throw ndException("%s: %s", t.second.c_str(),
              "invalid type");
            break;
        }

        for (auto &p : *mp)
            p.second->GetPlugin()->DispatchEvent(event, param);
    }
}

void ndPluginManager::BroadcastSinkPayload(
  ndPluginSinkPayload *payload) {
    lock_guard<mutex> ul(lock);

    if (sinks.empty()) {
        delete payload;
        return;
    }

    auto p = sinks.cbegin();

    for (; p != prev(sinks.cend()); p++) {
        ndPluginSinkPayload *sp = ndPluginSinkPayload::Create(payload);

        reinterpret_cast<ndPluginSink *>(p->second->GetPlugin())
          ->QueuePayload(sp);
    }

    reinterpret_cast<ndPluginSink *>(p->second->GetPlugin())
      ->QueuePayload(payload);
}

bool ndPluginManager::DispatchSinkPayload(
  const string &target, ndPluginSinkPayload *payload) {
    lock_guard<mutex> ul(lock);

    auto p = sinks.find(target);

    if (p == sinks.end()) return false;

    reinterpret_cast<ndPluginSink *>((*p).second->GetPlugin())
      ->QueuePayload(payload);

    return true;
}

void ndPluginManager::BroadcastProcessorEvent(
  ndPluginProcessor::Event event, ndFlowMap *flow_map) {
    lock_guard<mutex> ul(lock);

    for (auto &p : processors) {
        reinterpret_cast<ndPluginProcessor *>(p.second->GetPlugin())
          ->DispatchProcessorEvent(event, flow_map);
    }
}

void ndPluginManager::BroadcastProcessorEvent(
  ndPluginProcessor::Event event, nd_flow_ptr &flow) {
    lock_guard<mutex> ul(lock);

    for (auto &p : processors) {
        reinterpret_cast<ndPluginProcessor *>(p.second->GetPlugin())
          ->DispatchProcessorEvent(event, flow);
    }
}

void ndPluginManager::BroadcastProcessorEvent(
  ndPluginProcessor::Event event, ndInterfaces *interfaces) {
    lock_guard<mutex> ul(lock);

    for (auto &p : processors) {
        reinterpret_cast<ndPluginProcessor *>(p.second->GetPlugin())
          ->DispatchProcessorEvent(event, interfaces);
    }
}

void ndPluginManager::BroadcastProcessorEvent(
  ndPluginProcessor::Event event, const string &iface,
  ndPacketStats *stats) {
    lock_guard<mutex> ul(lock);

    for (auto &p : processors) {
        reinterpret_cast<ndPluginProcessor *>(p.second->GetPlugin())
          ->DispatchProcessorEvent(event, iface, stats);
    }
}

void ndPluginManager::BroadcastProcessorEvent(
  ndPluginProcessor::Event event, ndPacketStats *stats) {
    lock_guard<mutex> ul(lock);

    for (auto &p : processors) {
        reinterpret_cast<ndPluginProcessor *>(p.second->GetPlugin())
          ->DispatchProcessorEvent(event, stats);
    }
}

void ndPluginManager::BroadcastProcessorEvent(
  ndPluginProcessor::Event event, ndInstanceStatus *status) {
    lock_guard<mutex> ul(lock);

    for (auto &p : processors) {
        reinterpret_cast<ndPluginProcessor *>(p.second->GetPlugin())
          ->DispatchProcessorEvent(event, status);
    }
}

void ndPluginManager::BroadcastProcessorEvent(
  ndPluginProcessor::Event event) {
    lock_guard<mutex> ul(lock);

    for (auto &p : processors) {
        reinterpret_cast<ndPluginProcessor *>(p.second->GetPlugin())
          ->DispatchProcessorEvent(event);
    }
}

void ndPluginManager::Encode(nlohmann::json &output) const {
    auto add_plugins =
      [](const map_plugin &plugins_in, json &plugins_out,
        const string &type) {
        for (auto &p : plugins_in) {
            json plugin;

            plugin["tag"] = p.first;
            plugin["type"] = type;

            string version;
            p.second->GetPlugin()->GetVersion(version);

            plugin["version"] = version;

            json status;
            p.second->GetPlugin()->GetStatus(status);
            plugin["status"] = status;

            plugins_out[p.first] = plugin;
        }
    };

    json plugins;
    add_plugins(processors, plugins, "processor");
    add_plugins(sinks, plugins, "sink");

    output["plugins"] = plugins;
}

void ndPluginManager::DisplayStatus(const nlohmann::json &status) const {
    auto display_plugin = [this](const json &plugin) {
        string tag = "<tag>", version = "<version>",
               type = "<type>";

        auto i = plugin.find("tag");
        if (i != plugin.end() && i->is_string())
            tag = i->get<string>();
        i = plugin.find("version");
        if (i != plugin.end() && i->is_string())
            version = i->get<string>();
        i = plugin.find("type");
        if (i != plugin.end() && i->is_string())
            type = i->get<string>();

        fprintf(stdout, "%s%s/%s%s (%s)\n",
          ndTerm::Attr::BOLD, tag.c_str(), version.c_str(),
          ndTerm::Attr::RESET, type.c_str());

        ndPluginLoader *pl = nullptr;

        if (type == "processor") {
            for (auto &p : processors) {
                if (p.second->GetTag() != tag) continue;
                pl = p.second;
                break;
            }
        }
        else if (type == "sink") {
            for (auto &p : sinks) {
                if (p.second->GetTag() != tag) continue;
                pl = p.second;
                break;
            }
        }

        if (pl != nullptr) {
            auto s = plugin.find("status");
            if (s != plugin.end() && s->is_object())
                pl->GetPlugin()->DisplayStatus(
                  s->get<json::object_t>());
        }
        else {
            fprintf(stdout, "%s%s%s %s\n", ndTerm::Color::RED,
              ndTerm::Icon::WARN, ndTerm::Attr::RESET,
              "Plugin no longer loaded.");
        }
    };

    auto plugins = status.find("plugins");
    if (plugins != status.end() && plugins->is_object()) {
        for (auto &it_kvp : plugins->get<json::object_t>())
            display_plugin(it_kvp.second);
    }
    else {
        fprintf(stdout, "%s%s%s %s\n", ndTerm::Color::RED,
          ndTerm::Icon::FAIL, ndTerm::Attr::RESET,
          "Plugin status unavailable.");
    }
}

void ndPluginManager::DumpVersions(ndPlugin::Type type) {
    for (auto &t : ndPlugin::types) {
        if (type != ndPlugin::Type::BASE && type != t.first)
            continue;

        map_plugin *mp = nullptr;

        switch (t.first) {
        case ndPlugin::Type::PROC: mp = &processors; break;
        case ndPlugin::Type::SINK: mp = &sinks; break;
        default:
            throw ndException("%s: %s", t.second.c_str(),
              "invalid type");
            break;
        }

        lock_guard<mutex> ul(lock);

        for (auto &p : *mp) {
            string version;
            p.second->GetPlugin()->GetVersion(version);
            if (version.empty())
                version = "Error loading plugin!";

            cerr
              << " " << ndTerm::Attr::BOLD << p.second->GetTag()
              << "/" << version << ndTerm::Attr::RESET << endl
              << "    "
              << p.second->GetPlugin()->GetConfiguration() << endl
              << "    " << p.second->GetObjectName() << endl;
        }
    }
}
