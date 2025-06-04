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

#include <curl/curl.h>
#include <unistd.h>

#include <ctime>
#include <map>
#include <nlohmann/json.hpp>

#include "nd-config.hpp"
#include "nd-thread.hpp"
#include "nd-util.hpp"

class ndNetifyApiManager;

class ndNetifyApiThread : public ndThread
{
public:
    ndNetifyApiThread();
    virtual ~ndNetifyApiThread();

    virtual void *Entry(void) = 0;

    void AppendContent(const char *data, size_t length);

    void ParseHeader(const std::string &header_raw);

    enum class Method : uint8_t {
        GET,
        HEAD,
        POST,
    };

    typedef std::map<std::string, std::string> Headers;

protected:
    friend class ndNetifyApiManager;

    void CreateHeaders(const Headers &headers);
    void DestroyHeaders(void);

    void Perform(Method method, const std::string &url,
      const Headers &headers,
      const std::string &payload = "");

    CURL *ch;

    CURLcode curl_rc;
    long http_rc;

    Headers headers_rx;
    struct curl_slist *headers_tx;

    std::string payload;

    std::string content;
    std::string content_type;
    std::string content_filename;
};

class ndNetifyApiBootstrap : public ndNetifyApiThread
{
public:
    ndNetifyApiBootstrap() : ndNetifyApiThread() { }

    virtual void *Entry(void);

protected:
    friend class ndNetifyApiManager;
};

class ndNetifyApiDownload : public ndNetifyApiThread
{
public:
    ndNetifyApiDownload(const std::string &token,
      const std::string &url,
      const std::string &filename = "");

    virtual ~ndNetifyApiDownload();

    virtual void *Entry(void);

protected:
    friend class ndNetifyApiManager;

    std::string tag;
    std::string token;
    std::string url;
    ndDigest digest = { { 0 } };
};

class ndNetifyApiManager
{
public:
    ndNetifyApiManager() : ttl_last_update(0) { }
    virtual ~ndNetifyApiManager() { Terminate(); }

    bool Update(void);
    void Terminate(void);

    inline const nlohmann::json &GetStatus(void) const {
        return jstatus;
    }

protected:
    struct RequestHash {
        template <typename T>
        size_t operator()(T t) const {
            return static_cast<std::size_t>(t);
        }
    };

    enum class Request : uint8_t {
        NONE,
        BOOTSTRAP,
        DOWNLOAD_CONFIG,
        DOWNLOAD_CATEGORIES,
    };

    typedef std::unordered_map<Request, ndNetifyApiThread *, RequestHash> Requests;

    Requests requests;

    typedef std::unordered_map<Request, std::string, RequestHash> Urls;

    Urls urls;

    std::string token;
    time_t ttl_last_update;

    typedef std::unordered_map<Request, bool, RequestHash> Results;

    Results download_results;

    bool ProcessBootstrapRequest(ndNetifyApiBootstrap *bootstrap);
    bool ProcessDownloadRequest(ndNetifyApiDownload *download,
      Request type);

    nlohmann::json jstatus;
};
