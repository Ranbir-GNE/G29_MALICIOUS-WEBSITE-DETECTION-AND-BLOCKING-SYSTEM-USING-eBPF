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
#include <string>

#include "nd-except.hpp"

#define ND_THREAD_MAX_PROCNAMELEN 16

class ndThread
{
public:
    ndThread(const std::string &tag, long cpu = -1, bool ipc = false);
    virtual ~ndThread();

    const std::string &GetTag(void) { return tag; }
    pthread_t GetId(void) { return id; }

    void SetProcName(void);

    virtual void Create(void);
    virtual void *Entry(void) = 0;

    virtual inline void Terminate(void) {
        terminate = true;
    }
    inline bool ShouldTerminate(void) {
        return terminate.load();
    }

    inline void SetTerminated(void) { terminated = true; }
    inline bool HasTerminated(void) {
        return terminated.load();
    }

    void Lock(void);
    void Unlock(void);

    void SendIPC(uint32_t id);
    uint32_t RecvIPC(void);

protected:
    std::string tag;
    pthread_t id;
    long cpu;
    pthread_attr_t attr;
    pthread_mutex_t lock;

    enum class PipeEnd : uint8_t { READ, WRITE, MAX };
    int fd_ipc[static_cast<unsigned>(PipeEnd::MAX)];

    int Join(void);

private:
    std::atomic<bool> terminate;
    std::atomic<bool> terminated;
};
