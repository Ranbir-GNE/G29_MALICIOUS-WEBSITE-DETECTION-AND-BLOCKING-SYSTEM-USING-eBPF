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

#include <pthread.h>
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <csignal>
#include <cstring>

#include "nd-except.hpp"
#include "nd-thread.hpp"
#include "nd-util.hpp"

using namespace std;

static void *nd_thread_entry(void *param) {
    void *rv = NULL;
    ndThread *thread = NULL;

    sigset_t signal_set;
    sigfillset(&signal_set);
    sigdelset(&signal_set, SIGPROF);

    try {
        int rc;
        if ((rc = pthread_sigmask(SIG_BLOCK, &signal_set, NULL)) != 0)
        {
            throw ndExceptionSystemErrno(__PRETTY_FUNCTION__,
              "pthread_sigmask", rc);
        }

        thread = reinterpret_cast<ndThread *>(param);
        thread->SetProcName();
        rv = thread->Entry();
    }
    catch (ndException &e) {
        nd_printf("%s: Exception: %s\n",
          thread->GetTag().c_str(), e.what());
    }

    thread->SetTerminated();

    return rv;
}

ndThread::ndThread(const string &tag, long cpu, bool ipc)
  : tag(tag), id(0), cpu(cpu), fd_ipc{ -1, -1 } {
    terminate = false;
    terminated = false;

    int rc;

    if ((rc = pthread_attr_init(&attr)) != 0) {
        throw ndExceptionSystemErrno(__PRETTY_FUNCTION__,
          "pthread_attr_init", rc);
    }

    if ((rc = pthread_mutex_init(&lock, NULL)) != 0) {
        throw ndExceptionSystemErrno(__PRETTY_FUNCTION__,
          "pthread_mutex_init", rc);
    }

    if (ipc &&
      socketpair(AF_LOCAL, SOCK_STREAM | SOCK_NONBLOCK, 0, fd_ipc) < 0)
    {
        throw ndExceptionSystemError(__PRETTY_FUNCTION__,
          "socketpair");
    }

    if (cpu == -1) return;
#if defined(HAVE_PTHREAD_ATTR_SETAFFINITY_NP)
#ifdef HAVE_SYS_CPUSET_H
    typedef cpuset_t cpu_set_t;
#endif
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);

    rc = pthread_attr_setaffinity_np(&attr, sizeof(cpuset), &cpuset);
#endif
}

ndThread::~ndThread(void) {
    pthread_attr_destroy(&attr);
    pthread_mutex_destroy(&lock);

    if (fd_ipc[0] != -1) close(fd_ipc[0]);
    if (fd_ipc[1] != -1) close(fd_ipc[1]);
}

void ndThread::SetProcName(void) {
#if defined(HAVE_PTHREAD_SETNAME_NP) && ! defined(_ND_LEAN_AND_MEAN)
    array<char, ND_THREAD_MAX_PROCNAMELEN> name;

    snprintf(name.data(), ND_THREAD_MAX_PROCNAMELEN, "%s",
      tag.c_str());
    if (tag.length() >= ND_THREAD_MAX_PROCNAMELEN - 1)
        name[ND_THREAD_MAX_PROCNAMELEN - 2] = '+';

    pthread_setname_np(id, name.data());
#endif
}

void ndThread::Create(void) {
    int rc;

    if (id != 0) {
        throw ndException("%s: thread already constructed",
          __PRETTY_FUNCTION__);
    }
    if ((rc = pthread_create(&id, &attr, nd_thread_entry,
           static_cast<void *>(this))) != 0)
    {
        throw ndExceptionSystemErrno(__PRETTY_FUNCTION__,
          "pthread_create", rc);
    }
}

int ndThread::Join(void) {
    if (id == 0) {
        throw ndException("%s: %s: %s", __PRETTY_FUNCTION__,
          "thread ID", strerror(EINVAL));
    }

    int rc;
    if ((rc = pthread_join(id, NULL)) != 0) {
        throw ndExceptionSystemErrno(__PRETTY_FUNCTION__,
          "pthread_join", rc);
    }

    id = 0;
    return 0;
}

void ndThread::Lock(void) {
    int rc = pthread_mutex_lock(&lock);

    if (rc != 0) {
        throw ndExceptionSystemErrno(__PRETTY_FUNCTION__,
          "pthread_mutex_lock", rc);
    }
}

void ndThread::Unlock(void) {
    int rc = pthread_mutex_unlock(&lock);

    if (rc != 0) {
        throw ndExceptionSystemErrno(__PRETTY_FUNCTION__,
          "pthread_mutex_unlock", rc);
    }
}

void ndThread::SendIPC(uint32_t id) {
    ssize_t bytes_wrote = 0;

    bytes_wrote = send(fd_ipc[ndEnumCast(PipeEnd, WRITE)],
      &id, sizeof(uint32_t), 0);

    if (bytes_wrote != sizeof(uint32_t)) {
        throw ndException(
          "%s: failed to send IPC message: %s", tag.c_str(),
          strerror(errno));
    }
}

uint32_t ndThread::RecvIPC(void) {
    uint32_t id = 0;
    ssize_t bytes_read = 0;

    bytes_read = recv(fd_ipc[ndEnumCast(PipeEnd, READ)],
      &id, sizeof(uint32_t), 0);

    if (bytes_read != sizeof(uint32_t)) {
        throw ndException(
          "%s: failed to receive IPC message: %s",
          tag.c_str(), strerror(errno));
    }

    return id;
}
