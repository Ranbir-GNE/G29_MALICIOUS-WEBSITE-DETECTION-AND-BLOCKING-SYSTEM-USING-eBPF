// Netify Agent 🥷
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

#include <syslog.h>

#include <exception>
#include <iostream>
#include <locale>

#include "nd-instance.hpp"
#include "nd-signal.hpp"
#include "nd-util.hpp"
#include "netifyd.hpp"

using namespace std;

int main(int argc, char* argv[]) {
    int rc = 0;
    uint32_t result;

    try {
        locale::global(locale("C"));

        cout.imbue(locale());
        cerr.imbue(locale());
    }
    catch (exception& e) {
        fprintf(stderr, "Exception while setting locale.\n");
    }

    openlog(ND_NAME_SHORT,
      LOG_NDELAY | LOG_PID | LOG_PERROR, LOG_DAEMON);

    nd_seed_rng();

    sigset_t sigset;
    sigfillset(&sigset);

    // sigdelset(&sigset, SIGPROF);
    // sigdelset(&sigset, SIGINT);
    sigdelset(&sigset, SIGQUIT);

    sigprocmask(SIG_BLOCK, &sigset, NULL);

    sigemptyset(&sigset);
    sigaddset(&sigset, ND_SIG_UPDATE);
    sigaddset(&sigset, ND_SIG_UPDATE_NAPI);
    sigaddset(&sigset, SIGHUP);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGIO);
#ifdef SIGPWR
    sigaddset(&sigset, SIGPWR);
#endif
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGUSR1);
    sigaddset(&sigset, SIGUSR2);

    ndInstance& instance = ndInstance::Create();

    result = instance.InitializeConfig(argc, argv);

    if (ndCR_Result(result) != ndInstance::ConfigResult::OK)
        return ndCR_Code(result);

    if (instance.Daemonize() == false) return 1;

    // When using provided timers, ensure they initialized
    // after Daemonize() is called, otherwise on some
    // platforms, timer IDs are not maintained after fork(2).
    if (instance.InitializeTimers() == false) return 1;

    rc = instance.Run();

    if (rc == 0) {
        siginfo_t si;
        const struct timespec tspec_sigwait = { 1, 0 };

        while (! instance.HasTerminated()) {
            if (sigtimedwait(&sigset, &si, &tspec_sigwait) < 0)
            {
                if (errno == EAGAIN || errno == EINTR)
                    continue;

                nd_printf("sigwaitinfo: %s\n", strerror(errno));

                rc = -1;
                instance.Terminate();
                continue;
            }

            instance.SendSignal(si);
        }
    }

    ndInstance::Destroy();

    return rc;
}
