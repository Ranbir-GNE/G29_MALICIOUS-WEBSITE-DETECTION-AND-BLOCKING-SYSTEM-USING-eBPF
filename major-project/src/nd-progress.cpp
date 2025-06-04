// Netify Agent
// Copyright (C) 2024 eGloo Incorporated
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

#include <chrono>
#include <cstdlib>
#include <iostream>

#include "nd-progress.hpp"
#include "nd-util.hpp"

using namespace std;
using namespace std::chrono;

static void nd_progress_spinner(atomic<ndProgress::State> *state,
  const string *message, const string *complete,
  const time_t *delay) {

    if (! ndTerm::IsTTY()) cout << *message << endl;
    else cout << ndTerm::Attr::CURSOR_HIDE << flush;

    while (*state != ndProgress::State::STOPPED) {
        if (*state == ndProgress::State::PAUSED || ! ndTerm::IsTTY())
        {
            this_thread::sleep_for(seconds(1));
            continue;
        }

        unsigned a = (rand() % (255 - 232)) + 232;
        unsigned b = (rand() % (255 - 232)) + 232;
        unsigned c = (rand() % (255 - 232)) + 232;

        if (rand() % 10 == 5) {
            switch (rand() % 3) {
            case 0: a = 196; break;
            case 1: b = 196; break;
            case 2: c = 196; break;
            default: break;
            }
            switch (rand() % 3) {
            case 0: a = 82; break;
            case 1: b = 82; break;
            case 2: c = 82; break;
            default: break;
            }
            switch (rand() % 3) {
            case 0: a = 226; break;
            case 1: b = 226; break;
            case 2: c = 226; break;
            default: break;
            }
        }

        cout
          << "\r[38;5;" << a << "m"
          << (nd_progress_chars[rand() % nd_progress_size])
          << "[38;5;" << b << "m"
          << (nd_progress_chars[rand() % nd_progress_size])
          << "[38;5;" << c << "m"
          << (nd_progress_chars[rand() % nd_progress_size])
          << ndTerm::Attr::RESET << " " << *message << flush;

        this_thread::sleep_for(microseconds(*delay));
    }

    if (! ndTerm::IsTTY()) cout << *complete << endl;
    else {
        cout << "\r" << ndTerm::Attr::CLEAR_EOL << *complete << endl;
        cout << ndTerm::Attr::CURSOR_SHOW
             << ndTerm::Attr::RESET << flush;
    }
}

ndProgress::ndProgress(const std::string &message,
  const std::string &complete)
  : message(message), complete(complete){};

ndProgress::~ndProgress() {
    Stop();
}

bool ndProgress::Start(void) {
    if (worker != nullptr || state != State::INIT)
        return false;

    switch (type) {
    case ndProgress::Type::SPINNER:
        state = State::RUNNING;
        worker = new thread(nd_progress_spinner, &state,
          &message, &complete, &delay);
        break;
    default: return false;
    }

    return true;
}

void ndProgress::Stop(void) {
    if (worker != nullptr) {
        state = State::STOPPED;
        worker->join();
        delete worker;
        worker = nullptr;
    }
}
