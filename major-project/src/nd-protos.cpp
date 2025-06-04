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

#include "nd-protos.hpp"

using namespace ndProto;
using namespace ndProto::nDPI;

const uint16_t ndProto::nDPI::Find(Id id) {
    if (id == Id::UNKNOWN) return NDPI_PROTOCOL_UNKNOWN;

    for (auto &it : Protos) {
        if (it.second != id) continue;
        return it.first;
    }

    return NDPI_PROTOCOL_UNKNOWN;
}
