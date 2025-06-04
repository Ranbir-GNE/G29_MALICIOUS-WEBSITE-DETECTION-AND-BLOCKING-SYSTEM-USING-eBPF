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

#define _NDFP_MAX_BUFLEN        256

#define _NDFP_OTHER_UNKNOWN     0
#define _NDFP_OTHER_UNSUPPORTED 1
#define _NDFP_OTHER_LOCAL       2
#define _NDFP_OTHER_MULTICAST   3
#define _NDFP_OTHER_BROADCAST   4
#define _NDFP_OTHER_REMOTE      5
#define _NDFP_OTHER_ERROR       6

#define _NDFP_TUNNEL_NONE       0
#define _NDFP_TUNNEL_GTP        1

#define _NDFP_ORIGIN_UNKNOWN    0
#define _NDFP_ORIGIN_LOCAL      1
#define _NDFP_ORIGIN_OTHER      2

#if 0
#define _NDFP_debugf(f, ...) nd_dprintf(f, __VA_ARGS__)
#else
#define _NDFP_debugf(f, ...) \
    do { \
    } \
    while (0)
#endif
