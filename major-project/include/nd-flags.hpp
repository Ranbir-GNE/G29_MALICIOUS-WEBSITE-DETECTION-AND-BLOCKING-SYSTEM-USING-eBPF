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

#pragma once

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <type_traits>

#define ndFlagBoolean(flags, bits) \
    ((flags & (bits)) == (bits))
#define ndFlagBooleanAny(flags, bits) \
    (static_cast<unsigned>(flags & (bits)) != 0)

template <typename T>
struct ndFlags {
    T flags;

    ndFlags() = default;
    ndFlags(T v) : flags(v) { }

    T operator=(const T &rhs) { return (flags = rhs); }

    bool operator==(const T &rhs) const {
        return (flags == rhs);
    }

    bool operator!=(const T &rhs) const {
        return (flags != rhs);
    }

    T operator|(const T &rhs) const {
        return static_cast<T>(
          static_cast<typename std::underlying_type<T>::type>(flags) |
          static_cast<typename std::underlying_type<T>::type>(rhs));
    }

    T operator&(const T &rhs) const {
        return static_cast<T>(
          static_cast<typename std::underlying_type<T>::type>(flags) &
          static_cast<typename std::underlying_type<T>::type>(rhs));
    }

    T operator~() const {
        return static_cast<T>(
          ~static_cast<typename std::underlying_type<T>::type>(flags));
    }

    T &operator|=(const T &rhs) {
        flags = static_cast<T>(
          static_cast<typename std::underlying_type<T>::type>(flags) |
          static_cast<typename std::underlying_type<T>::type>(rhs));
        return flags;
    }

    T &operator|=(const ndFlags<T> &rhs) {
        flags = static_cast<T>(
          static_cast<typename std::underlying_type<T>::type>(flags) |
          static_cast<typename std::underlying_type<T>::type>(
            rhs.flags));
        return flags;
    }

    T &operator&=(const T &rhs) {
        flags = static_cast<T>(
          static_cast<typename std::underlying_type<T>::type>(flags) &
          static_cast<typename std::underlying_type<T>::type>(rhs));
        return flags;
    }

    T &operator&=(const ndFlags<T> &rhs) {
        flags = static_cast<T>(
          static_cast<typename std::underlying_type<T>::type>(flags) &
          static_cast<typename std::underlying_type<T>::type>(
            rhs.flags));
        return flags;
    }

    friend std::ostream &
    operator<<(std::ostream &lhs, const T &rhs) {
        lhs << "0x" << std::hex << std::setw(2)
            << std::setfill('0')
            << static_cast<typename std::underlying_type<T>::type>(rhs);
        return lhs;
    }

    friend std::ostream &
    operator<<(std::ostream &lhs, const ndFlags<T> &rhs) {
        uint8_t width =
          sizeof(static_cast<typename std::underlying_type<T>::type>(
            rhs.flags)) *
          2;
        auto flags = lhs.flags();
        lhs << std::resetiosflags(flags) << "0x" << std::hex
            << std::setw(width) << std::setfill('0')
            << static_cast<typename std::underlying_type<T>::type>(
                 rhs.flags)
            << std::setiosflags(flags);
        return lhs;
    }
};

template <typename T>
bool operator==(const ndFlags<T> &lhs, const ndFlags<T> &rhs) {
    return (lhs.flags == rhs.flags);
}

template <typename T>
bool operator!=(const ndFlags<T> &lhs, const ndFlags<T> &rhs) {
    return (lhs.flags != rhs.flags);
}

template <typename T>
T operator|(const ndFlags<T> &lhs, const ndFlags<T> &rhs) {
    return static_cast<T>(
      static_cast<typename std::underlying_type<T>::type>(
        lhs.flags) |
      static_cast<typename std::underlying_type<T>::type>(
        rhs.flags));
}

template <typename T>
T operator|(const T &lhs, const T &rhs) {
    return static_cast<T>(
      static_cast<typename std::underlying_type<T>::type>(lhs) |
      static_cast<typename std::underlying_type<T>::type>(rhs));
}

template <typename T>
T operator~(const T &rhs) {
    return static_cast<T>(
      ~static_cast<typename std::underlying_type<T>::type>(rhs));
}
