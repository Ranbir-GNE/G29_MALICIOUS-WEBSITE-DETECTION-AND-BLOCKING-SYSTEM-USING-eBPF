#pragma once

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <type_traits>

template <typename T>
struct ndFlags {
    T flags;

    ndFlags() = default;
    ndFlags(T v) : flags(v) { }

    T operator=(const T &rhs) { return (flags = rhs); }

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
        lhs << resetiosflags(flags) << "0x" << std::hex
            << std::setw(width) << std::setfill('0')
            << static_cast<typename std::underlying_type<T>::type>(
                 rhs.flags)
            << setiosflags(flags);
        return lhs;
    }
};

template <typename T>
T operator|(const ndFlags<T> &lhs, const ndFlags<T> &rhs) {
    std::cout
      << static_cast<typename std::underlying_type<T>::type>(
           lhs.flags)
      << " |A "
      << static_cast<typename std::underlying_type<T>::type>(
           rhs.flags)
      << std::endl;
    return static_cast<T>(
      static_cast<typename std::underlying_type<T>::type>(
        lhs.flags) |
      static_cast<typename std::underlying_type<T>::type>(
        rhs.flags));
}

template <typename T>
T operator|(const T &lhs, const T &rhs) {
    std::cout
      << static_cast<typename std::underlying_type<T>::type>(lhs)
      << " |B "
      << static_cast<typename std::underlying_type<T>::type>(rhs)
      << std::endl;
    return static_cast<T>(
      static_cast<typename std::underlying_type<T>::type>(lhs) |
      static_cast<typename std::underlying_type<T>::type>(rhs));
}

template <typename T>
T operator~(const T &rhs) {
    return static_cast<T>(
      ~static_cast<typename std::underlying_type<T>::type>(rhs));
}
