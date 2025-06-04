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

#include <array>
#include <stdexcept>

class ndException : public std::exception
{
public:
    explicit ndException(const char *format, ...) throw();

    virtual const char *what() const throw() {
        return message.data();
    }

protected:
    static constexpr size_t _ND_EXCEPT_MAX_MESSAGE = { 128 };
    std::array<char, _ND_EXCEPT_MAX_MESSAGE> message;
};

#define ndExceptionSystemError(ctag, what) \
    ndException("%s: %s: %s", ctag, what, strerror(errno));

#define ndExceptionSystemErrno(ctag, what, errno) \
    ndException("%s: %s: %s", ctag, what, strerror(errno));
