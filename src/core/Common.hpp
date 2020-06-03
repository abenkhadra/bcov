/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#pragma once

#include <cinttypes>
#include <cassert>
#include "gsl/gsl-lite.hpp"

#define UNUSED(x) (void)(x)

namespace bcov {

#define BCOV_FORWARD(OBJ)   \
    namespace bcov {        \
        class OBJ;          \
    }

#define BCOV_FORWARD_T(OBJ)     \
    namespace bcov {            \
        template<class T>       \
        class OBJ;              \
    }

#ifdef NDEBUG
#define BCOV_DEBUG(x) void()
#else
#define BCOV_DEBUG(x) x
#endif

#ifdef NDEBUG
#define BCOV_UNREACHABLE __builtin_unreachable();
#else
#define BCOV_UNREACHABLE assert("unreachable!");
#endif

using addr_t = uint64_t;

using uoffset_t = uint64_t;

using soffset_t = int64_t;

using buffer_t = const uint8_t *;

using czstring = gsl::czstring;

using sstring = std::string;

using sstring_view = gsl::cstring_span;

template<typename T> using span = gsl::span<T>;

template<typename T>
std::string to_hex(T v);

sstring hex_dump(const void *a, size_t len);

template<typename T>
std::string
to_hex(T v)
{
    // copied from libelfin/elf/to_hex.hh
    static_assert(std::is_integral<T>::value,
                  "to_hex applied to non-integral type");
    if (v == 0)
        return std::string("0");
    char buf[sizeof(T) * 2 + 1];
    char *pos = &buf[sizeof(buf) - 1];
    *pos-- = '\0';
    while (v && pos >= buf) {
        int digit = v & 0xf;
        if (digit < 10)
            *pos = '0' + digit;
        else
            *pos = 'a' + (digit - 10);
        pos--;
        v >>= 4;
    }
    return std::string(pos + 1);
}

template<typename T>
constexpr auto to_integral(T e) -> typename std::underlying_type<T>::type
{
    return static_cast<typename std::underlying_type<T>::type>(e);
}

template<typename T>
typename T::iterator get_forward_iter(T &vec, typename T::reverse_iterator rev_it)
{
    return vec.begin() + (vec.rend() - rev_it) - 1;
}

template<typename T>
typename T::reverse_iterator get_reverse_iter(T &vec, typename T::iterator fwd_it)
{
    return vec.rbegin() + (vec.end() - fwd_it) - 1;
}

} // bcov
