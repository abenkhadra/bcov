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

#include "libelfin/elf/elf++.hh"

namespace elf {

static inline bool
is_read(const section &sec)
{
    return (sec.get_hdr().flags & shf::write) == shf::write;
}

static inline bool
is_alloc(const section &sec)
{
    return (sec.get_hdr().flags & shf::alloc) == shf::alloc;
}

static inline bool
is_executable(const section &sec)
{
    return (sec.get_hdr().flags & shf::execinstr) == shf::execinstr;
}

static inline bool
is_executable(const segment &seg)
{
    return (seg.get_hdr().flags & pf::x) == pf::x;
}

static inline bool
is_loadable(const segment &seg)
{
    return seg.get_hdr().type == pt::load;
}

static inline bool
is_gnu_relro(const segment &seg)
{
    return seg.get_hdr().type == pt::gnu_relro;
}

static inline bool
is_writable(const segment &seg)
{
    return (seg.get_hdr().flags & pf::w) == pf::w;
}

static inline bool
is_readable(const segment &seg)
{
    return (seg.get_hdr().flags & pf::r) == pf::r;
}

} // elf
