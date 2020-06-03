/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include <cstring>
#include "Region.hpp"

namespace bcov {

sstring
to_string(const FileRegion &region)
{
    return "pos:" + to_hex((addr_t) region.base_pos) +
           ", size:" + to_hex(region.size);
}

//===============================================

MemoryRegion::MemoryRegion(buffer_t pos, addr_t addr, size_t size) :
    m_base_pos(pos),
    m_base_address(addr),
    m_size(size)
{ }

sstring
to_string(const MemoryRegion &region)
{
    return "base_pos:" + to_hex((addr_t) region.base_pos()) +
           ", base_addr:" + to_hex(region.base_address()) +
           ", size:" + to_hex(region.size());
}

//===============================================

void
MMappedFileRegion::init(void *base_pos, addr_t base_addr, size_t size)
{
    this->m_base_pos = (ptr_type) base_pos;
    this->m_cur_pos = (ptr_type) base_pos;
    this->m_base_address = base_addr;
    this->m_size = size;
}

void
MMappedFileRegion::write(const void *buf, size_t size)
{
    std::memcpy(m_cur_pos, buf, size);
    m_cur_pos += size;
}

sstring
to_string(const MMappedFileRegion &region)
{
    return "base_pos:" + to_hex((addr_t) region.m_base_pos) +
           ", cur_pos:" + to_hex((addr_t) region.m_cur_pos) +
           ", base_addr:" + to_hex((addr_t) region.m_base_address) +
           ", size:" + to_hex(region.m_size);
}

} // bcov
