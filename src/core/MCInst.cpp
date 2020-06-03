/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */
#include "MCInst.hpp"

namespace bcov {

MCInst::MCInst(uint32_t idx, uint32_t cs_id, addr_t addr, uint16_t size,
               MCInstAttr attr) :
    m_idx(idx), m_csid(cs_id), m_addr(addr), m_size(size), m_attr(attr)
{ }

sstring_view
MCInst::text() const noexcept
{
    return m_text;
}

sstring
to_string(const MCInst &inst)
{
    return to_hex(inst.address()) + " " + inst.text().data();
}

} //bcov
