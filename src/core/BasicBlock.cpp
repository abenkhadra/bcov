/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */
#include "BasicBlock.hpp"

namespace bcov {

BasicBlock::BasicBlock() :
    m_kind(BasicBlockKind::kUnknown),
    m_idx(0),
    m_insts(),
    m_byte_size(0)
{

}

BasicBlockKind
BasicBlock::kind() const noexcept
{
    return m_kind;
}

void
BasicBlock::kind(BasicBlockKind kind) noexcept
{
    m_kind = kind;
}

BasicBlock::Idx
BasicBlock::id() const noexcept
{
    return m_idx;
}

void
BasicBlock::id(size_t id) noexcept
{
    m_idx = (BasicBlock::Idx) id;
}

addr_t
BasicBlock::address() const noexcept
{
    return is_virtual() ? (addr_t) m_kind : m_insts.front().address();
}

addr_t
BasicBlock::end() const noexcept
{
    return address() + m_byte_size;
}

size_t
BasicBlock::size() const noexcept
{
    return m_insts.size();
}

size_t
BasicBlock::byte_size() const noexcept
{
    return m_byte_size;
}

span<const MCInst>
BasicBlock::instructions() const noexcept
{
    return m_insts;
}

bool
BasicBlock::is_branching() const noexcept
{
    return (m_kind & BasicBlockKind::kBranch) == BasicBlockKind::kBranch;
}

bool
BasicBlock::is_padding() const noexcept
{
    return (m_kind & BasicBlockKind::kPadding) == BasicBlockKind::kPadding;
}

bool
BasicBlock::is_landing_pad() const noexcept
{
    return (m_kind & BasicBlockKind::kLandingPad) == BasicBlockKind::kLandingPad;
}

bool
BasicBlock::is_fallthrough() const noexcept
{
    return (m_kind & BasicBlockKind::kFallthrough) == BasicBlockKind::kFallthrough;
}

bool
BasicBlock::is_virtual() const noexcept
{
    return ((unsigned) m_kind & 0x10U) != 0;
}

bool
BasicBlock::is_inside(addr_t address) const noexcept
{
    return this->address() <= address && address < end();
}

} // bcov
