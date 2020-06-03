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

#include "core/Common.hpp"
#include "core/MCInst.hpp"

#define MAX_BASIC_BLOCK_COUNT (0xFFFF)

namespace bcov {

enum class BasicBlockKind : uint8_t {
    kUnknown = 0x00,
    kFallthrough = 0x01,
    kBranch = 0x02,
    kLandingPad = 0x04,
    kPadding = 0x08,        // fallthrough bb inside a function to improve alignment
    kDangling = 0x28,       // fallthrough bb at function end representing UB
    kEntry = 0x10,
    kExit = 0x12
};

static inline BasicBlockKind operator&(BasicBlockKind a, BasicBlockKind b)
{
    return (BasicBlockKind) ((uint8_t) a & (uint8_t) b);
}

static inline BasicBlockKind operator|(BasicBlockKind a, BasicBlockKind b)
{
    return (BasicBlockKind) ((uint8_t) a | (uint8_t) b);
}

class BasicBlock {
    friend class FunctionBuilder;

public:
    using Idx = uint16_t; // should be enough for sane binaries

public:
    BasicBlock();

    BasicBlock(const BasicBlock &other) = default;

    BasicBlock &operator=(const BasicBlock &other) = default;

    BasicBlock(BasicBlock &&other) noexcept = default;

    BasicBlock &operator=(BasicBlock &&other) noexcept = default;

    ~BasicBlock() = default;

    //===============================================

    BasicBlockKind kind() const noexcept;

    void kind(BasicBlockKind kind) noexcept;

    Idx id() const noexcept;

    void id(size_t id) noexcept;

    addr_t address() const noexcept;

    addr_t end() const noexcept;

    size_t size() const noexcept;

    size_t byte_size() const noexcept;

    span<const MCInst> instructions() const noexcept;

    bool is_branching() const noexcept;

    bool is_fallthrough() const noexcept;

    bool is_padding() const noexcept;

    bool is_landing_pad() const noexcept;

    /// a basic block inserted for analysis purposes only
    bool is_virtual() const noexcept;

    bool is_inside(addr_t address) const noexcept;

private:
    BasicBlockKind m_kind;
    Idx m_idx;
    span<const MCInst> m_insts;
    unsigned short m_byte_size;
};

static inline bool operator<(const BasicBlock &a, const BasicBlock &b)
{
    return (!a.is_virtual() && !b.is_virtual() && a.address() < b.address());
}

/// valid equality iff a and b belong to the same function.
/// for comparison across functions use start addresses
static inline bool operator==(const BasicBlock &a, const BasicBlock &b)
{
    return a.id() == b.id();
}

static inline bool operator!=(const BasicBlock &a, const BasicBlock &b)
{
    return !(a == b);
}

} // bcov
