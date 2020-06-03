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

#include "Common.hpp"

namespace bcov {

class MCInst;

using MCInstId = uint32_t;
using MCInstPtr = const MCInst *;
using MCInstPtrVec =std::vector<MCInstPtr>;

enum class MCInstAttr : uint16_t {
    kNone = 0U,             // uninitialized or ordinary instruction
    kJump = 1U << 0U,       // all jump instructions (conditional+direct+indirect jumps)
    kCall = 1U << 1U,       // all call instructions
    kReturn = 1U << 2U,     // all return instructions
    kInterrupt = 1U << 3U,  // all interrupt instructions
    kRelative = 1U << 4U,   // explicitly or implicitly depend on program counter (rip)
    kPrivilege = 1U << 5U,  // all privileged instructions
    kDirect = 1U << 6U,     // instruction has one immediate operand
    kCond = 1U << 7U,       // all conditional instructions
    kPCRel = 1U << 8U,      // explicitly accesses program counter (rip)
    kIntRet = 1U << 9U      // interrupt return
};

static inline MCInstAttr operator&(MCInstAttr a, MCInstAttr b)
{
    return (MCInstAttr) (static_cast<unsigned>(a) & static_cast<unsigned>(b));
}

static inline MCInstAttr operator|(MCInstAttr a, MCInstAttr b)
{
    return (MCInstAttr) (static_cast<unsigned>(a) | static_cast<unsigned>(b));
}

static inline void operator|=(MCInstAttr &a, MCInstAttr b)
{
    a = a | b;
}

static inline void operator&=(MCInstAttr &a, MCInstAttr b)
{
    a = a & b;
}

class MCInst {
    friend class FunctionBuilder;

public:

    MCInst() = default;

    MCInst(const MCInst &other) = default;

    MCInst &operator=(const MCInst &other) = default;

    MCInst(MCInst &&other) noexcept = default;

    MCInst &operator=(MCInst &&other) noexcept = default;

    ~MCInst() = default;

    // operator overloads
    bool operator<(const MCInst &other) const noexcept
    {
        return m_addr < other.m_addr;
    }

    bool operator==(const MCInst &other) const noexcept
    {
        return m_addr == other.m_addr;
    }

    // public methods
    /// capstone's instruction identifier
    inline unsigned cs_id() const noexcept
    {
        return m_csid;
    }

    /// unique instruction identifier inside a function
    inline MCInstId id() const noexcept
    {
        return m_idx;
    }

    inline addr_t address() const noexcept
    {
        return m_addr;
    }

    inline addr_t end() const noexcept
    {
        return m_addr + m_size;
    }

    inline uint16_t size() const noexcept
    {
        return m_size;
    }

    inline MCInstAttr kind() const noexcept
    {
        return m_attr;
    }

    inline bool is_branch() const noexcept
    {
        return ((unsigned) m_attr & 0xFU) != 0;
    }

    inline bool is_jump() const noexcept
    {
        return (m_attr & MCInstAttr::kJump) == MCInstAttr::kJump;
    }

    inline bool is_call() const noexcept
    {
        return (m_attr & MCInstAttr::kCall) == MCInstAttr::kCall;
    }

    inline bool is_interrupt() const noexcept
    {
        return (m_attr & MCInstAttr::kInterrupt) == MCInstAttr::kInterrupt;
    }

    inline bool is_return() const noexcept
    {
        return (m_attr & MCInstAttr::kReturn) == MCInstAttr::kReturn;
    }

    inline bool is_conditional() const noexcept
    {
        return (m_attr & MCInstAttr::kCond) == MCInstAttr::kCond;
    }

    inline bool is_direct() const noexcept
    {
        return (m_attr & MCInstAttr::kDirect) == MCInstAttr::kDirect;
    }

    inline bool is_relative() const noexcept
    {
        return (m_attr & MCInstAttr::kRelative) == MCInstAttr::kRelative;
    }

    inline bool is_pc_relative() const noexcept
    {
        return (m_attr & MCInstAttr::kPCRel) == MCInstAttr::kPCRel;
    }

    sstring_view text() const noexcept;

protected:

    MCInst(MCInstId idx, uint32_t cs_id, addr_t addr, uint16_t size,
           MCInstAttr attr);

private:
    MCInstId m_idx;
    uint32_t m_csid;     // capstone's instruction id
    addr_t m_addr;       // virtual address
    uint16_t m_size;     // size in bytes
    MCInstAttr m_attr;
    sstring m_text;
};

sstring to_string(const MCInst &inst);

} //bcov

namespace std {

template<>
struct hash<bcov::MCInst> {
    auto operator()(const bcov::MCInst &x) const noexcept
    {
        return std::hash<uint64_t>{}(x.address());
    }
};

}
