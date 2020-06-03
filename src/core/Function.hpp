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
#include "MCInst.hpp"
#include "BasicBlock.hpp"
#include "graph/CFG.hpp"
#include "graph/DominatorTree.hpp"

BCOV_FORWARD(Demangler)

namespace bcov {

enum class CallSiteKind : uint8_t {
    kUnknown = 0x0,
    kDirectCall = 0x1,
    kDirectTail = 0x2,
    kLocalCall = 0xd,       // direct intra-procedural call
    kNoReturnCall = 0x5,    // direct call to a noreturn function
    kIndirect = 0x10,       // just a bit mask
    kIndirectCall = 0x11,
    kIndirectTail = 0x12,
    kTrap = 0x14,
    kReturn = 0x30
};

static inline CallSiteKind operator&(CallSiteKind a, CallSiteKind b)
{
    return (CallSiteKind) ((uint64_t) a & (uint64_t) b);
}

static inline CallSiteKind operator|(CallSiteKind a, CallSiteKind b)
{
    return (CallSiteKind) ((uint64_t) a | (uint64_t) b);
}

enum class FunctionAttrs : uint8_t {
    kNone = 0x0,
    kReturn = 0x1,
    kMayReturn = 0x2,
    kNoReturn = 0x4,
    kExported = 0x10
};

static inline FunctionAttrs operator&(FunctionAttrs a, FunctionAttrs b)
{
    return (FunctionAttrs) ((uint64_t) a & (uint64_t) b);
}

static inline FunctionAttrs operator|(FunctionAttrs a, FunctionAttrs b)
{
    return (FunctionAttrs) ((uint64_t) a | (uint64_t) b);
}

static inline bool is_attr_set(FunctionAttrs a, FunctionAttrs attr)
{
    return (a & attr) == attr;
}

static inline void set_attr(FunctionAttrs &a, FunctionAttrs attr)
{
    a = a | attr;
}

static inline FunctionAttrs get_return_mode(FunctionAttrs a)
{
    return (FunctionAttrs) ((unsigned) a & 0xFU);
}

static inline void set_return_mode(FunctionAttrs &a, FunctionAttrs mode)
{
    a = mode | (FunctionAttrs) ((unsigned) a & 0xF0U);
}

enum class JumpTabKind : uint8_t {
    kInvalid = 0x0,
    kOffsetI8 = 0x1,
    kOffsetI16 = 0x2,
    kOffsetI32 = 0x4,
    kOffsetU8 = 0x11,
    kOffsetU16 = 0x12,
    kAbsAddr32 = 0xF4,
    kAbsAddr64 = 0xF8,
};

static inline bool is_offset_kind(JumpTabKind a)
{
    return ((uint8_t) a & 0xF0) != 0xF0;
}

static inline unsigned entry_size(JumpTabKind a)
{
    return ((uint8_t) a) & 0x0FU;
}

class JumpTabEntryReader {
public:
    virtual addr_t read(const uint8_t *buf, addr_t base_addr) const = 0;
};

class JumpTabEntryAbs32Reader : public JumpTabEntryReader {
public:
    addr_t read(const uint8_t *buf, addr_t base_addr) const override;
};

class JumpTabEntryAbs64Reader : public JumpTabEntryReader {
public:
    addr_t read(const uint8_t *buf, addr_t base_addr) const override;
};

class JumpTabEntryOffI32Reader : public JumpTabEntryReader {
public:
    addr_t read(const uint8_t *buf, addr_t base_addr) const override;
};

class JumpTabEntryOffI16Reader : public JumpTabEntryReader {
public:
    addr_t read(const uint8_t *buf, addr_t base_addr) const override;
};

class JumpTabEntryOffI8Reader : public JumpTabEntryReader {
public:
    addr_t read(const uint8_t *buf, addr_t base_addr) const override;
};

class JumpTabEntryOffU16Reader : public JumpTabEntryReader {
public:
    addr_t read(const uint8_t *buf, addr_t base_addr) const override;
};

class JumpTabEntryOffU8Reader : public JumpTabEntryReader {
public:
    addr_t read(const uint8_t *buf, addr_t base_addr) const override;
};

class JumpTabEntryWriter {
public:
    virtual void write(addr_t target, addr_t base_addr, uint8_t *buf) const = 0;
};

class JumpTabEntryOff32Writer : public JumpTabEntryWriter {
public:
    void write(addr_t target, addr_t base_addr, uint8_t *buf) const override;
};

class JumpTabEntryAbs32Writer : public JumpTabEntryWriter {
public:
    void write(addr_t target, addr_t base_addr, uint8_t *buf) const override;
};

class JumpTabEntryAbs64Writer : public JumpTabEntryWriter {
public:
    void write(addr_t target, addr_t base_addr, uint8_t *buf) const override;
};

const JumpTabEntryReader *
get_jumptab_reader(JumpTabKind kind) __attribute__((const));

const JumpTabEntryWriter *
get_jumptab_writer(JumpTabKind kind) __attribute__((const));

class FunctionBase {
    friend class ElfModuleBuilder;

public:
    using Idx = unsigned;

    FunctionBase();

    FunctionBase(sstring_view name, addr_t address, const uint8_t *data,
                 size_t size);

    virtual ~FunctionBase() = default;

    FunctionAttrs attrs() const noexcept;

    Idx idx() const noexcept;

    const uint8_t *data() const noexcept;

    addr_t address() const noexcept;

    size_t size() const noexcept;

    const sstring &name() const noexcept;

    bool is_dynamic() const noexcept;

    bool is_runtime() const noexcept;

    bool is_static() const noexcept;

    bool is_inside(addr_t address) const noexcept;

    bool valid() const noexcept;

private:
    FunctionAttrs m_attrs;
    Idx m_idx;
    const uint8_t *m_data;
    addr_t m_addr;
    size_t m_size;
    sstring m_name;
};

template<>
struct identify<FunctionBase> {
    size_t operator()(const FunctionBase &f) const noexcept
    {
        return f.idx();
    }
};

static inline bool operator<(const FunctionBase &a, const FunctionBase &b)
{
    return a.address() < b.address();
}

static inline bool operator==(const FunctionBase &a, const FunctionBase &b)
{
    return a.address() == b.address();
}

using CallGraph= OrderedGraph<FunctionBase>;
using CallGraphVertices = OrderedVertexStore<FunctionBase>;

class CallSite {
    friend class ElfModuleBuilder;

public:
    CallSite();

    CallSite(CallSiteKind kind, addr_t src, addr_t target);

    CallSite(const CallSite &other) = default;

    CallSite &operator=(const CallSite &other) = default;

    CallSite(CallSite &&other) noexcept = default;

    CallSite &operator=(CallSite &&other) noexcept = default;

    ~CallSite() = default;

    CallSiteKind kind() const noexcept;

    addr_t address() const noexcept;

    addr_t target() const noexcept;

    bool is_tail_call() const noexcept;

    bool is_noreturn_call() const noexcept;

    bool is_local_call() const noexcept;

    bool is_trap() const noexcept;

    bool is_return() const noexcept;

    bool is_direct() const noexcept;

    bool is_call() const noexcept;

private:
    CallSiteKind m_kind;
    addr_t m_origin;
    addr_t m_target;
};

inline bool operator<(const CallSite &a, const CallSite &b)
{
    return a.address() < b.address();
}

sstring to_string(const CallSite &call_site);

class JumpTable {
public:
    using Targets = std::vector<addr_t>;

    JumpTable();

    ~JumpTable() = default;

    JumpTabKind kind() const noexcept;

    void kind(JumpTabKind kind) noexcept;

    addr_t base_address() const noexcept;

    void base_address(addr_t address) noexcept;

    addr_t jump_address() const noexcept;

    void jump_address(addr_t address) noexcept;

    const Targets &targets() const noexcept;

    void targets(const Targets &targets) noexcept;

    bool valid() const noexcept;

    size_t byte_size() const noexcept;

    size_t entry_count() const noexcept;

    void reset() noexcept;

private:
    JumpTabKind m_kind;
    unsigned m_entry_count;
    addr_t m_jumptab_base_addr;
    addr_t m_jump_inst_addr;
    Targets m_targets;
};

/// pimpl implementation, cheaply copyable
class IFunction {
    friend class FunctionBuilder;

public:
    using Idx = FunctionBase::Idx;

    IFunction();

    IFunction(const IFunction &other) = default;

    IFunction &operator=(const IFunction &other) = default;

    IFunction(IFunction &&other) noexcept = default;

    IFunction &operator=(IFunction &&other) noexcept = default;

    virtual ~IFunction() = default;

    //===============================================

    bool operator<(const IFunction &other) const
    {
        return address() < other.address();
    }

    bool operator==(const IFunction &other) const
    {
        return address() == other.address();
    }

    //===============================================

    Idx idx() const noexcept;

    const sstring &name() const noexcept;

    sstring demangled_name() noexcept;

    addr_t address() const noexcept;

    size_t byte_size() const noexcept;

    const uint8_t *data() const noexcept;

    span<const MCInst> instructions() const noexcept;

    span<const BasicBlock> basic_blocks() const noexcept;

    const BasicBlock *get_basic_block_of(addr_t address) const noexcept;

    bool is_valid() const noexcept;

    bool is_inside(addr_t address) const noexcept;

    buffer_t get_buffer(addr_t address) const noexcept;

    const CFG &cfg() const noexcept;

    const DominatorTree &predominator() const noexcept;

    const DominatorTree &postdominator() const noexcept;

    const std::vector<JumpTable> &jump_tables() const noexcept;

protected:
    void idx(Idx idx) noexcept;

    void name(sstring_view name) noexcept;

    void address(addr_t addr) noexcept;

    void byte_size(size_t value) noexcept;

    void data(const uint8_t *data) noexcept;

    std::vector<MCInst> &instructions_ex() noexcept;

    std::vector<BasicBlock> &basic_blocks_ex() noexcept;

    CFG &cfg_ex() noexcept;

    DominatorTree &predominator_ex() noexcept;

    DominatorTree &postdominator_ex() noexcept;

    std::vector<JumpTable> &jump_tables_ex() noexcept;

    void demangler(Demangler *demangler) noexcept;

private:
    struct Impl;
    std::shared_ptr<Impl> m_impl;
};

class FunctionException : public std::logic_error {
public:

    explicit FunctionException(const std::string &what_arg);

    explicit FunctionException(const char *what_arg);

    ~FunctionException() override = default;
};

} // bcov
