/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */
#include <set>
#include <cstring>
#include <vector>
#include "easylogging/easylogging++.h"
#include "CSInstWrapper.hpp"
#include "util/Demangler.hpp"
#include "Function.hpp"

namespace bcov {

FunctionBase::FunctionBase() :
    m_attrs(FunctionAttrs::kNone), m_idx(0), m_data(nullptr), m_addr(0), m_size(0)
{ }

FunctionBase::FunctionBase(sstring_view name, addr_t address, const uint8_t *data,
                           size_t size) :
    m_attrs(FunctionAttrs::kNone),
    m_data(data),
    m_addr(address),
    m_size(size),
    m_name(name.data())
{ }

FunctionAttrs
FunctionBase::attrs() const noexcept
{
    return m_attrs;
}

const sstring &
FunctionBase::name() const noexcept
{
    return m_name;
}

addr_t
FunctionBase::address() const noexcept
{
    return m_addr;
}

const uint8_t *
FunctionBase::data() const noexcept
{
    return m_data;
}

size_t
FunctionBase::size() const noexcept
{
    return m_size;
}

bool
FunctionBase::is_dynamic() const noexcept
{
    return m_data == nullptr;
}

bool
FunctionBase::is_runtime() const noexcept
{
    return !is_dynamic() && size() == 0;
}

bool
FunctionBase::is_static() const noexcept
{
    return !is_dynamic() && size() != 0;
}

FunctionBase::Idx
FunctionBase::idx() const noexcept
{
    return m_idx;
}

bool
FunctionBase::is_inside(addr_t address) const noexcept
{
    return m_addr <= address && address < (m_addr + m_size);
}

bool
FunctionBase::valid() const noexcept
{
    return address() != 0;
}

//==============================================================================

CallSite::CallSite() :
    m_kind(CallSiteKind::kUnknown),
    m_origin(0),
    m_target(0)
{ }

CallSite::CallSite(CallSiteKind kind, addr_t src, addr_t target) :
    m_kind(kind),
    m_origin(src),
    m_target(target)
{ }

CallSiteKind
CallSite::kind() const noexcept
{
    return m_kind;
}

addr_t
CallSite::address() const noexcept
{
    return m_origin;
}

addr_t
CallSite::target() const noexcept
{
    return m_target;
}

bool
CallSite::is_tail_call() const noexcept
{
    return (m_kind & CallSiteKind::kDirectTail) == CallSiteKind::kDirectTail;
}

bool
CallSite::is_noreturn_call() const noexcept
{
    return m_kind == CallSiteKind::kNoReturnCall;
}

bool
CallSite::is_local_call() const noexcept
{
    return m_kind == CallSiteKind::kLocalCall;
}

bool
CallSite::is_trap() const noexcept
{
    return m_kind == CallSiteKind::kTrap;
}

bool
CallSite::is_return() const noexcept
{
    return m_kind == CallSiteKind::kReturn;
}

bool
CallSite::is_direct() const noexcept
{
    return m_target != 0;
}

bool
CallSite::is_call() const noexcept
{
    return (m_kind & CallSiteKind::kDirectCall) == CallSiteKind::kDirectCall;
}

sstring
to_string(const CallSite &call_site)
{
    return to_hex(call_site.address()) + "->" + to_hex(call_site.target());
}

//==============================================================================

const static JumpTabEntryOffI8Reader JTEntryOffI8ReaderInstance;
const static JumpTabEntryOffI16Reader JTEntryOffI16ReaderInstance;
const static JumpTabEntryOffU8Reader JTEntryOffU8ReaderInstance;
const static JumpTabEntryOffU16Reader JTEntryOffU16ReaderInstance;
const static JumpTabEntryOffI32Reader JTEntryOffI32ReaderInstance;
const static JumpTabEntryAbs32Reader JTEntryAbs32ReaderInstance;
const static JumpTabEntryAbs64Reader JTEntryAbs64ReaderInstance;

const static JumpTabEntryOff32Writer JTEntryOff32WriterInstance;
const static JumpTabEntryAbs32Writer JTEntryAbs32WriterInstance;
const static JumpTabEntryAbs64Writer JTEntryAbs64WriterInstance;

addr_t
JumpTabEntryAbs32Reader::read(const uint8_t *buf, addr_t base_addr) const
{
    UNUSED(base_addr);
    return *(reinterpret_cast<const uint32_t *>(buf));
}

addr_t
JumpTabEntryAbs64Reader::read(const uint8_t *buf, addr_t base_addr) const
{
    UNUSED(base_addr);
    return *(reinterpret_cast<const uint64_t *>(buf));
}

addr_t
JumpTabEntryOffI32Reader::read(const uint8_t *buf, addr_t base_addr) const
{
    return *(reinterpret_cast<const int32_t *>(buf)) + base_addr;
}

addr_t
JumpTabEntryOffI16Reader::read(const uint8_t *buf, addr_t base_addr) const
{
    return *(reinterpret_cast<const int16_t *>(buf)) + base_addr;
}

addr_t
JumpTabEntryOffI8Reader::read(const uint8_t *buf, addr_t base_addr) const
{
    return *(reinterpret_cast<const int8_t *>(buf)) + base_addr;
}

addr_t
JumpTabEntryOffU16Reader::read(const uint8_t *buf, addr_t base_addr) const
{
    return *(reinterpret_cast<const uint16_t *>(buf)) + base_addr;
}

addr_t
JumpTabEntryOffU8Reader::read(const uint8_t *buf, addr_t base_addr) const
{
    return *(reinterpret_cast<const uint8_t *>(buf)) + base_addr;
}

void
JumpTabEntryOff32Writer::write(addr_t target, addr_t base_addr, uint8_t *buf) const
{
    auto p = reinterpret_cast<int32_t *>(buf);
    *p = (int64_t) (target - base_addr);
    DCHECK(*p == (int64_t) (target - base_addr));
}

void
JumpTabEntryAbs32Writer::write(addr_t target, addr_t base_addr, uint8_t *buf) const
{
    UNUSED(base_addr);
    auto p = reinterpret_cast<uint32_t *>(buf);
    *p = (uint32_t) target;
    DCHECK(*p == target);
}

void
JumpTabEntryAbs64Writer::write(addr_t target, addr_t base_addr, uint8_t *buf) const
{
    UNUSED(base_addr);
    auto p = reinterpret_cast<uint64_t *>(buf);
    *p = (uint64_t) target;
}

const JumpTabEntryReader *
get_jumptab_reader(JumpTabKind kind)
{
    switch (kind) {
    case JumpTabKind::kOffsetI8 : return &JTEntryOffI8ReaderInstance;
    case JumpTabKind::kOffsetU8 : return &JTEntryOffU8ReaderInstance;
    case JumpTabKind::kOffsetI16: return &JTEntryOffI16ReaderInstance;
    case JumpTabKind::kOffsetU16: return &JTEntryOffU16ReaderInstance;
    case JumpTabKind::kOffsetI32: return &JTEntryOffI32ReaderInstance;
    case JumpTabKind::kAbsAddr32: return &JTEntryAbs32ReaderInstance;
    case JumpTabKind::kAbsAddr64: return &JTEntryAbs64ReaderInstance;
    default:return nullptr;
    }
}

const JumpTabEntryWriter *
get_jumptab_writer(JumpTabKind kind)
{
    switch (kind) {
    case JumpTabKind::kOffsetI32: return &JTEntryOff32WriterInstance;
    case JumpTabKind::kAbsAddr32: return &JTEntryAbs32WriterInstance;
    case JumpTabKind::kAbsAddr64: return &JTEntryAbs64WriterInstance;
    default:return nullptr;
    }
}

//==============================================================================

JumpTable::JumpTable() : m_kind(JumpTabKind::kInvalid), m_jump_inst_addr(0)
{ }

bool
JumpTable::valid() const noexcept
{
    return m_kind != JumpTabKind::kInvalid;
}

void
JumpTable::reset() noexcept
{
    m_kind = JumpTabKind::kInvalid;
    m_jump_inst_addr = 0;
    m_targets.clear();
}

size_t
JumpTable::entry_count() const noexcept
{
    return m_entry_count;
}

size_t
JumpTable::byte_size() const noexcept
{
    return entry_size(m_kind) * entry_count();
}

JumpTabKind
JumpTable::kind() const noexcept
{
    return m_kind;
}

void
JumpTable::kind(JumpTabKind kind) noexcept
{
    m_kind = kind;
}

addr_t
JumpTable::jump_address() const noexcept
{
    return m_jump_inst_addr;
}

void
JumpTable::jump_address(addr_t address) noexcept
{
    m_jump_inst_addr = address;
}

const JumpTable::Targets &
JumpTable::targets() const noexcept
{
    return m_targets;
}

void
JumpTable::targets(const Targets &targets) noexcept
{
    std::set<addr_t> unique_targets;
    unique_targets.insert(targets.begin(), targets.end());
    m_entry_count = targets.size();
    m_targets.reserve(unique_targets.size());
    std::copy(unique_targets.begin(), unique_targets.end(),
              std::back_inserter(m_targets));
}

addr_t
JumpTable::base_address() const noexcept
{
    return m_jumptab_base_addr;
}

void
JumpTable::base_address(addr_t address) noexcept
{
    m_jumptab_base_addr = address;
}

//==============================================================================
struct IFunction::Impl {
    Impl();

    ~Impl() = default;

    Idx m_idx;
    addr_t m_addr;
    const uint8_t *m_data;
    size_t m_byte_size;
    sstring m_name;
    Demangler *m_demangler;
    std::vector<BasicBlock> m_basic_blocks;
    std::vector<JumpTable> m_jump_tabs;
    std::vector<MCInst> m_insts;
    CFG m_cfg;
    DominatorTree m_predom;
    DominatorTree m_postdom;
};

IFunction::Impl::Impl() :
    m_idx(0),
    m_addr(0),
    m_data(nullptr),
    m_byte_size(0),
    m_name("")
{ }

IFunction::IFunction() :
    m_impl(std::make_shared<Impl>())
{ }

IFunction::Idx
IFunction::idx() const noexcept
{
    return m_impl->m_idx;
}

void
IFunction::idx(Idx idx) noexcept
{
    m_impl->m_idx = idx;
}

void
IFunction::name(sstring_view name) noexcept
{
    m_impl->m_name = gsl::to_string(name);
}

void
IFunction::address(addr_t addr) noexcept
{
    m_impl->m_addr = addr;
}

void
IFunction::byte_size(size_t value) noexcept
{
    m_impl->m_byte_size = value;
}

void
IFunction::data(const uint8_t *data) noexcept
{
    m_impl->m_data = data;
}

void
IFunction::demangler(Demangler *demangler) noexcept
{
    m_impl->m_demangler = demangler;
}

addr_t
IFunction::address() const noexcept
{
    return m_impl->m_addr;
}

const CFG &
IFunction::cfg() const noexcept
{
    return m_impl->m_cfg;
}

span<const BasicBlock>
IFunction::basic_blocks() const noexcept
{
    return {&m_impl->m_basic_blocks.front(), m_impl->m_basic_blocks.size()};
}

const BasicBlock *
IFunction::get_basic_block_of(addr_t address) const noexcept
{
    auto bb_it = std::lower_bound(m_impl->m_basic_blocks.begin(),
                                  m_impl->m_basic_blocks.end(),
                                  address,
                                  [](const BasicBlock &bb, addr_t address) {
                                      return bb.address() <= address;
                                  });
    // bb_it points to the consecutive block if exists
    if (bb_it == m_impl->m_basic_blocks.end()) {
        auto &lst_bb = m_impl->m_basic_blocks.back();
        return (lst_bb.is_inside(address)) ? &lst_bb : nullptr;
    } else {
        --bb_it;
        return (bb_it->is_inside(address)) ? &(*bb_it) : nullptr;
    }
}

size_t
IFunction::byte_size() const noexcept
{
    return m_impl->m_byte_size;
}

const uint8_t *
IFunction::data() const noexcept
{
    return m_impl->m_data;
}

span<const MCInst>
IFunction::instructions() const noexcept
{
    return {&m_impl->m_insts.front(), m_impl->m_insts.size()};
}

const sstring &
IFunction::name() const noexcept
{
    return m_impl->m_name;
}

sstring
IFunction::demangled_name() noexcept
{
    if (m_impl->m_demangler->is_unmangled_name(name())) {
        return name();
    }
    m_impl->m_demangler->demangle(name());
    if (m_impl->m_demangler->is_success()) {
        return m_impl->m_demangler->demangled_name();
    } else {
        return name();
    }
}

bool
IFunction::is_valid() const noexcept
{
    return !m_impl->m_insts.empty();
}

bool
IFunction::is_inside(addr_t address) const noexcept
{
    return m_impl->m_addr <= address &&
           address < (m_impl->m_addr + m_impl->m_byte_size);
}

buffer_t
IFunction::get_buffer(addr_t address) const noexcept
{
    DCHECK(is_inside(address));
    return m_impl->m_data + (address - m_impl->m_addr);
}

const DominatorTree &
IFunction::predominator() const noexcept
{
    return m_impl->m_predom;
}

const DominatorTree &
IFunction::postdominator() const noexcept
{
    return m_impl->m_postdom;
}

const std::vector<JumpTable> &
IFunction::jump_tables() const noexcept
{
    return m_impl->m_jump_tabs;
}

std::vector<MCInst> &
IFunction::instructions_ex() noexcept
{
    return m_impl->m_insts;
}

std::vector<BasicBlock> &
IFunction::basic_blocks_ex() noexcept
{
    return m_impl->m_basic_blocks;
}

CFG &
IFunction::cfg_ex() noexcept
{
    return m_impl->m_cfg;
}

DominatorTree &
IFunction::predominator_ex() noexcept
{
    return m_impl->m_predom;
}

DominatorTree &
IFunction::postdominator_ex() noexcept
{
    return m_impl->m_postdom;
}

std::vector<JumpTable> &
IFunction::jump_tables_ex() noexcept
{
    return m_impl->m_jump_tabs;
}

//===============================================

FunctionException::FunctionException(const std::string &what_arg) :
    logic_error(what_arg)
{
}

FunctionException::FunctionException(const char *what_arg) :
    logic_error(what_arg)
{
}

} // bcov
