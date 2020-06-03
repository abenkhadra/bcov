/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include "easylogging/easylogging++.h"
#include "core/Common.hpp"
#include "x64/Inst.hpp"
#include "core/Disassembler.hpp"
#include "flax/Emulator.hpp"
#include "elf/Util.hpp"
#include "Flax.hpp"

namespace bcov {
namespace flax {

static inline void
log_fatal_if(bool condition, sstring_view msg)
{
    LOG_IF(condition, FATAL) << "flax: " << msg;
}

static inline void
log_error_if(bool condition, sstring_view msg)
{
    LOG_IF(condition, ERROR) << "flax: " << msg;
}

sstring
to_string(const MemorySegment &seg)
{
    std::stringstream os;
    os << std::hex << "st: " << seg.start() << ", end: " << seg.end()
       << ", size: " << seg.size() << ", fsize: " << seg.file_size()
       << ", perm: " << seg.perms();
    return os.str();
}

static Permissions
to_permisions(elf::pf flags)
{
    using namespace elf;
    auto result = Permissions::None;
    if ((flags & pf::x) == pf::x) {
        result = result | Permissions::X;
    }
    if ((flags & pf::r) == pf::r) {
        result = result | Permissions::R;
    }

    if ((flags & pf::w) == pf::w) {
        result = result | Permissions::W;
    }

    return result;
}

//==============================================================================

static void
flax_mgr_code_callback(uc_engine *uc, uint64_t address, uint32_t size,
                       void *user_data)
{
    UNUSED(uc);
    auto mgr = (FlaxManager *) (user_data);
    DVLOG(5) << "flax: executing inst " << std::hex << address << " orig @ "
             << mgr->get_original(address);
    mgr->visitor()->visit_instruction(mgr, address, size);
    mgr->inc_executed_instruction_count();
}

static void
flax_mgr_valid_mem_callback(uc_engine *uc, uc_mem_type type, uint64_t address,
                            int size, int64_t value, void *user_data)
{
    UNUSED(uc);
    auto mgr = (FlaxManager *) (user_data);
    mgr->visitor()->visit_valid_mem_access(mgr, type, address, size, value);
}

static bool
flax_mgr_invalid_mem_callback(uc_engine *uc, uc_mem_type type, uint64_t address,
                              int size, int64_t value, void *user_data)
{
    UNUSED(uc);
    auto mgr = (FlaxManager *) (user_data);
    bool progress;
    if (type == UC_MEM_FETCH_UNMAPPED || type == UC_MEM_FETCH_PROT) {
        progress = mgr->visitor()->visit_invalid_code_access(mgr, type, address,
                                                             size, value);
    } else {
        progress = mgr->visitor()->visit_invalid_mem_access(mgr, type, address,
                                                            size, value);
    }

    if (!progress) {
        mgr->stop();
    }
    return progress;
}

//==============================================================================

struct FlaxManager::Impl {

    static constexpr addr_t kDefaultBaseAddress = 0x555555554000;
    static constexpr addr_t kCoreSegCount = 6;
    static constexpr unsigned kNoteDataSegIdx = 0;
    static constexpr unsigned kCodeSegIdx = 1;
    static constexpr unsigned kRoDataSegIdx = 2;
    static constexpr unsigned kRelRoSegIdx = 3;
    static constexpr unsigned kDataSegIdx = 4;
    static constexpr unsigned kStackSegIdx = 5;
    static constexpr unsigned kCallbackCount = 4;

    static constexpr unsigned kCodeHookKind = UC_HOOK_CODE;
    static constexpr unsigned kValidMemHookKind = UC_HOOK_MEM_VALID;
    static constexpr unsigned kInvalidMemHookKind = UC_HOOK_MEM_INVALID;
    static constexpr unsigned kInvalidCodeHookKind = UC_HOOK_MEM_FETCH_INVALID;

    Impl();

    ~Impl();

    MemorySegment &code_segment()
    { return m_mem_segments[kCodeSegIdx]; }

    MemorySegment &data_segment()
    { return m_mem_segments[kDataSegIdx]; }

    MemorySegment &rodata_segment()
    { return m_mem_segments[kRoDataSegIdx]; }

    MemorySegment &relro_segment()
    { return m_mem_segments[kRelRoSegIdx]; }

    MemorySegment &stack_segment()
    { return m_mem_segments[kStackSegIdx]; }

    void load_code_segment(const elf::segment &seg);

    void load_rodata_segment(const elf::segment &seg);

    void load_data_segment(const elf::segment &seg);

    void set_relro_segment(const elf::segment &seg);

    void load_segment(const elf::segment &seg, MemorySegment &mem_seg);

    void reset_data_segment();

    void set_stack_segment(addr_t start_addr, size_t size);

    void reset_stack_segment();

    void unmap_memory();

    bool print_memory_mapping();

    void add_hooks(FlaxManager *mgr);

    void add_hooks_promiscuous(FlaxManager *mgr);

    void remove_hooks_promiscuous();

    void remove_hooks();

    void save_last_reachable_addr();

    addr_t m_base_address;
    addr_t m_last_reachable_addr;
    uint8_t *m_bss_seg_buf;
    unsigned m_run_inst_count;
    FlaxVisitorBase *m_visitor;
    std::vector<MemorySegment> m_mem_segments;
    std::array<uc_hook, kCallbackCount> m_callbacks;
    EmulatorEngine m_engine;
};

FlaxManager::Impl::Impl()
    : m_base_address(0), m_last_reachable_addr(0),
      m_bss_seg_buf(nullptr), m_visitor(nullptr), m_mem_segments(kCoreSegCount)
{ }

FlaxManager::Impl::~Impl()
{
    unmap_memory();
    if (m_bss_seg_buf != nullptr) {
        free(m_bss_seg_buf);
    }
    if (stack_segment().valid()) {
        free(const_cast<uint8_t *>(stack_segment().buffer()));
    }
}

void
FlaxManager::Impl::save_last_reachable_addr()
{
    auto err = uc_reg_read(m_engine.get(), UC_X86_REG_RIP, &m_last_reachable_addr);
    log_fatal_if(err != UC_ERR_OK, uc_strerror(err));
}

void
FlaxManager::Impl::load_code_segment(const elf::segment &seg)
{
    if (seg.get_hdr().vaddr == 0) {
        // cast kDefaultBaseAddress to create a temporary avoiding odr-use link error
        LOG(INFO)
            << "flax: module seems position independent, relocating to "
            << "base address @ " << std::hex << (addr_t) kDefaultBaseAddress;
        m_base_address = kDefaultBaseAddress;
    }
    MemorySegment &mem_seg = code_segment();
    load_segment(seg, mem_seg);
    DVLOG(3) << "flax: mapped code segment " << to_string(mem_seg);
}

void
FlaxManager::Impl::load_data_segment(const elf::segment &seg)
{
    MemorySegment &mem_seg = data_segment();

    load_segment(seg, mem_seg);

    auto bss_buf_size = mem_seg.size() - mem_seg.file_size();
    if (bss_buf_size > 0) {
        m_bss_seg_buf = (uint8_t *) malloc(bss_buf_size);
        std::memset(m_bss_seg_buf, 0, bss_buf_size);
        auto err = uc_mem_write(m_engine.get(),
                                mem_seg.start() + mem_seg.file_size(),
                                m_bss_seg_buf, bss_buf_size);
        log_fatal_if(err != UC_ERR_OK, uc_strerror(err));
    }
    DVLOG(3) << "flax: mapped data segment " << to_string(mem_seg);
}

void
FlaxManager::Impl::load_segment(const elf::segment &seg, MemorySegment &mem_seg)
{
    DCHECK(!mem_seg.valid());
    mem_seg.buffer((buffer_t) seg.data());
    mem_seg.start(seg.get_hdr().vaddr + m_base_address);
    mem_seg.end(mem_seg.start() + seg.get_hdr().memsz);
    mem_seg.perms((uint8_t) to_permisions(seg.get_hdr().flags));
    mem_seg.file_size(seg.get_hdr().filesz);

    auto low_bound = x64::page_aligned_lower(mem_seg.start());
    auto high_bound = x64::page_aligned_higher(mem_seg.end());

    auto err = uc_mem_map(m_engine.get(), low_bound, high_bound - low_bound,
                          mem_seg.perms());
    log_fatal_if(err != UC_ERR_OK, uc_strerror(err));
    err = uc_mem_write(m_engine.get(), mem_seg.start(), mem_seg.buffer(),
                       mem_seg.file_size());
    log_fatal_if(err != UC_ERR_OK, uc_strerror(err));
}

void
FlaxManager::Impl::load_rodata_segment(const elf::segment &seg)
{
    MemorySegment &mem_seg = rodata_segment();

    load_segment(seg, mem_seg);

    DCHECK(mem_seg.size() == mem_seg.file_size());
    DVLOG(3) << "flax: mapped rodata segment " << to_string(mem_seg);
}

void
FlaxManager::Impl::set_relro_segment(const elf::segment &seg)
{
    MemorySegment &relro_seg = relro_segment();
    relro_seg.buffer((buffer_t) seg.data());
    relro_seg.start(seg.get_hdr().vaddr + m_base_address);
    relro_seg.end(relro_seg.start() + seg.get_hdr().memsz);
    relro_seg.perms(UC_PROT_READ);
    relro_seg.file_size(seg.get_hdr().filesz);

    auto low_bound = x64::page_aligned_lower(relro_seg.start());
    auto high_bound = x64::page_aligned_higher(relro_seg.end());
    auto relro_aligned_size = high_bound - low_bound;
    auto err = uc_mem_protect(m_engine.get(), low_bound, relro_aligned_size,
                              relro_seg.perms());

    log_fatal_if(err != UC_ERR_OK, uc_strerror(err));
    LOG_IF(relro_seg.start() != data_segment().start(), ERROR)
        << "unsupported relro segment mapping!";
    auto fixed_data_seg_start = low_bound + relro_aligned_size;
    auto offset = (fixed_data_seg_start - data_segment().start());
    data_segment().file_size(data_segment().file_size() - offset);
    data_segment().start(fixed_data_seg_start);
    data_segment().buffer(data_segment().buffer() + offset);
    DVLOG(3) << "flax: mapped relro segment " << to_string(relro_seg);
    DVLOG(3) << "flax: adjust data segment  " << to_string(data_segment());
}

void
FlaxManager::Impl::unmap_memory()
{
    VLOG(2) << "flax: unmapping engine memory";
    for (const auto &seg : m_mem_segments) {
        if (!seg.valid()) {
            continue;
        }

        auto low_bound = x64::page_aligned_lower(seg.start());
        auto high_bound = x64::page_aligned_higher(seg.end());

        auto err = uc_mem_unmap(m_engine.get(), low_bound, high_bound - low_bound);
        log_fatal_if(err != UC_ERR_OK, uc_strerror(err));
    }

    if (data_segment().valid()) {
        free(m_bss_seg_buf);
        m_bss_seg_buf = nullptr;
    }

    if (stack_segment().valid()) {
        free(const_cast<uint8_t *>(stack_segment().buffer()));
        stack_segment().invalidate();
    }
}

bool
FlaxManager::Impl::print_memory_mapping()
{

    uc_mem_region *regions;
    uint32_t count;
    auto err = uc_mem_regions(m_engine.get(), &regions, &count);
    log_fatal_if(err != UC_ERR_OK, uc_strerror(err));

    for (unsigned i = 0; i < count; ++i) {
        VLOG(4) << "flax: mapped memory " << std::hex << regions[i].begin
                << " - " << regions[i].end << " perms:" << regions[i].perms;
    }
    uc_free((void *) regions);
    return true;
}

void
FlaxManager::Impl::add_hooks(FlaxManager *mgr)
{
    auto err = uc_hook_add(m_engine.get(), &m_callbacks[0], kCodeHookKind,
                           (void *) flax_mgr_code_callback, mgr, 1, 0);
    log_fatal_if(err != UC_ERR_OK, uc_strerror(err));

    err = uc_hook_add(m_engine.get(), &m_callbacks[1], kValidMemHookKind,
                      (void *) flax_mgr_valid_mem_callback, mgr, 1, 0);
    log_fatal_if(err != UC_ERR_OK, uc_strerror(err));

    err = uc_hook_add(m_engine.get(), &m_callbacks[2], kInvalidMemHookKind,
                      (void *) flax_mgr_invalid_mem_callback, mgr, 1, 0);
    log_fatal_if(err != UC_ERR_OK, uc_strerror(err));
}

void
FlaxManager::Impl::remove_hooks()
{
    auto err = uc_hook_del(m_engine.get(), m_callbacks[0]);
    log_fatal_if(err != UC_ERR_OK, uc_strerror(err));
    err = uc_hook_del(m_engine.get(), m_callbacks[1]);
    log_fatal_if(err != UC_ERR_OK, uc_strerror(err));
    err = uc_hook_del(m_engine.get(), m_callbacks[2]);
    log_fatal_if(err != UC_ERR_OK, uc_strerror(err));
}

void
FlaxManager::Impl::add_hooks_promiscuous(FlaxManager *mgr)
{
    // XXX: hooking invalid code without hooking invalid memory drives unicorn crazy!
    auto err = uc_hook_add(m_engine.get(), &m_callbacks[0], kCodeHookKind,
                           (void *) flax_mgr_code_callback, mgr, 1, 0);
    log_fatal_if(err != UC_ERR_OK, uc_strerror(err));

    err = uc_hook_add(m_engine.get(), &m_callbacks[2], kInvalidMemHookKind,
                      (void *) flax_mgr_invalid_mem_callback, mgr, 1, 0);
    log_fatal_if(err != UC_ERR_OK, uc_strerror(err));
}

void
FlaxManager::Impl::remove_hooks_promiscuous()
{
    auto err = uc_hook_del(m_engine.get(), m_callbacks[0]);
    log_fatal_if(err != UC_ERR_OK, uc_strerror(err));
    err = uc_hook_del(m_engine.get(), m_callbacks[2]);
    log_fatal_if(err != UC_ERR_OK, uc_strerror(err));
}

void
FlaxManager::Impl::reset_data_segment()
{
    if (!data_segment().valid()) {
        return;
    }
    auto &seg = data_segment();
    auto err = uc_mem_write(m_engine.get(), seg.start(),
                            seg.buffer(), seg.file_size());
    log_fatal_if(err != UC_ERR_OK, uc_strerror(err));

    err = uc_mem_write(m_engine.get(), seg.start() + seg.file_size(),
                       m_bss_seg_buf, seg.size() - seg.file_size());
    log_fatal_if(err != UC_ERR_OK, uc_strerror(err));
    DVLOG(3) << "flax: reset data segment " << to_string(seg);
}

void
FlaxManager::Impl::reset_stack_segment()
{
    if (!stack_segment().valid()) {
        return;
    }

    auto err = uc_mem_write(m_engine.get(), stack_segment().start(),
                            stack_segment().buffer(), stack_segment().size());

    log_fatal_if(err != UC_ERR_OK, uc_strerror(err));
    DVLOG(3) << "flax: reset stack segment " << to_string(stack_segment());
}

void
FlaxManager::Impl::set_stack_segment(addr_t start_addr, size_t size)
{
    if (stack_segment().valid()) {
        return;
    }
    stack_segment().start(start_addr);
    stack_segment().end(start_addr + size);
    stack_segment().file_size(size);
    auto stack_buf = (uint8_t *) malloc(size);
    std::memset(stack_buf, 0, size);
    stack_segment().buffer(stack_buf);
    stack_segment().perms(UC_PROT_WRITE | UC_PROT_READ);
    auto low_bound = x64::page_aligned_lower(stack_segment().start());
    auto high_bound = x64::page_aligned_higher(stack_segment().end());

    auto err = uc_mem_map(m_engine.get(), low_bound, high_bound - low_bound,
                          stack_segment().perms());
    log_fatal_if(err != UC_ERR_OK, uc_strerror(err));

    err = uc_mem_write(m_engine.get(), stack_segment().start(),
                       stack_segment().buffer(), stack_segment().size());
    log_fatal_if(err != UC_ERR_OK, uc_strerror(err));
    DVLOG(3) << "flax: mapped stack segment " << to_string(stack_segment());
}

//==============================================================================

FlaxManager::FlaxManager() : m_impl(std::make_shared<Impl>())
{ }

void
FlaxManager::load_module(const elf::elf &module)
{
    if (!m_impl->m_engine.valid()) {
        m_impl->m_engine.init(UC_ARCH_X86, UC_MODE_64);
    } else {
        m_impl->unmap_memory();
    }

    for (const auto &seg : module.segments()) {
        if (elf::is_gnu_relro(seg)) {
            DCHECK(data_segment().valid());
            m_impl->set_relro_segment(seg);
        }

        if (!elf::is_loadable(seg)) {
            continue;
        }
        if (elf::is_executable(seg)) {
            m_impl->load_code_segment(seg);
            continue;
        }
        if (elf::is_writable(seg)) {
            m_impl->load_data_segment(seg);
            continue;
        }
        if (!elf::is_writable(seg) && code_segment().valid()) {
            // ignore read-only segment before code segment
            m_impl->load_rodata_segment(seg);
            continue;
        }
    }
    DCHECK(m_impl->print_memory_mapping());
}

void
FlaxManager::reset_data_segment()
{
    m_impl->reset_data_segment();
}

void
FlaxManager::reset_stack_segment()
{
    m_impl->reset_stack_segment();
}

bool
FlaxManager::is_readable(addr_t address)
{
    return (code_segment().start() <= address && address < data_segment().end()) ||
           stack_segment().is_inside(address);
}

bool
FlaxManager::is_executable(addr_t address)
{
    return code_segment().is_inside(address);
}

bool
FlaxManager::is_writable(addr_t address)
{
    return data_segment().is_inside(address) || stack_segment().is_inside(address);
}

const MemorySegment &
FlaxManager::code_segment() const noexcept
{
    return m_impl->code_segment();
}

const MemorySegment &
FlaxManager::rodata_segment() const noexcept
{
    return m_impl->rodata_segment();
}

const MemorySegment &
FlaxManager::data_segment() const noexcept
{
    return m_impl->data_segment();
}

const MemorySegment &
FlaxManager::stack_segment() const noexcept
{
    return m_impl->m_mem_segments[Impl::kStackSegIdx];
}

const MemorySegment &
FlaxManager::relro_segment() const noexcept
{
    return m_impl->relro_segment();
}

void
FlaxManager::set_stack_segment(addr_t base_addr, size_t size)
{
    m_impl->set_stack_segment(base_addr, size);
}

addr_t
FlaxManager::get_stack_base() const
{
    return m_impl->stack_segment().start();
}

addr_t
FlaxManager::get_stack_size() const
{
    return m_impl->stack_segment().size();
}

addr_t
FlaxManager::get_mapped(addr_t orig_addr) const
{
    return orig_addr + m_impl->m_base_address;
}

addr_t
FlaxManager::get_original(addr_t mapped_addr) const
{
    return mapped_addr - m_impl->m_base_address;
}

EmulatorEngine &
FlaxManager::engine() const
{
    return m_impl->m_engine;
}

void
FlaxManager::run(FlaxVisitorBase *visitor, addr_t start, addr_t end,
                 size_t run_count, size_t inst_count)
{
    m_impl->m_visitor = visitor;
    m_impl->add_hooks(this);
    DVLOG(3) << "flax: executing " << std::dec << run_count << " runs from @ "
             << std::hex << start << " to @ " << end;

    visitor->visit_start(this);
    for (unsigned i = 0; i < run_count && !visitor->is_finished(); ++i) {
        visitor->visit_run_start(this, i);
        auto err = uc_emu_start(m_impl->m_engine.get(), start, end, 0,
                                inst_count);
        m_impl->save_last_reachable_addr();
        visitor->visit_run_finish(this, i);
        if (err != UC_ERR_OK && !visitor->visit_emulation_error(this, err)) {
            break;
        }
    }

    visitor->visit_finish(this);
    m_impl->remove_hooks();
    m_impl->m_visitor = nullptr;
}

void
FlaxManager::run_promiscuous(FlaxVisitorBase *visitor, addr_t start, addr_t end,
                             size_t run_count, size_t inst_count)
{
    // a work around to
    // (1) avoid setting fs & gs register which are needed for checks based TLS
    // (2) avoid the extra cost of stopping and resuming on invalid memory accesses

    auto err = uc_mem_map(m_impl->m_engine.get(), 0, EMULATOR_PAGE_SIZE,
                          UC_PROT_WRITE | UC_PROT_READ);

    log_fatal_if(err != UC_ERR_OK, uc_strerror(err));

    m_impl->m_visitor = visitor;
    m_impl->add_hooks_promiscuous(this);
    DVLOG(3) << "flax: force executing " << std::dec << run_count
             << " runs from @ " << std::hex << start << " orig @ "
             << get_original(start);

    visitor->visit_start(this);
    for (unsigned i = 0; i < run_count && !visitor->is_finished(); ++i) {
        visitor->visit_run_start(this, i);
        m_impl->m_run_inst_count = 0;
        err = uc_emu_start(m_impl->m_engine.get(), start, end, 0, inst_count);
        log_fatal_if(err != UC_ERR_OK, uc_strerror(err));
        while (m_impl->m_run_inst_count < inst_count && !visitor->is_run_finished()) {
            DVLOG(4) << "flax: resuming from @ " << std::hex
                     << visitor->get_resume_address()
                     << " orig @ " << get_original(visitor->get_resume_address());
            err = uc_emu_start(m_impl->m_engine.get(), visitor->get_resume_address(),
                               end, 0, inst_count);

            if (err != UC_ERR_OK && !visitor->visit_emulation_error(this, err)) {
                break;
            }
        }
        visitor->visit_run_finish(this, i);
    }

    visitor->visit_finish(this);
    m_impl->remove_hooks_promiscuous();
    m_impl->m_visitor = nullptr;

    err = uc_mem_unmap(m_impl->m_engine.get(), 0, EMULATOR_PAGE_SIZE);
    log_fatal_if(err != UC_ERR_OK, uc_strerror(err));

}

void
FlaxManager::run_instructions(FlaxVisitorBase *visitor, addr_t *addresses,
                              size_t run_count, size_t inst_count)
{
    m_impl->m_visitor = visitor;
    m_impl->add_hooks(this);
    DVLOG(3) << "flax: executing slice " << std::dec << run_count << " runs from @ "
             << std::hex << addresses[0] << " a total of " << inst_count
             << " instructions";

    visitor->visit_start(this);
    for (unsigned i = 0; i < run_count && !visitor->is_finished(); ++i) {
        visitor->visit_run_start(this, i);
        for (unsigned j = 0; j < inst_count && !visitor->is_run_finished(); ++j) {
            DVLOG(5) << x64::EmulatorUtils::dump_gpr_context(m_impl->m_engine.get());
            auto err = uc_emu_start(m_impl->m_engine.get(), addresses[j],
                                    x64::kMaxInstSize, 0, 1);
            m_impl->save_last_reachable_addr();
            if (err != UC_ERR_OK && !visitor->visit_emulation_error(this, err)) {
                break;
            }
        }
        visitor->visit_run_finish(this, i);
    }
    visitor->visit_finish(this);
    m_impl->remove_hooks();
    m_impl->m_visitor = nullptr;
}

addr_t
FlaxManager::last_reachable_address() const noexcept
{
    return m_impl->m_last_reachable_addr;
}

size_t
FlaxManager::get_executed_instruction_count() const noexcept
{
    return m_impl->m_run_inst_count;
}

void
FlaxManager::inc_executed_instruction_count()
{
    m_impl->m_run_inst_count++;
}

void
FlaxManager::stop()
{
    uc_emu_stop(m_impl->m_engine.get());
}

FlaxVisitorBase *
FlaxManager::visitor() const noexcept
{
    return m_impl->m_visitor;
}

//==============================================================================

void
FlaxVisitorBase::visit_instruction(FlaxManager *mgr, addr_t address, uint32_t size)
{
    UNUSED(mgr);
    UNUSED(address);
    UNUSED(size);
}

void
FlaxVisitorBase::visit_valid_mem_access(FlaxManager *mgr, uc_mem_type type,
                                        uint64_t address, int size, int64_t value)
{
    UNUSED(mgr);
    UNUSED(type);
    UNUSED(address);
    UNUSED(size);
    UNUSED(value);
}

bool
FlaxVisitorBase::visit_invalid_mem_access(FlaxManager *mgr, uc_mem_type type,
                                          uint64_t address, int size,
                                          int64_t value)
{
    UNUSED(mgr);
    UNUSED(type);
    UNUSED(address);
    UNUSED(size);
    UNUSED(value);
    return false;
}

bool
FlaxVisitorBase::visit_invalid_code_access(FlaxManager *mgr, uc_mem_type type,
                                           uint64_t address, int size, int64_t value)
{
    UNUSED(mgr);
    UNUSED(type);
    UNUSED(address);
    UNUSED(size);
    UNUSED(value);
    return false;
}

bool
FlaxVisitorBase::visit_emulation_error(FlaxManager *mgr, uc_err error)
{
    UNUSED(mgr);
    LOG(ERROR) << "flax: emulation error - " << uc_strerror(error);
    return false;
}

void
FlaxVisitorBase::visit_start(FlaxManager *mgr)
{
    UNUSED(mgr);
}

void
FlaxVisitorBase::visit_finish(FlaxManager *mgr)
{
    UNUSED(mgr);
}

void
FlaxVisitorBase::visit_run_start(FlaxManager *mgr, unsigned run_num)
{
    UNUSED(mgr);
    UNUSED(run_num);
}

void
FlaxVisitorBase::visit_run_finish(FlaxManager *mgr, unsigned run_num)
{
    UNUSED(mgr);
    UNUSED(run_num);
}

bool
FlaxVisitorBase::is_finished() const noexcept
{
    return false;
}

bool
FlaxVisitorBase::is_run_finished() const noexcept
{
    return false;
}

addr_t
FlaxVisitorBase::get_resume_address() const noexcept
{
    return 0;
}

} // flax
} // bcov
