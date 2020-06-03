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

#include <unicorn/unicorn.h>
#include "elf/ElfModule.hpp"
#include "core/MCInst.hpp"
#include "flax/Emulator.hpp"
#include "x64/Arch.hpp"
#include "core/Region.hpp"

struct cs_insn;

namespace bcov {
namespace flax {

class MemorySegment {
public:
    MemorySegment() = default;

    ~MemorySegment() = default;

    void start(addr_t address)
    { m_start = address; }

    void end(addr_t address)
    { m_end = address; }

    void buffer(buffer_t buffer)
    { m_buffer = const_cast<uint8_t *>(buffer); }

    void perms(uint32_t perms)
    { m_perms = (uint8_t) perms; }

    void file_size(size_t size)
    { m_file_size = (unsigned) size; }

    void invalidate()
    { m_end = 0; }

    buffer_t buffer() const
    { return m_buffer; }

    buffer_t buffer(addr_t addr) const
    { return m_buffer + (addr - m_start); }

    addr_t start() const
    { return m_start; }

    addr_t end() const
    { return m_end; }

    uint32_t perms() const
    { return m_perms; }

    size_t size() const
    { return m_end - m_start; }

    size_t file_size() const
    { return m_file_size; }

    bool valid() const
    { return m_end != 0; }

    bool is_inside(addr_t addr) const
    { return m_start <= addr && addr < m_end; }

private:
    addr_t m_end = 0;
    addr_t m_start;
    uint8_t *m_buffer;
    uint8_t m_perms;
    unsigned m_file_size;
};

class FlaxVisitorBase;

class FlaxManager {
public:

    FlaxManager();

    FlaxManager(const FlaxManager &other) = default;

    FlaxManager &operator=(const FlaxManager &other) = default;

    FlaxManager(FlaxManager &&other) noexcept = default;

    FlaxManager &operator=(FlaxManager &&other) noexcept = default;

    virtual ~FlaxManager() = default;

    void load_module(const elf::elf &module);

    void reset_data_segment();

    void reset_stack_segment();

    bool is_readable(addr_t address);

    bool is_executable(addr_t address);

    bool is_writable(addr_t address);

    const MemorySegment &code_segment() const noexcept;

    const MemorySegment &rodata_segment() const noexcept;

    const MemorySegment &data_segment() const noexcept;

    const MemorySegment &relro_segment() const noexcept;

    const MemorySegment &stack_segment() const noexcept;

    void set_stack_segment(addr_t base_addr, size_t size);

    addr_t get_mapped(addr_t orig_addr) const;

    addr_t get_original(addr_t mapped_addr) const;

    addr_t get_stack_base() const;

    addr_t get_stack_size() const;

    EmulatorEngine &engine() const;

    void run(FlaxVisitorBase *visitor, addr_t start, addr_t end, size_t run_count,
             size_t inst_count = 0);

    void run_promiscuous(FlaxVisitorBase *visitor, addr_t start, addr_t end,
                         size_t run_count, size_t inst_count);

    void run_instructions(FlaxVisitorBase *visitor, addr_t *addresses,
                          size_t run_count, size_t inst_count);

    addr_t last_reachable_address() const noexcept;

    size_t get_executed_instruction_count() const noexcept;

    void inc_executed_instruction_count();

    void stop();

    FlaxVisitorBase *visitor() const noexcept;

private:
    struct Impl;
    std::shared_ptr<FlaxManager::Impl> m_impl;
};

class FlaxVisitorBase {
public:

    FlaxVisitorBase() = default;

    virtual ~FlaxVisitorBase() = default;

    virtual void visit_instruction(FlaxManager *mgr, addr_t address, uint32_t size);

    virtual void visit_valid_mem_access(FlaxManager *mgr, uc_mem_type type,
                                        uint64_t address, int size,
                                        int64_t value);

    virtual bool visit_invalid_mem_access(FlaxManager *mgr, uc_mem_type type,
                                          uint64_t address, int size,
                                          int64_t value);

    virtual bool visit_invalid_code_access(FlaxManager *mgr, uc_mem_type type,
                                           uint64_t address, int size,
                                           int64_t value);

    virtual bool visit_emulation_error(FlaxManager *mgr, uc_err error);

    virtual void visit_start(FlaxManager *mgr);

    virtual void visit_finish(FlaxManager *mgr);

    virtual void visit_run_start(FlaxManager *mgr, unsigned run_num);

    virtual void visit_run_finish(FlaxManager *mgr, unsigned run_num);

    virtual bool is_finished() const noexcept;

    virtual bool is_run_finished() const noexcept;

    virtual addr_t get_resume_address() const noexcept;

};

} // flax
} // bcov
