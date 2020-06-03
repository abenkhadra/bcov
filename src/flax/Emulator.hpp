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

#include "x64/Arch.hpp"
#include <unicorn/unicorn.h>

#define EMULATOR_PAGE_SIZE (0x1000ULL)

namespace bcov {
namespace x64 {

constexpr addr_t kPageMask = ((addr_t) EMULATOR_PAGE_SIZE - 1);

static inline addr_t
page_aligned_lower(addr_t addr)
{
    return (addr & ~kPageMask);
}

static inline uint64_t
page_aligned_higher(addr_t addr)
{
    return page_aligned_lower(addr + EMULATOR_PAGE_SIZE - 1);
}

class EmulatorUtils {
public:

    static void
    write_context(uc_engine *emulator,
                  const RegisterContext<RegisterContextType::kGPR> &reg_ctx);

    static void
    read_context(uc_engine *emulator,
                 RegisterContext<RegisterContextType::kGPR> &reg_ctx);

    static void
    write_gpr_context(uc_engine *emulator, const RegisterContext<> &reg_ctx);

    static void
    read_gpr_context(uc_engine *emulator, RegisterContext<> &reg_ctx);

    static void
    write_avx_context(uc_engine *emulator, const RegisterContext<> &reg_ctx);

    static void
    read_avx_context(uc_engine *emulator, RegisterContext<> &reg_ctx);

    static void
    write_context(uc_engine *emulator, const RegisterContext<> &reg_ctx);

    static void
    read_context(uc_engine *emulator, RegisterContext<> &reg_ctx);

    static sstring dump_gpr_context(uc_engine *emulator);
};

X64Reg get_x64_reg(uc_x86_reg uc_reg) __attribute__((const));

uc_x86_reg get_uc_reg(X64Reg reg) __attribute__((const));

} // x64

namespace flax {

class EmulatorContext {
    friend class EmulatorEngine;
public:

    EmulatorContext() = default;

    EmulatorContext(const EmulatorContext &other) = delete;

    EmulatorContext &operator=(const EmulatorContext &other) = delete;

    EmulatorContext(EmulatorContext &&other) noexcept;

    EmulatorContext &operator=(EmulatorContext &&other) noexcept;

    ~EmulatorContext();

    bool valid() const;

    uc_context *get() const;

private:
    uc_context *m_context = nullptr;
};

class EmulatorEngine {
public:

    EmulatorEngine();

    EmulatorEngine(const EmulatorEngine &other) = delete;

    EmulatorEngine &operator=(const EmulatorEngine &other) = delete;

    EmulatorEngine(EmulatorEngine &&other) noexcept;

    EmulatorEngine &operator=(EmulatorEngine &&other) noexcept;

    ~EmulatorEngine();

    void make_context(EmulatorContext &context);

    void init(uc_arch arch, uc_mode mode);

    bool valid() const noexcept;

    uc_engine *get() const noexcept;

    void save_context(EmulatorContext &context);

    void restore_context(const EmulatorContext &context);

private:
    uc_engine *m_emulator;
};

void dummy_code_callback(uc_engine *uc, uint64_t address, uint32_t size,
                         void *user_data);

void dummy_mem_callback(uc_engine *uc, uc_mem_type type, uint64_t address, int size,
                        int64_t value, void *user_data);

czstring to_string(uc_mem_type mem_type) __attribute__((const));

} // flax
} // bcov
