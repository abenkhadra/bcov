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

struct cs_insn;

namespace bcov {
namespace x64 {

constexpr unsigned kMaxInstSize = 15;

enum class Opnd : uint8_t {
    One = 0,
    Two,
    Three,
    Four,
    Five,
    Six,
    Seven,
    Eight,
    END
};

bool is_jump(const cs_insn *inst) noexcept  __attribute__ ((const));

bool is_call(const cs_insn *inst) noexcept  __attribute__ ((const));

/// @brief: call, jmp, ret or  any control-transfer instruction
bool is_branch(const cs_insn *inst) noexcept  __attribute__ ((const));

uint8_t opnd_count(const cs_insn *inst) noexcept  __attribute__ ((const));

bool is_opnd_read(const cs_insn *inst, Opnd opnd) noexcept  __attribute__ ((const));

bool is_opnd_write(const cs_insn *inst, Opnd opnd) noexcept  __attribute__ ((const));

bool
is_opnd_immediate(const cs_insn *inst, Opnd opnd) noexcept  __attribute__ ((const));

bool is_opnd_rip_immediate(const cs_insn *inst,
                           Opnd opnd) noexcept  __attribute__ ((const));

bool is_opnd_reg(const cs_insn *inst, Opnd opnd) noexcept  __attribute__ ((const));

bool is_opnd_mem(const cs_insn *inst, Opnd opnd) noexcept  __attribute__ ((const));

/// @brief: inst has a single immediate argument
bool has_one_const_opnd(const cs_insn *inst) noexcept  __attribute__ ((const));

/// @brief: inst has a single rip-based immediate argument
bool has_rip_rel_const_opnd(const cs_insn *inst) noexcept  __attribute__ ((const));

/// precondition: inst is jump. returns zero for indirect jumps
addr_t
get_direct_branch_target(const cs_insn *inst) noexcept  __attribute__ ((const));

addr_t
get_rip_rel_branch_target(const cs_insn *inst) noexcept  __attribute__ ((const));

bool is_branch_relative(const cs_insn *inst) noexcept  __attribute__ ((const));

bool is_rip_relative(const cs_insn *inst) noexcept  __attribute__ ((const));

bool is_loop(const cs_insn *inst) noexcept  __attribute__ ((const));

bool is_relative(const cs_insn *inst) noexcept  __attribute__ ((const));

bool is_trap(const cs_insn *inst) noexcept  __attribute__ ((const));

/// @brief: inst reads the flags register
bool is_conditional(const cs_insn *inst) noexcept  __attribute__ ((const));

bool is_return(const cs_insn *inst) noexcept  __attribute__ ((const));

/// @brief: inst zeros a register by xor'ing it with itself.
bool is_const_xor(const cs_insn *inst) noexcept  __attribute__ ((const));

namespace abi {

bool sysv_is_call_arg_reg(const cs_insn *inst,
                          Opnd opnd) noexcept  __attribute__ ((const));

bool sysv_is_scratch_reg(const cs_insn *inst,
                         Opnd opnd) noexcept  __attribute__ ((const));

bool sysv_is_call_result_reg(const cs_insn *inst,
                             Opnd opnd) noexcept  __attribute__ ((const));

}

} // x64
} // bcov
