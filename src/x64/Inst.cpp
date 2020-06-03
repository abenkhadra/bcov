/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include "Inst.hpp"
#include "easylogging/easylogging++.h"
#include <capstone/capstone.h>

namespace bcov {
namespace x64 {

x86_reg
get_canonical(x86_reg reg)
{
    switch (reg) {
    case X86_REG_AL:
    case X86_REG_AX:
    case X86_REG_EAX:return X86_REG_RAX;

    case X86_REG_BL:
    case X86_REG_BX:
    case X86_REG_EBX:return X86_REG_RBX;

    case X86_REG_CL:
    case X86_REG_CX:
    case X86_REG_ECX:return X86_REG_RCX;

    case X86_REG_DL:
    case X86_REG_DX:
    case X86_REG_EDX:return X86_REG_RDX;

    case X86_REG_SIL:
    case X86_REG_SI:
    case X86_REG_ESI:return X86_REG_RSI;

    case X86_REG_DIL:
    case X86_REG_DI:
    case X86_REG_EDI:return X86_REG_RDI;

    case X86_REG_BPL:
    case X86_REG_BP:
    case X86_REG_EBP:return X86_REG_RBP;

    case X86_REG_SPL:
    case X86_REG_SP:
    case X86_REG_ESP:return X86_REG_RSP;

    case X86_REG_R8B:
    case X86_REG_R8W:
    case X86_REG_R8D:return X86_REG_R8;

    case X86_REG_R9B:
    case X86_REG_R9W:
    case X86_REG_R9D:return X86_REG_R9;

    case X86_REG_R10B:
    case X86_REG_R10W:
    case X86_REG_R10D:return X86_REG_R10;

    case X86_REG_R11B:
    case X86_REG_R11W:
    case X86_REG_R11D:return X86_REG_R11;

    case X86_REG_R12B:
    case X86_REG_R12W:
    case X86_REG_R12D:return X86_REG_R12;

    case X86_REG_R13B:
    case X86_REG_R13W:
    case X86_REG_R13D:return X86_REG_R13;

    case X86_REG_R14B:
    case X86_REG_R14W:
    case X86_REG_R14D:return X86_REG_R14;

    case X86_REG_R15B:
    case X86_REG_R15W:
    case X86_REG_R15D:return X86_REG_R15;

    default:return reg;
    }
}

bool
is_branch(const cs_insn *inst) noexcept
{
    for (uint8_t i = 0; i < inst->detail->groups_count; ++i) {
        if (inst->detail->groups[i] == CS_GRP_JUMP ||
            inst->detail->groups[i] == CS_GRP_CALL ||
            inst->detail->groups[i] == CS_GRP_RET ||
            inst->detail->groups[i] == CS_GRP_INT ||
            inst->detail->groups[i] == CS_GRP_IRET ||
            inst->detail->groups[i] == CS_GRP_BRANCH_RELATIVE) {
            return true;
        }
    }
    return is_trap(inst) || is_loop(inst);
}

bool
is_call(const cs_insn *inst) noexcept
{
    for (uint8_t i = 0; i < inst->detail->groups_count; ++i) {
        if (inst->detail->groups[i] == CS_GRP_CALL) {
            return true;
        }
    }
    return false;
}

bool
is_jump(const cs_insn *inst) noexcept
{
    for (uint8_t i = 0; i < inst->detail->groups_count; ++i) {
        if (inst->detail->groups[i] == CS_GRP_JUMP) {
            return true;
        }
    }
    return false;
}

uint8_t
opnd_count(const cs_insn *inst) noexcept
{
    return inst->detail->x86.op_count;
}

bool
is_opnd_read(const cs_insn *inst, Opnd opnd) noexcept
{
    const cs_x86_op &opnd_ref = inst->detail->x86.operands[to_integral(opnd)];
    return (opnd_ref.access & CS_AC_READ) == CS_AC_READ;
}

bool
is_opnd_write(const cs_insn *inst, Opnd opnd) noexcept
{
    const cs_x86_op &opnd_ref = inst->detail->x86.operands[to_integral(opnd)];
    return (opnd_ref.access & CS_AC_WRITE) == CS_AC_WRITE;
}

bool
is_opnd_immediate(const cs_insn *inst, Opnd opnd) noexcept
{
    const cs_x86_op &opnd_ref = inst->detail->x86.operands[to_integral(opnd)];
    return opnd_ref.type == X86_OP_IMM;
}

bool
is_opnd_rip_immediate(const cs_insn *inst, Opnd opnd) noexcept
{
    const cs_x86_op &opnd_ref = inst->detail->x86.operands[to_integral(opnd)];
    return opnd_ref.type == X86_OP_MEM && opnd_ref.mem.base == X86_REG_RIP &&
           opnd_ref.mem.index == X86_REG_INVALID;
}

bool
is_opnd_reg(const cs_insn *inst, Opnd opnd) noexcept
{
    const cs_x86_op &opnd_ref = inst->detail->x86.operands[to_integral(opnd)];
    return opnd_ref.type == X86_OP_REG;
}

bool
is_opnd_mem(const cs_insn *inst, Opnd opnd) noexcept
{
    const cs_x86_op &opnd_ref = inst->detail->x86.operands[to_integral(opnd)];
    return opnd_ref.type == X86_OP_MEM;
}

bool
has_one_const_opnd(const cs_insn *inst) noexcept
{
    return inst->detail->x86.op_count == 1 && is_opnd_immediate(inst, Opnd::One);
}

bool
has_rip_rel_const_opnd(const cs_insn *inst) noexcept
{
    return inst->detail->x86.op_count == 1 && is_opnd_rip_immediate(inst, Opnd::One);
}

addr_t
get_direct_branch_target(const cs_insn *inst) noexcept
{
    // precondition: inst is a branch instruction
    return has_one_const_opnd(inst) ? (addr_t) inst->detail->x86.operands[0].imm : 0;
}

addr_t
get_rip_rel_branch_target(const cs_insn *inst) noexcept
{
    // precondition: inst is a branch instruction
    return has_rip_rel_const_opnd(inst) ? inst->address + inst->size +
                                          inst->detail->x86.operands[0].mem.disp : 0;
}

bool
is_branch_relative(const cs_insn *inst) noexcept
{
    for (uint8_t i = 0; i < inst->detail->groups_count; ++i) {
        if (inst->detail->groups[i] == CS_GRP_BRANCH_RELATIVE) {
            return true;
        }
    }
    return false;
}

bool
is_rip_relative(const cs_insn *inst) noexcept
{
    for (int i = 0; i < inst->detail->x86.op_count; ++i) {
        if (inst->detail->x86.operands[i].type != X86_OP_MEM) {
            continue;
        }
        if (inst->detail->x86.operands[i].mem.base == X86_REG_RIP) {
            return true;
        }
    }
    return false;
}

bool
is_loop(const cs_insn *inst) noexcept
{
    return inst->id == X86_INS_LOOP || inst->id == X86_INS_LOOPE ||
           inst->id == X86_INS_LOOPNE;
}

bool
is_trap(const cs_insn *inst) noexcept
{
    return inst->id == X86_INS_UD2 || inst->id == X86_INS_UD0 ||
           inst->id == X86_INS_UD1 || inst->id == X86_INS_HLT;
}

bool
is_relative(const cs_insn *inst) noexcept
{
    // XXX: assuming that relative instructions
    // in x64 can either be (1) relative branch or (2) rip-relative
    return is_branch_relative(inst) || is_rip_relative(inst);
}

bool
is_conditional(const cs_insn *inst) noexcept
{
    for (int i = 0; i < inst->detail->regs_read_count; ++i) {
        if (inst->detail->regs_read[i] == X86_REG_EFLAGS) {
            return true;
        }
    }
    return false;
}

bool
is_return(const cs_insn *inst) noexcept
{
    for (uint8_t i = 0; i < inst->detail->groups_count; ++i) {
        if (inst->detail->groups[i] == CS_GRP_RET) {
            return true;
        }
    }
    return false;
}

bool
is_const_xor(const cs_insn *inst) noexcept
{
    if (inst->id != X86_INS_XOR) {
        return false;
    }
    auto &operands = inst->detail->x86.operands;
    return operands[0].reg == operands[1].reg;
}

namespace abi {
bool
sysv_is_call_arg_reg(const cs_insn *inst, Opnd opnd) noexcept
{
    const cs_x86_op &opnd_ref = inst->detail->x86.operands[to_integral(opnd)];
    if (opnd_ref.type != X86_OP_REG) {
        return false;
    }
    auto reg = get_canonical(opnd_ref.reg);
    return reg == X86_REG_RDI || reg == X86_REG_RSI || reg == X86_REG_RDX ||
           reg == X86_REG_RCX || reg == X86_REG_R8 || reg == X86_REG_R9;
}

bool
sysv_is_scratch_reg(const cs_insn *inst, Opnd opnd) noexcept
{
    const cs_x86_op &opnd_ref = inst->detail->x86.operands[to_integral(opnd)];
    if (opnd_ref.type != X86_OP_REG) {
        return false;
    }
    auto reg = get_canonical(opnd_ref.reg);
    return reg == X86_REG_RBX || reg == X86_REG_R10 || reg == X86_REG_R11 ||
           reg == X86_REG_R12 || reg == X86_REG_R13 || reg == X86_REG_R14 ||
           reg == X86_REG_R15;
}

bool
sysv_is_call_result_reg(const cs_insn *inst, Opnd opnd) noexcept
{
    const cs_x86_op &opnd_ref = inst->detail->x86.operands[to_integral(opnd)];
    if (opnd_ref.type != X86_OP_REG) {
        return false;
    }
    auto reg = get_canonical(opnd_ref.reg);
    return reg == X86_REG_RAX;
}

} // abi
} // x64
} // bcov
