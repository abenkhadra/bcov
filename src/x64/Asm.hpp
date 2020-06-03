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

#include "core/CSInstWrapper.hpp"
#include "core/Disassembler.hpp"
#include "core/MCInst.hpp"

namespace bcov {
namespace x64 {

constexpr unsigned kInstRIPRelMoveSize = 7U;

constexpr unsigned kInstJMPRel32Size = 5U;

constexpr unsigned kInstJccRel32Size = 6U;

constexpr unsigned kInstJMPRel8Size = 2U;

// jmp QWORD PTR [rsp]
static constexpr uint32_t kJmpRSPMemDisp0Inst = 0x002424FFU;

static constexpr uint32_t kJmpRSPMemDisp0InstSize = 3U;

// jmp QWORD PTR [rsp + disp8]
static constexpr uint32_t kJmpRSPMemDisp8Inst = 0x002464FFU;

static constexpr uint32_t kJmpRSPMemDisp8InstSize = 4U;

// jmp QWORD PTR [rsp + disp32]
static constexpr uint32_t kJmpRSPMemDisp32Inst = 0x0024A4FFU;

static constexpr uint32_t kJmpRSPMemDisp32InstSize = 7U;

// sub QWORD PTR [rsp],imm8
static constexpr unsigned kRSPAdjustByteSize = 5U;

static constexpr unsigned kQWORD = 8U;

static constexpr unsigned kDWORD = 4U;

static constexpr unsigned kWORD = 2U;

static constexpr uint8_t kCondShortJmpCXZ = 0xE3U;

} // x64

class X64Asm {
public:
    static void jmp_rel_32(uint8_t *buf, addr_t src, addr_t dst);

    static void call_rel_32(uint8_t *buf, addr_t src, addr_t dst);

    static void jmp_rel_8(uint8_t *buf, addr_t src, addr_t dst);

    // sub QWORD PTR [rsp],imm8
    static void sub_rsp_mem_imm8(uint8_t *buf, int8_t off);

    // call QWORD PTR [rsp + disp32]
    static void jmp_rsp_mem_disp32(uint8_t *buf, int32_t off);

    // mov [rip+disp32], imm8
    static void
    mov_rip_mem_imm8(uint8_t *buf, addr_t inst_addr, addr_t mem_addr, uint8_t imm8);

    static void fill_nop(uint8_t *buf, size_t size);

    static void fill_int3(uint8_t *buf, size_t size);

};

//@brief: rewrites a given instruction to a different address. Assumes a small code model
class X64InstRewriter {
public:

    X64InstRewriter() = default;

    ~X64InstRewriter() = default;

    static void
    rewrite_call(const MCInst &inst, buffer_t src_buf, addr_t dst_addr,
                 uint8_t **dst_buf_p);

    static void
    rewrite_call_to_jmp(uint8_t *inst_p);

    static void
    rewrite_uncond_jmp(const MCInst &inst, buffer_t src_buf, addr_t dst_addr,
                       uint8_t **dst_buf_p);

    static void
    rewrite_cond_jmp(const MCInst &inst, buffer_t src_buf, addr_t dst_addr,
                     uint8_t **dst_buf_p);

    static void
    rewrite_pc_rel_inst(const MCInst &inst, buffer_t src_buf, addr_t dst_addr,
                        uint8_t **dst_buf_p);

    static void
    rewrite(const MCInst &inst, buffer_t src_buf, addr_t dst_addr,
            uint8_t **dst_buf_p);
};

} // bcov
