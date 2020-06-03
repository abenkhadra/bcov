/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include <cstring>
#include "easylogging/easylogging++.h"
#include "x64/Inst.hpp"
#include "Asm.hpp"

namespace bcov {

static constexpr uint8_t kDirRelCall = 0xE8U;
static constexpr uint8_t kDirAbsCall = 0x9AU;
static constexpr uint8_t kDirLongJmp = 0xE9U;
static constexpr uint8_t kDirShortJmp = 0xEBU;
static constexpr uint8_t kCondShortJmpCXZSize = 2U;
static constexpr uint8_t kCondShortJmpMask = 0x70U;

// sub QWORD PTR [rsp],imm8
static constexpr uint32_t kSubRSPMemImm8Inst = 0x242C8348U;

// jmp QWORD PTR [rsp + disp32]
static constexpr uint32_t kJmpRSPMemDisp32Inst = 0x0024a4FFU;

static inline bool
is_long_cond_jmp(const uint8_t *buf)
{
    auto val = *reinterpret_cast<const uint16_t *>(buf);
    return (val & 0xF0FFU) == 0x800F;
}

static inline bool
is_short_cond_jmp_cxz(const uint8_t *buf)
{
    return *buf == x64::kCondShortJmpCXZ;
}

static inline uint8_t
to_long_cond_jmp(const uint8_t *buf)
{
    return (*buf & 0x0FU) | 0x80U;
}

static inline bool
has_disp_at_end(const MCInst &inst)
{
    return inst.cs_id() == X86_INS_LEA || inst.cs_id() == X86_INS_JMP ||
           inst.cs_id() == X86_INS_CALL;
}

static int32_t
parse_rip_displacement(sstring_view inst_text)
{
    int64_t res = 0;
    auto char_p = strstr(inst_text.data(), "rip");
    DCHECK(char_p != nullptr);
    char sign = '+';
    for (; char_p < inst_text.data() + inst_text.size(); ++char_p) {
        if (*char_p == '+' || *char_p == '-') {
            sign = *char_p;
            break;
        }
    }
    res = strtol(++char_p, nullptr, 16);
    DCHECK(res != 0L);
    return sign == '+' ? (int32_t) res : -((int32_t) res);
}


void
X64Asm::jmp_rel_32(uint8_t *buf, addr_t src, addr_t dst)
{
    buf[0] = 0xe9;
    auto disp = (int32_t) (dst - (src + x64::kInstJMPRel32Size));
    DCHECK(dst == (src + x64::kInstJMPRel32Size + disp));
    *reinterpret_cast<int32_t *>(buf + 1) = disp;
}

void
X64Asm::call_rel_32(uint8_t *buf, addr_t src, addr_t dst)
{
    buf[0] = 0xe8;
    auto disp = (int32_t) (dst - (src + x64::kInstJMPRel32Size));
    DCHECK(dst == (src + x64::kInstJMPRel32Size + disp));
    *reinterpret_cast<int32_t *>(buf + 1) = disp;
}

void
X64Asm::jmp_rel_8(uint8_t *buf, addr_t src, addr_t dst)
{
    auto disp = (int8_t) (dst - (src + x64::kInstJMPRel8Size));
    DCHECK(dst == (src + x64::kInstJMPRel8Size + disp));
    buf[0] = 0xeb;
    *reinterpret_cast<int8_t *>(buf + 1) = disp;
}

void
X64Asm::sub_rsp_mem_imm8(uint8_t *buf, int8_t off)
{
    *reinterpret_cast<uint32_t *>(buf) = kSubRSPMemImm8Inst;
    buf[4] = off;
}

void
X64Asm::jmp_rsp_mem_disp32(uint8_t *buf, int32_t off)
{
    *reinterpret_cast<uint32_t *>(buf) = kJmpRSPMemDisp32Inst;
    *reinterpret_cast<int32_t *>(buf + 3) = off;
}

void
X64Asm::mov_rip_mem_imm8(uint8_t *buf, addr_t inst_addr, addr_t mem_addr,
                         uint8_t imm8)
{
    auto disp = (int32_t) (mem_addr - (inst_addr + x64::kInstRIPRelMoveSize));
    DCHECK(mem_addr == ((inst_addr + x64::kInstRIPRelMoveSize) + disp));
    *reinterpret_cast<uint16_t *>(buf) = 0x05C6U;
    *reinterpret_cast<int32_t *>(buf + 2) = disp;
    buf[6] = imm8;
}

void
X64Asm::fill_nop(uint8_t *buf, size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        buf[i] = 0x90;
    }
}

void
X64Asm::fill_int3(uint8_t *buf, size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        buf[i] = 0xCC;
    }
}

//==============================================================================

void
rewrite_rel_disp_32(const MCInst &inst, buffer_t src_buf, addr_t dst_addr,
                    uint8_t *dst_buf)
{
    auto src_disp_ptr = reinterpret_cast<const int32_t *>(src_buf);
    auto dst_disp_ptr = reinterpret_cast<int32_t *>(dst_buf);
    addr_t target = inst.address() + inst.size() + *src_disp_ptr;
    int64_t dst_disp = target - (dst_addr + inst.size());
    *dst_disp_ptr = dst_disp;
    DCHECK(*dst_disp_ptr == dst_disp);
}

void
rewrite_rel_disp_jmp_8(const MCInst &inst, buffer_t src_buf, addr_t dst_addr,
                       uint8_t *dst_buf)
{
    auto src_disp_ptr = reinterpret_cast<const int8_t *>(src_buf);
    auto dst_disp_ptr = reinterpret_cast<int32_t *>(dst_buf);
    addr_t target = inst.address() + x64::kInstJMPRel8Size + *src_disp_ptr;
    int64_t dst_disp = target - (dst_addr + x64::kInstJMPRel32Size);
    *dst_disp_ptr = dst_disp;
    DCHECK(*dst_disp_ptr == dst_disp);
}

void
rewrite_short_cond_jmp_cxz(const MCInst &inst, buffer_t src_buf, addr_t dst_addr,
                           uint8_t **dst_buf_p)
{
    DCHECK(is_short_cond_jmp_cxz(src_buf));
    auto dst_buf = *dst_buf_p;
    *dst_buf_p += x64::kInstJMPRel8Size + 2 * x64::kInstJMPRel32Size;
    *dst_buf = *src_buf;
    addr_t through_addr = inst.address() + kCondShortJmpCXZSize;
    addr_t taken_addr =
        through_addr + *reinterpret_cast<const int8_t *>(src_buf + 1);
    *(dst_buf + 1) = x64::kInstJMPRel32Size; // set displacement
    X64Asm::jmp_rel_32(dst_buf + 2, dst_addr + 2, through_addr);
    X64Asm::jmp_rel_32(dst_buf + 7, dst_addr + 7, taken_addr);
}

void
X64InstRewriter::rewrite_call(const MCInst &inst, buffer_t src_buf, addr_t dst_addr,
                              uint8_t **dst_buf_p)
{
    DCHECK(*src_buf != kDirAbsCall);
    auto dst_buf = *dst_buf_p;
    *dst_buf_p += inst.size();
    if (*src_buf == kDirRelCall) {
        // 32-bit relative sign-extended displacement
        *dst_buf = kDirRelCall; // copy inst id
        rewrite_rel_disp_32(inst, src_buf + 1, dst_addr, dst_buf + 1);
        return;
    }

    DCHECK(!inst.is_direct());
    std::memcpy(dst_buf, src_buf, inst.size());
}

void
X64InstRewriter::rewrite_call_to_jmp(uint8_t *inst_p)
{
    if (*inst_p == 0xE8) {
        *inst_p = 0xE9;
        return;
    }
    if (*inst_p == 0x41 || *inst_p == 0x42 || *inst_p == 0x43) {
        ++inst_p;
    }
    if (*inst_p == 0xFF) {
        ++inst_p;
        uint8_t h = (((*inst_p & 0xF0U) >> 4U) + 1) << 4U;
        *inst_p = (*inst_p & 0x0FU) | h;
        return;
    }
    BCOV_UNREACHABLE
}

void
X64InstRewriter::rewrite_uncond_jmp(const MCInst &inst, buffer_t src_buf,
                                    addr_t dst_addr, uint8_t **dst_buf_p)
{
    auto dst_buf = *dst_buf_p;
    if (*src_buf == kDirLongJmp) {
        *dst_buf = kDirLongJmp; // copy inst id
        rewrite_rel_disp_32(inst, src_buf + 1, dst_addr, dst_buf + 1);
        *dst_buf_p += x64::kInstJMPRel32Size;
        return;
    }

    if (*src_buf == kDirShortJmp) {
        *dst_buf = kDirLongJmp; // change inst id
        rewrite_rel_disp_jmp_8(inst, src_buf + 1, dst_addr, dst_buf + 1);
        *dst_buf_p += x64::kInstJMPRel32Size;
        return;
    }

    DCHECK(!inst.is_direct());
    std::memcpy(dst_buf, src_buf, inst.size());
    *dst_buf_p += inst.size();
}

void
X64InstRewriter::rewrite_cond_jmp(const MCInst &inst, buffer_t src_buf,
                                  addr_t dst_addr, uint8_t **dst_buf_p)
{
    if (is_short_cond_jmp_cxz(src_buf)) {
        rewrite_short_cond_jmp_cxz(inst, src_buf, dst_addr, dst_buf_p);
        return;
    }
    auto dst_buf = *dst_buf_p;
    *dst_buf_p += x64::kInstJccRel32Size + x64::kInstJMPRel32Size;
    addr_t through_addr = inst.address() + inst.size();
    addr_t taken_addr;

    *dst_buf = 0x0F;
    if (is_long_cond_jmp(src_buf)) {
        *(dst_buf + 1) = *(src_buf + 1);
        taken_addr = through_addr + *reinterpret_cast<const int32_t *>(src_buf + 2);
    } else {
        DCHECK((*src_buf & kCondShortJmpMask) == kCondShortJmpMask);
        *(dst_buf + 1) = to_long_cond_jmp(src_buf);
        taken_addr = through_addr + *reinterpret_cast<const int8_t *>(src_buf + 1);
    }

    auto disp = (int32_t) (taken_addr - (dst_addr + x64::kInstJccRel32Size));
    DCHECK(taken_addr == (dst_addr + x64::kInstJccRel32Size + disp));
    *reinterpret_cast<int32_t *>(dst_buf + 2) = disp;
    X64Asm::jmp_rel_32(dst_buf + x64::kInstJccRel32Size,
                       dst_addr + x64::kInstJccRel32Size, through_addr);
}

void
X64InstRewriter::rewrite_pc_rel_inst(const MCInst &inst, buffer_t src_buf,
                                     addr_t dst_addr, uint8_t **dst_buf_p)
{
    auto dst_buf = *dst_buf_p;
    *dst_buf_p += inst.size();

    std::memcpy(dst_buf, src_buf, inst.size());
    if (has_disp_at_end(inst)) {
        rewrite_rel_disp_32(inst, src_buf + inst.size() - sizeof(int32_t), dst_addr,
                            dst_buf + inst.size() - sizeof(int32_t));
        return;
    }
    auto orig_disp = parse_rip_displacement(inst.text());
    auto disp_buf = src_buf + inst.size() - sizeof(int32_t);

    // XXX: can we have an instruction where disp32 == imm32?
    uint8_t disp_match_count = 0;
    for (auto p = disp_buf; src_buf < p; --p) {
        if (*reinterpret_cast<const int32_t *>(p) == orig_disp) {
            disp_buf = p;
            p -= sizeof(int32_t) - 1;
            ++disp_match_count;
        }
    }
    DCHECK(disp_match_count == 1);
    rewrite_rel_disp_32(inst, disp_buf, dst_addr, dst_buf + (disp_buf - src_buf));
}

void
X64InstRewriter::rewrite(const MCInst &inst, buffer_t src_buf, addr_t dst_addr,
                         uint8_t **dst_buf_p)
{
    if (inst.is_call()) {
        if (inst.is_pc_relative()) {
            rewrite_pc_rel_inst(inst, src_buf, dst_addr, dst_buf_p);
        } else {
            rewrite_call(inst, src_buf, dst_addr, dst_buf_p);
        }
        rewrite_call_to_jmp(*dst_buf_p - inst.size());
        return;
    }

    if (inst.is_jump()) {
        if (inst.is_conditional()) {
            rewrite_cond_jmp(inst, src_buf, dst_addr, dst_buf_p);
        } else if (inst.is_pc_relative()) {
            rewrite_pc_rel_inst(inst, src_buf, dst_addr, dst_buf_p);
        } else {
            rewrite_uncond_jmp(inst, src_buf, dst_addr, dst_buf_p);
        }
        return;
    }

    if (!inst.is_relative()) {
        auto dst_buf = *dst_buf_p;
        *dst_buf_p += inst.size();
        std::memcpy(dst_buf, src_buf, inst.size());
        return;
    }

    if (inst.is_pc_relative()) {
        // instruction that explicitly uses RIP
        rewrite_pc_rel_inst(inst, src_buf, dst_addr, dst_buf_p);
        return;
    }

    BCOV_UNREACHABLE
}

} // bcov
