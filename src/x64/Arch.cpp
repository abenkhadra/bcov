/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include "Arch.hpp"
#include "Inst.hpp"
#include "easylogging/easylogging++.h"
#include <capstone/capstone.h>

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#pragma GCC warning "We assume a little endian machine!"
#endif

/*
 * core GPR registers:  19 * 8  (count * size in bytes)
 * segment registers:   2  * 8
 * avx-512 registers :  32 * 64
 * opmask registers:    8  * 8
 *
 * NOTE: we ignore system registers
 */

namespace bcov {
namespace x64 {

MCOpnd::MCOpnd()
    : m_kind(MCOpndKind::kNone)
{ }

MCOpnd::MCOpnd(MCOpndKind kind, X64Reg reg, MCAccMode mode)
    : m_kind(kind), m_mode(mode), m_size(get_reg_size(reg)), m_reg(reg)
{
    if (!this->is_reg_type()) {
        m_kind = MCOpndKind::kNone;
    }
}

MCOpnd::MCOpnd(MCOpndKind kind, int64_t imm)
    : m_kind(kind), m_mode(MCAccMode::kRead), m_imm(imm)
{
    if (!this->is_imm_type()) {
        m_kind = MCOpndKind::kNone;
    }
}

MCOpnd::MCOpnd(addr_t target, uint8_t size, MCAccMode mode)
    : m_kind(MCOpndKind::kMem), m_mode(mode), m_size(size), m_target(target)
{ }

MCAccMode
get_access_mode(uint8_t ac_mode)
{
    MCAccMode res = MCAccMode::kNone;
    if ((ac_mode & CS_AC_READ) == CS_AC_READ) {
        res = MCAccMode::kRead;
    }

    if ((ac_mode & CS_AC_WRITE) == CS_AC_WRITE) {
        res |= MCAccMode::kWrite;
    }

    return res;
}

//==============================================================================

const char *
to_string(X64Reg reg)
{
    switch (reg) {
    case X64Reg::RAX: return "rax";
    case X64Reg::RBX: return "rbx";
    case X64Reg::RCX: return "rcx";
    case X64Reg::RDX: return "rdx";
    case X64Reg::RSI: return "rsi";
    case X64Reg::RDI: return "rdi";
    case X64Reg::RBP: return "rbp";
    case X64Reg::RSP: return "rsp";
    case X64Reg::R8: return "r8";
    case X64Reg::R9: return "r9";
    case X64Reg::R10: return "r10";
    case X64Reg::R11: return "r11";
    case X64Reg::R12: return "r12";
    case X64Reg::R13: return "r13";
    case X64Reg::R14: return "r14";
    case X64Reg::R15: return "r15";
    case X64Reg::RFLAGS: return "rflags";
    case X64Reg::RIP: return "rip";
    case X64Reg::ST0: return "st0";
    case X64Reg::ST1: return "st1";
    case X64Reg::ST2: return "st2";
    case X64Reg::ST3: return "st3";
    case X64Reg::ST4: return "st4";
    case X64Reg::ST5: return "st5";
    case X64Reg::ST6: return "st6";
    case X64Reg::ST7: return "st7";
    case X64Reg::ZMM0: return "zmm0";
    case X64Reg::ZMM1: return "zmm1";
    case X64Reg::ZMM2: return "zmm2";
    case X64Reg::ZMM3: return "zmm3";
    case X64Reg::ZMM4: return "zmm4";
    case X64Reg::ZMM5: return "zmm5";
    case X64Reg::ZMM6: return "zmm6";
    case X64Reg::ZMM7: return "zmm7";
    case X64Reg::ZMM8: return "zmm8";
    case X64Reg::ZMM9: return "zmm9";
    case X64Reg::ZMM10: return "zmm10";
    case X64Reg::ZMM11: return "zmm11";
    case X64Reg::ZMM12: return "zmm12";
    case X64Reg::ZMM13: return "zmm13";
    case X64Reg::ZMM14: return "zmm14";
    case X64Reg::ZMM15: return "zmm15";
    case X64Reg::ZMM16: return "zmm16";
    case X64Reg::ZMM17: return "zmm17";
    case X64Reg::ZMM18: return "zmm18";
    case X64Reg::ZMM19: return "zmm19";
    case X64Reg::ZMM20: return "zmm20";
    case X64Reg::ZMM21: return "zmm21";
    case X64Reg::ZMM22: return "zmm22";
    case X64Reg::ZMM23: return "zmm23";
    case X64Reg::ZMM24: return "zmm24";
    case X64Reg::ZMM25: return "zmm25";
    case X64Reg::ZMM26: return "zmm26";
    case X64Reg::ZMM27: return "zmm27";
    case X64Reg::ZMM28: return "zmm28";
    case X64Reg::ZMM29: return "zmm29";
    case X64Reg::ZMM30: return "zmm30";
    case X64Reg::ZMM31: return "zmm31";
    case X64Reg::K0: return "k0";
    case X64Reg::K1: return "k1";
    case X64Reg::K2: return "k2";
    case X64Reg::K3: return "k3";
    case X64Reg::K4: return "k4";
    case X64Reg::K5: return "k5";
    case X64Reg::K6: return "k6";
    case X64Reg::K7: return "k7";
    case X64Reg::CR0: return "cr0";
    case X64Reg::CR1: return "cr1";
    case X64Reg::CR2: return "cr2";
    case X64Reg::CR3: return "cr3";
    case X64Reg::CR4: return "cr4";
    case X64Reg::CR5: return "cr5";
    case X64Reg::CR6: return "cr6";
    case X64Reg::CR7: return "cr7";
    case X64Reg::CR8: return "cr8";
    case X64Reg::CR9: return "cr9";
    case X64Reg::CR10: return "cr10";
    case X64Reg::CR11: return "cr11";
    case X64Reg::CR12: return "cr12";
    case X64Reg::CR13: return "cr13";
    case X64Reg::CR14: return "cr14";
    case X64Reg::CR15: return "cr15";
    case X64Reg::DR0: return "dr0";
    case X64Reg::DR1: return "dr1";
    case X64Reg::DR2: return "dr2";
    case X64Reg::DR3: return "dr3";
    case X64Reg::DR4: return "dr4";
    case X64Reg::DR5: return "dr5";
    case X64Reg::DR6: return "dr6";
    case X64Reg::DR7: return "dr7";
    case X64Reg::DR8: return "dr8";
    case X64Reg::DR9: return "dr9";
    case X64Reg::DR10: return "dr10";
    case X64Reg::DR11: return "dr11";
    case X64Reg::DR12: return "dr12";
    case X64Reg::DR13: return "dr13";
    case X64Reg::DR14: return "dr14";
    case X64Reg::DR15: return "dr15";
    case X64Reg::CS: return "cs";
    case X64Reg::SS: return "ss";
    case X64Reg::DS: return "ds";
    case X64Reg::ES: return "es";
    case X64Reg::FS: return "fs";
    case X64Reg::GS: return "gs";
    case X64Reg::GDTR: return "gdtr";
    case X64Reg::TR: return "tr";
    case X64Reg::IDTR: return "idtr";
    case X64Reg::LDTR: return "ldtr";
    case X64Reg::FP_IP: return "fp_ip";
    case X64Reg::FP_DP: return "fp_dp";
    case X64Reg::FP_CS: return "fp_cs";
    case X64Reg::FPCW: return "cw";
    case X64Reg::FPSW: return "sw";
    case X64Reg::FPTW: return "tw";
    case X64Reg::AL: return "al";
    case X64Reg::AH: return "ah";
    case X64Reg::AX: return "ax";
    case X64Reg::EAX: return "eax";
    case X64Reg::BL: return "bl";
    case X64Reg::BH: return "bh";
    case X64Reg::BX: return "bx";
    case X64Reg::EBX: return "ebx";
    case X64Reg::CL: return "cl";
    case X64Reg::CH: return "ch";
    case X64Reg::CX: return "cx";
    case X64Reg::ECX: return "ecx";
    case X64Reg::DL: return "dl";
    case X64Reg::DH: return "dh";
    case X64Reg::DX: return "dx";
    case X64Reg::EDX: return "edx";
    case X64Reg::SIL: return "sil";
    case X64Reg::SI: return "si";
    case X64Reg::ESI: return "esi";
    case X64Reg::DIL: return "dil";
    case X64Reg::DI: return "di";
    case X64Reg::EDI: return "edi";
    case X64Reg::BPL: return "bpl";
    case X64Reg::BP: return "bp";
    case X64Reg::EBP: return "ebp";
    case X64Reg::SPL: return "spl";
    case X64Reg::SP: return "sp";
    case X64Reg::ESP: return "esp";
    case X64Reg::R8B: return "r8b";
    case X64Reg::R8W: return "r8w";
    case X64Reg::R8D: return "r8d";
    case X64Reg::R9B: return "r9b";
    case X64Reg::R9W: return "r9w";
    case X64Reg::R9D: return "r9d";
    case X64Reg::R10B: return "r10b";
    case X64Reg::R10W: return "r10w";
    case X64Reg::R10D: return "r10d";
    case X64Reg::R11B: return "r11b";
    case X64Reg::R11W: return "r11w";
    case X64Reg::R11D: return "r11d";
    case X64Reg::R12B: return "r12b";
    case X64Reg::R12W: return "r12w";
    case X64Reg::R12D: return "r12d";
    case X64Reg::R13B: return "r13b";
    case X64Reg::R13W: return "r13w";
    case X64Reg::R13D: return "r13d";
    case X64Reg::R14B: return "r14b";
    case X64Reg::R14W: return "r14w";
    case X64Reg::R14D: return "r14d";
    case X64Reg::R15B: return "r15b";
    case X64Reg::R15W: return "r15w";
    case X64Reg::R15D: return "r15d";
    case X64Reg::EIP: return "eip";
    case X64Reg::EFLAGS: return "eflags";
    case X64Reg::MM0: return "mm0";
    case X64Reg::MM1: return "mm1";
    case X64Reg::MM2: return "mm2";
    case X64Reg::MM3: return "mm3";
    case X64Reg::MM4: return "mm4";
    case X64Reg::MM5: return "mm5";
    case X64Reg::MM6: return "mm6";
    case X64Reg::MM7: return "mm7";
    case X64Reg::XMM0: return "xmm0";
    case X64Reg::XMM1: return "xmm1";
    case X64Reg::XMM2: return "xmm2";
    case X64Reg::XMM3: return "xmm3";
    case X64Reg::XMM4: return "xmm4";
    case X64Reg::XMM5: return "xmm5";
    case X64Reg::XMM6: return "xmm6";
    case X64Reg::XMM7: return "xmm7";
    case X64Reg::XMM8: return "xmm8";
    case X64Reg::XMM9: return "xmm9";
    case X64Reg::XMM10: return "xmm10";
    case X64Reg::XMM11: return "xmm11";
    case X64Reg::XMM12: return "xmm12";
    case X64Reg::XMM13: return "xmm13";
    case X64Reg::XMM14: return "xmm14";
    case X64Reg::XMM15: return "xmm15";
    case X64Reg::YMM0: return "ymm0";
    case X64Reg::YMM1: return "ymm1";
    case X64Reg::YMM2: return "ymm2";
    case X64Reg::YMM3: return "ymm3";
    case X64Reg::YMM4: return "ymm4";
    case X64Reg::YMM5: return "ymm5";
    case X64Reg::YMM6: return "ymm6";
    case X64Reg::YMM7: return "ymm7";
    case X64Reg::YMM8: return "ymm8";
    case X64Reg::YMM9: return "ymm9";
    case X64Reg::YMM10: return "ymm10";
    case X64Reg::YMM11: return "ymm11";
    case X64Reg::YMM12: return "ymm12";
    case X64Reg::YMM13: return "ymm13";
    case X64Reg::YMM14: return "ymm14";
    case X64Reg::YMM15: return "ymm15";
    default: return "unused";
    }
}

X64Reg
get_x64_reg(uint16_t cs_reg)
{
    switch (cs_reg) {
    case X86_REG_RAX    : return X64Reg::RAX;
    case X86_REG_RBX    : return X64Reg::RBX;
    case X86_REG_RCX    : return X64Reg::RCX;
    case X86_REG_RDX    : return X64Reg::RDX;
    case X86_REG_RSI    : return X64Reg::RSI;
    case X86_REG_RDI    : return X64Reg::RDI;
    case X86_REG_RBP    : return X64Reg::RBP;
    case X86_REG_RSP    : return X64Reg::RSP;
    case X86_REG_R8     : return X64Reg::R8;
    case X86_REG_R9     : return X64Reg::R9;
    case X86_REG_R10    : return X64Reg::R10;
    case X86_REG_R11    : return X64Reg::R11;
    case X86_REG_R12    : return X64Reg::R12;
    case X86_REG_R13    : return X64Reg::R13;
    case X86_REG_R14    : return X64Reg::R14;
    case X86_REG_R15    : return X64Reg::R15;
    case X86_REG_RIP    : return X64Reg::RIP;
    case X86_REG_ST0    : return X64Reg::ST0;
    case X86_REG_ST1    : return X64Reg::ST1;
    case X86_REG_ST2    : return X64Reg::ST2;
    case X86_REG_ST3    : return X64Reg::ST3;
    case X86_REG_ST4    : return X64Reg::ST4;
    case X86_REG_ST5    : return X64Reg::ST5;
    case X86_REG_ST6    : return X64Reg::ST6;
    case X86_REG_ST7    : return X64Reg::ST7;
    case X86_REG_ZMM0   : return X64Reg::ZMM0;
    case X86_REG_ZMM1   : return X64Reg::ZMM1;
    case X86_REG_ZMM2   : return X64Reg::ZMM2;
    case X86_REG_ZMM3   : return X64Reg::ZMM3;
    case X86_REG_ZMM4   : return X64Reg::ZMM4;
    case X86_REG_ZMM5   : return X64Reg::ZMM5;
    case X86_REG_ZMM6   : return X64Reg::ZMM6;
    case X86_REG_ZMM7   : return X64Reg::ZMM7;
    case X86_REG_ZMM8   : return X64Reg::ZMM8;
    case X86_REG_ZMM9   : return X64Reg::ZMM9;
    case X86_REG_ZMM10  : return X64Reg::ZMM10;
    case X86_REG_ZMM11  : return X64Reg::ZMM11;
    case X86_REG_ZMM12  : return X64Reg::ZMM12;
    case X86_REG_ZMM13  : return X64Reg::ZMM13;
    case X86_REG_ZMM14  : return X64Reg::ZMM14;
    case X86_REG_ZMM15  : return X64Reg::ZMM15;
    case X86_REG_ZMM16  : return X64Reg::ZMM16;
    case X86_REG_ZMM17  : return X64Reg::ZMM17;
    case X86_REG_ZMM18  : return X64Reg::ZMM18;
    case X86_REG_ZMM19  : return X64Reg::ZMM19;
    case X86_REG_ZMM20  : return X64Reg::ZMM20;
    case X86_REG_ZMM21  : return X64Reg::ZMM21;
    case X86_REG_ZMM22  : return X64Reg::ZMM22;
    case X86_REG_ZMM23  : return X64Reg::ZMM23;
    case X86_REG_ZMM24  : return X64Reg::ZMM24;
    case X86_REG_ZMM25  : return X64Reg::ZMM25;
    case X86_REG_ZMM26  : return X64Reg::ZMM26;
    case X86_REG_ZMM27  : return X64Reg::ZMM27;
    case X86_REG_ZMM28  : return X64Reg::ZMM28;
    case X86_REG_ZMM29  : return X64Reg::ZMM29;
    case X86_REG_ZMM30  : return X64Reg::ZMM30;
    case X86_REG_ZMM31  : return X64Reg::ZMM31;
    case X86_REG_K0     : return X64Reg::K0;
    case X86_REG_K1     : return X64Reg::K1;
    case X86_REG_K2     : return X64Reg::K2;
    case X86_REG_K3     : return X64Reg::K3;
    case X86_REG_K4     : return X64Reg::K4;
    case X86_REG_K5     : return X64Reg::K5;
    case X86_REG_K6     : return X64Reg::K6;
    case X86_REG_K7     : return X64Reg::K7;
    case X86_REG_CR0    : return X64Reg::CR0;
    case X86_REG_CR1    : return X64Reg::CR1;
    case X86_REG_CR2    : return X64Reg::CR2;
    case X86_REG_CR3    : return X64Reg::CR3;
    case X86_REG_CR4    : return X64Reg::CR4;
    case X86_REG_CR5    : return X64Reg::CR5;
    case X86_REG_CR6    : return X64Reg::CR6;
    case X86_REG_CR7    : return X64Reg::CR7;
    case X86_REG_CR8    : return X64Reg::CR8;
    case X86_REG_CR9    : return X64Reg::CR9;
    case X86_REG_CR10   : return X64Reg::CR10;
    case X86_REG_CR11   : return X64Reg::CR11;
    case X86_REG_CR12   : return X64Reg::CR12;
    case X86_REG_CR13   : return X64Reg::CR13;
    case X86_REG_CR14   : return X64Reg::CR14;
    case X86_REG_CR15   : return X64Reg::CR15;
    case X86_REG_DR0    : return X64Reg::DR0;
    case X86_REG_DR1    : return X64Reg::DR1;
    case X86_REG_DR2    : return X64Reg::DR2;
    case X86_REG_DR3    : return X64Reg::DR3;
    case X86_REG_DR4    : return X64Reg::DR4;
    case X86_REG_DR5    : return X64Reg::DR5;
    case X86_REG_DR6    : return X64Reg::DR6;
    case X86_REG_DR7    : return X64Reg::DR7;
    case X86_REG_DR8    : return X64Reg::DR8;
    case X86_REG_DR9    : return X64Reg::DR9;
    case X86_REG_DR10   : return X64Reg::DR10;
    case X86_REG_DR11   : return X64Reg::DR11;
    case X86_REG_DR12   : return X64Reg::DR12;
    case X86_REG_DR13   : return X64Reg::DR13;
    case X86_REG_DR14   : return X64Reg::DR14;
    case X86_REG_DR15   : return X64Reg::DR15;
    case X86_REG_CS     : return X64Reg::CS;
    case X86_REG_SS     : return X64Reg::SS;
    case X86_REG_DS     : return X64Reg::DS;
    case X86_REG_ES     : return X64Reg::ES;
    case X86_REG_FS     : return X64Reg::FS;
    case X86_REG_GS     : return X64Reg::GS;
    case X86_REG_FPSW   : return X64Reg::FPSW;
    case X86_REG_AL     : return X64Reg::AL;
    case X86_REG_AH     : return X64Reg::AH;
    case X86_REG_AX     : return X64Reg::AX;
    case X86_REG_EAX    : return X64Reg::EAX;
    case X86_REG_BL     : return X64Reg::BL;
    case X86_REG_BH     : return X64Reg::BH;
    case X86_REG_BX     : return X64Reg::BX;
    case X86_REG_EBX    : return X64Reg::EBX;
    case X86_REG_CL     : return X64Reg::CL;
    case X86_REG_CH     : return X64Reg::CH;
    case X86_REG_CX     : return X64Reg::CX;
    case X86_REG_ECX    : return X64Reg::ECX;
    case X86_REG_DL     : return X64Reg::DL;
    case X86_REG_DH     : return X64Reg::DH;
    case X86_REG_DX     : return X64Reg::DX;
    case X86_REG_EDX    : return X64Reg::EDX;
    case X86_REG_SIL    : return X64Reg::SIL;
    case X86_REG_SI     : return X64Reg::SI;
    case X86_REG_ESI    : return X64Reg::ESI;
    case X86_REG_DIL    : return X64Reg::DIL;
    case X86_REG_DI     : return X64Reg::DI;
    case X86_REG_EDI    : return X64Reg::EDI;
    case X86_REG_BPL    : return X64Reg::BPL;
    case X86_REG_BP     : return X64Reg::BP;
    case X86_REG_EBP    : return X64Reg::EBP;
    case X86_REG_SPL    : return X64Reg::SPL;
    case X86_REG_SP     : return X64Reg::SP;
    case X86_REG_ESP    : return X64Reg::ESP;
    case X86_REG_R8B    : return X64Reg::R8B;
    case X86_REG_R8W    : return X64Reg::R8W;
    case X86_REG_R8D    : return X64Reg::R8D;
    case X86_REG_R9B    : return X64Reg::R9B;
    case X86_REG_R9W    : return X64Reg::R9W;
    case X86_REG_R9D    : return X64Reg::R9D;
    case X86_REG_R10B   : return X64Reg::R10B;
    case X86_REG_R10W   : return X64Reg::R10W;
    case X86_REG_R10D   : return X64Reg::R10D;
    case X86_REG_R11B   : return X64Reg::R11B;
    case X86_REG_R11W   : return X64Reg::R11W;
    case X86_REG_R11D   : return X64Reg::R11D;
    case X86_REG_R12B   : return X64Reg::R12B;
    case X86_REG_R12W   : return X64Reg::R12W;
    case X86_REG_R12D   : return X64Reg::R12D;
    case X86_REG_R13B   : return X64Reg::R13B;
    case X86_REG_R13W   : return X64Reg::R13W;
    case X86_REG_R13D   : return X64Reg::R13D;
    case X86_REG_R14B   : return X64Reg::R14B;
    case X86_REG_R14W   : return X64Reg::R14W;
    case X86_REG_R14D   : return X64Reg::R14D;
    case X86_REG_R15B   : return X64Reg::R15B;
    case X86_REG_R15W   : return X64Reg::R15W;
    case X86_REG_R15D   : return X64Reg::R15D;
    case X86_REG_EIP    : return X64Reg::EIP;
    case X86_REG_EFLAGS : return X64Reg::RFLAGS;
    case X86_REG_MM0    : return X64Reg::MM0;
    case X86_REG_MM1    : return X64Reg::MM1;
    case X86_REG_MM2    : return X64Reg::MM2;
    case X86_REG_MM3    : return X64Reg::MM3;
    case X86_REG_MM4    : return X64Reg::MM4;
    case X86_REG_MM5    : return X64Reg::MM5;
    case X86_REG_MM6    : return X64Reg::MM6;
    case X86_REG_MM7    : return X64Reg::MM7;
    case X86_REG_XMM0   : return X64Reg::XMM0;
    case X86_REG_XMM1   : return X64Reg::XMM1;
    case X86_REG_XMM2   : return X64Reg::XMM2;
    case X86_REG_XMM3   : return X64Reg::XMM3;
    case X86_REG_XMM4   : return X64Reg::XMM4;
    case X86_REG_XMM5   : return X64Reg::XMM5;
    case X86_REG_XMM6   : return X64Reg::XMM6;
    case X86_REG_XMM7   : return X64Reg::XMM7;
    case X86_REG_XMM8   : return X64Reg::XMM8;
    case X86_REG_XMM9   : return X64Reg::XMM9;
    case X86_REG_XMM10  : return X64Reg::XMM10;
    case X86_REG_XMM11  : return X64Reg::XMM11;
    case X86_REG_XMM12  : return X64Reg::XMM12;
    case X86_REG_XMM13  : return X64Reg::XMM13;
    case X86_REG_XMM14  : return X64Reg::XMM14;
    case X86_REG_XMM15  : return X64Reg::XMM15;
    case X86_REG_YMM0   : return X64Reg::YMM0;
    case X86_REG_YMM1   : return X64Reg::YMM1;
    case X86_REG_YMM2   : return X64Reg::YMM2;
    case X86_REG_YMM3   : return X64Reg::YMM3;
    case X86_REG_YMM4   : return X64Reg::YMM4;
    case X86_REG_YMM5   : return X64Reg::YMM5;
    case X86_REG_YMM6   : return X64Reg::YMM6;
    case X86_REG_YMM7   : return X64Reg::YMM7;
    case X86_REG_YMM8   : return X64Reg::YMM8;
    case X86_REG_YMM9   : return X64Reg::YMM9;
    case X86_REG_YMM10  : return X64Reg::YMM10;
    case X86_REG_YMM11  : return X64Reg::YMM11;
    case X86_REG_YMM12  : return X64Reg::YMM12;
    case X86_REG_YMM13  : return X64Reg::YMM13;
    case X86_REG_YMM14  : return X64Reg::YMM14;
    case X86_REG_YMM15  : return X64Reg::YMM15;
    default: return X64Reg::Invalid;
    }
}

uint8_t
get_reg_size(X64Reg reg)
{
    switch (reg) {
    case X64Reg::Invalid: return 0;
    case X64Reg::ST0:
    case X64Reg::ST1:
    case X64Reg::ST2:
    case X64Reg::ST3:
    case X64Reg::ST4:
    case X64Reg::ST5:
    case X64Reg::ST6:
    case X64Reg::ST7: return 10;
    case X64Reg::ZMM0:
    case X64Reg::ZMM1:
    case X64Reg::ZMM2:
    case X64Reg::ZMM3:
    case X64Reg::ZMM4:
    case X64Reg::ZMM5:
    case X64Reg::ZMM6:
    case X64Reg::ZMM7:
    case X64Reg::ZMM8:
    case X64Reg::ZMM9:
    case X64Reg::ZMM10:
    case X64Reg::ZMM11:
    case X64Reg::ZMM12:
    case X64Reg::ZMM13:
    case X64Reg::ZMM14:
    case X64Reg::ZMM15:
    case X64Reg::ZMM16:
    case X64Reg::ZMM17:
    case X64Reg::ZMM18:
    case X64Reg::ZMM19:
    case X64Reg::ZMM20:
    case X64Reg::ZMM21:
    case X64Reg::ZMM22:
    case X64Reg::ZMM23:
    case X64Reg::ZMM24:
    case X64Reg::ZMM25:
    case X64Reg::ZMM26:
    case X64Reg::ZMM27:
    case X64Reg::ZMM28:
    case X64Reg::ZMM29:
    case X64Reg::ZMM30:
    case X64Reg::ZMM31: return 64;
    case X64Reg::AL: return 1;
    case X64Reg::AH: return 1;
    case X64Reg::AX: return 2;
    case X64Reg::EAX: return 4;
    case X64Reg::BL: return 1;
    case X64Reg::BH: return 1;
    case X64Reg::BX: return 2;
    case X64Reg::EBX: return 4;
    case X64Reg::CL: return 1;
    case X64Reg::CH: return 1;
    case X64Reg::CX: return 2;
    case X64Reg::ECX: return 4;
    case X64Reg::DL: return 1;
    case X64Reg::DH: return 1;
    case X64Reg::DX: return 2;
    case X64Reg::EDX: return 4;
    case X64Reg::SIL: return 1;
    case X64Reg::SI: return 2;
    case X64Reg::ESI: return 4;
    case X64Reg::DIL: return 1;
    case X64Reg::DI: return 2;
    case X64Reg::EDI: return 4;
    case X64Reg::BPL: return 1;
    case X64Reg::BP: return 2;
    case X64Reg::EBP: return 4;
    case X64Reg::SPL: return 1;
    case X64Reg::SP: return 2;
    case X64Reg::ESP: return 4;
    case X64Reg::R8B: return 1;
    case X64Reg::R8W: return 2;
    case X64Reg::R8D: return 4;
    case X64Reg::R9B: return 1;
    case X64Reg::R9W: return 2;
    case X64Reg::R9D: return 4;
    case X64Reg::R10B: return 1;
    case X64Reg::R10W: return 2;
    case X64Reg::R10D: return 4;
    case X64Reg::R11B: return 1;
    case X64Reg::R11W: return 2;
    case X64Reg::R11D: return 4;
    case X64Reg::R12B: return 1;
    case X64Reg::R12W: return 2;
    case X64Reg::R12D: return 4;
    case X64Reg::R13B: return 1;
    case X64Reg::R13W: return 2;
    case X64Reg::R13D: return 4;
    case X64Reg::R14B: return 1;
    case X64Reg::R14W: return 2;
    case X64Reg::R14D: return 4;
    case X64Reg::R15B: return 1;
    case X64Reg::R15W: return 2;
    case X64Reg::R15D: return 4;
    case X64Reg::EIP: return 4;
    case X64Reg::EFLAGS:return 4;
    case X64Reg::XMM0:
    case X64Reg::XMM1:
    case X64Reg::XMM2:
    case X64Reg::XMM3:
    case X64Reg::XMM4:
    case X64Reg::XMM5:
    case X64Reg::XMM6:
    case X64Reg::XMM7:
    case X64Reg::XMM8:
    case X64Reg::XMM9:
    case X64Reg::XMM10:
    case X64Reg::XMM11:
    case X64Reg::XMM12:
    case X64Reg::XMM13:
    case X64Reg::XMM14:
    case X64Reg::XMM15: return 16;
    case X64Reg::YMM0:
    case X64Reg::YMM1:
    case X64Reg::YMM2:
    case X64Reg::YMM3:
    case X64Reg::YMM4:
    case X64Reg::YMM5:
    case X64Reg::YMM6:
    case X64Reg::YMM7:
    case X64Reg::YMM8:
    case X64Reg::YMM9:
    case X64Reg::YMM10:
    case X64Reg::YMM11:
    case X64Reg::YMM12:
    case X64Reg::YMM13:
    case X64Reg::YMM14:
    case X64Reg::YMM15: return 32;
    default: return 8;
    }
}

} // x64
} // bcov
