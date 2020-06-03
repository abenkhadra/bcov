/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include "Emulator.hpp"
#include "easylogging/easylogging++.h"

#define UC_GPR_REG_ARR_SIZE (18U)
#define UC_AVX_REG_ARR_SIZE (16U)

static int UCGPRRegisterIds[] =
    {
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12,
        UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15, UC_X86_REG_EFLAGS,
        UC_X86_REG_RIP
    };

// XXX: AVX-512 is still not supported by unicorn. x87 FPU is ignored
// XXX: modifying UC_X86_REG_FS or UC_X86_REG_GS leads to SIGEV in unicorn
static int UCAVX256RegisterIds[] =
    {
        UC_X86_REG_YMM0, UC_X86_REG_YMM1, UC_X86_REG_YMM2, UC_X86_REG_YMM3,
        UC_X86_REG_YMM4, UC_X86_REG_YMM5, UC_X86_REG_YMM6, UC_X86_REG_YMM7,
        UC_X86_REG_YMM8, UC_X86_REG_YMM9, UC_X86_REG_YMM10, UC_X86_REG_YMM11,
        UC_X86_REG_YMM12, UC_X86_REG_YMM13, UC_X86_REG_YMM14, UC_X86_REG_YMM15
    };

namespace bcov {
namespace x64 {

void
EmulatorUtils::write_context(uc_engine *emulator,
                             const RegisterContext<RegisterContextType::kGPR> &reg_ctx)
{
    auto error = uc_reg_write_batch(emulator, UCGPRRegisterIds,
                                    (void *const *) reg_ctx.get_reg_ptrs(),
                                    UC_GPR_REG_ARR_SIZE);
    DCHECK(error == UC_ERR_OK);
}

void
EmulatorUtils::read_context(uc_engine *emulator,
                            RegisterContext<RegisterContextType::kGPR> &reg_ctx)
{
    auto error = uc_reg_read_batch(emulator, UCGPRRegisterIds,
                                   (void **) reg_ctx.get_reg_ptrs(),
                                   UC_GPR_REG_ARR_SIZE);
    DCHECK(error == UC_ERR_OK);
}

void
EmulatorUtils::write_gpr_context(uc_engine *emulator,
                                 const RegisterContext<> &reg_ctx)
{
    auto error = uc_reg_write_batch(emulator, UCGPRRegisterIds,
                                    (void *const *) reg_ctx.get_reg_ptrs(),
                                    UC_GPR_REG_ARR_SIZE);
    DCHECK(error == UC_ERR_OK);
}

void
EmulatorUtils::read_gpr_context(uc_engine *emulator, RegisterContext<> &reg_ctx)
{
    auto error = uc_reg_read_batch(emulator, UCGPRRegisterIds,
                                   (void **) reg_ctx.get_reg_ptrs(),
                                   UC_GPR_REG_ARR_SIZE);
    DCHECK(error == UC_ERR_OK);
}

void
EmulatorUtils::write_avx_context(uc_engine *emulator,
                                 const RegisterContext<> &reg_ctx)
{
    auto idx = get_canonical_index(X64Reg::ZMM0) - 1;
    auto reg_ptrs = reg_ctx.get_reg_ptrs();
    auto error = uc_reg_write_batch(emulator, UCAVX256RegisterIds,
                                    (void *const *) &reg_ptrs[idx],
                                    UC_AVX_REG_ARR_SIZE);
    DCHECK(error == UC_ERR_OK);
}

void
EmulatorUtils::read_avx_context(uc_engine *emulator, RegisterContext<> &reg_ctx)
{
    auto idx = get_canonical_index(X64Reg::ZMM0) - 1;
    auto reg_ptrs = reg_ctx.get_reg_ptrs();
    auto error = uc_reg_read_batch(emulator, UCAVX256RegisterIds,
                                   (void **) &reg_ptrs[idx], UC_AVX_REG_ARR_SIZE);
    DCHECK(error == UC_ERR_OK);
}

void
EmulatorUtils::write_context(uc_engine *emulator, const RegisterContext<> &reg_ctx)
{
    write_gpr_context(emulator, reg_ctx);
    write_avx_context(emulator, reg_ctx);
}

void
EmulatorUtils::read_context(uc_engine *emulator, RegisterContext<> &reg_ctx)
{
    read_gpr_context(emulator, reg_ctx);
    read_avx_context(emulator, reg_ctx);
}

sstring
EmulatorUtils::dump_gpr_context(uc_engine *emulator)
{
    RegisterContext<RegisterContextType::kGPR> reg_ctx;
    read_context(emulator, reg_ctx);
    std::stringstream sstream;
    for (X64_REG_BASE_TYPE i = 1; i < get_canonical_index(X64Reg::RIP); ++i) {
        auto reg = get_canonical_reg_at(i);
        sstream << std::hex << to_string(reg) << "=" << reg_ctx.read_reg64(reg)
                << " ";
    }
    return sstream.str();
}

X64Reg
get_x64_reg(uc_x86_reg uc_reg)
{
    switch (uc_reg) {
    case UC_X86_REG_RAX     : return X64Reg::RAX;
    case UC_X86_REG_RBX     : return X64Reg::RBX;
    case UC_X86_REG_RCX     : return X64Reg::RCX;
    case UC_X86_REG_RDX     : return X64Reg::RDX;
    case UC_X86_REG_RSI     : return X64Reg::RSI;
    case UC_X86_REG_RDI     : return X64Reg::RDI;
    case UC_X86_REG_RBP     : return X64Reg::RBP;
    case UC_X86_REG_RSP     : return X64Reg::RSP;
    case UC_X86_REG_R8      : return X64Reg::R8;
    case UC_X86_REG_R9      : return X64Reg::R9;
    case UC_X86_REG_R10     : return X64Reg::R10;
    case UC_X86_REG_R11     : return X64Reg::R11;
    case UC_X86_REG_R12     : return X64Reg::R12;
    case UC_X86_REG_R13     : return X64Reg::R13;
    case UC_X86_REG_R14     : return X64Reg::R14;
    case UC_X86_REG_R15     : return X64Reg::R15;
    case UC_X86_REG_EFLAGS  : return X64Reg::RFLAGS;
    case UC_X86_REG_EIP     : return X64Reg::EIP;
    case UC_X86_REG_RIP     : return X64Reg::RIP;
    case UC_X86_REG_ZMM0    : return X64Reg::ZMM0;
    case UC_X86_REG_ZMM1    : return X64Reg::ZMM1;
    case UC_X86_REG_ZMM2    : return X64Reg::ZMM2;
    case UC_X86_REG_ZMM3    : return X64Reg::ZMM3;
    case UC_X86_REG_ZMM4    : return X64Reg::ZMM4;
    case UC_X86_REG_ZMM5    : return X64Reg::ZMM5;
    case UC_X86_REG_ZMM6    : return X64Reg::ZMM6;
    case UC_X86_REG_ZMM7    : return X64Reg::ZMM7;
    case UC_X86_REG_ZMM8    : return X64Reg::ZMM8;
    case UC_X86_REG_ZMM9    : return X64Reg::ZMM9;
    case UC_X86_REG_ZMM10   : return X64Reg::ZMM10;
    case UC_X86_REG_ZMM11   : return X64Reg::ZMM11;
    case UC_X86_REG_ZMM12   : return X64Reg::ZMM12;
    case UC_X86_REG_ZMM13   : return X64Reg::ZMM13;
    case UC_X86_REG_ZMM14   : return X64Reg::ZMM14;
    case UC_X86_REG_ZMM15   : return X64Reg::ZMM15;
    case UC_X86_REG_ZMM16   : return X64Reg::ZMM16;
    case UC_X86_REG_ZMM17   : return X64Reg::ZMM17;
    case UC_X86_REG_ZMM18   : return X64Reg::ZMM18;
    case UC_X86_REG_ZMM19   : return X64Reg::ZMM19;
    case UC_X86_REG_ZMM20   : return X64Reg::ZMM20;
    case UC_X86_REG_ZMM21   : return X64Reg::ZMM21;
    case UC_X86_REG_ZMM22   : return X64Reg::ZMM22;
    case UC_X86_REG_ZMM23   : return X64Reg::ZMM23;
    case UC_X86_REG_ZMM24   : return X64Reg::ZMM24;
    case UC_X86_REG_ZMM25   : return X64Reg::ZMM25;
    case UC_X86_REG_ZMM26   : return X64Reg::ZMM26;
    case UC_X86_REG_ZMM27   : return X64Reg::ZMM27;
    case UC_X86_REG_ZMM28   : return X64Reg::ZMM28;
    case UC_X86_REG_ZMM29   : return X64Reg::ZMM29;
    case UC_X86_REG_ZMM30   : return X64Reg::ZMM30;
    case UC_X86_REG_ZMM31   : return X64Reg::ZMM31;
    case UC_X86_REG_ST0     : return X64Reg::ST0;
    case UC_X86_REG_ST1     : return X64Reg::ST1;
    case UC_X86_REG_ST2     : return X64Reg::ST2;
    case UC_X86_REG_ST3     : return X64Reg::ST3;
    case UC_X86_REG_ST4     : return X64Reg::ST4;
    case UC_X86_REG_ST5     : return X64Reg::ST5;
    case UC_X86_REG_ST6     : return X64Reg::ST6;
    case UC_X86_REG_ST7     : return X64Reg::ST7;
    case UC_X86_REG_FPSW    : return X64Reg::FPSW;
    case UC_X86_REG_GS      : return X64Reg::GS;
    case UC_X86_REG_FS      : return X64Reg::FS;
    case UC_X86_REG_CS      : return X64Reg::CS;
    case UC_X86_REG_SS      : return X64Reg::SS;
    case UC_X86_REG_DS      : return X64Reg::DS;
    case UC_X86_REG_K0      : return X64Reg::K0;
    case UC_X86_REG_K1      : return X64Reg::K1;
    case UC_X86_REG_K2      : return X64Reg::K2;
    case UC_X86_REG_K3      : return X64Reg::K3;
    case UC_X86_REG_K4      : return X64Reg::K4;
    case UC_X86_REG_K5      : return X64Reg::K5;
    case UC_X86_REG_K6      : return X64Reg::K6;
    case UC_X86_REG_K7      : return X64Reg::K7;
    case UC_X86_REG_CR0     : return X64Reg::CR0;
    case UC_X86_REG_CR1     : return X64Reg::CR1;
    case UC_X86_REG_CR2     : return X64Reg::CR2;
    case UC_X86_REG_CR3     : return X64Reg::CR3;
    case UC_X86_REG_CR4     : return X64Reg::CR4;
    case UC_X86_REG_CR5     : return X64Reg::CR5;
    case UC_X86_REG_CR6     : return X64Reg::CR6;
    case UC_X86_REG_CR7     : return X64Reg::CR7;
    case UC_X86_REG_CR8     : return X64Reg::CR8;
    case UC_X86_REG_CR9     : return X64Reg::CR9;
    case UC_X86_REG_CR10    : return X64Reg::CR10;
    case UC_X86_REG_CR11    : return X64Reg::CR11;
    case UC_X86_REG_CR12    : return X64Reg::CR12;
    case UC_X86_REG_CR13    : return X64Reg::CR13;
    case UC_X86_REG_CR14    : return X64Reg::CR14;
    case UC_X86_REG_CR15    : return X64Reg::CR15;
    case UC_X86_REG_DR0     : return X64Reg::DR0;
    case UC_X86_REG_DR1     : return X64Reg::DR1;
    case UC_X86_REG_DR2     : return X64Reg::DR2;
    case UC_X86_REG_DR3     : return X64Reg::DR3;
    case UC_X86_REG_DR4     : return X64Reg::DR4;
    case UC_X86_REG_DR5     : return X64Reg::DR5;
    case UC_X86_REG_DR6     : return X64Reg::DR6;
    case UC_X86_REG_DR7     : return X64Reg::DR7;
    case UC_X86_REG_DR8     : return X64Reg::DR8;
    case UC_X86_REG_DR9     : return X64Reg::DR9;
    case UC_X86_REG_DR10    : return X64Reg::DR10;
    case UC_X86_REG_DR11    : return X64Reg::DR11;
    case UC_X86_REG_DR12    : return X64Reg::DR12;
    case UC_X86_REG_DR13    : return X64Reg::DR13;
    case UC_X86_REG_DR14    : return X64Reg::DR14;
    case UC_X86_REG_DR15    : return X64Reg::DR15;
    case UC_X86_REG_ES      : return X64Reg::ES;
    case UC_X86_REG_AL      : return X64Reg::AL;
    case UC_X86_REG_AH      : return X64Reg::AH;
    case UC_X86_REG_AX      : return X64Reg::AX;
    case UC_X86_REG_EAX     : return X64Reg::EAX;
    case UC_X86_REG_BL      : return X64Reg::BL;
    case UC_X86_REG_BH      : return X64Reg::BH;
    case UC_X86_REG_BX      : return X64Reg::BX;
    case UC_X86_REG_EBX     : return X64Reg::EBX;
    case UC_X86_REG_CL      : return X64Reg::CL;
    case UC_X86_REG_CH      : return X64Reg::CH;
    case UC_X86_REG_CX      : return X64Reg::CX;
    case UC_X86_REG_ECX     : return X64Reg::ECX;
    case UC_X86_REG_DL      : return X64Reg::DL;
    case UC_X86_REG_DH      : return X64Reg::DH;
    case UC_X86_REG_DX      : return X64Reg::DX;
    case UC_X86_REG_EDX     : return X64Reg::EDX;
    case UC_X86_REG_SIL     : return X64Reg::SIL;
    case UC_X86_REG_SI      : return X64Reg::SI;
    case UC_X86_REG_ESI     : return X64Reg::ESI;
    case UC_X86_REG_DIL     : return X64Reg::DIL;
    case UC_X86_REG_DI      : return X64Reg::DI;
    case UC_X86_REG_EDI     : return X64Reg::EDI;
    case UC_X86_REG_BPL     : return X64Reg::BPL;
    case UC_X86_REG_BP      : return X64Reg::BP;
    case UC_X86_REG_EBP     : return X64Reg::EBP;
    case UC_X86_REG_SPL     : return X64Reg::SPL;
    case UC_X86_REG_SP      : return X64Reg::SP;
    case UC_X86_REG_ESP     : return X64Reg::ESP;
    case UC_X86_REG_R8B     : return X64Reg::R8B;
    case UC_X86_REG_R8W     : return X64Reg::R8W;
    case UC_X86_REG_R8D     : return X64Reg::R8D;
    case UC_X86_REG_R9B     : return X64Reg::R9B;
    case UC_X86_REG_R9W     : return X64Reg::R9W;
    case UC_X86_REG_R9D     : return X64Reg::R9D;
    case UC_X86_REG_R10B    : return X64Reg::R10B;
    case UC_X86_REG_R10W    : return X64Reg::R10W;
    case UC_X86_REG_R10D    : return X64Reg::R10D;
    case UC_X86_REG_R11B    : return X64Reg::R11B;
    case UC_X86_REG_R11W    : return X64Reg::R11W;
    case UC_X86_REG_R11D    : return X64Reg::R11D;
    case UC_X86_REG_R12B    : return X64Reg::R12B;
    case UC_X86_REG_R12W    : return X64Reg::R12W;
    case UC_X86_REG_R12D    : return X64Reg::R12D;
    case UC_X86_REG_R13B    : return X64Reg::R13B;
    case UC_X86_REG_R13W    : return X64Reg::R13W;
    case UC_X86_REG_R13D    : return X64Reg::R13D;
    case UC_X86_REG_R14B    : return X64Reg::R14B;
    case UC_X86_REG_R14W    : return X64Reg::R14W;
    case UC_X86_REG_R14D    : return X64Reg::R14D;
    case UC_X86_REG_R15B    : return X64Reg::R15B;
    case UC_X86_REG_R15W    : return X64Reg::R15W;
    case UC_X86_REG_R15D    : return X64Reg::R15D;
    case UC_X86_REG_MM0     : return X64Reg::MM0;
    case UC_X86_REG_MM1     : return X64Reg::MM1;
    case UC_X86_REG_MM2     : return X64Reg::MM2;
    case UC_X86_REG_MM3     : return X64Reg::MM3;
    case UC_X86_REG_MM4     : return X64Reg::MM4;
    case UC_X86_REG_MM5     : return X64Reg::MM5;
    case UC_X86_REG_MM6     : return X64Reg::MM6;
    case UC_X86_REG_MM7     : return X64Reg::MM7;
    case UC_X86_REG_XMM0    : return X64Reg::XMM0;
    case UC_X86_REG_XMM1    : return X64Reg::XMM1;
    case UC_X86_REG_XMM2    : return X64Reg::XMM2;
    case UC_X86_REG_XMM3    : return X64Reg::XMM3;
    case UC_X86_REG_XMM4    : return X64Reg::XMM4;
    case UC_X86_REG_XMM5    : return X64Reg::XMM5;
    case UC_X86_REG_XMM6    : return X64Reg::XMM6;
    case UC_X86_REG_XMM7    : return X64Reg::XMM7;
    case UC_X86_REG_XMM8    : return X64Reg::XMM8;
    case UC_X86_REG_XMM9    : return X64Reg::XMM9;
    case UC_X86_REG_XMM10   : return X64Reg::XMM10;
    case UC_X86_REG_XMM11   : return X64Reg::XMM11;
    case UC_X86_REG_XMM12   : return X64Reg::XMM12;
    case UC_X86_REG_XMM13   : return X64Reg::XMM13;
    case UC_X86_REG_XMM14   : return X64Reg::XMM14;
    case UC_X86_REG_XMM15   : return X64Reg::XMM15;
    case UC_X86_REG_YMM0    : return X64Reg::YMM0;
    case UC_X86_REG_YMM1    : return X64Reg::YMM1;
    case UC_X86_REG_YMM2    : return X64Reg::YMM2;
    case UC_X86_REG_YMM3    : return X64Reg::YMM3;
    case UC_X86_REG_YMM4    : return X64Reg::YMM4;
    case UC_X86_REG_YMM5    : return X64Reg::YMM5;
    case UC_X86_REG_YMM6    : return X64Reg::YMM6;
    case UC_X86_REG_YMM7    : return X64Reg::YMM7;
    case UC_X86_REG_YMM8    : return X64Reg::YMM8;
    case UC_X86_REG_YMM9    : return X64Reg::YMM9;
    case UC_X86_REG_YMM10   : return X64Reg::YMM10;
    case UC_X86_REG_YMM11   : return X64Reg::YMM11;
    case UC_X86_REG_YMM12   : return X64Reg::YMM12;
    case UC_X86_REG_YMM13   : return X64Reg::YMM13;
    case UC_X86_REG_YMM14   : return X64Reg::YMM14;
    case UC_X86_REG_YMM15   : return X64Reg::YMM15;
    default: return X64Reg::Invalid;
    }
}

uc_x86_reg
get_uc_reg(X64Reg reg)
{
    switch (reg) {
    case X64Reg::RAX    : return UC_X86_REG_RAX;
    case X64Reg::RBX    : return UC_X86_REG_RBX;
    case X64Reg::RCX    : return UC_X86_REG_RCX;
    case X64Reg::RDX    : return UC_X86_REG_RDX;
    case X64Reg::RSI    : return UC_X86_REG_RSI;
    case X64Reg::RDI    : return UC_X86_REG_RDI;
    case X64Reg::RBP    : return UC_X86_REG_RBP;
    case X64Reg::RSP    : return UC_X86_REG_RSP;
    case X64Reg::R8     : return UC_X86_REG_R8;
    case X64Reg::R9     : return UC_X86_REG_R9;
    case X64Reg::R10    : return UC_X86_REG_R10;
    case X64Reg::R11    : return UC_X86_REG_R11;
    case X64Reg::R12    : return UC_X86_REG_R12;
    case X64Reg::R13    : return UC_X86_REG_R13;
    case X64Reg::R14    : return UC_X86_REG_R14;
    case X64Reg::R15    : return UC_X86_REG_R15;
    case X64Reg::RFLAGS : return UC_X86_REG_EFLAGS;
    case X64Reg::EIP    : return UC_X86_REG_EIP;
    case X64Reg::RIP    : return UC_X86_REG_RIP;
    case X64Reg::ZMM0   : return UC_X86_REG_ZMM0;
    case X64Reg::ZMM1   : return UC_X86_REG_ZMM1;
    case X64Reg::ZMM2   : return UC_X86_REG_ZMM2;
    case X64Reg::ZMM3   : return UC_X86_REG_ZMM3;
    case X64Reg::ZMM4   : return UC_X86_REG_ZMM4;
    case X64Reg::ZMM5   : return UC_X86_REG_ZMM5;
    case X64Reg::ZMM6   : return UC_X86_REG_ZMM6;
    case X64Reg::ZMM7   : return UC_X86_REG_ZMM7;
    case X64Reg::ZMM8   : return UC_X86_REG_ZMM8;
    case X64Reg::ZMM9   : return UC_X86_REG_ZMM9;
    case X64Reg::ZMM10  : return UC_X86_REG_ZMM10;
    case X64Reg::ZMM11  : return UC_X86_REG_ZMM11;
    case X64Reg::ZMM12  : return UC_X86_REG_ZMM12;
    case X64Reg::ZMM13  : return UC_X86_REG_ZMM13;
    case X64Reg::ZMM14  : return UC_X86_REG_ZMM14;
    case X64Reg::ZMM15  : return UC_X86_REG_ZMM15;
    case X64Reg::ZMM16  : return UC_X86_REG_ZMM16;
    case X64Reg::ZMM17  : return UC_X86_REG_ZMM17;
    case X64Reg::ZMM18  : return UC_X86_REG_ZMM18;
    case X64Reg::ZMM19  : return UC_X86_REG_ZMM19;
    case X64Reg::ZMM20  : return UC_X86_REG_ZMM20;
    case X64Reg::ZMM21  : return UC_X86_REG_ZMM21;
    case X64Reg::ZMM22  : return UC_X86_REG_ZMM22;
    case X64Reg::ZMM23  : return UC_X86_REG_ZMM23;
    case X64Reg::ZMM24  : return UC_X86_REG_ZMM24;
    case X64Reg::ZMM25  : return UC_X86_REG_ZMM25;
    case X64Reg::ZMM26  : return UC_X86_REG_ZMM26;
    case X64Reg::ZMM27  : return UC_X86_REG_ZMM27;
    case X64Reg::ZMM28  : return UC_X86_REG_ZMM28;
    case X64Reg::ZMM29  : return UC_X86_REG_ZMM29;
    case X64Reg::ZMM30  : return UC_X86_REG_ZMM30;
    case X64Reg::ZMM31  : return UC_X86_REG_ZMM31;
    case X64Reg::ST0    : return UC_X86_REG_ST0;
    case X64Reg::ST1    : return UC_X86_REG_ST1;
    case X64Reg::ST2    : return UC_X86_REG_ST2;
    case X64Reg::ST3    : return UC_X86_REG_ST3;
    case X64Reg::ST4    : return UC_X86_REG_ST4;
    case X64Reg::ST5    : return UC_X86_REG_ST5;
    case X64Reg::ST6    : return UC_X86_REG_ST6;
    case X64Reg::ST7    : return UC_X86_REG_ST7;
    case X64Reg::FPSW   : return UC_X86_REG_FPSW;
    case X64Reg::GS     : return UC_X86_REG_GS;
    case X64Reg::FS     : return UC_X86_REG_FS;
    case X64Reg::CS     : return UC_X86_REG_CS;
    case X64Reg::SS     : return UC_X86_REG_SS;
    case X64Reg::DS     : return UC_X86_REG_DS;
    case X64Reg::K0     : return UC_X86_REG_K0;
    case X64Reg::K1     : return UC_X86_REG_K1;
    case X64Reg::K2     : return UC_X86_REG_K2;
    case X64Reg::K3     : return UC_X86_REG_K3;
    case X64Reg::K4     : return UC_X86_REG_K4;
    case X64Reg::K5     : return UC_X86_REG_K5;
    case X64Reg::K6     : return UC_X86_REG_K6;
    case X64Reg::K7     : return UC_X86_REG_K7;
    case X64Reg::CR0    : return UC_X86_REG_CR0;
    case X64Reg::CR1    : return UC_X86_REG_CR1;
    case X64Reg::CR2    : return UC_X86_REG_CR2;
    case X64Reg::CR3    : return UC_X86_REG_CR3;
    case X64Reg::CR4    : return UC_X86_REG_CR4;
    case X64Reg::CR5    : return UC_X86_REG_CR5;
    case X64Reg::CR6    : return UC_X86_REG_CR6;
    case X64Reg::CR7    : return UC_X86_REG_CR7;
    case X64Reg::CR8    : return UC_X86_REG_CR8;
    case X64Reg::CR9    : return UC_X86_REG_CR9;
    case X64Reg::CR10   : return UC_X86_REG_CR10;
    case X64Reg::CR11   : return UC_X86_REG_CR11;
    case X64Reg::CR12   : return UC_X86_REG_CR12;
    case X64Reg::CR13   : return UC_X86_REG_CR13;
    case X64Reg::CR14   : return UC_X86_REG_CR14;
    case X64Reg::CR15   : return UC_X86_REG_CR15;
    case X64Reg::DR0    : return UC_X86_REG_DR0;
    case X64Reg::DR1    : return UC_X86_REG_DR1;
    case X64Reg::DR2    : return UC_X86_REG_DR2;
    case X64Reg::DR3    : return UC_X86_REG_DR3;
    case X64Reg::DR4    : return UC_X86_REG_DR4;
    case X64Reg::DR5    : return UC_X86_REG_DR5;
    case X64Reg::DR6    : return UC_X86_REG_DR6;
    case X64Reg::DR7    : return UC_X86_REG_DR7;
    case X64Reg::DR8    : return UC_X86_REG_DR8;
    case X64Reg::DR9    : return UC_X86_REG_DR9;
    case X64Reg::DR10   : return UC_X86_REG_DR10;
    case X64Reg::DR11   : return UC_X86_REG_DR11;
    case X64Reg::DR12   : return UC_X86_REG_DR12;
    case X64Reg::DR13   : return UC_X86_REG_DR13;
    case X64Reg::DR14   : return UC_X86_REG_DR14;
    case X64Reg::DR15   : return UC_X86_REG_DR15;
    case X64Reg::ES     : return UC_X86_REG_ES;
    case X64Reg::AL     : return UC_X86_REG_AL;
    case X64Reg::AH     : return UC_X86_REG_AH;
    case X64Reg::AX     : return UC_X86_REG_AX;
    case X64Reg::EAX    : return UC_X86_REG_EAX;
    case X64Reg::BL     : return UC_X86_REG_BL;
    case X64Reg::BH     : return UC_X86_REG_BH;
    case X64Reg::BX     : return UC_X86_REG_BX;
    case X64Reg::EBX    : return UC_X86_REG_EBX;
    case X64Reg::CL     : return UC_X86_REG_CL;
    case X64Reg::CH     : return UC_X86_REG_CH;
    case X64Reg::CX     : return UC_X86_REG_CX;
    case X64Reg::ECX    : return UC_X86_REG_ECX;
    case X64Reg::DL     : return UC_X86_REG_DL;
    case X64Reg::DH     : return UC_X86_REG_DH;
    case X64Reg::DX     : return UC_X86_REG_DX;
    case X64Reg::EDX    : return UC_X86_REG_EDX;
    case X64Reg::SIL    : return UC_X86_REG_SIL;
    case X64Reg::SI     : return UC_X86_REG_SI;
    case X64Reg::ESI    : return UC_X86_REG_ESI;
    case X64Reg::DIL    : return UC_X86_REG_DIL;
    case X64Reg::DI     : return UC_X86_REG_DI;
    case X64Reg::EDI    : return UC_X86_REG_EDI;
    case X64Reg::BPL    : return UC_X86_REG_BPL;
    case X64Reg::BP     : return UC_X86_REG_BP;
    case X64Reg::EBP    : return UC_X86_REG_EBP;
    case X64Reg::SPL    : return UC_X86_REG_SPL;
    case X64Reg::SP     : return UC_X86_REG_SP;
    case X64Reg::ESP    : return UC_X86_REG_ESP;
    case X64Reg::R8B    : return UC_X86_REG_R8B;
    case X64Reg::R8W    : return UC_X86_REG_R8W;
    case X64Reg::R8D    : return UC_X86_REG_R8D;
    case X64Reg::R9B    : return UC_X86_REG_R9B;
    case X64Reg::R9W    : return UC_X86_REG_R9W;
    case X64Reg::R9D    : return UC_X86_REG_R9D;
    case X64Reg::R10B   : return UC_X86_REG_R10B;
    case X64Reg::R10W   : return UC_X86_REG_R10W;
    case X64Reg::R10D   : return UC_X86_REG_R10D;
    case X64Reg::R11B   : return UC_X86_REG_R11B;
    case X64Reg::R11W   : return UC_X86_REG_R11W;
    case X64Reg::R11D   : return UC_X86_REG_R11D;
    case X64Reg::R12B   : return UC_X86_REG_R12B;
    case X64Reg::R12W   : return UC_X86_REG_R12W;
    case X64Reg::R12D   : return UC_X86_REG_R12D;
    case X64Reg::R13B   : return UC_X86_REG_R13B;
    case X64Reg::R13W   : return UC_X86_REG_R13W;
    case X64Reg::R13D   : return UC_X86_REG_R13D;
    case X64Reg::R14B   : return UC_X86_REG_R14B;
    case X64Reg::R14W   : return UC_X86_REG_R14W;
    case X64Reg::R14D   : return UC_X86_REG_R14D;
    case X64Reg::R15B   : return UC_X86_REG_R15B;
    case X64Reg::R15W   : return UC_X86_REG_R15W;
    case X64Reg::R15D   : return UC_X86_REG_R15D;
    case X64Reg::MM0    : return UC_X86_REG_MM0;
    case X64Reg::MM1    : return UC_X86_REG_MM1;
    case X64Reg::MM2    : return UC_X86_REG_MM2;
    case X64Reg::MM3    : return UC_X86_REG_MM3;
    case X64Reg::MM4    : return UC_X86_REG_MM4;
    case X64Reg::MM5    : return UC_X86_REG_MM5;
    case X64Reg::MM6    : return UC_X86_REG_MM6;
    case X64Reg::MM7    : return UC_X86_REG_MM7;
    case X64Reg::XMM0   : return UC_X86_REG_XMM0;
    case X64Reg::XMM1   : return UC_X86_REG_XMM1;
    case X64Reg::XMM2   : return UC_X86_REG_XMM2;
    case X64Reg::XMM3   : return UC_X86_REG_XMM3;
    case X64Reg::XMM4   : return UC_X86_REG_XMM4;
    case X64Reg::XMM5   : return UC_X86_REG_XMM5;
    case X64Reg::XMM6   : return UC_X86_REG_XMM6;
    case X64Reg::XMM7   : return UC_X86_REG_XMM7;
    case X64Reg::XMM8   : return UC_X86_REG_XMM8;
    case X64Reg::XMM9   : return UC_X86_REG_XMM9;
    case X64Reg::XMM10  : return UC_X86_REG_XMM10;
    case X64Reg::XMM11  : return UC_X86_REG_XMM11;
    case X64Reg::XMM12  : return UC_X86_REG_XMM12;
    case X64Reg::XMM13  : return UC_X86_REG_XMM13;
    case X64Reg::XMM14  : return UC_X86_REG_XMM14;
    case X64Reg::XMM15  : return UC_X86_REG_XMM15;
    case X64Reg::YMM0   : return UC_X86_REG_YMM0;
    case X64Reg::YMM1   : return UC_X86_REG_YMM1;
    case X64Reg::YMM2   : return UC_X86_REG_YMM2;
    case X64Reg::YMM3   : return UC_X86_REG_YMM3;
    case X64Reg::YMM4   : return UC_X86_REG_YMM4;
    case X64Reg::YMM5   : return UC_X86_REG_YMM5;
    case X64Reg::YMM6   : return UC_X86_REG_YMM6;
    case X64Reg::YMM7   : return UC_X86_REG_YMM7;
    case X64Reg::YMM8   : return UC_X86_REG_YMM8;
    case X64Reg::YMM9   : return UC_X86_REG_YMM9;
    case X64Reg::YMM10  : return UC_X86_REG_YMM10;
    case X64Reg::YMM11  : return UC_X86_REG_YMM11;
    case X64Reg::YMM12  : return UC_X86_REG_YMM12;
    case X64Reg::YMM13  : return UC_X86_REG_YMM13;
    case X64Reg::YMM14  : return UC_X86_REG_YMM14;
    case X64Reg::YMM15  : return UC_X86_REG_YMM15;
    default: return UC_X86_REG_INVALID;
    }
}

} // x64

namespace flax {

EmulatorEngine::EmulatorEngine() : m_emulator(nullptr)
{ }

EmulatorEngine::EmulatorEngine(EmulatorEngine &&other) noexcept
{
    m_emulator = other.m_emulator;
    other.m_emulator = nullptr;
}

EmulatorEngine &EmulatorEngine::operator=(EmulatorEngine &&other) noexcept
{
    m_emulator = other.m_emulator;
    other.m_emulator = nullptr;
    return *this;
}

void
EmulatorEngine::init(uc_arch arch, uc_mode mode)
{
    auto err = uc_open(arch, mode, &m_emulator);
    LOG_IF(err != UC_ERR_OK, ERROR) << uc_strerror(err);
}

void
EmulatorEngine::make_context(EmulatorContext &context)
{
    auto err = uc_context_alloc(m_emulator, &context.m_context);
    LOG_IF(err != UC_ERR_OK, ERROR) << uc_strerror(err);
}

EmulatorEngine::~EmulatorEngine()
{
    if (m_emulator != nullptr) {
        uc_close(m_emulator);
        m_emulator = nullptr;
    }
}

bool
EmulatorEngine::valid() const noexcept
{
    return m_emulator != nullptr;
}

uc_engine *
EmulatorEngine::get() const noexcept
{
    return m_emulator;
}

void
EmulatorEngine::save_context(EmulatorContext &context)
{
    auto err = uc_context_save(m_emulator, context.get());
    LOG_IF(err != UC_ERR_OK, ERROR) << uc_strerror(err);
}

void
EmulatorEngine::restore_context(const EmulatorContext &context)
{
    auto err = uc_context_restore(m_emulator, context.get());
    LOG_IF(err != UC_ERR_OK, ERROR) << uc_strerror(err);
}

//==============================================================================

EmulatorContext::EmulatorContext(EmulatorContext &&other) noexcept
{
    m_context = other.m_context;
    other.m_context = nullptr;
}

EmulatorContext &EmulatorContext::operator=(EmulatorContext &&other) noexcept
{
    m_context = other.m_context;
    other.m_context = nullptr;
    return *this;
}

EmulatorContext::~EmulatorContext()
{
    if (m_context != nullptr) {
        uc_free(m_context);
        m_context = nullptr;
    }
}

bool
EmulatorContext::valid() const
{
    return m_context != nullptr;
}

uc_context *
EmulatorContext::get() const
{
    return m_context;
}

//==============================================================================

void
dummy_code_callback(uc_engine *uc, uint64_t address, uint32_t size,
                    void *user_data)
{
    UNUSED(uc);
    UNUSED(user_data);
    VLOG(4) << "executing instruction @ " << std::hex << address
            << " , size: " << size;
}

void
dummy_mem_callback(uc_engine *uc, uc_mem_type type, uint64_t address, int size,
                   int64_t value, void *user_data)
{
    UNUSED(uc);
    UNUSED(user_data);
    VLOG(5) << "memory access @ " << std::hex << address << " , size: " << size
            << " , mem: " << to_string(type) << " , value: " << value;
}

czstring
to_string(uc_mem_type mem_type)
{
    switch (mem_type) {
    case UC_MEM_READ : return "read";
    case UC_MEM_WRITE: return "write";
    case UC_MEM_FETCH: return "fetch";
    case UC_MEM_READ_UNMAPPED: return "read-unmapped";
    case UC_MEM_WRITE_UNMAPPED: return "write-unmapped";
    case UC_MEM_FETCH_UNMAPPED: return "fetch-unmapped";
    case UC_MEM_WRITE_PROT: return "write-protected";
    case UC_MEM_READ_PROT: return "read-protected";
    case UC_MEM_FETCH_PROT: return "fetch-protected";
    case UC_MEM_READ_AFTER: return "read-after";
    default: return "unknown";
    }
}

} // flax
} // bcov
