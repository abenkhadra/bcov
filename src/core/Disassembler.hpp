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

#include "Common.hpp"

namespace bcov {

// Capstone's handle used with all API
typedef size_t csh;

// following enums are consistent with their corresponding ones in capstone
enum class DisasmArch {
    kARM = 0,   // ARM architecture (including Thumb, Thumb-2)
    kARM64,     // ARM-64, also called AArch64
    KMIPS,      // Mips architecture
    kX86,       // X86 architecture (including x86 & x86-64)
    kPPC,       // PowerPC architecture
    kSPARC,     // Sparc architecture
    kSYSZ,      // SystemZ architecture
    kXCORE,     // XCore architecture
};

enum class DisasmMode {
    kLITTLE_ENDIAN = 0,    // little-endian mode (default mode)
    kARM = 0,    // 32-bit ARM
    k16 = 1U << 1U,    // 16-bit mode (X86)
    k32 = 1U << 2U,    // 32-bit mode (X86)
    k64 = 1U << 3U,    // 64-bit mode (X86, PPC)
    kTHUMB = 1U << 4U,    // ARM's Thumb mode, including Thumb-2
    kMCLASS = 1U << 5U,    // ARM's Cortex-M series
    kV8 = 1U << 6U,    // ARMv8 A32 encodings for ARM
    kMICRO = 1U << 4U, // MicroMips mode (MIPS)
    kMIPS3 = 1U << 5U, // Mips III ISA
    kMIPS32R6 = 1U << 6U, // Mips32r6 ISA
    kMIPS2 = 1U << 7U, // Mips II ISA
    kV9 = 1U << 4U, // SparcV9 mode (Sparc)
    kQPX = 1U << 4U // Quad Processing eXtensions mode (PPC)
};

class Disassembler {
public:

    Disassembler();

    Disassembler(const Disassembler &other) = default;

    Disassembler &operator=(const Disassembler &other) = default;

    Disassembler(Disassembler &&other) noexcept = default;

    Disassembler &operator=(Disassembler &&other) noexcept = default;

    void init(DisasmArch arch, DisasmMode mode);

    bool is_valid() const noexcept;

    csh get() const noexcept;

    ~Disassembler();

private:
    csh m_disasm;
};

} // bcov
