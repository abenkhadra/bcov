/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include <stdexcept>
#include <capstone/capstone.h>
#include "Disassembler.hpp"

namespace bcov {

Disassembler::Disassembler() : m_disasm(0)
{ }

void
Disassembler::init(DisasmArch arch, DisasmMode mode)
{
    cs_err err = cs_open((cs_arch) arch, (cs_mode) mode, &m_disasm);
    if (err != CS_ERR_OK) {
        throw std::runtime_error("failed to initialize capstone!");
    }
    cs_option(m_disasm, CS_OPT_DETAIL, CS_OPT_ON);
    if (arch == DisasmArch::kX86) {
        cs_option(m_disasm, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
    }
}

bool
Disassembler::is_valid() const noexcept
{
    return m_disasm != 0;
}

csh
Disassembler::get() const noexcept
{
    return m_disasm;
}

Disassembler::~Disassembler()
{
    if (m_disasm != 0) {
        cs_close(&m_disasm);
    }
}
} // bcov
