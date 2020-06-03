/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include "CSInstWrapper.hpp"
#include "Common.hpp"

namespace bcov {

CSInstWrapper::CSInstWrapper()
{
    m_buf = new uint8_t[sizeof(cs_insn) + sizeof(cs_detail)];
    auto inst = (cs_insn *) m_buf;
    inst->detail = (cs_detail *) (m_buf + sizeof(cs_insn));
}

cs_insn *
CSInstWrapper::get() const noexcept
{
    return (cs_insn *) m_buf;
}

CSInstWrapper::CSInstWrapper(CSInstWrapper &&other) noexcept
{
    this->m_buf = other.m_buf;
    other.m_buf = nullptr;
}

CSInstWrapper &
CSInstWrapper::operator=(CSInstWrapper &&other) noexcept
{
    this->m_buf = other.m_buf;
    other.m_buf = nullptr;
    return *this;
}

CSInstWrapper::~CSInstWrapper()
{
    delete[]m_buf;
}

std::string
to_string(const CSInstWrapper &inst)
{
    return sstring(to_hex(inst.get()->address)
                   + " " + inst.get()->mnemonic + " " + inst.get()->op_str);
}
} //bcov
