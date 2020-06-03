/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief simple wrapper for capstone's cs_insn and cs_detail.
 */

#pragma once

#include "Common.hpp"
#include <capstone/capstone.h>

namespace bcov {

class CSInstWrapper {
public:
    CSInstWrapper();

    CSInstWrapper(const CSInstWrapper &other) = delete;

    CSInstWrapper &operator=(const CSInstWrapper &other) = delete;

    CSInstWrapper(CSInstWrapper &&other) noexcept;

    CSInstWrapper &operator=(CSInstWrapper &&other) noexcept;

    ~CSInstWrapper();

    cs_insn *get() const noexcept;

private:
    uint8_t *m_buf;
};

sstring to_string(const CSInstWrapper &inst);

}
