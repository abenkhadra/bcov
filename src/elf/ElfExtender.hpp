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

#include "libelfin/elf/elf++.hh"
#include "elf/Util.hpp"
#include "core/Common.hpp"

namespace bcov {

class ElfExtender {
public:

    ElfExtender();

    ElfExtender(size_t code_seg_size, size_t data_seg_size);

    virtual ~ElfExtender() = default;

    void code_segment_size(size_t size);

    void data_segment_size(size_t size);

    bool extend(sstring_view input_file, sstring_view output_file);

private:
    struct Impl;
    size_t m_code_seg_size;
    size_t m_data_seg_size;
};

class ElfExtenderException : public std::logic_error {
public:

    explicit ElfExtenderException(const std::string &what_arg);

    explicit ElfExtenderException(const char *what_arg);

    ~ElfExtenderException() override = default;
};

} // bcov
