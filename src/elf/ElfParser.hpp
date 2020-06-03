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

#include "util/BcovConfig.hpp"
#include "libelfin/elf/elf++.hh"

namespace bcov {

class ElfParser {
public:
    ElfParser() = delete;

    ElfParser(const ElfParser &other) = delete;

    ElfParser &operator=(const ElfParser &other) = delete;

    ElfParser(ElfParser &&other) noexcept = default;

    ElfParser &operator=(ElfParser &&other) noexcept = default;

    virtual ~ElfParser() = default;

    static elf::elf parse(sstring_view file_name);

};

class ElfLogicException : public std::logic_error {
public:

    explicit ElfLogicException(const std::string &what_arg);

    explicit ElfLogicException(const char *what_arg);

    ~ElfLogicException() override = default;
};

}
