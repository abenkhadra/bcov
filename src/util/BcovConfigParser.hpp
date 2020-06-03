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

#include "core/Common.hpp"
#include "BcovConfig.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <regex>
#include <stdexcept>

namespace bcov {

class BcovConfigParser {
public:
    BcovConfigParser();

    BcovConfigParser(const BcovConfigParser &other) = default;

    BcovConfigParser &operator=(const BcovConfigParser &other) = default;

    BcovConfigParser(BcovConfigParser &&other) noexcept = default;

    BcovConfigParser &operator=(BcovConfigParser &&other) noexcept = default;

    virtual ~BcovConfigParser() = default;

    BcovConfig parse(sstring_view file_name) const;

protected:

    std::string parse_function_name(const std::string &line) const noexcept;

    bool parse_jump_table(const std::string &line, addr_t &jump_tab_addr,
                          ConfJumpTabTargets &targets) const noexcept;

private:
    std::regex m_func_name_regex;
    std::regex m_address_regex;
};

class ConfigParseException : public std::runtime_error {
public:

    explicit ConfigParseException(const std::string &what_arg);

    explicit ConfigParseException(const char *what_arg);

    ~ConfigParseException() override = default;
};

} // bcov
