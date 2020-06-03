/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include "BcovConfigParser.hpp"
#include <fstream>


namespace bcov {

BcovConfigParser::BcovConfigParser() :
    m_func_name_regex("[._[:alnum:]]+"),
    m_address_regex("0x[[:xdigit:]]{2,16}")
{ }

BcovConfig
BcovConfigParser::parse(sstring_view file_name) const
{
    BcovConfig config;
    if (file_name.empty()) {
        return config;
    }

    std::ifstream config_file(file_name.data());
    int line_num = 1;
    FuncConfigItem *func_item = nullptr;

    for (std::string line; std::getline(config_file, line);) {
        if (line.empty()) {
            continue;
        }
        auto func_name = parse_function_name(line);
        bool sucess;
        if (!func_name.empty()) {
            func_item = config.add_function(func_name);
            sucess = true;
        } else {
            addr_t tab_addr;
            ConfJumpTabTargets targets;
            sucess = parse_jump_table(line, tab_addr, targets);
            if (sucess && func_item != nullptr) {
                func_item->add_jump_table(tab_addr, targets);
            }
        }
        if (!sucess) {
            throw ConfigParseException(
                "Could not parse configuration at line:" + std::to_string(line_num));
        }
        line_num++;
    }
    return config;
}

std::string
BcovConfigParser::parse_function_name(const std::string &line) const noexcept
{
    if ((line.front()) != '[' or (line.back()) != ']') {
        return "";
    }
    std::smatch m;
    if (!std::regex_search(line, m, m_func_name_regex)) {
        return "";
    }
    return m[0];
}

bool
BcovConfigParser::parse_jump_table(const std::string &line, addr_t &jump_tab_addr,
                                   ConfJumpTabTargets &targets) const noexcept
{
    auto addr_begin = std::sregex_iterator(line.begin(), line.end(),
                                           m_address_regex);
    auto addr_end = std::sregex_iterator();
    bool status = false;
    try {
        if (std::distance(addr_begin, addr_end) == 0) {
            return status;
        }
        jump_tab_addr = std::stoul((*addr_begin).str(), nullptr, 16);
        for (std::sregex_iterator it = ++addr_begin; it != addr_end; ++it) {
            targets.push_back(std::stoul((*it).str(), nullptr, 16));
        }
        if (targets.size() > 2) {
            status = true;
        }
    } catch (std::invalid_argument &exp) {
    } catch (std::out_of_range &exp) {
    }
    return status;
}

ConfigParseException::ConfigParseException(const std::string &what_arg) :
    runtime_error(what_arg)
{ }

ConfigParseException::ConfigParseException(const char *what_arg) :
    runtime_error(what_arg)
{
}
} // bcov
