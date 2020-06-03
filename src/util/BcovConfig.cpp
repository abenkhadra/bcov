/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include "BcovConfig.hpp"

namespace bcov {

FuncConfigItem::FuncConfigItem(sstring_view func_name)
    : m_func_name(func_name.data()),
      m_jump_table_map()
{
}

void
FuncConfigItem::add_jump_table(addr_t inst_addr, std::vector<addr_t> &targets)
{
    m_jump_table_map.emplace(std::make_pair(inst_addr, std::move(targets)));
}

const sstring &
FuncConfigItem::func_name() const noexcept
{
    return m_func_name;
}

bool
FuncConfigItem::has_jump_tables() const noexcept
{
    return !m_jump_table_map.empty();
}

ConfJumpTabIter
FuncConfigItem::begin() const noexcept
{
    return m_jump_table_map.cbegin();
}

ConfJumpTabIter
FuncConfigItem::end() const noexcept
{
    return m_jump_table_map.cend();
}

const ConfJumpTabMap &
FuncConfigItem::jump_tables() const noexcept
{
    return m_jump_table_map;
}

bool
FuncConfigItem::is_valid() const noexcept
{
    return !m_func_name.empty();
}

std::ostream &operator<<(std::ostream &os, const FuncConfigItem &item)
{
    os << "Function: " << item.m_func_name << "\n";
    for (const auto &jump_tab_pair : item.m_jump_table_map) {
        os << "Jump Table: " << std::hex << std::showbase << jump_tab_pair.first
           << " | ";
        for (auto target : jump_tab_pair.second) {
            os << std::hex << std::showbase << target << " ";
        }
        os << "\n";
    }
    return os;
}

FuncConfigItem *
BcovConfig::add_function(sstring_view func_name)
{
    m_func_items.emplace_back(FuncConfigItem(func_name));
    return (&m_func_items.back());
}

span<const FuncConfigItem>
BcovConfig::functions() const noexcept
{
    return m_func_items;
}
} // bcov
