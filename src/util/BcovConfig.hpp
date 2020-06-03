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
#include <unordered_map>

namespace bcov {

using ConfJumpTabTargets = std::vector<addr_t>;
using ConfJumpTabMap = std::unordered_map<addr_t, ConfJumpTabTargets>;
using ConfJumpTabIter = ConfJumpTabMap::const_iterator;

class FuncConfigItem {
public:

    FuncConfigItem() = default;

    explicit FuncConfigItem(sstring_view func_name);

    FuncConfigItem(const FuncConfigItem &other) = default;

    FuncConfigItem &operator=(const FuncConfigItem &other) = default;

    FuncConfigItem(FuncConfigItem &&other) noexcept = default;

    FuncConfigItem &operator=(FuncConfigItem &&other) noexcept = default;

    ~FuncConfigItem() = default;

    void add_jump_table(addr_t inst_addr, ConfJumpTabTargets &targets);

    const sstring &func_name() const noexcept;

    bool has_jump_tables() const noexcept;

    ConfJumpTabIter begin() const noexcept;

    ConfJumpTabIter end() const noexcept;

    const ConfJumpTabMap &jump_tables() const noexcept;

    bool is_valid() const noexcept;

    friend std::ostream &
    operator<<(std::ostream &stream, const FuncConfigItem &matrix);

private:
    sstring m_func_name;
    ConfJumpTabMap m_jump_table_map;
};

class BcovConfig {
public:

    BcovConfig() = default;

    BcovConfig(const BcovConfig &other) = default;

    BcovConfig &operator=(const BcovConfig &other) = default;

    BcovConfig(BcovConfig &&other) noexcept = default;

    BcovConfig &operator=(BcovConfig &&other) noexcept = default;

    virtual ~BcovConfig() = default;

    FuncConfigItem *add_function(sstring_view func_name);

    span<const FuncConfigItem> functions() const noexcept;

private:
    std::vector<FuncConfigItem> m_func_items;
};
}

