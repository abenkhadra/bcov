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

#include <set>
#include "Common.hpp"
#include "Function.hpp"
#include "elf/ElfModule.hpp" // XXX: breaks modularity
#include "flax/Flax.hpp"
#include "util/BcovConfig.hpp"


BCOV_FORWARD(CSInstWrapper)

namespace bcov {

class FunctionBuilder {
public:

    FunctionBuilder();

    FunctionBuilder(const FunctionBuilder &other) = default;

    FunctionBuilder &operator=(const FunctionBuilder &other) = default;

    FunctionBuilder(FunctionBuilder &&other) noexcept = default;

    FunctionBuilder &operator=(FunctionBuilder &&other) noexcept = default;

    virtual ~FunctionBuilder() = default;

    void set_build_dominator_trees();

    void set_function_info(IFunction::Idx idx, sstring_view name, addr_t address,
                           size_t byte_size, const uint8_t *data);

    IFunction
    build(const ElfModule *module, flax::FlaxManager *microx_mgr = nullptr);

protected:
    const MCInst *add_instruction(const CSInstWrapper *cs_inst);

    void build_instructions_and_basic_block_entries(std::set<addr_t> &bb_entries);

    void build_basic_blocks(const std::set<addr_t> &bb_entries);

    void build_cfg(const ElfModule *module);

    void build_jump_tabs_and_update_cfg(const ElfModule *module,
                                        std::set<addr_t> &bb_entries);

    void finalize_cfg(const ElfModule *module,
                      const ElfFunction::LandingPads &landing_pads);

    void cfg_link_landing_pads(const ElfFunction::LandingPads &landing_pads);

    void cfg_link_setjmps(const ElfModule *module);

    void build_dominator_trees();

private:
    struct Impl;
    std::shared_ptr<Impl> m_impl;
};

class FunctionBuilderException : public std::logic_error {
public:
    explicit FunctionBuilderException(const std::string &what_arg);

    explicit FunctionBuilderException(const char *what_arg);

    ~FunctionBuilderException() override = default;
};

} // bcov
