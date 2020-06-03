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

#include "core/Function.hpp"
#include "flax/Flax.hpp"

namespace bcov {
namespace x64 {

class JumpTabAnalyzer {
public:

    static void
    build(const IFunction &func, const BasicBlock &pivot_bb,
          flax::FlaxManager *microx_mgr, JumpTable &result);
};

} // x64
} // bcov
