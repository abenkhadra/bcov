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

#include "CFG.hpp"

namespace bcov {

class DominatorTree {
    friend class DominatorTreeBuilder;

public:

    DominatorTree();

    DominatorTree(const DominatorTree &other) = default;

    DominatorTree &operator=(const DominatorTree &other) = default;

    DominatorTree(DominatorTree &&other) noexcept = default;

    DominatorTree &operator=(DominatorTree &&other) noexcept = default;

    virtual ~DominatorTree() = default;

    const CFG::Node *root() const noexcept;

    const CFG::Node *idom(const CFG::Node *bb) const noexcept;

    const CFG::Graph &tree() const noexcept;

    bool dominates(const CFG::Node *a, const CFG::Node *b) const noexcept;

    bool valid() const noexcept;

private:
    struct Impl;
    std::shared_ptr<Impl> m_impl;
};

class DominatorTreeBuilder {
public:

    DominatorTree build(const CFG::Node *root, const CFG::Graph &forward_graph,
                        const CFG::Graph &backward_graph);

};

} // bcov
