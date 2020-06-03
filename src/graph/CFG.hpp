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
#include "core/BasicBlock.hpp"
#include "graph/DirectedGraph.hpp"

namespace bcov {

template<>
struct identify<BasicBlock> {
    size_t operator()(const BasicBlock &bb) const noexcept
    {
        return bb.id();
    }
};

using BBPtrVec = std::vector<const BasicBlock *>;

class CFG {
    friend class FunctionBuilder;

public:
    using Node =  BasicBlock;
    using Graph = OrderedGraph<Node, identify<BasicBlock>>;
    using Edges = Graph::Edges;
    using VertexStore = Graph::VertexStore;
    using Vertices = Graph::VertexStore::Vertices;

    CFG();

    CFG(const CFG &other) = default;

    CFG &operator=(const CFG &other) = default;

    CFG(CFG &&other) noexcept = default;

    CFG &operator=(CFG &&other) noexcept = default;

    virtual ~CFG() = default;

    //===============================================

    const BasicBlock *virtual_entry() const noexcept;

    const BasicBlock *virtual_exit() const noexcept;

    const Edges &successors(const BasicBlock &bb) const;

    const Edges &predecessors(const BasicBlock &bb) const;

    void insert_edge(const BasicBlock &src, const BasicBlock &dst);

    void reset_padding_edges(const BasicBlock &bb);

    void reset_edges(const BasicBlock &bb);

    void reset();

    const Graph &forward() const noexcept;

    const Graph &backward() const noexcept;

    size_t size() const noexcept;

protected:
    void basic_blocks(span<const BasicBlock> basic_blocks);

    /// supports defining functions with multiple entry blocks. In practice,
    /// there should only one entry.
    void add_entry_block(const BasicBlock &bb);

    void add_exit_block(const BasicBlock &bb);

private:
    struct Impl;
    std::shared_ptr<Impl> m_impl;

};

} // bcov
