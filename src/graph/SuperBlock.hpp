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
#include "graph/CFG.hpp"

BCOV_FORWARD(IFunction)

namespace bcov {

enum class SuperBlockKind : unsigned char {
    kNone = 0,
    kAllNode,
    kAnyNode
};

static inline bool is_instrumentable(SuperBlockKind kind)
{
    return kind != SuperBlockKind::kNone;
}

class SuperBlock {
    friend class SuperBlockStoreBuilder;

public:
    using Idx = BasicBlock::Idx;

    SuperBlock();

    ~SuperBlock() = default;

    const BBPtrVec &basic_blocks() const noexcept;

    bool exists(const BasicBlock *bb) const noexcept;

    SuperBlockKind kind() const noexcept;

    Idx idx() const noexcept;

    bool valid() const noexcept;

    bool is_virtual_root() const noexcept;

private:
    SuperBlockKind m_kind;
    Idx m_idx;
    BBPtrVec m_basic_blocks;
};

template<>
struct identify<SuperBlock> {
    size_t operator()(const SuperBlock &sb) const noexcept
    {
        return sb.idx();
    }
};

/// @brief owns super-blocks and their graphs
class SuperBlockStore {
    friend class SuperBlockStoreBuilder;

public:
    using Node =  SuperBlock;
    using Graph = OrderedGraph<Node, identify<SuperBlock>>;
    using Edges = Graph::Edges;
    using VertexStore = OrderedVertexStore<SuperBlock, size_t>;
    using Vertices = VertexStore::Vertices;

    SuperBlockStore();

    ~SuperBlockStore() = default;

    const Node *virtual_root() const noexcept;

    const Graph &forward_dom_graph() const noexcept;

    const Graph &backward_dom_graph() const noexcept;

    span<const SuperBlock> super_blocks() const noexcept;

    /// @brief return true if a is predecessor to b in the dominator graph
    bool dominates(const Node &a, const Node &b) const;

    const Edges &get_dominators(const Node &a) const;

    const SuperBlock *get_super_block(const BasicBlock *bb) const noexcept;

    bool valid() const noexcept;

private:
    struct Impl;
    std::shared_ptr<Impl> m_impl;
};

static inline bool operator==(const SuperBlock &a, const SuperBlock &b)
{
    return a.idx() == b.idx();
}

static inline bool operator!=(const SuperBlock &a, const SuperBlock &b)
{
    return !(a == b);
}

class SuperBlockStoreBuilder {
public:
    static SuperBlockStore build(const IFunction *function);

    struct Impl;
};

} // bcov
