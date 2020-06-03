/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include "SuperBlock.hpp"
#include "core/Function.hpp"
#include "graph/Dot.hpp"
#include "easylogging/easylogging++.h"
#include <stack>

namespace bcov {

using BBIndexVec = std::vector<BasicBlock::Idx>;

//==============================================================================

SuperBlock::SuperBlock() : m_kind(SuperBlockKind::kNone), m_idx(0)
{ }

const BBPtrVec &
SuperBlock::basic_blocks() const noexcept
{
    return m_basic_blocks;
}

bool
SuperBlock::exists(const BasicBlock *bb) const noexcept
{
    // pointer comparison can be dangerous!
    return std::find(m_basic_blocks.cbegin(), m_basic_blocks.cend(), bb) !=
           m_basic_blocks.cend();
}

SuperBlock::Idx
SuperBlock::idx() const noexcept
{
    return m_idx;
}

bool
SuperBlock::valid() const noexcept
{
    return !m_basic_blocks.empty();
}

bool
SuperBlock::is_virtual_root() const noexcept
{
    return m_idx == 0 && valid();
}

SuperBlockKind
SuperBlock::kind() const noexcept
{
    return m_kind;
}

//==============================================================================

struct SuperBlockStore::Impl {
    Impl();

    ~Impl() = default;

    inline SuperBlock::Idx dfs_num(const SuperBlock &a) const noexcept;

    inline SuperBlock::Idx dfs_low(const SuperBlock &a) const noexcept;

    bool
    dominates(const SuperBlockStore::Node &a, const SuperBlockStore::Node &b) const;

    bool
    find_successor(const SuperBlockStore::Node &a,
                   const SuperBlockStore::Node &b) const;

    inline bool
    inside_dom_subgraph(const SuperBlockStore::Node &a,
                        const SuperBlockStore::Node &b) const;

    // super block that contains the virtual entry and the virtual exit
    const SuperBlock *m_root;
    std::vector<SuperBlock::Idx> m_bb_to_sb_map;
    std::vector<SuperBlock::Idx> m_dfs_num;
    std::vector<SuperBlock::Idx> m_low;
    std::vector<SuperBlock> m_super_blocks;
    SuperBlockStore::VertexStore m_vertices;
    SuperBlockStore::Graph m_sb_dom_forward;
    SuperBlockStore::Graph m_sb_dom_backward;
};

SuperBlockStore::Impl::Impl() : m_root(nullptr)
{ }

SuperBlock::Idx
SuperBlockStore::Impl::dfs_num(const SuperBlock &a) const noexcept
{
    return m_dfs_num[a.idx()];
}

SuperBlock::Idx
SuperBlockStore::Impl::dfs_low(const SuperBlock &a) const noexcept
{
    return m_low[a.idx()];
}

bool
SuperBlockStore::Impl::inside_dom_subgraph(const SuperBlockStore::Node &a,
                                           const SuperBlockStore::Node &b) const
{
    return dfs_low(a) <= dfs_num(b) && dfs_num(b) <= dfs_num(a);
}

bool
SuperBlockStore::Impl::dominates(const SuperBlockStore::Node &a,
                                 const SuperBlockStore::Node &b) const
{
    if (dfs_num(a) == dfs_num(b)) {
        // trivial case
        return true;
    }
    if (!inside_dom_subgraph(a, b)) {
        return false;
    }

    return find_successor(a, b);
}

bool
SuperBlockStore::Impl::find_successor(const SuperBlockStore::Node &a,
                                      const SuperBlockStore::Node &b) const
{
    const SuperBlockStore::Node *next = nullptr;
    for (const auto succ : m_sb_dom_forward.get_edges(a)) {
        if (dfs_num(*succ) == dfs_num(b)) {
            return true;
        }
        if (!succ->is_virtual_root() && inside_dom_subgraph(*succ, b)) {
            next = succ;
            break;
        }
    }
    return next == nullptr ? false : find_successor(*next, b);
}

//==============================================================================

SuperBlockStore::SuperBlockStore() : m_impl(std::make_shared<Impl>())
{ }

const SuperBlockStore::Node *
SuperBlockStore::virtual_root() const noexcept
{
    return m_impl->m_root;
}

const SuperBlockStore::Graph &
SuperBlockStore::forward_dom_graph() const noexcept
{
    return m_impl->m_sb_dom_forward;
}

const SuperBlockStore::Graph &
SuperBlockStore::backward_dom_graph() const noexcept
{
    return m_impl->m_sb_dom_backward;
}

span<const SuperBlock>
SuperBlockStore::super_blocks() const noexcept
{
    return m_impl->m_super_blocks;
}

bool
SuperBlockStore::dominates(const SuperBlockStore::Node &a,
                           const SuperBlockStore::Node &b) const
{
    return m_impl->dominates(a, b);
}

const SuperBlockStore::Edges &
SuperBlockStore::get_dominators(const SuperBlockStore::Node &a) const
{
    return m_impl->m_sb_dom_backward.get_edges(a);
}

const SuperBlock *
SuperBlockStore::get_super_block(const BasicBlock *bb) const noexcept
{
    DCHECK(bb->id() < m_impl->m_bb_to_sb_map.size());
    auto index = m_impl->m_bb_to_sb_map[bb->id()];
    return index == 0 && !bb->is_virtual() ? nullptr
                                           : &m_impl->m_super_blocks[index];
}

bool
SuperBlockStore::valid() const noexcept
{
    return m_impl->m_root != nullptr;
}

//==============================================================================

struct SuperBlockStoreBuilder::Impl {

    void build_bb_dom_graph(CFG::Graph &bb_dom_graph) const;

    void init_super_blocks();

    void init_graphs();

    void do_probe_minimization();

    SuperBlockKind compute_probe_kind(const SuperBlock &sb) const;

    void mark_reachable_basic_blocks(const CFG::Graph &graph,
                                     const BasicBlock &node,
                                     std::vector<bool> &visited,
                                     bool &virtual_node_reached) const;

    void mark_dominated_super_blocks(const SuperBlock &sb,
                                     std::vector<bool> &visited) const;


    void add_super_block(BBPtrVec &basic_blocks);

    void reset_visited(std::vector<bool> &vec) const;

    const IFunction *function = nullptr;
    SuperBlockStore::Impl *store = nullptr;
    mutable std::vector<bool> m_sb_dom_visited;
    mutable std::vector<bool> m_forward_visited;
    mutable std::vector<bool> m_backward_visited;
};

void
SuperBlockStoreBuilder::Impl::reset_visited(std::vector<bool> &vec) const
{
    std::fill(vec.begin(), vec.end(), false);
}

void
SuperBlockStoreBuilder::Impl::build_bb_dom_graph(CFG::Graph &bb_dom_graph) const
{
    CFG::VertexStore bb_vertices;
    bb_vertices.init(function->cfg().forward().get_vertices());
    bb_dom_graph.set_vertex_store(bb_vertices);

    // build the dominator graph by merging pre- and post-dominator trees
    for (const auto bb : bb_dom_graph.get_vertices()) {
        auto predom = function->predominator().idom(bb);
        if (predom != nullptr) {
            bb_dom_graph.insert_edge(*predom, *bb);
        }

        auto postdom = function->postdominator().idom(bb);
        // loops can cause duplicate edges in the dominator graph but this
        // should not be a problem
        if (postdom != nullptr) {
            bb_dom_graph.insert_edge(*postdom, *bb);
        }
    }
}

void
SuperBlockStoreBuilder::Impl::init_super_blocks()
{
    auto total_bb_count = function->cfg().size();
    store->m_bb_to_sb_map.resize(total_bb_count, 0);
    DCHECK(store->m_super_blocks.empty());
    // virtual entry and exit are always in the same super block
    BBPtrVec root_sb_nodes = {function->cfg().virtual_entry(),
                              function->cfg().virtual_exit()};
    add_super_block(root_sb_nodes);

    // heuristic approximation
    store->m_super_blocks.reserve(total_bb_count / 2);
}

void
SuperBlockStoreBuilder::Impl::init_graphs()
{
    store->m_dfs_num.resize(store->m_super_blocks.size(), 0);
    store->m_low.resize(store->m_super_blocks.size(), 0);
    store->m_vertices.init(store->m_super_blocks);
    store->m_sb_dom_forward.set_vertex_store(store->m_vertices);
    store->m_sb_dom_backward.set_vertex_store(store->m_vertices);
}

void
SuperBlockStoreBuilder::Impl::do_probe_minimization()
{
    m_sb_dom_visited.resize(store->m_super_blocks.size(), false);
    m_forward_visited.resize(function->cfg().size(), false);
    m_backward_visited.resize(function->cfg().size(), false);

    // Any-node probe minimization as depicted in figure 11, see
    // Agrawal, "Dominators, Super Blocks, and Program Coverage", in POPL'94

    auto sb_it = store->m_super_blocks.begin();
    for (++sb_it; sb_it < store->m_super_blocks.end(); ++sb_it) {
        auto &dom_successors = store->m_sb_dom_forward.get_edges(*sb_it);
        if (dom_successors.empty()) {
            sb_it->m_kind = SuperBlockKind::kAllNode;
            continue;
        }
        if (dom_successors.size() == 1) {
            sb_it->m_kind = SuperBlockKind::kAnyNode;
            continue;
        }
        sb_it->m_kind = compute_probe_kind(*sb_it);
    }
}

SuperBlockKind
SuperBlockStoreBuilder::Impl::compute_probe_kind(const SuperBlock &sb) const
{
    reset_visited(m_sb_dom_visited);
    reset_visited(m_forward_visited);

    mark_dominated_super_blocks(sb, m_sb_dom_visited);

    for (unsigned i = 1; i < store->m_super_blocks.size(); ++i) {
        if (m_sb_dom_visited[i]) {
            auto bb = store->m_super_blocks[i].basic_blocks().front();
            m_forward_visited[bb->id()] = true;
        }
    }

    m_backward_visited = m_forward_visited;
    bool exit_reachable = false;
    mark_reachable_basic_blocks(function->cfg().forward(),
                                *sb.basic_blocks().front(), m_forward_visited,
                                exit_reachable);

    if (!exit_reachable) {
        return SuperBlockKind::kNone;
    }

    bool entry_reachable = false;
    mark_reachable_basic_blocks(function->cfg().backward(),
                                *sb.basic_blocks().front(), m_backward_visited,
                                entry_reachable);

    if (!entry_reachable) {
        return SuperBlockKind::kNone;
    }

    return SuperBlockKind::kAnyNode;
}

void SuperBlockStoreBuilder::Impl::mark_reachable_basic_blocks(
    const CFG::Graph &graph, const BasicBlock &node, std::vector<bool> &visited,
    bool &virtual_node_reached) const
{
    visited[node.id()] = true;
    if (node.is_virtual()) {
        virtual_node_reached = true;
    }
    for (const auto succ : graph.get_edges(node)) {
        if (!visited[succ->id()] && !virtual_node_reached) {
            mark_reachable_basic_blocks(graph, *succ, visited, virtual_node_reached);
        }
    }
}

void
SuperBlockStoreBuilder::Impl::mark_dominated_super_blocks
    (const SuperBlock &sb, std::vector<bool> &visited) const
{
    // workaround cycles involving virtual root
    visited[store->m_root->idx()] = true;
    for (const auto succ : store->m_sb_dom_forward.get_edges(sb)) {
        if (!visited[succ->idx()]) {
            visited[succ->idx()] = true;
            mark_dominated_super_blocks(*succ, visited);
        }
    }
    if (!sb.is_virtual_root()) {
        visited[store->m_root->idx()] = false;
    }
}

void
SuperBlockStoreBuilder::Impl::add_super_block(BBPtrVec &basic_blocks)
{
    // TODO: this method does not need to be in the public interface
    DCHECK(!basic_blocks.empty());
    store->m_super_blocks.emplace_back(SuperBlock());
    auto &last_sb = store->m_super_blocks.back();
    last_sb.m_idx = (SuperBlock::Idx) (store->m_super_blocks.size() - 1);
    last_sb.m_basic_blocks = std::move(basic_blocks);
    for (const auto bb : last_sb.basic_blocks()) {
        store->m_bb_to_sb_map[bb->id()] = last_sb.idx();
    }
}

//==============================================================================

/// @brief implementation of Tarjan's algorithm for finding strongly connected
/// components (SCCs) in a directed graph
class SBGraphNodeBuilder : public GraphVisitorBase<CFG::Node> {
public:
    explicit SBGraphNodeBuilder(SuperBlockStoreBuilder::Impl &sb_builder,
                                SuperBlockStore &sb_graph,
                                size_t bb_count);

    void visit_preorder(const CFG::Node &node, const CFG::Node *parent) override;

    void visit_peek(const CFG::Node &node, const CFG::Node &parent) override;

    void visit_postorder(const CFG::Node &node, const CFG::Node *parent) override;

    BasicBlock::Idx low(const CFG::Node &node) const noexcept;

    BasicBlock::Idx index(const CFG::Node &node) const noexcept;

    void set_low(const CFG::Node &node, BasicBlock::Idx idx) noexcept;

    void set_index(const CFG::Node &node, BasicBlock::Idx idx) noexcept;

private:
    SuperBlockStoreBuilder::Impl &m_bld_impl;
    SuperBlockStore &m_sb_store;
    SuperBlock::Idx m_cur_index;
    BBIndexVec m_index;
    BBIndexVec m_low;
    std::stack<const BasicBlock *> m_stack;
};

SBGraphNodeBuilder::SBGraphNodeBuilder(SuperBlockStoreBuilder::Impl &sb_builder,
                                       SuperBlockStore &sb_graph,
                                       size_t bb_count)
    : m_bld_impl(sb_builder), m_sb_store(sb_graph), m_cur_index(0),
      m_index(bb_count, 0), m_low(bb_count, 0)
{ }

BasicBlock::Idx
SBGraphNodeBuilder::low(const CFG::Node &node) const noexcept
{
    return m_low[node.id()];
}

BasicBlock::Idx
SBGraphNodeBuilder::index(const CFG::Node &node) const noexcept
{
    return m_index[node.id()];
}

void
SBGraphNodeBuilder::set_low(const CFG::Node &node, BasicBlock::Idx idx) noexcept
{
    m_low[node.id()] = idx;
}

void
SBGraphNodeBuilder::set_index(const CFG::Node &node, BasicBlock::Idx idx) noexcept
{
    m_index[node.id()] = idx;
}

void
SBGraphNodeBuilder::visit_preorder(const CFG::Node &node, const CFG::Node *parent)
{
    UNUSED(parent);
    // virtual nodes and unreachable nodes will have index zero
    ++m_cur_index;
    set_index(node, m_cur_index);
    set_low(node, m_cur_index);
    m_stack.push(&node);
}

void
SBGraphNodeBuilder::visit_peek(const CFG::Node &node, const CFG::Node &parent)
{
    if (m_sb_store.get_super_block(&node) != nullptr) {
        return;
    }
    if (index(node) < low(parent)) {
        set_low(parent, index(node));
    }
}

void
SBGraphNodeBuilder::visit_postorder(const CFG::Node &node, const CFG::Node *parent)
{
    if (node.is_virtual()) {
        return;
    }
    if (index(node) == low(node)) {
        BBPtrVec basic_blocks;
        const CFG::Node *last_node;
        do {
            last_node = m_stack.top();
            if (!last_node->is_virtual()) {
                basic_blocks.push_back(last_node);
            }
            m_stack.pop();
        } while (!m_stack.empty() && *last_node != node);

        m_bld_impl.add_super_block(basic_blocks);
    }

    if (parent != nullptr && low(node) < low(*parent)) {
        set_low(*parent, low(node));
    }
}

//==============================================================================

class SBGraphEdgeBuilder : public GraphVisitorBase<CFG::Node> {
public:
    explicit SBGraphEdgeBuilder(SuperBlockStore &store,
                                SuperBlockStore::Graph &graph);

    void visit_preorder(const CFG::Node &node, const CFG::Node *parent) override;

    void visit_peek(const CFG::Node &node, const CFG::Node &parent) override;

    void insert_edge(const CFG::Node *src, const CFG::Node *dst);

    void set_dom_graph_mode() noexcept;

private:
    SuperBlockStore &m_sb_store;
    SuperBlockStore::Graph &m_sb_graph;
    bool m_dom_graph_mode;
};

SBGraphEdgeBuilder::SBGraphEdgeBuilder(SuperBlockStore &store,
                                       SuperBlockStore::Graph &graph)
    : m_sb_store(store), m_sb_graph(graph),
      m_dom_graph_mode(false)
{ }

void
SBGraphEdgeBuilder::set_dom_graph_mode() noexcept
{
    m_dom_graph_mode = true;
}

void
SBGraphEdgeBuilder::visit_preorder(const CFG::Node &node, const CFG::Node *parent)
{
    if (parent != nullptr &&
        m_sb_store.get_super_block(&node) != m_sb_store.get_super_block(parent)) {
        insert_edge(parent, &node);
    }
}

void
SBGraphEdgeBuilder::visit_peek(const CFG::Node &node, const CFG::Node &parent)
{
    if (m_sb_store.get_super_block(&node) != m_sb_store.get_super_block(&parent)) {
        insert_edge(&parent, &node);
    }
}

void
SBGraphEdgeBuilder::insert_edge(const CFG::Node *src, const CFG::Node *dst)
{
    const auto src_sb = m_sb_store.get_super_block(src);
    const auto dst_sb = m_sb_store.get_super_block(dst);
    if (!m_dom_graph_mode) {
        m_sb_graph.insert_edge(*src_sb, *dst_sb);
    } else if (!dst_sb->is_virtual_root() &&
               !m_sb_graph.edge_exists(*src_sb, *dst_sb)) {
        m_sb_graph.insert_edge(*src_sb, *dst_sb);
    }
}

//==============================================================================

using SBNodePtrVec = std::vector<SuperBlockStore::Node *>;

class DGDFSMarker : public GraphVisitorBase<SuperBlockStore::Node> {
public:
    DGDFSMarker(std::vector<SuperBlock::Idx> &index,
                std::vector<SuperBlock::Idx> &low);

    void visit_postorder(const SuperBlockStore::Node &node,
                         const SuperBlockStore::Node *parent) override;

    void visit_peek(const SuperBlockStore::Node &node,
                    const SuperBlockStore::Node &parent) override;

private:
    std::vector<SuperBlock::Idx> &m_index;
    std::vector<SuperBlock::Idx> &m_low;
    SuperBlock::Idx m_cur_index;
};

DGDFSMarker::DGDFSMarker(std::vector<SuperBlock::Idx> &index,
                         std::vector<SuperBlock::Idx> &low)
    : m_index(index), m_low(low), m_cur_index(0)
{ }

void
DGDFSMarker::visit_postorder(const SuperBlockStore::Node &node,
                             const SuperBlockStore::Node *parent)
{
    m_index[node.idx()] = ++m_cur_index;
    if (m_low[node.idx()] == 0) {
        m_low[node.idx()] = m_index[node.idx()];
    }
    if (parent != nullptr &&
        (m_low[parent->idx()] == 0 || m_low[node.idx()] < m_low[parent->idx()])) {
        m_low[parent->idx()] = m_low[node.idx()];
    }
}

void
DGDFSMarker::visit_peek(const SuperBlockStore::Node &node,
                        const SuperBlockStore::Node &parent)
{
    if (m_low[node.idx() == 0]) {
        // work around possible cycles caused by virtual root
        return;
    }
    if (m_low[parent.idx()] == 0 || m_low[node.idx()] < m_low[parent.idx()]) {
        m_low[parent.idx()] = m_low[node.idx()];
    }
}

//==============================================================================

SuperBlockStore
SuperBlockStoreBuilder::build(const IFunction *function)
{
    if (function == nullptr) return SuperBlockStore();
    CFG::Graph bb_dom_graph;
    SuperBlockStore sb_store;
    SuperBlockStoreBuilder::Impl impl;
    impl.function = function;
    impl.store = sb_store.m_impl.get();

    // phase 1: build super-blocks
    impl.build_bb_dom_graph(bb_dom_graph);
    impl.init_super_blocks();
    auto total_bb_count = function->cfg().size();
    SBGraphNodeBuilder sb_node_builder(impl, sb_store, total_bb_count);
    bb_dom_graph.traverse_depth_first(sb_node_builder,
                                      *function->cfg().virtual_entry());

    impl.store->m_root = sb_store.get_super_block(function->cfg().virtual_entry());

    // phase 2: build super-block graphs
    impl.init_graphs();

    SBGraphEdgeBuilder dom_edge_builder(sb_store, impl.store->m_sb_dom_forward);
    dom_edge_builder.set_dom_graph_mode();
    bb_dom_graph.traverse_depth_first(dom_edge_builder,
                                      *function->cfg().virtual_entry());

    DGDFSMarker dom_marker(impl.store->m_dfs_num, impl.store->m_low);
    sb_store.forward_dom_graph().traverse_depth_first(dom_marker,
                                                      *sb_store.virtual_root());

    for (const auto vertex : sb_store.forward_dom_graph().get_vertices()) {
        for (const auto succ : sb_store.forward_dom_graph().get_edges(*vertex)) {
            if (!succ->is_virtual_root()) {
                // virtual root can add cycles to the dominator graph and can not
                // be instrumented anyway.
                impl.store->m_sb_dom_backward.insert_edge(*succ, *vertex);
            }
        }
    }

    impl.do_probe_minimization();

    return sb_store;
}

} // bcov
