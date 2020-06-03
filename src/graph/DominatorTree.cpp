/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief Implentation of SEMI-NCA dominator tree algorithm based on
 *
 *  - L. Georgiadis. "Linear-Time Algorithms for Dominators and Related Problems".
 *      PhD thesis, Princeton University, 2005.
 *
 */

#include "DominatorTree.hpp"
#include "core/Function.hpp"
#include "easylogging/easylogging++.h"
#include "Dot.hpp"

#define DFS_INDEX_START (1)
#define NODE_ID(x) Identify()(*(x))

namespace bcov {

using NodePtrVec = std::vector<const CFG::Node *>;

/// @brief depth-first search marker for dominator tree
template<typename T, typename Identify = identify<T>>
class DTDFSMarker : public GraphVisitorBase<T> {
    using NodePtrVec = std::vector<const T *>;

public:
    DTDFSMarker(NodePtrVec &ordered_vertices, NodePtrVec &parents,
                std::vector<unsigned int> &dfnums);

    void visit_preorder(const T &node, const T *parent) override;

private:
    NodePtrVec &m_ordered_vertices;
    NodePtrVec &m_parents;
    std::vector<unsigned> &m_dfnums;
    unsigned m_cur_num;
};

template<typename T, typename Identify>
DTDFSMarker<T, Identify>::DTDFSMarker(NodePtrVec &ordered_vertices,
                                      NodePtrVec &parents,
                                      std::vector<unsigned int> &dfnums)
    : m_ordered_vertices(ordered_vertices), m_parents(parents), m_dfnums(dfnums),
      m_cur_num(DFS_INDEX_START)
{ }

template<typename T, typename Identify>
void
DTDFSMarker<T, Identify>::visit_preorder(const T &node, const T *parent)
{
    m_parents[NODE_ID(&node)] = parent;
    m_dfnums[NODE_ID(&node)] = m_cur_num;
    m_ordered_vertices.push_back(&node);
    m_cur_num++;
}

template<typename T, typename Identify = identify<T>>
struct DominatorTreeBuildHelper {
    using NodePtrVec = std::vector<const T *>;
    using Graph = OrderedGraph<T, Identify>;

    explicit DominatorTreeBuildHelper(NodePtrVec &idoms)
        : m_idoms(idoms)
    { }

    ~DominatorTreeBuildHelper() = default;

    void init(const Graph &forward_graph, const T *root);

    const NodePtrVec &ordered_vertices() const
    { return m_ordered_vertices; }

    const CFG::Node *sdom(const T *node) const noexcept
    { return m_sdom[NODE_ID(node)]; }

    void set_sdom(const T *node, const T *sdom)
    { m_sdom[NODE_ID(node)] = sdom; }

    const CFG::Node *parent(const T *node) const noexcept
    { return m_idoms[NODE_ID(node)]; }

    unsigned depth(const CFG::Node *node) const
    { return m_dfnums[NODE_ID(node)]; }

    unsigned eval(const T *pred, unsigned last_linked);

    bool validate_dom_tree(const Graph &backward_graph);

    const T *get_node_at(unsigned dfs_depth) const
    { return m_ordered_vertices[dfs_depth - DFS_INDEX_START]; }

    void build(const Graph &backward_graph);

    NodePtrVec &m_idoms;
    NodePtrVec m_ordered_vertices;
    NodePtrVec m_sdom;
    std::vector<unsigned> m_dfnums;
};

template<typename T, typename Identify>
unsigned
DominatorTreeBuildHelper<T, Identify>::eval(const T *pred, unsigned last_linked)
{
    if (depth(pred) < last_linked) {
        // forward arcs
        return depth(pred);
    }
    // cross and back arcs
    // TODO: evaluate path compression
    auto result = depth(sdom(pred));
    do {
        if (depth(sdom(pred)) < result) {
            result = depth(sdom(pred));
        }
        pred = parent(pred);
    } while (depth(pred) > last_linked);
    return result;
}

template<typename T, typename Identify>
void
DominatorTreeBuildHelper<T, Identify>::init(const Graph &forward_graph,
                                            const T *root)
{
    auto vec_size = forward_graph.get_vertices().size();
    m_idoms.resize(vec_size, nullptr);
    m_ordered_vertices.reserve(vec_size);
    m_dfnums.resize(vec_size, 0);

    // preorder sort nodes in m_ordered_vertices
    DTDFSMarker<T> dfst_marker(m_ordered_vertices, m_idoms, m_dfnums);
    forward_graph.traverse_depth_first(dfst_marker, *root);
    m_sdom = m_idoms;
}

template<typename T, typename Identify>
bool
DominatorTreeBuildHelper<T, Identify>::validate_dom_tree(const Graph &backward_graph)
{
    // Implementation of dominator tree algorithm using iterative dataflow
    // based on Cooper et. al. "A Simple, Fast Dominance Algorithm". TR-06-33870

    // Note that the published algorithm in Figure 3 has a typo in method *intersect*.
    // Conditions for advancing fingers must be inversed.

    NodePtrVec v_idoms;
    v_idoms.resize(backward_graph.get_vertices().size(), nullptr);
    auto entry_node = m_ordered_vertices.front();
    v_idoms[NODE_ID(entry_node)] = entry_node;
    bool changed = true;
    while (changed) {
        changed = false;
        for (auto it = m_ordered_vertices.begin() + 1;
             it != m_ordered_vertices.end(); ++it) {
            const T *n = (*it);
            auto candidate = backward_graph.get_edges(*n).back();
            for (const auto &p : backward_graph.get_edges(*n)) {
                if (v_idoms[NODE_ID(p)] == nullptr || depth(p) == 0) {
                    // skip unvisited parents and infinite loops in postdom
                    continue;
                }
                if (depth(candidate) == 0) {
                    candidate = p;
                    continue;
                }
                auto finger1 = candidate;
                auto finger2 = p;
                while (finger1 != nullptr && finger2 != nullptr &&
                       *finger1 != *finger2) {
                    if (depth(finger1) > depth(finger2)) {
                        finger1 = v_idoms[NODE_ID(finger1)];
                    }
                    if (finger1 != nullptr && depth(finger2) > depth(finger1)) {
                        finger2 = v_idoms[NODE_ID(finger2)];
                    }
                }
                candidate = (finger1 != nullptr) ? finger1 : finger2;
            }
            if (v_idoms[NODE_ID(n)] == nullptr ||
                (*v_idoms[NODE_ID(n)]) != *candidate) {
                v_idoms[NODE_ID(n)] = candidate;
                changed = true;
            }
        }
    }

    bool result = true;
    for (auto it = m_ordered_vertices.begin() + 1;
         it != m_ordered_vertices.end(); ++it) {
        if (*v_idoms[NODE_ID(*it)] != *m_idoms[NODE_ID(*it)]) {
            DLOG(ERROR) << "domtree: invalid parent for bb @ " << NODE_ID(*it)
                        << " found " << NODE_ID(m_idoms[NODE_ID(*it)])
                        << " should be " << NODE_ID(v_idoms[NODE_ID(*it)]);
            result = false;
        }
    }
    return result;
}

template<typename T, typename Identify>
void DominatorTreeBuildHelper<T, Identify>::build(
    const DominatorTreeBuildHelper::Graph &backward_graph)
{
    DCHECK(ordered_vertices().size() > 2);
    for (unsigned i = (unsigned) ordered_vertices().size() - 1; i > 1; --i) {
        auto n = ordered_vertices()[i];
        auto semi = depth(sdom(n));
        for (const auto u : backward_graph.get_edges(*n)) {
            unsigned v = eval(u, i + 1);
            LOG_IF(v == 0, INFO) << "infinite loop head detected @ "
                                 << to_hex(u->address());
            if (v != 0 && v < semi) {
                semi = v;
            }
        }
        CHECK(semi > 0);
        set_sdom(n, get_node_at(semi));
    }

    for (auto it = ordered_vertices().begin() + 1;
         it != ordered_vertices().end(); ++it) {
        auto idom = m_idoms[NODE_ID(*it)];
        while (depth(idom) > depth(sdom(*it))) {
            idom = m_idoms[NODE_ID(idom)];
        }
        m_idoms[NODE_ID(*it)] = idom;
    }

    DLOG_IF(!validate_dom_tree(backward_graph), ERROR) << "dominator tree mismatch!";
}

//===============================================

struct DominatorTree::Impl {

    Impl();

    ~Impl() = default;

    const CFG::Node *idom(const CFG::Node *node) const
    { return m_idoms[node->id()]; }

    const CFG::Node *m_root;
    CFG::Graph m_dom_tree;
    CFG::VertexStore m_vertex_store;
    std::vector<const CFG::Node *> m_idoms;
};

DominatorTree::Impl::Impl()
    : m_root(nullptr), m_dom_tree(), m_idoms()
{ }

DominatorTree::DominatorTree()
    : m_impl(std::make_shared<Impl>())
{ }

const CFG::Node *
DominatorTree::root() const noexcept
{
    return m_impl->m_root;
}

const CFG::Node *
DominatorTree::idom(const CFG::Node *bb) const noexcept
{
    return m_impl->m_idoms[bb->id()];
}

const CFG::Graph &
DominatorTree::tree() const noexcept
{
    return m_impl->m_dom_tree;
}

bool
DominatorTree::dominates(const CFG::Node *a, const CFG::Node *b) const noexcept
{
    if (a->is_virtual() || b->is_virtual()) {
        return false;
    }
    auto current = b;
    while (current != nullptr && !current->is_virtual()) {
        if (*current == *a) {
            return true;
        }
        current = idom(current);
    }
    return false;
}

bool
DominatorTree::valid() const noexcept
{
    return m_impl->m_root != nullptr;
}

DominatorTree
DominatorTreeBuilder::build(const CFG::Node *root, const CFG::Graph &forward_graph,
                            const CFG::Graph &backward_graph)
{
    DominatorTree instance;
    DominatorTree::Impl &impl = *instance.m_impl;
    impl.m_root = root;
    DominatorTreeBuildHelper<CFG::Node> bd(impl.m_idoms);
    bd.init(forward_graph, root);

    bd.build(backward_graph);

    impl.m_vertex_store.init(forward_graph.get_vertices());
    impl.m_dom_tree.set_vertex_store(impl.m_vertex_store);
    for (auto it = bd.ordered_vertices().begin() + 1;
         it != bd.ordered_vertices().end(); ++it) {
        auto node = *it;
        impl.m_dom_tree.insert_edge(*impl.idom(node), *node);
    }
    return instance;
}

} // bcov
