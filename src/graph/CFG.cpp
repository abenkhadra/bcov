/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include "CFG.hpp"
#include "graph/DirectedGraph.hpp"

namespace bcov {

struct CFG::Impl {

    Impl();

    ~Impl() = default;

    BasicBlock m_entry;
    BasicBlock m_exit;
    CFG::VertexStore m_vertex_store;
    CFG::Graph m_successors;
    CFG::Graph m_predecessors;
};

CFG::Impl::Impl()
{
    m_entry.kind(BasicBlockKind::kEntry);
    m_exit.kind(BasicBlockKind::kExit);
}

CFG::CFG() : m_impl(std::make_shared<Impl>())
{

}

const BasicBlock *
CFG::virtual_entry() const noexcept
{
    return &m_impl->m_entry;
}

const BasicBlock *
CFG::virtual_exit() const noexcept
{
    return &m_impl->m_exit;
}

void
CFG::basic_blocks(span<const BasicBlock> basic_blocks)
{
    m_impl->m_vertex_store.init(basic_blocks);
    m_impl->m_successors.set_vertex_store(m_impl->m_vertex_store);
    m_impl->m_predecessors.set_vertex_store(m_impl->m_vertex_store);
    m_impl->m_entry.id(basic_blocks.size());
    m_impl->m_exit.id(basic_blocks.size() + 1);
    m_impl->m_vertex_store.insert_vertex(&m_impl->m_entry);
    m_impl->m_vertex_store.insert_vertex(&m_impl->m_exit);
    m_impl->m_successors.resize();
    m_impl->m_predecessors.resize();
}

void
CFG::reset()
{
    m_impl->m_vertex_store.reset();
    m_impl->m_successors.reset();
    m_impl->m_predecessors.reset();
}

const CFG::Edges &
CFG::successors(const BasicBlock &bb) const
{
    return m_impl->m_successors.get_edges(bb);
}

const CFG::Edges &
CFG::predecessors(const BasicBlock &bb) const
{
    return m_impl->m_predecessors.get_edges(bb);
}

void
CFG::insert_edge(const BasicBlock &src, const BasicBlock &dst)
{
    m_impl->m_successors.insert_edge(src, dst);
    m_impl->m_predecessors.insert_edge(dst, src);
}

void
CFG::reset_padding_edges(const BasicBlock &bb)
{
    auto succ = m_impl->m_successors.get_edges(bb)[0];
    m_impl->m_predecessors.remove_edge(*succ, bb);
    reset_edges(bb);
}

void
CFG::reset_edges(const BasicBlock &bb)
{
    m_impl->m_successors.clear_edges(bb);
    m_impl->m_predecessors.clear_edges(bb);
}

void
CFG::add_entry_block(const BasicBlock &bb)
{
    insert_edge(m_impl->m_entry, bb);
}

void
CFG::add_exit_block(const BasicBlock &bb)
{
    insert_edge(bb, m_impl->m_exit);
}

const CFG::Graph &
CFG::forward() const noexcept
{
    return m_impl->m_successors;
}

const CFG::Graph &
CFG::backward() const noexcept
{
    return m_impl->m_predecessors;
}

size_t
CFG::size() const noexcept
{
    return m_impl->m_vertex_store.vertices().size();
}

} // bcov
