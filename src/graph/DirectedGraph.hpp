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
#include <vector>
#include <unordered_map>
#include <queue>
#include <algorithm>
#include <type_traits>

namespace bcov {

enum class VertexStatus: unsigned char {
    kUnvisited,
    kTouched,
    kVisited
};

/// functor which returns a unique id of a vertex, please specialize
template<class T>
struct identify {
    size_t
    operator()(const T &arg) const noexcept
    {
        return reinterpret_cast<size_t>(&arg);
    }
};

template<class T>
class GraphVisitorBase {
public:
    /// @brief called once per node when visited in BFS
    virtual void visit(const T &vertex);

    /// @brief called once per node when first visited in DFS.
    virtual void visit_preorder(const T &vertex, const T *parent);

    /// @brief called once per node after visiting all children in DFS
    virtual void visit_postorder(const T &vertex, const T *parent);

    /// @brief called when an already seen node is re-discovered in DFS
    virtual void visit_peek(const T &vertex, const T &parent);

    virtual bool is_finished() const noexcept;

    virtual bool is_path_finished(const T &vertex) const noexcept;
};

template<class T>
void GraphVisitorBase<T>::visit(const T &vertex)
{
    UNUSED(vertex);
}

/// @brief called before visiting any child
template<class T>
void GraphVisitorBase<T>::visit_preorder(const T &vertex, const T *parent)
{
    UNUSED(vertex);
    UNUSED(parent);
}

/// @brief called after visiting all children
template<class T>
void GraphVisitorBase<T>::visit_postorder(const T &vertex, const T *parent)
{
    UNUSED(vertex);
    UNUSED(parent);
}

/// @brief to peek into a child which have already been seen before
template<class T>
void GraphVisitorBase<T>::visit_peek(const T &vertex, const T &parent)
{
    UNUSED(vertex);
    UNUSED(parent);
}

template<class T>
bool GraphVisitorBase<T>::is_finished() const noexcept
{
    return false;
}

template<class T>
bool GraphVisitorBase<T>::is_path_finished(const T &vertex) const noexcept
{
    UNUSED(vertex);
    return false;
}

class GraphException : public std::logic_error {
public:

    explicit GraphException(const std::string &what_arg) : logic_error(what_arg)
    { }

    explicit GraphException(const char *what_arg) : logic_error(what_arg)
    { }

    ~GraphException() override = default;
};

//===============================================

template<class T, class Identify = identify<T>>
class DirectedGraph {

public:
    using VertexId = size_t;
    using Vertices = std::unordered_map<VertexId, const T *>;
    using Edges = std::vector<const T *>;
    using AdjList = std::unordered_map<VertexId, Edges>;
    using VertexStatusMap = std::unordered_map<VertexId, VertexStatus>;

    DirectedGraph() = default;

    explicit DirectedGraph(span<const T> vertices) :
        m_vertices(),
        m_adjlist(),
        m_status_map()
    {
        insert_vertices(vertices);
    };

    ~DirectedGraph() = default;

    //===============================================

    /// @brief it is the user's responsability not to duplicate edges
    void insert_edge(const T &src, const T &dst)
    {
        const auto result = m_vertices.find(get_id(src));
        if (result != m_vertices.cend()) {
            m_adjlist[get_id(src)].push_back(get_ptr(dst));
        } else {
            throw GraphException("cannot insert edge for a nonexistent vertex");
        }
    }

    void insert_vertex(const T &vertex)
    {
        m_vertices[get_id(vertex)] = &vertex;
        m_adjlist[get_id(vertex)] = Edges();
        m_status_map[get_id(vertex)] = VertexStatus::kUnvisited;
    }

    void insert_vertices(span<const T> vertices)
    {
        for (const auto &vertex : vertices) {
            insert_vertex(vertex);
        }
    }

    void set_status(const T &vertex, VertexStatus status) const
    {
        m_status_map.at(get_id(vertex)) = status;
    }

    VertexStatus get_status(const T &vertex) const
    {
        return m_status_map.at(get_id(vertex));
    }

    VertexId get_id(const T &vertex) const
    {
        return Identify()(vertex);
    }

    const Edges &get_edges(const T &vertex) const
    {
        return m_adjlist.at(get_id(vertex));
    }

    const Vertices &
    get_vertices() const noexcept
    {
        return m_vertices;
    }

    void
    traverse_breadth_first(GraphVisitorBase<T> &visitor, const T &vertex) const
    {
        std::queue<const T *> vertex_queue;
        vertex_queue.push(get_ptr(vertex));
        while (!vertex_queue.empty() && !visitor.is_finished()) {
            auto current_vertex = vertex_queue.front();
            if (get_status(*current_vertex) != VertexStatus::kVisited) {
                visitor.visit(*current_vertex);
                for (auto child : get_edges(*current_vertex)) {
                    vertex_queue.push(child);
                }
                set_status(*current_vertex, VertexStatus::kVisited);
            }
            vertex_queue.pop();
        }
        reset_status();
    }

    void
    traverse_depth_first(GraphVisitorBase<T> &visitor, const T &vertex) const
    {
        traverse_depth_first_rec(visitor, vertex, nullptr);
        reset_status();
    }

    void reset_status() const
    {
        for (auto &vertex : m_vertices) {
            m_status_map[vertex.first] = VertexStatus::kUnvisited;
        }
    }

    void reset()
    {
        m_vertices.clear();
        m_adjlist.clear();
        m_status_map.clear();
    }

protected:
    void
    traverse_depth_first_rec(GraphVisitorBase<T> &visitor, const T &vertex,
                             const T *parent) const
    {
        if (visitor.is_finished()) {
            return;
        }
        visitor.visit_preorder(vertex, parent);
        if (visitor.is_path_finished(vertex)) {
            set_status(vertex, VertexStatus::kVisited);
            return;
        }
        set_status(vertex, VertexStatus::kTouched);
        for (auto child : get_edges(vertex)) {
            if (get_status(*child) != VertexStatus::kUnvisited) {
                traverse_depth_first_rec(visitor, *child, &vertex);
            } else {
                visitor.visit_peek(*child, vertex);
            }
        }
        visitor.visit_postorder(vertex, parent);
        set_status(vertex, VertexStatus::kVisited);
    }

    // fails if element does not exists
    const T *get_ptr(const T &vertex) const
    {
        return m_vertices.at(get_id(vertex));
    }

private:
    Vertices m_vertices;
    AdjList m_adjlist;
    mutable VertexStatusMap m_status_map;
};

template<typename T, typename E = size_t>
class OrderedVertexStore {
public:
    using Vertices = std::vector<const T *>;

    OrderedVertexStore() = default;

    ~OrderedVertexStore() = default;

    void insert_vertex(const T *vertex)
    {
        m_vertices.push_back(vertex);
    }

    void init(span<const T> vertices)
    {
        m_vertices.reserve(vertices.size());
        for (const auto &vertex : vertices) {
            insert_vertex(&vertex);
        }
    }

    void init(const Vertices &vertices)
    {
        m_vertices.reserve(vertices.size());
        for (const auto vertex : vertices) {
            insert_vertex(vertex);
        }
    }

    // fails if element does not exists
    const T *at(const E id) const
    {
        return m_vertices.at(id);
    }

    const Vertices &vertices() const noexcept
    {
        return m_vertices;
    }

    void reset() noexcept
    {
        m_vertices.clear();
    }

private:
    Vertices m_vertices;
};

//===============================================

template<typename T, typename Identify = identify<T>>
class OrderedGraph {
public:
    using VertexId = size_t;
    using VertexStore = OrderedVertexStore<T, size_t>;
    using Vertices = typename VertexStore::Vertices;
    using Edges = std::vector<const T *>;
    using AdjList = std::vector<Edges>;
    using VertexStatusMap = std::vector<VertexStatus>;

    OrderedGraph() : m_store(nullptr)
    { }

    explicit OrderedGraph(const VertexStore &vertex_store)
    { set_vertex_store(vertex_store); }

    ~OrderedGraph() = default;

    void resize()
    {
        m_adjlist.resize(m_store->vertices().size());
        m_status_map.resize(m_store->vertices().size(), VertexStatus::kUnvisited);
    }

    void set_vertex_store(const VertexStore &vertex_store)
    {
        m_store = &vertex_store;
        m_adjlist.clear();
        m_status_map.clear();
        m_adjlist.resize(m_store->vertices().size());
        m_status_map.resize(m_store->vertices().size(), VertexStatus::kUnvisited);
    }

    // it is the user's responsability not to duplicate edges
    void insert_edge(const T &src, const T &dst)
    {
        m_adjlist.at(get_id(src)).push_back(get_ptr(dst));
    }

    void remove_edge(const T &src, const T &dst)
    {
        Edges &edges = m_adjlist.at(get_id(src));
        auto it = std::find_if(edges.begin(), edges.end(),
                               [&dst](const T *v) { return *v == dst; });
        if (it != edges.end()) {
            edges.erase(it);
        }
    }

    bool edge_exists(const T &src, const T &dst)
    {
        Edges &edges = m_adjlist.at(get_id(src));
        auto it = std::find_if(edges.begin(), edges.end(),
                               [&dst](const T *v) { return *v == dst; });
        return it != edges.end();
    }

    void set_status(const T &vertex, VertexStatus status) const
    {
        m_status_map.at(get_id(vertex)) = status;
    }

    VertexStatus get_status(const T &vertex) const
    {
        return m_status_map.at(get_id(vertex));
    }

    VertexId get_id(const T &vertex) const
    {
        return Identify()(vertex);
    }

    const Edges &get_edges(const T &vertex) const
    {
        return m_adjlist.at(get_id(vertex));
    }

    const Vertices &get_vertices() const noexcept
    {
        return m_store->vertices();
    }

    void traverse_breadth_first(GraphVisitorBase<T> &visitor, const T &vertex) const
    {
        std::queue<const T *> vertex_queue;
        vertex_queue.push(get_ptr(vertex));
        while (!vertex_queue.empty() && !visitor.is_finished()) {
            auto current_vertex = vertex_queue.front();
            if (get_status(*current_vertex) != VertexStatus::kVisited) {
                visitor.visit(*current_vertex);
                for (auto child : get_edges(*current_vertex)) {
                    vertex_queue.push(child);
                }
                set_status(*current_vertex, VertexStatus::kVisited);
            }
            vertex_queue.pop();
        }
        reset_status();
    }

    void traverse_depth_first(GraphVisitorBase<T> &visitor, const T &vertex) const
    {
        traverse_depth_first_rec(visitor, vertex, nullptr);
        reset_status();
    }

    void reset_status() const
    {
        for (auto &status : m_status_map) {
            status = VertexStatus::kUnvisited;
        }
    }

    void clear_edges(const T &vertex)
    {
        m_adjlist.at(get_id(vertex)).clear();
    }

    // fails if element does not exists
    const T *get_ptr(const T &vertex) const
    {
        return m_store->at(get_id(vertex));
    }

    void reset()
    {
        m_adjlist.clear();
        m_status_map.clear();
    }

protected:
    void
    traverse_depth_first_rec(GraphVisitorBase<T> &visitor, const T &vertex,
                             const T *parent) const
    {
        if (visitor.is_finished()) {
            return;
        }
        visitor.visit_preorder(vertex, parent);
        if (visitor.is_path_finished(vertex)) {
            set_status(vertex, VertexStatus::kVisited);
            return;
        }
        set_status(vertex, VertexStatus::kTouched);
        for (auto child : get_edges(vertex)) {
            auto status = get_status(*child);
            if (status == VertexStatus::kUnvisited) {
                traverse_depth_first_rec(visitor, *child, &vertex);
            } else {
                visitor.visit_peek(*child, vertex);
            }
        }
        visitor.visit_postorder(vertex, parent);
        set_status(vertex, VertexStatus::kVisited);
    }

private:
    const OrderedVertexStore<T> *m_store;
    AdjList m_adjlist;
    mutable VertexStatusMap m_status_map;
};

} // bcov
