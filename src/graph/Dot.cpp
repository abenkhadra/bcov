/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include "Dot.hpp"
#include "core/Function.hpp"
#include <fstream>

namespace bcov {
namespace dot {

void
write_attribute(std::ostream &out, const KeyValue &attr)
{
    out << attr.key << "=";
    if (attr.type == ValueType::kQuoted) {
        out << DOT_QUOTE_WORD(attr.value);
    } else {
        out << attr.value;
    }
}

void
write_attribute_list(std::ostream &out, const KeyValueList &attrs)
{
    out << " [";
    auto keyval_it = attrs.cbegin();
    for (; keyval_it < attrs.cend() - 1; ++keyval_it) {
        write_attribute(out, *keyval_it);
        out << DOT_ATTR_SEP;
    }
    if (keyval_it < attrs.cend()) {
        write_attribute(out, *keyval_it);
    }
    out << "];\n";
}

void
write_property_list(std::ostream &out, const PropertyList &props)
{
    for (const auto &property : props) {
        out << property.first;
        write_attribute_list(out, property.second);
    }
}

void
write_edge(std::ostream &out, sstring_view src, sstring_view dst,
           const KeyValueList &attrs)
{
    out << DOT_QUOTE_WORD(src) << " -> " << DOT_QUOTE_WORD(dst);
    write_attribute_list(out, attrs);
}

void
write_node(std::ostream &out, sstring_view node, const KeyValueList &attrs)
{
    out << DOT_QUOTE_WORD(node);
    write_attribute_list(out, attrs);
}

void
write_dot_header(std::ostream &out, sstring_view graph_name)
{
    KeyValueList graph_props;
    graph_props.emplace_back(KeyValue("bgcolor", "azure", ValueType::KPlain));
    graph_props.emplace_back(KeyValue("fontsize", "8", ValueType::KPlain));
    graph_props.emplace_back(KeyValue("fontname", "Courier"));
    graph_props.emplace_back(KeyValue("splines", "ortho"));

    KeyValueList node_props;
    node_props.emplace_back(KeyValue("fillcolor", "azure", ValueType::KPlain));
    node_props.emplace_back(KeyValue("style", "filled", ValueType::KPlain));
    node_props.emplace_back(KeyValue("shape", "box", ValueType::KPlain));

    KeyValueList edge_props;
    edge_props.emplace_back(KeyValue("arrowhead", "normal", ValueType::KPlain));

    PropertyList properties = {{"graph", graph_props},
                               {"node",  node_props},
                               {"edge",  edge_props}};
    out << "digraph " << graph_name << " { \n";
    write_property_list(out, properties);
}


//===============================================

class DotCFGVisitor : public GraphVisitorBase<CFG::Node> {
public:
    explicit DotCFGVisitor(std::ostream &out, const CFG::Graph &graph);

    void
    visit(const CFG::Node &bb) override;

    void
    write_basic_block(std::ostream &out, const CFG::Graph &graph,
                      const BasicBlock &bb);

private:
    std::ostream &m_out;
    const CFG::Graph &m_graph;
    KeyValueList m_bb_attrs;
    KeyValueList m_cond_jump_near_attrs;
    KeyValueList m_cond_jump_far_attrs;
    KeyValueList m_uncond_jump_attrs;
    KeyValueList m_jump_tab_attrs;
};

DotCFGVisitor::DotCFGVisitor(std::ostream &out, const CFG::Graph &graph)
    : m_out(out), m_graph(graph)
{
    m_bb_attrs.emplace_back(KeyValue("fillcolor", "palegreen"));
    m_bb_attrs.emplace_back(KeyValue("color", "#7f7f7f"));
    m_bb_attrs.emplace_back(KeyValue("fontname", "Courier"));
    m_bb_attrs.emplace_back(KeyValue("label", " "));
    m_cond_jump_near_attrs.emplace_back(KeyValue("color", "red"));
    m_cond_jump_far_attrs.emplace_back(KeyValue("color", "green"));
    m_uncond_jump_attrs.emplace_back(KeyValue("color", "blue"));
    m_jump_tab_attrs.emplace_back(KeyValue("color", "black"));
}

void
DotCFGVisitor::visit(const CFG::Node &bb)
{
    write_basic_block(m_out, m_graph, bb);
}

void
DotCFGVisitor::write_basic_block(std::ostream &out, const CFG::Graph &graph,
                                 const BasicBlock &bb)
{
    if (bb.is_virtual()) {
        return;
    }
    sstring bb_label =
        "loc:0x" + to_hex(bb.address()) + " | idx:" + std::to_string(bb.id()) +
        DOT_NEWLINE;
    for (const auto &inst: bb.instructions()) {
        bb_label += sstring(inst.text().data()) + DOT_NEWLINE;
    }

    m_bb_attrs.back().value = bb_label;
    write_node(out, to_hex(bb.address()), m_bb_attrs);
    auto &successors = graph.get_edges(bb);
    if (successors.size() == 1) {
        if (!successors.front()->is_virtual()) {
            write_edge(out, to_hex(bb.address()),
                       to_hex(successors.front()->address()), m_uncond_jump_attrs);
        }
        return;
    }
    if (successors.size() == 2) {
        write_edge(out, to_hex(bb.address()), to_hex(successors.front()->address()),
                   m_cond_jump_near_attrs);
        write_edge(out, to_hex(bb.address()), to_hex(successors.back()->address()),
                   m_cond_jump_far_attrs);
        return;
    }

    for (const auto &next: successors) {
        write_edge(out, to_hex(bb.address()), to_hex(next->address()),
                   m_jump_tab_attrs);
    }
}

//==============================================================================

class SuperBlockGraphVisitor : public GraphVisitorBase<SuperBlockStore::Node> {
public:
    explicit SuperBlockGraphVisitor(std::ostream &out,
                                    const SuperBlockStore::Graph &graph);

    void visit(const SuperBlockStore::Node &sb) override;

    void write_super_block(std::ostream &out, const SuperBlockStore::Graph &graph,
                           const SuperBlock &sb);

private:
    std::ostream &m_out;
    const SuperBlockStore::Graph &m_graph;
    KeyValueList m_sb_attrs;
    KeyValueList m_edge_attrs;
};

SuperBlockGraphVisitor::SuperBlockGraphVisitor(std::ostream &out,
                                               const SuperBlockStore::Graph &graph)
    : m_out(out), m_graph(graph)
{
    m_sb_attrs.emplace_back(KeyValue("fillcolor", "palegreen"));
    m_sb_attrs.emplace_back(KeyValue("color", "#7f7f7f"));
    m_sb_attrs.emplace_back(KeyValue("fontname", "Courier"));
    m_sb_attrs.emplace_back(KeyValue("label", " "));
    m_edge_attrs.emplace_back(KeyValue("color", "blue"));
}

void
SuperBlockGraphVisitor::visit(const SuperBlockStore::Node &sb)
{
    write_super_block(m_out, m_graph, sb);
}

void
SuperBlockGraphVisitor::write_super_block(std::ostream &out,
                                          const SuperBlockStore::Graph &graph,
                                          const SuperBlock &sb)
{
    if (sb.kind() == SuperBlockKind::kNone) {
        m_sb_attrs.front().value = "palegreen";
    } else if (sb.kind() == SuperBlockKind::kAllNode) {
        m_sb_attrs.front().value = "lightblue";
    } else {
        m_sb_attrs.front().value = "orange";
    }

    auto bb_it = sb.basic_blocks().cbegin();
    sstring sb_label = "idx:" + std::to_string(sb.idx()) + DOT_NEWLINE;
    sb_label += std::to_string((*bb_it)->id());
    for (++bb_it; bb_it < sb.basic_blocks().cend(); ++bb_it) {
        sb_label += "," + std::to_string((*bb_it)->id());
    }
    m_sb_attrs.back().value = sb_label;
    write_node(out, std::to_string(sb.idx()), m_sb_attrs);
    for (const auto succ: graph.get_edges(sb)) {
        write_edge(out, std::to_string(sb.idx()), std::to_string(succ->idx()),
                   m_edge_attrs);
    }
}

//==============================================================================

class DotDomTreeVisitor : public GraphVisitorBase<CFG::Node> {
public:
    explicit DotDomTreeVisitor(std::ostream &out, const CFG::Graph &graph);

    void visit(const CFG::Node &bb) override;

    void write_basic_block(std::ostream &out, const CFG::Graph &graph,
                           const BasicBlock &bb);

private:
    std::ostream &m_out;
    const CFG::Graph &m_graph;
    KeyValueList m_bb_attrs;
    KeyValueList m_jump_attrs;
};

DotDomTreeVisitor::DotDomTreeVisitor(std::ostream &out, const CFG::Graph &graph)
    : m_out(out), m_graph(graph)
{
    m_bb_attrs.emplace_back(KeyValue("fillcolor", "palegreen"));
    m_bb_attrs.emplace_back(KeyValue("color", "#7f7f7f"));
    m_bb_attrs.emplace_back(KeyValue("fontname", "Courier"));
    m_bb_attrs.emplace_back(KeyValue("label", " "));
    m_jump_attrs.emplace_back(KeyValue("color", "blue"));
}

void
DotDomTreeVisitor::visit(const CFG::Node &bb)
{
    write_basic_block(m_out, m_graph, bb);
}

void
DotDomTreeVisitor::write_basic_block(std::ostream &out, const CFG::Graph &graph,
                                     const BasicBlock &bb)
{
    sstring bb_label =
        "loc:0x" + to_hex(bb.address()) + " | idx:" + std::to_string(bb.id()) +
        DOT_NEWLINE;
    for (const auto &inst: bb.instructions()) {
        bb_label += sstring(inst.text().data()) + DOT_NEWLINE;
    }

    m_bb_attrs.back().value = bb_label;
    write_node(out, to_hex(bb.address()), m_bb_attrs);
    for (const auto &succ: graph.get_edges(bb)) {
        write_edge(out, to_hex(bb.address()), to_hex(succ->address()), m_jump_attrs);
    }
}

//===============================================
void
write_cfg(std::ostream &out, sstring_view graph_name, const CFG::Node *root,
          const CFG::Graph &graph)
{
    write_dot_header(out, graph_name);
    DotCFGVisitor visitor(out, graph);
    graph.traverse_breadth_first(visitor, *root);
    out << "} \n";
}

void
write_cfg(sstring_view file_name, sstring_view graph_name,
          const CFG::Node *root, const CFG::Graph &graph)
{
    std::ofstream output_file;
    output_file.open(file_name.data());
    write_cfg(output_file, graph_name, root, graph);
    output_file.close();
}

void
write_domtree(std::ostream &out, sstring_view graph_name,
              const CFG::Node *root, const CFG::Graph &graph)
{
    write_dot_header(out, graph_name);
    DotDomTreeVisitor visitor(out, graph);
    graph.traverse_breadth_first(visitor, *root);
    out << "} \n";
}

void
write_domtree(sstring_view file_name, sstring_view graph_name,
              const CFG::Node *root, const CFG::Graph &graph)
{
    std::ofstream output_file;
    output_file.open(file_name.data());
    write_domtree(output_file, graph_name, root, graph);
    output_file.close();
}

void
write_sb_graph(std::ostream &out, sstring_view graph_name,
               const SuperBlock *root, const SuperBlockStore::Graph &graph)
{
    write_dot_header(out, graph_name);
    SuperBlockGraphVisitor visitor(out, graph);
    graph.traverse_breadth_first(visitor, *root);
    out << "} \n";
}

void
write_sb_graph(sstring_view file_name, sstring_view graph_name,
               const SuperBlock *root, const SuperBlockStore::Graph &graph)
{
    std::ofstream output_file;
    output_file.open(file_name.data());
    write_sb_graph(output_file, graph_name, root, graph);
    output_file.close();
}

} // dot
} // bcov
