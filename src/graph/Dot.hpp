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

#include "graph/CFG.hpp"
#include "graph/SuperBlock.hpp"

#define DOT_QUOTE_WORD(x)   "\"" << x << "\""
#define DOT_ATTR_SEP    ", "
#define DOT_NEWLINE  "\\l"

namespace bcov {
namespace dot {

enum class ValueType {
    kQuoted,
    KPlain
};

struct KeyValue {
    KeyValue() = default;

    ~KeyValue() = default;

    KeyValue(sstring_view key, sstring_view value,
             ValueType vtype = ValueType::kQuoted)
        : key(key.data()), value(value.data()), type(vtype)
    { }

    sstring key;
    sstring value;
    ValueType type;
};

using KeyValueList = std::vector<KeyValue>;
using PropertyList = std::vector<std::pair<sstring, KeyValueList>>;

void
write_attribute(std::ostream &out, const KeyValue &attr);

void
write_attribute_list(std::ostream &out, const KeyValueList &attrs);

void
write_property_list(std::ostream &out, const PropertyList &props);

void
write_edge(std::ostream &out, sstring_view src, sstring_view dst,
           const KeyValueList &attrs);

void
write_node(std::ostream &out, sstring_view node, const KeyValueList &attrs);

void
write_dot_header(std::ostream &out, sstring_view graph_name);

void
write_cfg(std::ostream &out, sstring_view graph_name,
          const CFG::Node *root, const CFG::Graph &graph);

void
write_cfg(sstring_view file_name, sstring_view graph_name,
          const CFG::Node *root, const CFG::Graph &graph);

void
write_domtree(std::ostream &out, sstring_view graph_name,
              const CFG::Node *root, const CFG::Graph &graph);

void
write_domtree(sstring_view file_name, sstring_view graph_name,
              const CFG::Node *root, const CFG::Graph &graph);

void
write_sb_graph(std::ostream &out, sstring_view graph_name,
               const SuperBlock *root, const SuperBlockStore::Graph &graph);

void
write_sb_graph(sstring_view file_name, sstring_view graph_name,
               const SuperBlock *root, const SuperBlockStore::Graph &graph);

} // dot
} // bcov
