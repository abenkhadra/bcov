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

#include "libelfin/elf/elf++.hh"
#include "util/Demangler.hpp"
#include "dwarf/EhFrame.hpp"
#include "flax/Flax.hpp"
#include "core/Function.hpp"
#include "core/Region.hpp"

BCOV_FORWARD(CallSite)
BCOV_FORWARD(Demangler)
BCOV_FORWARD(BcovConfig)

#define DOT_CALLGRAPH_DUMP_COUNT 100

namespace bcov {

class ElfFunction : public FunctionBase {
    friend class ElfModuleBuilder;

public:
    using LandingPads = std::vector<unsigned>;
    using CallSites = std::vector<CallSite>;

    ElfFunction();

    ElfFunction(sstring_view name, addr_t addr, const uint8_t *data, size_t size);

    ElfFunction(sstring_view name, addr_t got_address);

    ~ElfFunction() override = default;

    //===============================================

    addr_t got_offset() const noexcept;

    addr_t export_address() const noexcept;

    void add_call_site(CallSiteKind kind, addr_t src, addr_t target = 0);

    span<const CallSite> call_sites() const noexcept;

    uoffset_t eh_frame_offset() const noexcept;

    /// @brief return offsets of landing pads into the function
    const LandingPads &landing_pads() const noexcept;

    bool has_landing_pads() const noexcept;

    unsigned padding() const noexcept;

private:
    addr_t m_got_addr;
    addr_t m_export_addr;
    uint8_t m_padding;
    uint32_t m_eh_frame_offset;
    CallSites m_call_sites;
    LandingPads m_landing_pads;
};

static inline bool operator==(const ElfFunction &a, const ElfFunction &b)
{
    return a.address() == b.address();
}

static inline bool operator!=(const ElfFunction &a, const ElfFunction &b)
{
    return !(a == b);
}

template<>
struct identify<ElfFunction> {
    size_t operator()(const ElfFunction &f) const noexcept
    {
        return f.idx();
    }
};

class ElfCallGraph {
    friend class ElfModuleBuilder;

public:
    using Graph = OrderedGraph<ElfFunction>;

    const Graph &forward() const noexcept;

    const Graph &backward() const noexcept;

private:
    Graph::VertexStore m_store;
    Graph m_forward;
    Graph m_backward;
};

class ElfModule {
    friend class ElfModuleBuilder;

public:

    ElfModule();

    ElfModule(const ElfModule &other) = default;

    ElfModule &operator=(const ElfModule &other) = default;

    ElfModule(ElfModule &&other) noexcept = default;

    ElfModule &operator=(ElfModule &&other) noexcept = default;

    virtual ~ElfModule() = default;

    //===============================================

    span<const IFunction> probed_functions() const noexcept;

    span<const ElfFunction> static_functions() const noexcept;

    span<const ElfFunction> dynamic_functions() const noexcept;

    IFunction get_instrumented_function(sstring_view func_name) const;

    IFunction get_instrumented_function(addr_t func_address) const;

    ElfFunction *get_static_function_at(addr_t func_addr) const noexcept;

    ElfFunction *get_dynamic_function_at(addr_t func_addr) const noexcept;

    ElfFunction *
    get_dynamic_function_by_got(addr_t got_offset) const noexcept;

    ElfFunction *get_function_at(addr_t func_addr) const noexcept;

    ElfFunction *get_function_by_name(sstring_view func_name) const noexcept;

    bool exists(sstring_view func_name) const;

    const sstring &name() const noexcept;

    void name(sstring_view name) const noexcept;

    buffer_t get_buffer(addr_t address) const noexcept;

    bool is_inside_got_region(addr_t address) const noexcept;

    uint64_t read_address(addr_t address) const noexcept;

    const elf::elf &binary() const noexcept;

    Demangler *demangler() const noexcept;

    const dwarf::EhFrame &eh_frame() noexcept;

    const MemoryRegion &code_region() const noexcept;

    const MemoryRegion &data_region() const noexcept;

    bool is_position_independent_code() const noexcept;

protected:

    void add(IFunction function);

    void binary(elf::elf binary) noexcept;

    bool init_got_region() noexcept;

    void finalize() noexcept;

private:
    struct Impl;
    std::shared_ptr<Impl> m_impl;
};

class ElfModuleBuilder {
public:

    ElfModuleBuilder() = default;

    ElfModuleBuilder(const ElfModuleBuilder &other) = default;

    ElfModuleBuilder &operator=(const ElfModuleBuilder &other) = default;

    ElfModuleBuilder(ElfModuleBuilder &&other) noexcept = default;

    ElfModuleBuilder &operator=(ElfModuleBuilder &&other) noexcept = default;

    virtual ~ElfModuleBuilder() = default;

    static ElfModule build(sstring_view file, const BcovConfig &config);

    static ElfModule build(sstring_view file);

protected:
    static void do_initial_analyses(ElfModule &module);

private:
    struct Impl;
};

class ElfModuleBuilderException : public std::runtime_error {
public:
    explicit ElfModuleBuilderException(const std::string &what_arg);

    explicit ElfModuleBuilderException(const char *what_arg);

    ~ElfModuleBuilderException() override = default;
};

namespace dot {

void
write_call_graph(std::ostream &out, sstring_view graph_name, const ElfFunction &root,
                 const ElfCallGraph::Graph &graph,
                 unsigned max_node_count = DOT_CALLGRAPH_DUMP_COUNT);

void
write_call_graph(sstring_view file_name, sstring_view graph_name,
                 const ElfFunction &root, const ElfCallGraph::Graph &graph,
                 unsigned max_node_count = DOT_CALLGRAPH_DUMP_COUNT);

}
} // bcov
