/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include <set>
#include <algorithm>
#include <map>
#include "dump/patch.h"
#include "util/BcovConfig.hpp"
#include "core/FunctionBuilder.hpp"
#include "elf/ElfParser.hpp"
#include "easylogging/easylogging++.h"
#include "core/CSInstWrapper.hpp"
#include "core/Disassembler.hpp"
#include "graph/DirectedGraph.hpp"
#include "x64/Inst.hpp"
#include "util/FileUtil.hpp"
#include "util/ElfData.hpp"
#include "util/Demangler.hpp"
#include "graph/Dot.hpp"
#include "Util.hpp"
#include "ElfModule.hpp"

namespace bcov {

using FuncSymtab = std::map<sstring, elf::Sym<>>;
using GotDynFuncMap = std::map<addr_t, ElfFunction *>;
using IndexGotVec = std::vector<std::pair<uint32_t, uint64_t>>;
using DynSymValuePairVec = std::vector<std::pair<const char *, elf::Elf64::Addr>>;

static const std::array<czstring, 3> IgnorableStaticFunctions =
    {"_start", "__libc_csu_init", "__libc_csu_fini"};

template<typename T>
inline std::shared_ptr<T> make_shared_array(int size)
{
    return std::shared_ptr<T>(new T[size], [](T *p) { delete[] p; });
}

enum class NoReturnAnalysisPhase : char {
    kFirst = 0,
    kSecond,
    kThird
};

static inline bool
is_abi_noreturn_function(sstring_view func_name)
{
    return func_name == "__stack_chk_fail";
}

static void
initialize_known_noreturn_funcs(std::set<sstring> &noreturn_funcs)
{
    noreturn_funcs = {

        // functexcept.h: internal header which provides support for -fno-exceptions.
        //std::__throw_regex_error(std::regex_constants::error_type)
        //std::__throw_length_error(char const*)
        //std::__throw_domain_error(char const*)
        //std::__throw_out_of_range_fmt(char const*, ...)
        //std::__throw_bad_function_call()
        //std::__throw_runtime_error(char const*)
        //std::__throw_bad_cast()
        //std::__throw_bad_alloc()
        //std::__throw_bad_typeid()
        //std::__throw_range_error(char const*)
        //std::__throw_bad_exception()
        //std::__throw_system_error(int)
        //std::__throw_ios_failure(char const*)
        //std::__throw_out_of_range(char const*)
        //std::__throw_logic_error(char const*)
        //std::__throw_invalid_argument(char const*)
        //std::__throw_future_error(int)
        //std::__throw_underflow_error(char const*)
        //std::__throw_overflow_error(char const*)


        "_ZSt19__throw_regex_errorNSt15regex_constants10error_typeE",
        "_ZSt20__throw_length_errorPKc",
        "_ZSt20__throw_domain_errorPKc",
        "_ZSt24__throw_out_of_range_fmtPKcz",
        "_ZSt25__throw_bad_function_callv",
        "_ZSt21__throw_runtime_errorPKc",
        "_ZSt16__throw_bad_castv",
        "_ZSt17__throw_bad_allocv",
        "_ZSt18__throw_bad_typeidv",
        "_ZSt19__throw_range_errorPKc",
        "_ZSt21__throw_bad_exceptionv",
        "_ZSt20__throw_system_errori",
        "_ZSt19__throw_ios_failurePKc",
        "_ZSt20__throw_out_of_rangePKc",
        "_ZSt19__throw_logic_errorPKc",
        "_ZSt24__throw_invalid_argumentPKc",
        "_ZSt20__throw_future_errori",
        "_ZSt23__throw_underflow_errorPKc",
        "_ZSt22__throw_overflow_errorPKc",

        // standard c++ noreturn functions (abi)
        // see https://en.cppreference.com/w/cpp/language/attributes/noreturn
        // std::terminate
        "_ZSt9terminatev",
        // std::unexpected
        "_ZSt10unexpectedv",
        // std::rethrow_exception
        "_ZSt17rethrow_exceptionNSt15__exception_ptr13exception_ptrE",

        // cxxabi.h, c++ abi functions for exception handling are not mangled
        "__cxa_throw",
        "__cxa_rethrow",
        "__cxa_bad_cast",
        "__cxa_bad_typeid",
        "__cxa_throw_bad_array_new_length",
        "__cxa_pure_virtual",
        "__cxa_deleted_virtual",
        "__cxa_call_unexpected",

        // _Unwind_Resume is the only routine in the unwind library expected to
        // be called directly by generated code.
        "_Unwind_Resume",

        // for the sake of completeness, c allows calling main() while c++ does not
        "main",

        // stdlib.h
        "abort", "exit", "_Exit", "quick_exit",

        // unistd.h
        "_exit",

        // linux/unistd.h
        "exit_group",

        // setjmp.h
        "longjmp", "_longjmp", "siglongjmp", "__longjmp_chk",
        "__libc_siglongjmp", "__libc_longjmp",

        // stdio.h (glibc)
        "__libc_fatal", "__fortify_fail", "__fortify_fail_abort",

        // err.h
        "err", "verr", "errx", "verrx",

        // assert.h
        "__assert_fail", "__assert_perror_fail", "__assert",

        // assert.h (glibc)
        "__assert_fail_base",

        // stdio.h (glibc)
        "__libc_fatal", "__fortify_fail", "__fortify_fail_abort",

        // pthread.h (glibc)
        "pthread_exit", "__pthread_unwind_next", "__pthread_unwind",

        // exit.h (glibc)
        "__run_exit_handlers",

        // obstack.h (glibc)
        "obstack_alloc_failed_handler",

        // LSB 4.1. libc interface
        "__libc_start_main", "__stack_chk_fail", "__chk_fail",

        // misc functions
        "_hurd_exit", "__exit_thread", "thrd_exit"

        // TODO error is a mayreturn function
    };
}

static Permissions
to_bcov_permissions(elf::pf flags)
{
    using namespace elf;
    auto result = Permissions::None;
    if ((flags & pf::x) == pf::x) {
        result = result | Permissions::X;
    }
    if ((flags & pf::r) == pf::r) {
        result = result | Permissions::R;
    }
    if ((flags & pf::w) == pf::w) {
        result = result | Permissions::W;
    }
    return result;
}

static inline bool
is_known_noreturn_func(sstring_view name,
                       const std::set<sstring> &known_noreturn_funcs)
{
    const auto result = known_noreturn_funcs.find(name.data());
    return result != known_noreturn_funcs.cend();
}

static void
read_landing_pads(const dwarf::LSDA &lsda, const dwarf::DwarfPointerReader &reader,
                  ElfFunction::LandingPads &landing_pads)
{
    auto pp = lsda.call_site_tbl_start();
    const auto encoding = lsda.call_site_encoding();
    std::set<unsigned> landing_pad_set;
    while (pp < lsda.call_site_tbl_end()) {
        unsigned len;
        dwarf::LSDACallSiteEntry entry(pp, encoding);
        auto land_pad = reader.read(entry.landing_pad(), absolute(encoding), &len);
        if (land_pad != 0 &&
            landing_pad_set.find(land_pad) == landing_pad_set.end()) {
            landing_pads.push_back((unsigned) land_pad);
            landing_pad_set.insert((unsigned) land_pad);
        }
        pp = entry.next();
    }

    std::sort(landing_pads.begin(), landing_pads.end());
}

static CallSiteKind
get_call_site_kind(const cs_insn *inst)
{
    if (x64::is_return(inst))
        return CallSiteKind::kReturn;
    CallSiteKind result;
    if (x64::is_call(inst)) {
        result = CallSiteKind::kDirectCall;
    } else if (x64::is_trap(inst)) {
        result = CallSiteKind::kTrap;
    } else {
        result = CallSiteKind::kDirectTail;
    }
    return result;
}

static void
parse_rela_dyn_section(const ElfModule &module, const elf::section &sec,
                       IndexGotVec &rela_entries)
{
    auto end_entry = (const Elf64_Rela *) ((uint8_t *) sec.data() + sec.size());
    for (auto rela_entry = (Elf64_Rela *) sec.data();
         rela_entry < end_entry; ++rela_entry) {

        const auto idx = ELF64_R_SYM(rela_entry->r_info);
        const auto type = ELF64_R_TYPE(rela_entry->r_info);

        if (type == R_X86_64_GLOB_DAT &&
            module.is_inside_got_region(rela_entry->r_offset)) {
            rela_entries.emplace_back(std::make_pair(idx, rela_entry->r_offset));
        }
    }
}

static void
parse_rela_plt_section(const elf::section &rela_plt_sec, IndexGotVec &rela_entries)
{
    auto end_entry = (const Elf64_Rela *) ((uint8_t *) rela_plt_sec.data() +
                                           rela_plt_sec.size());
    for (auto rela_entry = (Elf64_Rela *) rela_plt_sec.data();
         rela_entry < end_entry; ++rela_entry) {

        const auto idx = ELF64_R_SYM(rela_entry->r_info);
        const auto type = ELF64_R_TYPE(rela_entry->r_info);

        if (type == R_X86_64_JUMP_SLOT) {
            rela_entries.emplace_back(std::make_pair(idx, rela_entry->r_offset));
        }
    }
}

static void
parse_dyn_sym_section(const elf::section &dyn_sym_sec,
                      DynSymValuePairVec &dyn_syms,
                      std::set<const char *> &dyn_func_name_set)
{
    size_t len;
    auto symtab = dyn_sym_sec.as_symtab();
    CHECK(symtab.valid());
    for (const auto &sym : symtab) {
        if (sym.get_data().type() == elf::stt::func) {
            auto result = dyn_func_name_set.insert(sym.get_name(&len));
            if (!result.second) {
                DLOG(WARNING) << "duplicate dynamic function symbol: "
                              << *result.first;
            }
        }
        dyn_syms.emplace_back(
            std::make_pair(sym.get_name(&len), sym.get_data().value));
    }
}

static addr_t
read_got_offset(const ElfModule &module, csh disasm, cs_insn *cs_inst, addr_t addr)
{
    auto data = module.get_buffer(addr);
    DCHECK(data != nullptr);
    size_t byte_size = x64::kMaxInstSize;

    auto result = cs_disasm_iter(disasm, &data, &byte_size, &addr, cs_inst);
    if (!result || !x64::is_jump(cs_inst) || !x64::has_rip_rel_const_opnd(cs_inst)) {
        return 0;
    }
    // capstone automatically modifies addr to next instruction
    return addr + cs_inst->detail->x86.operands[0].mem.disp;
}

static inline void
log_noreturn_status(const ElfFunction *func, NoReturnAnalysisPhase phase)
{
    if (is_attr_set(func->attrs(), FunctionAttrs::kReturn)) {
        return;
    }
    VLOG(3) << func->name() << ": phase-" << (char) ((uint8_t) phase + (uint8_t) '1')
            << " inferred function is "
            << (is_attr_set(func->attrs(), FunctionAttrs::kNoReturn) ? "noreturn"
                                                                     : "mayreturn");
}

//==============================================================================

ElfFunction::ElfFunction() :
    FunctionBase(),
    m_got_addr(0),
    m_eh_frame_offset(0)
{ }

ElfFunction::ElfFunction(sstring_view name, addr_t addr, const uint8_t *data,
                         size_t size) :
    FunctionBase(name, addr, data, size),
    m_got_addr(0),
    m_eh_frame_offset(0)
{ }

ElfFunction::ElfFunction(sstring_view name, addr_t got_address) :
    FunctionBase(name, 0, nullptr, 0),
    m_got_addr(got_address),
    m_eh_frame_offset(0)
{ }

addr_t
ElfFunction::got_offset() const noexcept
{
    return m_got_addr;
}

addr_t
ElfFunction::export_address() const noexcept
{
    return is_attr_set(attrs(), FunctionAttrs::kExported) ? m_export_addr : 0;
}

void
ElfFunction::add_call_site(CallSiteKind kind, addr_t src, addr_t target)
{
    m_call_sites.emplace_back(CallSite(kind, src, target));
}

span<const CallSite>
ElfFunction::call_sites() const noexcept
{
    return {&m_call_sites.front(), m_call_sites.size()};
}

uoffset_t
ElfFunction::eh_frame_offset() const noexcept
{
    return m_eh_frame_offset;
}

const ElfFunction::LandingPads &
ElfFunction::landing_pads() const noexcept
{
    return m_landing_pads;
}

bool
ElfFunction::has_landing_pads() const noexcept
{
    return !m_landing_pads.empty();
}

//==============================================================================
const ElfCallGraph::Graph &
ElfCallGraph::forward() const noexcept
{
    return m_forward;
}

const ElfCallGraph::Graph &
ElfCallGraph::backward() const noexcept
{
    return m_backward;
}

unsigned
ElfFunction::padding() const noexcept
{
    return m_padding;
}

//==============================================================================

struct ElfModule::Impl {
    static constexpr unsigned kUninitializedRegionIdx = 0;

    Impl();

    explicit Impl(sstring_view name);

    ~Impl() = default;

    sstring m_name;
    elf::elf m_binary;
    std::vector<IFunction> m_instrumented_funcs;
    std::vector<ElfFunction> m_static_funcs;
    std::vector<ElfFunction> m_dynamic_funcs;
    std::unordered_map<addr_t, ElfFunction *> m_addr_func_map;
    std::map<sstring, ElfFunction *> m_name_func_map;
    std::map<addr_t, ElfFunction *> m_func_alias_map;
    dwarf::EhFrame m_eh_frame;
    std::vector<MemoryRegion> m_mem_regions;
    ElfCallGraph m_call_graph;
    std::shared_ptr<uint8_t> m_data_region_buf;
    mutable Demangler m_demangler;
    bool m_is_position_independent_code = true;
    uint8_t m_code_region_idx = kUninitializedRegionIdx;
    uint8_t m_data_region_idx = kUninitializedRegionIdx;
    uint8_t m_got_region_idx = kUninitializedRegionIdx;
    uint8_t m_got_plt_region_idx = kUninitializedRegionIdx;
};

ElfModule::Impl::Impl() :
    m_name("Dummy")
{
}

ElfModule::Impl::Impl(sstring_view name) :
    m_name(name.data(), name.size())
{
}

ElfModule::ElfModule() :
    m_impl(std::make_shared<Impl>())
{
}

span<const IFunction>
ElfModule::probed_functions() const noexcept
{
    return {&m_impl->m_instrumented_funcs.front(),
            m_impl->m_instrumented_funcs.size()};
}

span<const ElfFunction>
ElfModule::static_functions() const noexcept
{
    return {&m_impl->m_static_funcs.front(), m_impl->m_static_funcs.size()};
}

span<const ElfFunction>
ElfModule::dynamic_functions() const noexcept
{
    return {&m_impl->m_dynamic_funcs.front(), m_impl->m_dynamic_funcs.size()};
}

const dwarf::EhFrame &
ElfModule::eh_frame() noexcept
{
    return m_impl->m_eh_frame;
}

const MemoryRegion &
ElfModule::code_region() const noexcept
{
    return m_impl->m_mem_regions[m_impl->m_code_region_idx];
}

const MemoryRegion &
ElfModule::data_region() const noexcept
{
    return m_impl->m_mem_regions[m_impl->m_data_region_idx];
}

bool
ElfModule::is_position_independent_code() const noexcept
{
    return m_impl->m_is_position_independent_code;
}

IFunction
ElfModule::get_instrumented_function(sstring_view func_name) const
{
    auto func_it = std::find_if(m_impl->m_instrumented_funcs.begin(),
                                m_impl->m_instrumented_funcs.end(),
                                [&func_name](const IFunction &func) {
                                    return func.name() == func_name;
                                });
    if (func_it != m_impl->m_instrumented_funcs.end()) {
        return *func_it;
    }
    return IFunction();
}

IFunction
ElfModule::get_instrumented_function(addr_t func_address) const
{
    auto func_it = std::find_if(m_impl->m_instrumented_funcs.begin(),
                                m_impl->m_instrumented_funcs.end(),
                                [&func_address](const IFunction &func) {
                                    return func.address() == func_address;
                                });
    if (func_it != m_impl->m_instrumented_funcs.end()) {
        return *func_it;
    }
    return IFunction();
}

ElfFunction *
ElfModule::get_function_by_name(sstring_view func_name) const noexcept
{
    auto result = m_impl->m_name_func_map.find(func_name.data());
    if (result == m_impl->m_name_func_map.end()) {
        return nullptr;
    } else {
        return result->second;
    }
}

ElfFunction *
ElfModule::get_static_function_at(addr_t func_addr) const noexcept
{
    auto result = get_function_at(func_addr);
    return result != nullptr && !result->is_dynamic() ? result : nullptr;
}

ElfFunction *
ElfModule::get_dynamic_function_at(addr_t func_addr) const noexcept
{
    auto result = get_function_at(func_addr);
    return result != nullptr && result->is_dynamic() ? result : nullptr;
}

ElfFunction *
ElfModule::get_dynamic_function_by_got(addr_t got_offset) const noexcept
{
    auto &functions = m_impl->m_dynamic_funcs;
    auto iter = std::lower_bound(functions.begin(), functions.end(), got_offset,
                                 [](const ElfFunction &func, addr_t addr) {
                                     return func.got_offset() < addr;
                                 });
    return (iter != functions.end() && (got_offset == iter->got_offset())) ? &(*iter)
                                                                           : nullptr;
}

ElfFunction *
ElfModule::get_function_at(addr_t func_addr) const noexcept
{
    const auto result = m_impl->m_addr_func_map.find(func_addr);
    if (result == m_impl->m_addr_func_map.end()) {
        return nullptr;
    }
    return result->second;
}

bool
ElfModule::exists(sstring_view func_name) const
{
    return get_function_by_name(func_name) != nullptr;
}

const sstring &
ElfModule::name() const noexcept
{
    return m_impl->m_name;
}

const elf::elf &
ElfModule::binary() const noexcept
{
    return m_impl->m_binary;
}

Demangler *
ElfModule::demangler() const noexcept
{
    return &m_impl->m_demangler;
}

buffer_t
ElfModule::get_buffer(addr_t address) const noexcept
{
    // faster lookup
    if (code_region().is_inside(address)) {
        return code_region().get_buffer(address);
    }

    if (data_region().is_inside(address)) {
        return data_region().get_buffer(address);
    }

    for (const auto &region : m_impl->m_mem_regions) {
        if (region.is_inside(address)) {
            return region.get_buffer(address);
        }
    }
    return nullptr;
}

uint64_t
ElfModule::read_address(addr_t address) const noexcept
{
    return *(reinterpret_cast<const uint64_t *>(get_buffer(address)));
}

bool
ElfModule::is_inside_got_region(addr_t address) const noexcept
{
    auto &got_region = m_impl->m_mem_regions[m_impl->m_got_region_idx];
    auto &got_plt_region = m_impl->m_mem_regions[m_impl->m_got_plt_region_idx];
    return got_region.is_inside(address) || got_plt_region.is_inside(address);
}

bool
ElfModule::init_got_region() noexcept
{
    const auto &got_sec = binary().get_section(GOT_SEC_NAME);
    auto &regions = m_impl->m_mem_regions;
    // XXX: address might just be located at the end of got regions
    if (got_sec.valid()) {
        regions.emplace_back(
            MemoryRegion((buffer_t) got_sec.data(), got_sec.get_hdr().addr,
                         got_sec.get_hdr().size + sizeof(void *)));
        regions.back().permissions(Permissions::R);
        m_impl->m_got_region_idx = regions.size() - 1;
    }

    const auto &got_plt_sec = binary().get_section(GOT_PLT_SEC_NAME);
    if (got_plt_sec.valid()) {
        // assuming sections are adjacent
        regions.emplace_back(
            MemoryRegion((buffer_t) got_plt_sec.data(), got_plt_sec.get_hdr().addr,
                         got_plt_sec.get_hdr().size + sizeof(void *)));
        regions.back().permissions(Permissions::R);
        m_impl->m_got_plt_region_idx = regions.size() - 1;
    }

    return m_impl->m_got_region_idx != m_impl->kUninitializedRegionIdx;
}

void
ElfModule::binary(elf::elf binary) noexcept
{
    m_impl->m_binary = binary;
}

void
ElfModule::finalize() noexcept
{
    std::sort(m_impl->m_instrumented_funcs.begin(),
              m_impl->m_instrumented_funcs.end());
}

void
ElfModule::name(sstring_view name) const noexcept
{
    m_impl->m_name = to_string(name);
}

void
ElfModule::add(IFunction function)
{
    m_impl->m_instrumented_funcs.push_back(function);
}

//==============================================================================

struct ElfModuleBuilder::Impl {

    static constexpr addr_t kMXStackSegBase = 0x7ffff7000000;
    // XXX: unicorn can raise cpu exceptions with bigger stack sizes
    static constexpr size_t kMXStackSegSize = 0x200000; // 2MB

    static constexpr size_t kMaxFuncPaddingSize = 0x40;

    explicit Impl(ElfModule &module);

    void build_loadable_segments();

    void check_position_independent_code();

    void build_static_functions();

    void build_dynamic_functions();

    void map_dynamic_functions();

    void build_call_sites();

    void build_call_graph();

    void compute_function_padding(ElfFunction &function);

    void do_global_noreturn_analysis();

    void do_rec_noreturn_analysis(ElfFunction *func,
                                  const ElfCallGraph::Graph &call_graph,
                                  std::vector<bool> &visited);

    void
    do_local_noreturn_analysis(ElfFunction *func, NoReturnAnalysisPhase phase);

    bool
    is_reachable_call_site(const ElfFunction *func, const CallSite &return_site);

    bool is_infinitely_recursive(const ElfFunction *func);

    void validate_noreturn_analysis();

    void build_eh_frame_info();

    inline ElfFunction *get_mutable_ptr(const ElfFunction *function) const
    {
        // what about const cast instead?
        //return m_func_ptr_map[function->idx()];
        return const_cast<ElfFunction *>(function);
    }

    static void init_microx_manager(const ElfModule &module,
                                    flax::FlaxManager &microx_mgr);

    void set_func_return_mode(ElfFunction *func, FunctionAttrs mode);

    ElfModule &m_module;
    std::set<addr_t> m_candidate_noreturn_funcs;
    std::vector<ElfFunction *> m_phase2_noreturn_funcs;
    std::queue<ElfFunction *> m_phase3_noreturn_funcs;
    CSInstWrapper m_cs_inst;
    Disassembler m_disasm;
};

ElfModuleBuilder::Impl::Impl(ElfModule &module) : m_module(module)
{
    m_disasm.init(DisasmArch::kX86, DisasmMode::k64);
}

void
ElfModuleBuilder::Impl::init_microx_manager(const ElfModule &module,
                                            flax::FlaxManager &microx_mgr)
{
    microx_mgr.load_module(module.binary());
    microx_mgr.set_stack_segment(Impl::kMXStackSegBase, Impl::kMXStackSegSize);
}

void
ElfModuleBuilder::Impl::validate_noreturn_analysis()
{
    for (const auto addr : m_candidate_noreturn_funcs) {
        auto candidate = m_module.get_function_at(addr);
        // for functions not yet properly implemented it can be the case that a call
        // to a return function exists followed by *builtin_unreachable*
        if (candidate->is_static()) {
            LOG_IF(is_attr_set(candidate->attrs(), FunctionAttrs::kReturn), WARNING)
                << candidate->name()
                << ": possible invalid classification of return function";
            LOG_IF(is_attr_set(candidate->attrs(), FunctionAttrs::kMayReturn), INFO)
                << candidate->name()
                << ": mayreturn function called last in function";
        }
    }
}

void
ElfModuleBuilder::Impl::check_position_independent_code()
{
    for (const auto &seg : m_module.m_impl->m_binary.segments()) {
        if (!elf::is_loadable(seg)) {
            continue;
        }
        m_module.m_impl->m_is_position_independent_code = seg.get_hdr().vaddr == 0;
        break;
    }
    DCHECK(!(m_module.m_impl->m_binary.get_hdr().type == elf::et::dyn &&
             !m_module.m_impl->m_is_position_independent_code));
}

void
ElfModuleBuilder::Impl::build_loadable_segments()
{
    auto &regions = m_module.m_impl->m_mem_regions;
    // start with an invalid region
    regions.emplace_back(MemoryRegion((buffer_t) nullptr, 0, 0));

    for (const auto &seg : m_module.m_impl->m_binary.segments()) {
        if (!elf::is_loadable(seg)) {
            continue;
        }

        regions.emplace_back(
            MemoryRegion((buffer_t) seg.data(), seg.get_hdr().vaddr,
                         seg.get_hdr().memsz));
        regions.back().permissions(to_bcov_permissions(seg.get_hdr().flags));

        if (elf::is_executable(seg)) {
            LOG_IF(m_module.m_impl->m_code_region_idx !=
                   m_module.m_impl->kUninitializedRegionIdx, FATAL)
                << "we expect only one code segment!";
            m_module.m_impl->m_code_region_idx = regions.size() - 1;
            continue;
        }

        if (!elf::is_writable(seg)) {
            continue;
        }

        LOG_IF(bcov_has_valid_magic((const uint8_t *) seg.data()), FATAL)
            << "given binary is already patched!";

        LOG_IF(m_module.m_impl->m_data_region_idx !=
               m_module.m_impl->kUninitializedRegionIdx, FATAL)
            << "expecting only one data segment!";

        m_module.m_impl->m_data_region_idx = regions.size() - 1;
        m_module.m_impl->m_data_region_buf =
            make_shared_array<uint8_t>(seg.get_hdr().memsz);
        auto buf = m_module.m_impl->m_data_region_buf.get();
        CHECK(seg.get_hdr().memsz >= seg.get_hdr().filesz);
        std::memcpy(buf, seg.data(), seg.get_hdr().filesz);
        // our data segment should account for .bss data in memory
        std::memset(buf + seg.get_hdr().filesz, 0,
                    seg.get_hdr().memsz - seg.get_hdr().filesz);
        regions.back() =
            MemoryRegion((buffer_t) buf, seg.get_hdr().vaddr,
                         seg.get_hdr().memsz);
        regions.back().permissions(to_bcov_permissions(seg.get_hdr().flags));
    }
    LOG_IF(m_module.m_impl->m_code_region_idx ==
           m_module.m_impl->kUninitializedRegionIdx, FATAL)
        << "code segment not found!";
}

void
ElfModuleBuilder::Impl::build_static_functions()
{
    static constexpr unsigned kInsertedFunctionSize = 0xFFFFFFFFU;

    std::vector<ElfFunction> static_funcs;
    const MemoryRegion &code_region = m_module.code_region();

    std::map<addr_t, unsigned> func_map;
    for (const auto &sec : m_module.binary().sections()) {
        if (sec.get_hdr().type != elf::sht::symtab) {
            continue;
        }
        auto symtab = sec.as_symtab();
        for (const auto &sym : symtab) {
            if (sym.get_data().type() != elf::stt::func ||
                sym.get_data().value == 0 ||
                sym.get_data().shnxd == elf::enums::undef) {
                // skip dynamic functions
                continue;
            }
            // symbols are not perfect!
            auto result =
                func_map.insert({sym.get_data().value, sym.get_data().size});
            bool success = result.second;
            auto entry_it = result.first;
            if (success) {
                continue;
            }
            if (sym.get_data().size == 0 ||
                sym.get_data().size == entry_it->second) {
                VLOG(3) << "ignoring duplicate static function @ " << std::hex
                        << sym.get_data().value;
                continue;
            }
            DCHECK(entry_it->second == 0);
            entry_it->second = sym.get_data().size;
        }

        for (const auto &sym : symtab) {
            if (sym.get_data().type() != elf::stt::func ||
                sym.get_data().value == 0 ||
                sym.get_data().shnxd == elf::enums::undef) {
                // skip dynamic functions
                continue;
            }

            auto entry_it = func_map.find(sym.get_data().value);
            if (entry_it == func_map.end() ||
                entry_it->second == kInsertedFunctionSize) {
                continue;
            }
            const uint8_t *data = code_region.get_buffer(sym.get_data().value);
            static_funcs.emplace_back(
                ElfFunction(sym.get_name(), sym.get_data().value, data,
                            entry_it->second));
            if (static_funcs.back().is_runtime()) {
                set_return_mode(static_funcs.back().m_attrs, FunctionAttrs::kReturn);
            }
            entry_it->second = kInsertedFunctionSize;
        }
    }
    std::sort(static_funcs.begin(), static_funcs.end(),
              [](const ElfFunction &a, const ElfFunction &b) {
                  return a.address() < b.address();
              });

    m_module.m_impl->m_static_funcs = std::move(static_funcs);

    ElfFunction::Idx idx = 0;
    for (auto &func : m_module.m_impl->m_static_funcs) {
        func.m_idx = idx++;
        m_module.m_impl->m_name_func_map[func.name()] = &func;
        m_module.m_impl->m_addr_func_map[func.address()] = &func;
        czstring output_str = func.is_static() ? "static" : "runtime";
        VLOG(3) << func.name() << ": found " << output_str << " function @ "
                << std::hex << func.address()
                << std::dec << " id " << func.idx();
    }
}

void
ElfModuleBuilder::Impl::build_dynamic_functions()
{
    std::set<const char *> dyn_func_names;
    DynSymValuePairVec dyn_syms;
    std::set<sstring> known_noreturn_funcs;
    IndexGotVec rela_entries;

    initialize_known_noreturn_funcs(known_noreturn_funcs);

    bool success = m_module.init_got_region();

    if (!success) {
        LOG(WARNING) << "<.got> section not found. "
                     << "proceed assuming binary is statically linked";
        return;
    }

    // collect dynamic function names and got offsets
    for (const auto &sec : m_module.binary().sections()) {
        if (sec.get_hdr().type == elf::sht::dynsym) {
            parse_dyn_sym_section(sec, dyn_syms, dyn_func_names);
        }
        if (sec.get_hdr().type == elf::sht::rela &&
            sec.get_name() == RELA_PLT_SEC_NAME) {
            parse_rela_plt_section(sec, rela_entries);
        }
        if (sec.get_hdr().type == elf::sht::rela &&
            sec.get_name() == RELA_DYN_SEC_NAME) {
            parse_rela_dyn_section(m_module, sec, rela_entries);
        }
    }

    std::vector<ElfFunction> dyn_funcs;

    for (const auto &entry  : rela_entries) {
        auto idx = entry.first;
        auto got_offset = entry.second;
        auto sym_name = dyn_syms[idx].first;
        auto sym_value = dyn_syms[idx].second;
        if (dyn_func_names.find(sym_name) == dyn_func_names.end()) {
            // symbol is not a dynamic function
            continue;
        }
        dyn_funcs.emplace_back(ElfFunction(sym_name, got_offset));
        if (sym_value != 0) {
            set_attr(dyn_funcs.back().m_attrs, FunctionAttrs::kExported);
            dyn_funcs.back().m_export_addr = sym_value;
        }

        if (is_known_noreturn_func(dyn_funcs.back().name(), known_noreturn_funcs)) {
            set_return_mode(dyn_funcs.back().m_attrs, FunctionAttrs::kNoReturn);
        } else {
            set_return_mode(dyn_funcs.back().m_attrs, FunctionAttrs::kReturn);
        }
        czstring log_str = is_attr_set(dyn_funcs.back().attrs(),
                                       FunctionAttrs::kNoReturn) ? " noreturn" : "";
        VLOG(3) << dyn_funcs.back().name()
                << ": found dynamic function @ "
                << std::hex << sym_value
                << " got@ " << dyn_funcs.back().got_offset() << log_str;
    }

    std::sort(dyn_funcs.begin(), dyn_funcs.end(),
              [](const ElfFunction &lhs, const ElfFunction &rhs) {
                  return lhs.got_offset() < rhs.got_offset();
              });

    m_module.m_impl->m_dynamic_funcs = std::move(dyn_funcs);
}

void
ElfModuleBuilder::Impl::map_dynamic_functions()
{
    ElfFunction::Idx idx = m_module.m_impl->m_static_funcs.size();
    auto &addr_func_map = m_module.m_impl->m_addr_func_map;
    auto &name_func_map = m_module.m_impl->m_name_func_map;
    for (auto &dyn_func : m_module.m_impl->m_dynamic_funcs) {
        dyn_func.m_idx = idx++;
        m_module.m_impl->m_addr_func_map[dyn_func.address()] = &dyn_func;
        if (is_attr_set(dyn_func.attrs(), FunctionAttrs::kExported)) {
            if (dyn_func.address() == 0 && dyn_func.export_address() != 0) {
                // function is not called by any static function
                dyn_func.m_addr = dyn_func.m_export_addr;
                dyn_func.m_export_addr = 0;
                dyn_func.m_attrs = get_return_mode(dyn_func.attrs());
                continue;
            }
            if (dyn_func.address() == dyn_func.export_address()) {
                dyn_func.m_export_addr = 0;
                dyn_func.m_attrs = get_return_mode(dyn_func.attrs());
                continue;
            }
            auto static_func_it = addr_func_map.find(dyn_func.export_address());
            if (static_func_it == addr_func_map.end()) {
                DLOG(WARNING) << dyn_func.name()
                              << ": exported dynamic function does not map to a static function";
                continue;
            }
            auto static_func = static_func_it->second;
            if (!is_attr_set(static_func->attrs(), FunctionAttrs::kExported)) {
                // exported dynamic functions conflict with the names of corresponding
                // static functions so they are not added to the name map
                set_attr(static_func->m_attrs, FunctionAttrs::kExported);
                static_func->m_export_addr = dyn_func.address();
                dyn_func.m_attrs = static_func->m_attrs;
            } else {
                m_module.m_impl->m_func_alias_map[static_func->address()] = &dyn_func;
                VLOG(2) << dyn_func.name()
                        << ": added dynamic alias to static function @ "
                        << std::hex << static_func->address();
            }
            continue;
        }

        if (name_func_map.find(dyn_func.name()) == name_func_map.end()) {
            name_func_map[dyn_func.name()] = &dyn_func;
        }
    }
}

void
ElfModuleBuilder::Impl::build_call_sites()
{
    CSInstWrapper tmp_cs_inst;
    for (auto &func : m_module.m_impl->m_static_funcs) {
        if (func.is_runtime()) {
            continue;
        }
        auto data = func.data();
        auto byte_size = func.size();
        auto cur_addr = func.address();
        auto last_branch_addr = func.address();

        DVLOG(5) << "building call sites for function @ "
                 << std::hex << func.address() << std::dec << " id " << func.idx();

        while (cs_disasm_iter(m_disasm.get(), &data, &byte_size, &cur_addr,
                              m_cs_inst.get())) {
            if (!x64::is_branch(m_cs_inst.get())) {
                continue;
            }
            last_branch_addr = m_cs_inst.get()->address;
            auto target_addr = x64::get_direct_branch_target(m_cs_inst.get());
            auto fixup_addr = cur_addr - m_cs_inst.get()->size;
            if (func.is_inside(target_addr)) {
                // handle recursive and intra-procedural calls and skip direct
                // intra-procedural jumps
                if (target_addr == func.address()) {
                    // recursive call
                    CallSiteKind kind = get_call_site_kind(m_cs_inst.get());
                    func.add_call_site(kind, fixup_addr, target_addr);
                    continue;
                }
                if (x64::is_call(m_cs_inst.get())) {
                    func.add_call_site(CallSiteKind::kLocalCall, fixup_addr,
                                       target_addr);
                    LOG(WARNING) << "call to a local address @ "
                                 << to_hex(fixup_addr);
                }

                continue;
            }
            auto rip_rel_addr =
                (target_addr == 0) ? x64::get_rip_rel_branch_target(m_cs_inst.get())
                                   : 0;

            if (target_addr == 0 && rip_rel_addr == 0) {
                CallSiteKind kind = get_call_site_kind(m_cs_inst.get());
                kind = kind | CallSiteKind::kIndirect;
                func.add_call_site(kind, fixup_addr);
                continue;
            }

            ElfFunction *target_func = nullptr;
            auto got_offset =
                (rip_rel_addr != 0) ? rip_rel_addr :
                read_got_offset(m_module, m_disasm.get(), tmp_cs_inst.get(),
                                target_addr);

            if (m_module.is_inside_got_region(got_offset)) {
                // target function is dynamic
                target_func = m_module.get_dynamic_function_by_got(got_offset);
                if (got_offset == 0 || target_func == nullptr) {
                    LOG(WARNING) << "call to unknown dynamic function "
                                 << " @ " << std::hex << fixup_addr
                                 << " target " << target_addr;
                    continue;
                }
                target_func->m_addr = target_addr != 0 ? target_addr : got_offset;

            } else {

                auto lookup_addr = target_addr != 0 ? target_addr :
                                   m_module.read_address(rip_rel_addr);
                target_func = m_module.get_static_function_at(lookup_addr);
                if (target_func == nullptr) {
                    LOG_IF(target_addr == 0, INFO)
                        << "call to unknown function in data segment: "
                        << "call @ " << std::hex << fixup_addr
                        << " target @ " << rip_rel_addr;

                    LOG_IF(target_addr != 0, WARNING)
                        << "call to unknown function: "
                        << "call @ " << std::hex << fixup_addr
                        << " target @ " << target_addr;

                    CallSiteKind kind = get_call_site_kind(m_cs_inst.get());
                    kind = kind | CallSiteKind::kIndirect;
                    // add indirect branch to call sites
                    func.add_call_site(kind, fixup_addr);
                    continue;
                }
            }
            CallSiteKind kind = get_call_site_kind(m_cs_inst.get());
            func.add_call_site(kind, fixup_addr, target_func->address());
        }
        compute_function_padding(func);
        if (byte_size > 0) {
            DLOG(WARNING) << func.name() << " : disassembly error occurred";
        }
        if (func.call_sites().empty()) {
            LOG(WARNING) << func.name() << " : no call sites detected!";
            return;
        }
        if (func.call_sites().back().is_call() &&
            func.call_sites().back().address() == last_branch_addr) {
            // last branch is a call
            m_candidate_noreturn_funcs.insert(func.call_sites().back().target());
            func.m_call_sites.back().m_kind = CallSiteKind::kNoReturnCall;
        }
    }
}

void
ElfModuleBuilder::Impl::compute_function_padding(ElfFunction &function)
{
    function.m_padding = 0;
    if (function.idx() >= m_module.static_functions().back().idx()) {
        return;
    }
    // used to check if padding exists
    auto &succ = m_module.static_functions()[function.idx() + 1];
    size_t padding_size = succ.address() - (function.address() + function.size());
    DLOG_IF(padding_size > size_t(kMaxFuncPaddingSize), WARNING)
            << "discovered unanalyzed code after function @ " << std::hex
            << function.address() << " size " << std::dec << padding_size;

    auto data = function.data() + function.size();
    auto cur_addr = function.address() + function.size();
    auto byte_size = std::min(padding_size, size_t(kMaxFuncPaddingSize));
    while (cs_disasm_iter(m_disasm.get(), &data, &byte_size, &cur_addr,
                          m_cs_inst.get())) {
        if (m_cs_inst.get()->id != X86_INS_NOP) {
            break;
        }
        function.m_padding += m_cs_inst.get()->size;
    }
}

void
ElfModuleBuilder::Impl::build_call_graph()
{
    auto &vertex_store = m_module.m_impl->m_call_graph.m_store;
    auto &callgraph_forward = m_module.m_impl->m_call_graph.m_forward;
    auto &callgraph_backward = m_module.m_impl->m_call_graph.m_backward;
    vertex_store.init(m_module.static_functions());
    for (const auto &func : m_module.dynamic_functions()) {
        vertex_store.insert_vertex(&func);
    }
    callgraph_forward.set_vertex_store(vertex_store);
    callgraph_backward.set_vertex_store(vertex_store);
    for (const auto &func : m_module.static_functions()) {
        std::set<addr_t> callees;
        for (const auto &call_site: func.call_sites()) {
            if (!call_site.is_direct() || call_site.is_local_call() ||
                callees.find(call_site.target()) != callees.end()) {
                continue;
            }
            auto successor = m_module.get_function_at(call_site.target());
            if (successor->is_dynamic() && successor->export_address() != 0) {
                successor = m_module.get_function_at(successor->export_address());
            }
            callgraph_forward.insert_edge(func, *successor);
            callgraph_backward.insert_edge(*successor, func);
            callees.insert(call_site.target());
        }
    }
    LOG(INFO) << "call graph built successfully";
}

bool
ElfModuleBuilder::Impl::is_reachable_call_site(const ElfFunction *func,
                                               const CallSite &return_site)
{
    auto noreturn_call_it = func->call_sites().begin();
    for (; noreturn_call_it < func->call_sites().end() &&
           noreturn_call_it->address() < return_site.address(); ++noreturn_call_it) {

        auto &cur_site = *noreturn_call_it;
        if (!cur_site.is_direct() || cur_site.is_local_call()) {
            continue;
        }
        auto target = m_module.get_function_at(cur_site.target());
        if (get_return_mode(target->attrs()) == FunctionAttrs::kNoReturn) {
            break;
        }
    }

    if (noreturn_call_it == func->call_sites().end() ||
        noreturn_call_it->address() >= return_site.address()) {
        return true;
    }

    auto data = func->data();
    auto byte_size = noreturn_call_it->address() - func->address();
    auto cur_addr = func->address();

    while (cs_disasm_iter(m_disasm.get(), &data, &byte_size, &cur_addr,
                          m_cs_inst.get())) {
        if (!x64::is_jump(m_cs_inst.get())) {
            continue;
        }
        auto target = x64::get_direct_branch_target(m_cs_inst.get());
        if (target > noreturn_call_it->address()) {
            return true;
        }
    }
    VLOG(3) << "unreachable return call-site found @ " << std::hex
            << return_site.address();
    return false;
}

bool
ElfModuleBuilder::Impl::is_infinitely_recursive(const ElfFunction *func)
{
    auto rec_call_it = func->call_sites().begin();
    for (; rec_call_it < func->call_sites().end(); ++rec_call_it) {
        if (rec_call_it->is_return() ||
            rec_call_it->address() == func->address()) {
            break;
        }
    }
    if (rec_call_it == func->call_sites().end() || rec_call_it->is_return()) {
        return false;
    }

    auto data = func->data();
    auto byte_size = rec_call_it->address() - func->address();
    auto cur_addr = func->address();
    while (cs_disasm_iter(m_disasm.get(), &data, &byte_size, &cur_addr,
                          m_cs_inst.get())) {

        if (!x64::is_jump(m_cs_inst.get())) {
            continue;
        }
        auto target = x64::get_direct_branch_target(m_cs_inst.get());
        if (target > rec_call_it->address()) {
            return false;
        }
    }
    VLOG(3) << "infinite recursive call found @ " << std::hex
            << rec_call_it->address();
    return true;
}

void
ElfModuleBuilder::Impl::set_func_return_mode(ElfFunction *func, FunctionAttrs mode)
{
    set_return_mode(func->m_attrs, mode);
    if (func->is_static() && func->export_address() != 0) {
        // propagate results to function thunk
        auto func_thunk = m_module.get_function_at(func->export_address());
        set_return_mode(func_thunk->m_attrs, mode);
        auto &alias_map = m_module.m_impl->m_func_alias_map;
        auto alias_func_it = alias_map.find(func->address());
        if (alias_func_it != alias_map.end()) {
            set_return_mode(alias_func_it->second->m_attrs, mode);
        }
    }
}

void
ElfModuleBuilder::Impl::do_local_noreturn_analysis(ElfFunction *func,
                                                   NoReturnAnalysisPhase phase)
{
    // noreturn function
    // (1) does not have a return call-site AND
    // (2) does not *tail* call into a return function.
    // NOTE: indirect tail calls are assumed, for now, to target return functions
    //
    // may-return function
    // (1) is not a noreturn function AND
    // (2) calls an api-level noreturn function
    //
    // Otherwise, the function is a return function

    bool has_return_call_site = false;
    bool has_return_tail_call = false;
    bool has_noreturn_exit_point = false;
    bool has_recursive_call = false;
    for (auto &call_site : func->m_call_sites) {
        if (call_site.is_trap() || call_site.is_noreturn_call()) {
            // check reachability of this?
            has_noreturn_exit_point = true;
            continue;
        }
        if (!call_site.is_direct()) {
            if (call_site.is_return() && is_reachable_call_site(func, call_site)) {
                has_return_call_site = true;
            }
            if (call_site.is_tail_call()) {
                // XXX: indirect tail calls are assumed to be inter-procedural and
                // that the callee would return. jump-tables violate this!
                has_return_call_site = true;
            }
            continue;
        }

        if (call_site.is_local_call()) {
            continue;
        }
        // handle direct calls and tail-calls
        auto target_func = m_module.get_function_at(call_site.target());
        if (get_return_mode(target_func->attrs()) == FunctionAttrs::kNone) {
            if (func->address() == target_func->address()) {
                // recursive calls are irrelevant
                has_recursive_call = true;
                continue;
            }
            // preliminary classification to be visited later
            set_func_return_mode(func, FunctionAttrs::kReturn);
            m_phase2_noreturn_funcs.push_back(func);
            CHECK(phase == NoReturnAnalysisPhase::kFirst);
            return;
        }
        if (get_return_mode(target_func->attrs()) == FunctionAttrs::kNoReturn) {
            if (!is_abi_noreturn_function(target_func->name())) {
                has_noreturn_exit_point = true;
            }
            continue;
        }
        if (call_site.is_tail_call()) {
            has_return_tail_call = true;
        }
    }
    if (has_recursive_call && !has_noreturn_exit_point) {
        has_noreturn_exit_point = is_infinitely_recursive(func);
    }
    if (!has_noreturn_exit_point) {
        set_func_return_mode(func, FunctionAttrs::kReturn);
        return;
    }
    if (has_return_call_site || has_return_tail_call) {
        // assuming that these sites are reachable
        set_func_return_mode(func, FunctionAttrs::kMayReturn);
    } else {
        set_func_return_mode(func, FunctionAttrs::kNoReturn);
        if (phase == NoReturnAnalysisPhase::kSecond) {
            m_phase3_noreturn_funcs.push(func);
        }
    }
    log_noreturn_status(func, phase);
}

void
ElfModuleBuilder::Impl::do_rec_noreturn_analysis
    (ElfFunction *func, const ElfCallGraph::Graph &call_graph,
     std::vector<bool> &visited)
{
    visited[func->idx()] = true;
    if (!func->is_static()) {
        return;
    }
    DCHECK(!func->call_sites().empty());
    for (auto successor : call_graph.get_edges(*func)) {
        if (!visited[successor->idx()]) {
            do_rec_noreturn_analysis(get_mutable_ptr(successor), call_graph,
                                     visited);
        }
    }
    do_local_noreturn_analysis(func, NoReturnAnalysisPhase::kFirst);
}

void
ElfModuleBuilder::Impl::do_global_noreturn_analysis()
{
    const auto &vertex_store = m_module.m_impl->m_call_graph.m_store;
    const auto &callgraph_forward = m_module.m_impl->m_call_graph.m_forward;
    const auto &callgraph_backward = m_module.m_impl->m_call_graph.m_backward;
    std::vector<bool> visited(vertex_store.vertices().size(), false);
    VLOG(2) << "starting noreturn analysis phase-1 with " << std::dec
            << m_module.static_functions().size() << " functions";

    for (auto func : vertex_store.vertices()) {
        auto &predecessors = callgraph_backward.get_edges(*func);
        if (predecessors.empty() ||
            (predecessors.size() == 1 && *predecessors.front() == *func)) {
            // depth first traversal from root node in call graph
            do_rec_noreturn_analysis(get_mutable_ptr(func),
                                     callgraph_forward, visited);
        }
    }
    VLOG(2) << "starting noreturn analysis phase-2 with " << std::dec
            << m_phase2_noreturn_funcs.size() << " functions";

    for (auto func: m_phase2_noreturn_funcs) {
        do_local_noreturn_analysis(func, NoReturnAnalysisPhase::kSecond);
    }
    m_phase2_noreturn_funcs.clear();

    VLOG(2) << "starting noreturn analysis phase-3 with " << std::dec
            << m_phase3_noreturn_funcs.size() << " functions";

    while (!m_phase3_noreturn_funcs.empty()) {
        auto func = m_phase3_noreturn_funcs.front();
        m_phase3_noreturn_funcs.pop();
        for (auto predecessor : callgraph_backward.get_edges(*func)) {
            if (get_return_mode(predecessor->attrs()) != FunctionAttrs::kReturn) {
                continue;
            }
            do_local_noreturn_analysis(get_mutable_ptr(predecessor),
                                       NoReturnAnalysisPhase::kThird);
            if (get_return_mode(predecessor->attrs()) == FunctionAttrs::kNoReturn) {
                m_phase3_noreturn_funcs.push(get_mutable_ptr(predecessor));
            }
        }
    }
}

void
ElfModuleBuilder::Impl::build_eh_frame_info()
{
    size_t fde_count = 0;
    auto &eh_frame_sec = m_module.binary().get_section(".eh_frame");
    if (!eh_frame_sec.valid()) {
        LOG(INFO) << "elf section <.eh_frame> not found";
        return;
    }

    auto &except_tbl_sec = m_module.binary().get_section(".gcc_except_table");
    LOG_IF(!except_tbl_sec.valid(), INFO)
        << "elf section <.gcc_except_table> not found";

    MemoryRegion except_tbl_region;
    if (except_tbl_sec.valid()) {
        except_tbl_region.base_pos((buffer_t) except_tbl_sec.data());
        except_tbl_region.base_address(except_tbl_sec.get_hdr().addr);
        except_tbl_region.size(except_tbl_sec.get_hdr().size);
    }

    m_module.m_impl->m_eh_frame.parse((const uint8_t *) eh_frame_sec.data(),
                                      eh_frame_sec.get_hdr().addr,
                                      eh_frame_sec.size());

    for (const auto &cie_entry : m_module.eh_frame().map()) {
        auto &cie = cie_entry.first;
        dwarf::CIEAugmentation cie_augm(cie.augmentation_str(),
                                        cie.augmentation_data());
        dwarf::DwarfPointerReader fde_reader;
        dwarf::DwarfPointerReader lsda_reader;
        fde_reader.set_cfi_base(m_module.eh_frame().virtual_address(),
                                m_module.eh_frame().data());
        for (const auto &fde: cie_entry.second) {
            addr_t pc;
            addr_t range;
            unsigned len;
            if (cie_augm.has_code_encoding()) {
                pc = fde_reader.read(fde.location(), cie_augm.code_enc(), &len);
                range = fde_reader.read(fde.range(cie_augm),
                                        absolute(cie_augm.code_enc()), &len);
            } else {
                pc = fde_reader.read_address(fde.location());
                range = fde_reader.read_address(fde.range(cie_augm));
            }

            auto func = m_module.get_static_function_at(pc);
            if (func == nullptr) {
                DLOG(INFO) << "fde refers to a nonstatic function @ "
                           << std::hex << pc;
                continue;
            }
            ++fde_count;
            func->m_eh_frame_offset = fde.record_offset();
            DLOG_IF(range != func->size(), WARNING)
                    << "fde size mismatch @ " << std::hex << pc << std::dec
                    << " found " << range << " expected " << func->size();

            if (!cie_augm.has_lsda_encoding()) {
                continue;
            }

            // collecting landing pads
            CHECK(except_tbl_sec.valid());
            DCHECK(!dwarf::is_indirect(cie_augm.lsda_enc()));
            auto lsda_addr = fde_reader.read(fde.augmentation_data(cie_augm),
                                             cie_augm.lsda_enc(), &len);
            CHECK(except_tbl_region.is_inside(lsda_addr));
            dwarf::LSDA lsda(except_tbl_region.get_buffer(lsda_addr));
            lsda_reader.set_cfi_base(0, fde.location());
            read_landing_pads(lsda, lsda_reader, func->m_landing_pads);
        }
    }
    LOG(INFO) << "eh_frame function count " << std::dec << fde_count
              << " while static function count "
              << m_module.static_functions().size();
}

void
ElfModuleBuilder::do_initial_analyses(ElfModule &module)
{
    Impl impl(module);
    impl.build_loadable_segments();
    impl.check_position_independent_code();
    impl.build_static_functions();
    impl.build_dynamic_functions();
    impl.build_call_sites();
    impl.map_dynamic_functions();
    impl.build_call_graph();
    impl.do_global_noreturn_analysis();
    BCOV_DEBUG(impl.validate_noreturn_analysis());
    impl.build_eh_frame_info();
}

ElfModule
ElfModuleBuilder::build(sstring_view file)
{
    static auto is_ignorable = [](const ElfFunction &function) {
        auto name_it = std::find(IgnorableStaticFunctions.begin(),
                                 IgnorableStaticFunctions.end(), function.name());
        return name_it != IgnorableStaticFunctions.end();
    };

    ElfModule module;
    module.binary(ElfParser::parse(file));
    module.name(get_base_name(file));

    // build all static functions
    do_initial_analyses(module);

    flax::FlaxManager microx_mgr;
    Impl::init_microx_manager(module, microx_mgr);

    FunctionBuilder func_builder;
    func_builder.set_build_dominator_trees();
    for (auto &static_func : module.static_functions()) {
        if (static_func.is_runtime()) {
            continue;
        }

        if (is_ignorable(static_func)) {
            VLOG(2) << static_func.name() << ": function will not be probed";
            continue;
        }

        func_builder.set_function_info(static_func.idx(), static_func.name(),
                                       static_func.address(),
                                       static_func.size(),
                                       static_func.data());
        auto probed_func = func_builder.build(&module, &microx_mgr);
        module.add(probed_func);
    }
    module.finalize();
    return module;
}

ElfModule
ElfModuleBuilder::build(sstring_view file, const BcovConfig &config)
{
    ElfModule module;
    module.binary(ElfParser::parse(file));
    module.name(get_base_name(file));

    do_initial_analyses(module);

    flax::FlaxManager microx_mgr;
    Impl::init_microx_manager(module, microx_mgr);

    FunctionBuilder func_builder;
    func_builder.set_build_dominator_trees();
    for (auto &config_func : config.functions()) {
        auto static_func = module.get_function_by_name(config_func.func_name());
        if (static_func == nullptr || !static_func->is_static()) {
            LOG(WARNING) << config_func.func_name() << ": static function not found";
            continue;
        }

        func_builder.set_function_info(static_func->idx(), static_func->name(),
                                       static_func->address(),
                                       static_func->size(),
                                       static_func->data());

        auto probed_func = func_builder.build(&module, &microx_mgr);
        module.add(probed_func);
    }
    module.finalize();
    return module;
}

//==============================================================================

ElfModuleBuilderException::ElfModuleBuilderException(const std::string &what_arg) :
    runtime_error(what_arg)
{ }

ElfModuleBuilderException::ElfModuleBuilderException(const char *what_arg) :
    runtime_error(what_arg)
{ }

//==============================================================================

namespace dot {

class ElfCallGraphVisitor : public GraphVisitorBase<ElfFunction> {
public:

    explicit ElfCallGraphVisitor(std::ostream &out,
                                 const ElfCallGraph::Graph &graph);

    void visit(const ElfFunction &function) override;

    bool is_finished() const noexcept override;

    void write_function(std::ostream &out, const ElfCallGraph::Graph &graph,
                        const ElfFunction &function);

    void set_max_print_count(unsigned node_count) noexcept;

private:
    std::ostream &m_out;
    const ElfCallGraph::Graph &m_graph;
    KeyValueList m_func_attrs;
    KeyValueList m_edge_attrs;
    unsigned m_max_node_count;
};

ElfCallGraphVisitor::ElfCallGraphVisitor(std::ostream &out,
                                         const ElfCallGraph::Graph &graph)
    : m_out(out), m_graph(graph), m_max_node_count(DOT_CALLGRAPH_DUMP_COUNT)
{
    m_func_attrs.emplace_back(KeyValue("fillcolor", "palegreen"));
    m_func_attrs.emplace_back(KeyValue("color", "#7f7f7f"));
    m_func_attrs.emplace_back(KeyValue("fontname", "Courier"));
    m_func_attrs.emplace_back(KeyValue("label", " "));
    m_edge_attrs.emplace_back(KeyValue("color", "blue"));
}

void ElfCallGraphVisitor::visit(const ElfFunction &function)
{
    write_function(m_out, m_graph, function);
    --m_max_node_count;
}

void
ElfCallGraphVisitor::write_function(std::ostream &out,
                                    const ElfCallGraph::Graph &graph,
                                    const ElfFunction &function)
{
    if (function.is_dynamic()) {
        m_func_attrs.front().value = "lightblue";
    } else if (function.is_runtime()) {
        m_func_attrs.front().value = "orange";
    } else {
        m_func_attrs.front().value = "palegreen";
    }

    sstring sb_label = "idx:" + std::to_string(function.idx()) + "|";
    sb_label += "loc:" + to_hex(function.address()) + "|";
    sb_label += function.name();
    m_func_attrs.back().value = sb_label;
    write_node(out, std::to_string(function.idx()), m_func_attrs);
    for (const auto succ: graph.get_edges(function)) {
        write_edge(out, std::to_string(function.idx()), std::to_string(succ->idx()),
                   m_edge_attrs);
    }
}

void
ElfCallGraphVisitor::set_max_print_count(unsigned node_count) noexcept
{
    m_max_node_count = node_count;
}

bool
ElfCallGraphVisitor::is_finished() const noexcept
{
    return m_max_node_count == 0;
}

void
write_call_graph(std::ostream &out, sstring_view graph_name, const ElfFunction &root,
                 const ElfCallGraph::Graph &graph, unsigned max_node_count)
{
    write_dot_header(out, graph_name);
    ElfCallGraphVisitor visitor(out, graph);
    visitor.set_max_print_count(max_node_count);
    graph.traverse_breadth_first(visitor, root);
    out << "} \n";
}

void
write_call_graph(sstring_view file_name, sstring_view graph_name,
                 const ElfFunction &root, const ElfCallGraph::Graph &graph,
                 unsigned max_node_count)
{
    std::ofstream output_file;
    output_file.open(file_name.data());
    write_call_graph(output_file, graph_name, root,
                     graph, max_node_count);
    output_file.close();
}

} // dot
} // bcov
