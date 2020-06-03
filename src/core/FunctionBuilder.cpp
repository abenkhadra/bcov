/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include <unordered_set>
#include <bitset>
#include <set>
#include "easylogging/easylogging++.h"
#include "FunctionBuilder.hpp"
#include "core/CSInstWrapper.hpp"
#include "Disassembler.hpp"
#include "x64/JumpTabAnalyzer.hpp"
#include "x64/Inst.hpp"


namespace bcov {

using GPRRegisterBitSet = std::bitset<X64_GPR_REG_COUNT>;

static constexpr int kSetJmpVariantCount = 4U;
static const char *kSetJmpFuncNames[kSetJmpVariantCount] =
    {"setjmp", "_setjmp", "sigsetjmp", "__sigsetjmp"};

static MCInstAttr
get_inst_group_kind(uint8_t group_type)
{
    switch (group_type) {
    case CS_GRP_JUMP           : return MCInstAttr::kJump;
    case CS_GRP_CALL           : return MCInstAttr::kCall;
    case CS_GRP_RET            : return MCInstAttr::kReturn;
    case CS_GRP_INT            : return MCInstAttr::kInterrupt;
    case CS_GRP_IRET           : return MCInstAttr::kIntRet | MCInstAttr::kReturn;
    case CS_GRP_PRIVILEGE      : return MCInstAttr::kPrivilege;
    case CS_GRP_BRANCH_RELATIVE: return MCInstAttr::kRelative;
    default:return MCInstAttr::kNone;
    }
}

static MCInstAttr
get_inst_attr(const cs_insn *inst)
{
    MCInstAttr kind = MCInstAttr::kNone;
    for (uint8_t i = 0; i < inst->detail->groups_count; ++i) {
        kind |= get_inst_group_kind(inst->detail->groups[i]);
    }

    if ((kind & MCInstAttr::kRelative) == MCInstAttr::kRelative) {
        // XXX: workaround as capstone may mark a relative branch with
        // CS_GRP_BRANCH_RELATIVE without CS_GRP_JUMP (or CS_GRP_CALL) 
        //which creates an ambiguity.
        kind |= (inst->id == X86_INS_CALL) ? MCInstAttr::kCall : MCInstAttr::kJump;
    }

    if (x64::is_branch_relative(inst)) {
        kind |= MCInstAttr::kRelative;
    } else if (x64::is_rip_relative(inst)) {
        kind |= MCInstAttr::kRelative;
        kind |= MCInstAttr::kPCRel;
    }

    DLOG_IF(x64::is_loop(inst), ERROR) << "loop instruction rewrite unsupported!";

    if (x64::is_loop(inst)) {
        kind |= MCInstAttr::kCond;
        kind |= MCInstAttr::kJump;
    }

    if (x64::has_one_const_opnd(inst) || x64::has_rip_rel_const_opnd(inst)) {
        kind |= MCInstAttr::kDirect;
    }

    if (x64::is_conditional(inst)) {
        kind |= MCInstAttr::kCond;
    }

    if ((kind & MCInstAttr::kInterrupt) == MCInstAttr::kInterrupt) {
        kind |= MCInstAttr::kCall;
    }

    if (x64::is_trap(inst)) {
        kind |= MCInstAttr::kInterrupt;
        kind |= MCInstAttr::kJump;
    }
    return kind;
}

static bool
is_padding(const BasicBlock &bb)
{
    return bb.instructions().front().cs_id() == X86_INS_NOP &&
           bb.instructions().back().cs_id() == X86_INS_NOP;
}

static const ElfFunction::LandingPads &
get_landing_pads(const ElfModule *module, addr_t func_address)
{
    auto func = module->get_static_function_at(func_address);
    return func->landing_pads();
}

static void
check_postdom_tree_reachability(const DominatorTree &domtree)
{
    for (const auto vertex : domtree.tree().get_vertices()) {
        if (domtree.idom(vertex) != nullptr || vertex->is_virtual() ||
            vertex->is_padding()) {
            continue;
        }
        DVLOG(4) << "postdominator tree: unreachable basic block @ " << std::hex
                 << vertex->address();
    }
}

static x64::X64Reg
get_modified_gpr_register(const cs_insn *inst)
{
    using namespace x64;
    auto &opnd = inst->detail->x86.operands[0];
    if (opnd.type != X86_OP_REG || !is_write_acc(opnd.access)) {
        return X64Reg::Invalid;
    }

    auto reg = get_canonical(get_x64_reg(opnd.reg));
    return is_gpr_reg(reg) ? reg : X64Reg::Invalid;
}

static bool
is_constant_arg_set(const cs_insn *inst)
{
    using namespace x64;
    // look for a constant argument to a mayreturn function
    if (is_const_xor(inst)) {
        return x64::abi::sysv_is_call_arg_reg(inst, Opnd::One);
    }
    if (inst->id == X86_INS_MOV) {
        // capstone does not set read flag for immediate values
        return is_opnd_reg(inst, Opnd::One) && is_opnd_immediate(inst, Opnd::Two);
    }

    return false;
}

//==============================================================================

struct FunctionBuilder::Impl {

    Impl() = default;

    ~Impl() = default;

    static bool
    check_return_call(const ElfModule *module, const CallSite &call_site);

    span<const CallSite> get_call_sites(const ElfModule *module);

    bool does_set_constant_func_arg(const BasicBlock &bb);

    IFunction m_instance;
    bool m_build_dom_trees = false;
    flax::FlaxManager *m_microx_mgr;
    CSInstWrapper m_cs_inst;
    Disassembler m_disasm;
};

FunctionBuilder::FunctionBuilder() : m_impl(std::make_shared<Impl>())
{
    m_impl->m_disasm.init(DisasmArch::kX86, DisasmMode::k64);
}

void
FunctionBuilder::set_function_info(IFunction::Idx idx, sstring_view name,
                                   addr_t address, size_t byte_size,
                                   const uint8_t *data)
{
    m_impl->m_instance = IFunction();
    m_impl->m_instance.idx(idx);
    m_impl->m_instance.name(name);
    m_impl->m_instance.address(address);
    m_impl->m_instance.byte_size(byte_size);
    m_impl->m_instance.data(data);
}

span<const CallSite>
FunctionBuilder::Impl::get_call_sites(const ElfModule *module)
{
    return module->static_functions()[m_instance.idx()].call_sites();
}

bool
FunctionBuilder::Impl::does_set_constant_func_arg(const BasicBlock &bb)
{
    auto data = m_instance.get_buffer(bb.address());
    auto byte_size = bb.byte_size();
    auto addr = bb.address();
    while (cs_disasm_iter(m_disasm.get(), &data, &byte_size, &addr,
                          m_cs_inst.get())) {
        if (is_constant_arg_set(m_cs_inst.get())) {
            VLOG(4) << "mayreturn: constant argument set : " << to_string(m_cs_inst);
            return true;
        }
    }
    return false;
}

bool
FunctionBuilder::Impl::check_return_call(const ElfModule *module,
                                         const CallSite &call_site)
{
    if (!call_site.is_call() || call_site.is_noreturn_call()) return false;

    if (!call_site.is_direct() || call_site.is_local_call()) return true;

    const auto target_func = module->get_function_at(call_site.target());

    return !is_attr_set(target_func->attrs(), FunctionAttrs::kNoReturn);
}

const MCInst *
FunctionBuilder::add_instruction(const CSInstWrapper *cs_inst)
{
    auto &instructions = m_impl->m_instance.instructions_ex();

    auto idx = (uint32_t) instructions.size();
    const auto details = cs_inst->get()->detail;

    // precondition: disassembly should be done with details enabled
    CHECK(details != nullptr);

    MCInstAttr attr = get_inst_attr(cs_inst->get());
    instructions.emplace_back(MCInst(idx, cs_inst->get()->id,
                                     cs_inst->get()->address,
                                     cs_inst->get()->size, attr));
    instructions.back().m_text =
        sstring(cs_inst->get()->mnemonic) + " " + cs_inst->get()->op_str;

    return &(instructions.back());
}

void
FunctionBuilder::build_instructions_and_basic_block_entries(
    std::set<addr_t> &bb_entries)
{
    auto &cs_inst = m_impl->m_cs_inst;
    auto &disasm = m_impl->m_disasm;
    auto data = m_impl->m_instance.data();
    auto byte_size = m_impl->m_instance.byte_size();
    auto addr = m_impl->m_instance.address();

    // collect instructions and bb entry points. linear sweep should work here!
    while (cs_disasm_iter(disasm.get(), &data, &byte_size, &addr, cs_inst.get())) {
        auto mc_inst = add_instruction(&cs_inst);
        if (!mc_inst->is_branch()) {
            continue;
        }
        auto target = x64::get_direct_branch_target(cs_inst.get());
        if (m_impl->m_instance.is_inside(target)) {
            bb_entries.insert(target);
        }
    }
    LOG_IF(m_impl->m_instance.instructions().empty(), WARNING)
        << m_impl->m_instance.name() << ": function without instructions!";
    const MCInst &last_inst = m_impl->m_instance.instructions().back();
    LOG_IF(last_inst.address() + last_inst.size() !=
           m_impl->m_instance.address() + m_impl->m_instance.byte_size(), ERROR)
        << "disassembly error @ " << std::hex << last_inst.address();
}

void
FunctionBuilder::build_basic_blocks(const std::set<addr_t> &bb_entries)
{
    auto &instructions = m_impl->m_instance.instructions_ex();
    auto &basic_blocks = m_impl->m_instance.basic_blocks_ex();

    size_t entry_idx = 0;
    size_t bb_size;
    auto bb_entry_it = bb_entries.cbegin();
    BasicBlock result;
    while (entry_idx < instructions.size()) {
        bb_size = 1;
        result.m_kind = BasicBlockKind::kUnknown;
        result.m_insts = {&instructions[entry_idx], bb_size};
        result.m_byte_size = instructions[entry_idx].m_size;
        if (bb_entry_it != bb_entries.cend() &&
            instructions[entry_idx].m_addr == *bb_entry_it) {
            ++bb_entry_it;
        }
        if (instructions[entry_idx].is_branch()) {
            result.m_kind = BasicBlockKind::kBranch;
            result.m_idx = basic_blocks.size();
            basic_blocks.push_back(result);
            entry_idx++;
            continue;
        }
        for (size_t i = entry_idx + 1; i < instructions.size(); ++i) {
            if (bb_entry_it != bb_entries.cend() &&
                instructions[i].m_addr == *bb_entry_it) {
                result.m_kind = BasicBlockKind::kFallthrough;
                ++bb_entry_it;
                break;
            }
            if (instructions[i].is_branch()) {
                result.m_kind = BasicBlockKind::kBranch;
                bb_size++;
                result.m_byte_size += instructions[i].m_size;
                break;
            }
            bb_size++;
            result.m_byte_size += instructions[i].m_size;
        }
        result.m_insts = {&instructions[entry_idx], bb_size};
        result.m_idx = basic_blocks.size();
        basic_blocks.push_back(result);
        entry_idx = entry_idx + bb_size;
    }

    if (!basic_blocks.back().is_branching() && !is_padding(basic_blocks.back())) {
        LOG(WARNING) << "found dangling basic block @ "
                     << std::hex << basic_blocks.back().address();
        basic_blocks.back().m_kind = BasicBlockKind::kDangling;
    }

    CHECK(basic_blocks.size() < MAX_BASIC_BLOCK_COUNT);
}

void
FunctionBuilder::build_cfg(const ElfModule *module)
{
    auto &basic_blocks = m_impl->m_instance.basic_blocks_ex();
    auto &cfg = m_impl->m_instance.cfg_ex();
    auto &func = m_impl->m_instance;
    cfg.basic_blocks(basic_blocks);
    std::unordered_map<addr_t, const BasicBlock *> bb_map;
    auto insert_edge = [&func, &cfg, &bb_map](const BasicBlock &src, addr_t dst) {
        if (!func.is_inside(dst)) {
            LOG(WARNING) << "ignoring non-local cfg edge from " << std::hex
                         << src.address() << " to " << dst;
            return;
        }
        cfg.insert_edge(src, *(bb_map.at(dst)));
    };

    for (const auto &bb : basic_blocks) {
        bb_map[bb.address()] = &bb;
    }

    for (const auto &jumptab : m_impl->m_instance.jump_tables()) {
        auto jumptab_bb =
            m_impl->m_instance.get_basic_block_of(jumptab.jump_address());
        if (jumptab_bb == nullptr) {
            throw FunctionBuilderException(
                "basic block not found for jump table @ 0x" +
                to_hex(jumptab.jump_address()));
        }
        for (const auto target : jumptab.targets()) {
            if (m_impl->m_instance.is_inside(target)) {
                try {
                    cfg.insert_edge(*jumptab_bb, *(bb_map.at(target)));
                } catch (const std::out_of_range &exp) {
                    LOG(ERROR) << "invalid jumptab target " << std::hex << target;
                }
            }
        }
    }

    auto &cs_inst = m_impl->m_cs_inst;
    auto &disasm = m_impl->m_disasm;
    auto call_sites = m_impl->get_call_sites(module);

    unsigned call_site_idx = 0;
    for (const auto &bb : basic_blocks) {
        const auto &bb_exit_inst = bb.instructions().back();
        if (bb.is_fallthrough()) {
            auto next_bb_addr = bb_exit_inst.address() + bb_exit_inst.size();
            insert_edge(bb, next_bb_addr);
            continue;
        }
        if (bb_exit_inst.is_conditional()) {
            // XXX: the convention is that the first edge is the near edge
            auto target_bb_addr = bb_exit_inst.address() + bb_exit_inst.size();
            insert_edge(bb, target_bb_addr);
        }

        if (call_site_idx < call_sites.size() &&
            call_sites[call_site_idx].address() == bb_exit_inst.address()) {

            auto &cur_call_site = call_sites[call_site_idx];
            bool is_return_call =
                m_impl->check_return_call(module, cur_call_site);
            if (is_return_call) {
                auto target_bb_addr = bb_exit_inst.address() + bb_exit_inst.size();
                insert_edge(bb, target_bb_addr);
            }
            if (cur_call_site.is_local_call()) {
                // XXX: in very rare cases, calls be intra-procedural
                insert_edge(bb, cur_call_site.target());
            }
            ++call_site_idx;
            continue;
        }
        if (bb_exit_inst.is_direct()) {
            DCHECK(bb_exit_inst.is_branch());
            auto addr = bb_exit_inst.address();
            auto data = m_impl->m_instance.get_buffer(addr);
            size_t byte_size = bb_exit_inst.size();
            bool success =
                cs_disasm_iter(disasm.get(), &data, &byte_size, &addr,
                               cs_inst.get());
            DLOG_IF(!success, WARNING) << m_impl->m_instance.name()
                                       << ": disassembly error in building cfg @ "
                                       << std::hex << addr;
            auto branch_target = x64::get_direct_branch_target(cs_inst.get());
            DCHECK(m_impl->m_instance.is_inside(branch_target));
            insert_edge(bb, branch_target);
        }
    }
    // assume that the first basic block is always an entry
    cfg.add_entry_block(basic_blocks[0]);
}

void
FunctionBuilder::build_jump_tabs_and_update_cfg(const ElfModule *module,
                                                std::set<addr_t> &bb_entries)
{
    if (m_impl->m_microx_mgr == nullptr) {
        return;
    }
    auto call_sites = module->static_functions()[m_impl->m_instance.idx()].call_sites();
    for (const auto &site : call_sites) {
        if (site.is_direct() || !site.is_tail_call()) {
            continue;
        }
        auto bb = m_impl->m_instance.get_basic_block_of(site.address());
        CHECK(bb != nullptr);
        VLOG(2) << "jumptab @ " << std::hex << site.address() << " analyzing ...";
        JumpTable jump_table;
        x64::JumpTabAnalyzer::build(m_impl->m_instance, *bb,
                                    m_impl->m_microx_mgr, jump_table);
        if (!jump_table.valid()) {
            VLOG(2) << "jumptab @ " << std::hex << site.address() << " no match";
            continue;
        }
        VLOG(2) << "jumptab @ " << std::hex << site.address() << " good match"
                << std::dec << ", target count: " << jump_table.targets().size()
                << ", total entry count: " << jump_table.entry_count();

        m_impl->m_instance.jump_tables_ex().emplace_back(std::move(jump_table));

        auto &jumptab_targets = m_impl->m_instance.jump_tables().back().targets();
        // add bb entries of jump table
        auto prev_bb_entry_count = bb_entries.size();
        std::copy_if(jumptab_targets.begin(), jumptab_targets.end(),
                     std::inserter(bb_entries, bb_entries.end()),
                     [this](addr_t target) {
                         return m_impl->m_instance.is_inside(target);
                     });

        VLOG(3) << m_impl->m_instance.name()
                << ": rebuilding cfg with bb entry count " << bb_entries.size()
                << " was " << prev_bb_entry_count;

        // now update cfg
        if (prev_bb_entry_count != bb_entries.size()) {
            m_impl->m_instance.basic_blocks_ex().clear();
            build_basic_blocks(bb_entries);
        }
        m_impl->m_instance.cfg_ex().reset();
        build_cfg(module);
    }
}

void
FunctionBuilder::cfg_link_setjmps(const ElfModule *module)
{
    // get the addresses of setjmp variants, if applicable
    std::array<addr_t, kSetJmpVariantCount> setjmp_func_addrs;
    setjmp_func_addrs.fill(0);
    bool setjmp_used = false;
    for (unsigned i = 0; i < kSetJmpVariantCount; ++i) {
        auto func = module->get_function_by_name(kSetJmpFuncNames[i]);
        if (func != nullptr) {
            setjmp_func_addrs[i] = func->address();
            setjmp_used = true;
        }
    }

    if (!setjmp_used) {
        // flag setjmp used can be cached for the same binary
        return;
    }

    auto &basic_blocks = m_impl->m_instance.basic_blocks_ex();
    auto &cfg = m_impl->m_instance.cfg_ex();

    auto call_sites = m_impl->get_call_sites(module);
    auto call_site_it = call_sites.begin();
    for (auto bb_it = basic_blocks.begin();
         bb_it != basic_blocks.end(); ++bb_it) {
        auto &exit_inst = bb_it->instructions().back();
        if (!exit_inst.is_call() || !exit_inst.is_direct()) {
            continue;
        }
        auto call_addr = bb_it->instructions().back().address();

        // find matching call site
        for (; call_site_it < call_sites.end() &&
               call_site_it->address() != call_addr; ++call_site_it);

        if (call_site_it == call_sites.end() || !call_site_it->is_direct()) {
            continue;
        }
        auto result = std::find(setjmp_func_addrs.begin(), setjmp_func_addrs.end(),
                                call_site_it->target());

        if (result != setjmp_func_addrs.end()) {
            DVLOG(1) << "call to setjmp @ " << std::hex << call_addr;
            DCHECK(bb_it + 1 != basic_blocks.end());
            cfg.add_entry_block(*(bb_it + 1));
        }
    }
}

void
FunctionBuilder::cfg_link_landing_pads(const ElfFunction::LandingPads &landing_pads)
{
    auto &basic_blocks = m_impl->m_instance.basic_blocks_ex();
    auto &cfg = m_impl->m_instance.cfg_ex();
    auto lp_offset_it = landing_pads.cbegin();
    // precondition: landing pad offsets are sorted
    for (auto bb_it = basic_blocks.begin();
         bb_it != basic_blocks.end() &&
         lp_offset_it != landing_pads.cend(); ++bb_it) {

        auto bb_offset = bb_it->address() - m_impl->m_instance.address();
        if (bb_offset != *lp_offset_it) {
            // skip bb which is not a landing pad
            continue;
        }

        if (!cfg.predecessors(*bb_it).empty()) {
            VLOG(1) << "landing-pad is intra-procedurally reachable @ "
                    << to_hex(bb_it->address());
        }
        cfg.add_entry_block(*bb_it);
        bb_it->m_kind = bb_it->m_kind | BasicBlockKind::kLandingPad;
        ++lp_offset_it;
    }
}

void
FunctionBuilder::finalize_cfg(const ElfModule *module,
                              const ElfFunction::LandingPads &landing_pads)
{
    auto &basic_blocks = m_impl->m_instance.basic_blocks_ex();
    auto &cfg = m_impl->m_instance.cfg_ex();

    cfg_link_setjmps(module);
    cfg_link_landing_pads(landing_pads);

    for (auto &bb : basic_blocks) {
        if (cfg.successors(bb).empty()) {
            // XXX: assume that indirect branches can not be intra-procedural
            // jump-tables should have been recovered before this.
            cfg.add_exit_block(bb);
        }
        if (cfg.predecessors(bb).size() > 1 || bb.is_landing_pad()) {
            continue;
        }
        if (!cfg.predecessors(bb).empty() && *cfg.predecessors(bb).front() != bb) {
            continue;
        }

        // handle basic blocks with no predecessors
        if (is_padding(bb)) {
            bb.m_kind = bb.m_kind | BasicBlockKind::kPadding;
            cfg.reset_padding_edges(bb);
            continue;
        }
        cfg.add_entry_block(bb);
        LOG(WARNING) << "bb unreachable from entry @ " << to_hex(bb.address());
    }
}

void
FunctionBuilder::set_build_dominator_trees()
{
    m_impl->m_build_dom_trees = true;
}

void
FunctionBuilder::build_dominator_trees()
{
    auto &predom = m_impl->m_instance.predominator_ex();
    auto &postdom = m_impl->m_instance.postdominator_ex();
    auto &cfg = m_impl->m_instance.cfg_ex();

    DominatorTreeBuilder dt_builder;
    predom = dt_builder.build(cfg.virtual_entry(), cfg.forward(), cfg.backward());
    VLOG(3) << m_impl->m_instance.name() << ": predom tree built successfully";

    postdom = dt_builder.build(cfg.virtual_exit(), cfg.backward(), cfg.forward());
    VLOG(3) << m_impl->m_instance.name() << ": postdom tree built successfully";
}

IFunction
FunctionBuilder::build(const ElfModule *module, flax::FlaxManager *microx_mgr)
{

    m_impl->m_instance.demangler(module->demangler());
    m_impl->m_microx_mgr = microx_mgr;
    std::set<addr_t> bb_entries;
    build_instructions_and_basic_block_entries(bb_entries);

    VLOG(2) << m_impl->m_instance.name() << ": analyzing function @ "
            << std::hex << m_impl->m_instance.address()
            << " id " << std::dec << m_impl->m_instance.idx();

    // add landing pads entries
    auto &landing_pads = get_landing_pads(module, m_impl->m_instance.address());
    for (const auto lp_offset : landing_pads) {
        bb_entries.insert(m_impl->m_instance.address() + lp_offset);
    }

    VLOG_IF(!landing_pads.empty(), 3) << m_impl->m_instance.name() << std::dec
                                      << ": landing-pads=" << landing_pads.size();

    // TODO: using ElfModule here breaks modularity. Fix later
    build_basic_blocks(bb_entries);
    build_cfg(module);
    build_jump_tabs_and_update_cfg(module, bb_entries);

    finalize_cfg(module, landing_pads);
    auto &instructions = m_impl->m_instance.instructions_ex();
    auto &basic_blocks = m_impl->m_instance.basic_blocks_ex();

    VLOG(4) << m_impl->m_instance.name() << std::dec
            << ":inst=" << instructions.size()
            << ",bb=" << basic_blocks.size();

    if (m_impl->m_build_dom_trees) {
        build_dominator_trees();
    }
    return std::move(m_impl->m_instance);
}

//===============================================

FunctionBuilderException::FunctionBuilderException(const std::string &what_arg)
    : std::logic_error(what_arg)
{ }

FunctionBuilderException::FunctionBuilderException(const char *what_arg)
    : std::logic_error(what_arg)
{ }

} // bcov
