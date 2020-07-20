/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include <forward_list>
#include <bitset>
#include <unordered_set>
#include "easylogging/easylogging++.h"
#include "JumpTabAnalyzer.hpp"
#include "core/CSInstWrapper.hpp"
#include "core/Disassembler.hpp"
#include "x64/Arch.hpp"
#include "x64/Inst.hpp"

namespace bcov {
namespace x64 {

class JTDependency;

using ValueIdx = unsigned;
using JTDependencySpan = span<const JTDependency>;
using JTDependencyVec = std::vector<JTDependency>;
using JTConstantIndexValueSpan = span<const int>;

enum class JTDepKind : uint8_t {
    kNone = 0x0,
    kHeadLink = 0x1,
    kLink = 0x3,
    kCondJump = 0x4,    // has a default target to jump-table
    kCondComp = 0x6,    // compares to constant bound
    kBadCondJump = 0x8,
    kBase = 0x5,        // kills a variable with a jump-table base
    kMerge = 0x7,
    kValueBound = 0x9,  // restricts value of a live variable
    kTemp = 0xF0,
    kFixed = 0x0F
};

static inline JTDepKind operator|(JTDepKind a, JTDepKind b)
{
    return (JTDepKind) ((unsigned) a | (unsigned) b);
}

static inline JTDepKind operator&(JTDepKind a, JTDepKind b)
{
    return (JTDepKind) ((unsigned) a & (unsigned) b);
}

static JTDepKind
make_temp(JTDepKind a)
{
    return (a | JTDepKind::kTemp);
}

static JTDepKind
make_fixed(JTDepKind a)
{
    return (a & JTDepKind::kFixed);
}

static bool
is_temp_dep(JTDepKind a)
{
    return (a & JTDepKind::kTemp) != JTDepKind::kNone;
}

enum class JTSlicerPathStatus : uint8_t {
    kNone = 0x0,
    kHasCond = 0x1,
    kSetsCond = 0x3
};

static JTSlicerPathStatus
operator|(const JTSlicerPathStatus a, const JTSlicerPathStatus b)
{
    return (JTSlicerPathStatus) ((unsigned) a | (unsigned) b);
}

static JTSlicerPathStatus
operator&(const JTSlicerPathStatus a, const JTSlicerPathStatus b)
{
    return (JTSlicerPathStatus) ((unsigned) a & (unsigned) b);
}

static inline void
log_fatal_if(bool condition, sstring_view msg)
{
    LOG_IF(condition, FATAL) << "jumptab: " << msg;
}

static bool
is_invalid(x86_reg reg)
{
    return reg == X86_REG_INVALID;
}

static bool
reads_carry_flag(const cs_insn *inst)
{
    return (inst->detail->x86.eflags & X86_EFLAGS_TEST_CF) != 0;
}

static bool
is_lea_inst(const cs_insn *inst)
{
    return inst->id == X86_INS_LEA;
}

static bool
is_constant_xor(const cs_insn *inst)
{
    if (inst->id != X86_INS_XOR) {
        return false;
    }
    auto &operands = inst->detail->x86.operands;
    return operands[1].type == X86_OP_REG && operands[0].reg == operands[1].reg;
}

static bool
reads_sign_flag(const cs_insn *inst)
{
    return (inst->detail->x86.eflags & X86_EFLAGS_TEST_SF) != 0;
}

static bool
is_valid_bound_jmp(const cs_insn *inst)
{
    // XXX: typically, but not always, it should be an unsigned check i.e. carry only
    return reads_carry_flag(inst) || reads_sign_flag(inst);
}

static bool
has_constant_opnd(const cs_insn *inst)
{
    // should we consider test reg, reg ?
    if (inst->detail->x86.op_count != 2) {
        return false;
    }
    auto &operands = inst->detail->x86.operands;
    if (is_lea_inst(inst) && operands[1].mem.base == X86_REG_RIP) {
        return true;
    }
    return operands[1].type == X86_OP_IMM;
}

static bool
is_plausible_cond_bound_constant(int64_t value)
{
    // found an edge case where the jumptable had > 6K cases. The binary
    // is llc compiled with clang-8
    return value > 2 && value < 0x2000;
}

static bool
is_plausible_data_bound_constant(int64_t value)
{
    return value > 2 && value < 8;
}

static bool
check_reads_single_byte(const cs_insn *inst)
{
    // should we consider - test reg, reg
    if (inst->detail->x86.op_count != 2) {
        return false;
    }
    auto &operands = inst->detail->x86.operands;
    return operands[1].size == 1 && is_read_acc(operands[1].access);
}

static uint64_t
check_sets_jumptab_base(const cs_insn *inst)
{
    auto &operands = inst->detail->x86.operands;
    if (inst->detail->x86.op_count != 2 || !is_write_acc(operands[0].access) ||
        operands[0].type != X86_OP_REG) {
        return 0;
    }
    if (is_lea_inst(inst) && operands[1].mem.base == X86_REG_RIP) {
        return inst->address + inst->size + operands[1].mem.disp;
    }
    if (operands[1].type == X86_OP_IMM) {
        // XXX: zero designates fail which should work here
        return operands[1].imm < 0 ? 0 : operands[1].imm;
    }
    return 0;
}

static int64_t
get_constant_opnd(const cs_insn *inst)
{
    if (inst->detail->x86.op_count != 2) {
        return 0;
    }
    auto &operands = inst->detail->x86.operands;
    if (operands[1].type == X86_OP_IMM) {
        return operands[1].imm;
    }
    if (is_lea_inst(inst) && operands[1].mem.base == X86_REG_RIP) {
        return inst->address + inst->size + operands[1].mem.disp;
    }
    return 0;
}

static bool
is_mov_inst(const cs_insn *inst)
{
    return inst->id == X86_INS_MOV;
}

static bool
is_comp_inst(const cs_insn *inst)
{
    return inst->id == X86_INS_CMP;
}

static cs_x86_op *
get_mem_opnd(const cs_insn *inst)
{
    if (is_lea_inst(inst)) {
        return nullptr;
    }
    for (unsigned i = 0; i < inst->detail->x86.op_count; ++i) {
        if (inst->detail->x86.operands[i].type == X86_OP_MEM) {
            return &inst->detail->x86.operands[i];
        }
    }
    return nullptr;
}

static inline bool
check_reads_mem(const cs_insn *inst)
{
    auto opnd_p = get_mem_opnd(inst);
    return opnd_p != nullptr && is_read_acc(opnd_p->access);
}

static uint8_t
get_arg_count(const x86_op_mem &mem_opnd)
{
    uint8_t result = 0;
    if (!is_invalid(mem_opnd.segment)) {
        ++result;
    }

    if (!is_invalid(mem_opnd.base)) {
        ++result;
    }

    if (!is_invalid(mem_opnd.index)) {
        result += 2;
    }

    if (mem_opnd.disp != 0) {
        ++result;
    }

    return result;
}

static uint
get_reg_arg_count(const x86_op_mem &mem_opnd)
{
    uint result = 0;
    if (!is_invalid(mem_opnd.segment)) {
        ++result;
    }

    if (!is_invalid(mem_opnd.base)) {
        ++result;
    }

    if (!is_invalid(mem_opnd.index)) {
        ++result;
    }

    return result;
}

static uint
get_opnd_read_count(const cs_insn *inst, x86_op_type opnd_type)
{
    uint result = 0;
    for (unsigned i = 0; i < inst->detail->x86.op_count; ++i) {
        auto &opnd = inst->detail->x86.operands[i];
        if (opnd.type == opnd_type && is_read_acc(opnd.access)) {
            ++result;
        }
    }
    return result;
}

static uint
get_opnd_write_count(const cs_insn *inst, x86_op_type opnd_type)
{
    uint result = 0;
    for (unsigned i = 0; i < inst->detail->x86.op_count; ++i) {
        auto &opnd = inst->detail->x86.operands[i];
        if (opnd.type == opnd_type && is_write_acc(opnd.access)) {
            ++result;
        }
    }
    return result;
}

static inline void
log_rip_value(const flax::FlaxManager *mgr)
{
    uint64_t rip;
    uc_reg_read(mgr->engine().get(), UC_X86_REG_RIP, &rip);
    DVLOG(4) << "rip @ " << std::hex << rip << " , orig @ " << mgr->get_original(rip)
             << ", last rip @ " << std::hex << mgr->last_reachable_address()
             << " , orig @ " << mgr->get_original(mgr->last_reachable_address());
}

static void
disasm_inst(const IFunction &function, const MCInst &inst,
            const Disassembler &disasm, cs_insn *result)
{
    auto address = inst.address();
    size_t byte_size = inst.size();
    auto data = function.get_buffer(address);
    auto success = cs_disasm_iter(disasm.get(), &data, &byte_size, &address, result);
    DCHECK(success);
}

//==============================================================================

class JTDependency {
    friend class BoundConditionSlicingVisitor;

    friend class BaseSlicingVisitor;

public:

    JTDependency();

    ~JTDependency() = default;

    JTDepKind kind() const noexcept
    {
        return m_kind;
    }

    bool valid() const noexcept
    {
        return m_kind != JTDepKind::kNone;
    }

    bool is_link() const noexcept
    {
        return (m_kind | JTDepKind::kLink) == JTDepKind::kLink;
    }

    bool is_head_link() const noexcept
    {
        return m_kind == JTDepKind::kHeadLink;
    }

    bool is_info() const noexcept
    {
        return valid() && !is_link();
    }

    bool is_cond_jump() const noexcept
    {
        return m_kind == JTDepKind::kCondJump;
    }

    bool is_cond_comp() const noexcept
    {
        return m_kind == JTDepKind::kCondComp;
    }

    bool is_base() const noexcept
    {
        return m_kind == JTDepKind::kBase;
    }

    bool is_merge() const noexcept
    {
        return m_kind == JTDepKind::kMerge;
    }

    MCInstPtr instruction() const noexcept
    {
        return !is_info() ? nullptr : m_info.m_inst;
    }

    int64_t constant() const noexcept
    {
        return m_info.m_constant;
    }

    const BasicBlock *node() const noexcept
    {
        return is_link() ? m_link.m_node : nullptr;
    }

    const BasicBlock *parent() const noexcept
    {
        return is_link() ? m_link.m_parent : nullptr;
    }

private:
    JTDepKind m_kind;

    struct Link {
        const BasicBlock *m_node;
        const BasicBlock *m_parent;
    };

    struct Info {
        MCInstPtr m_inst;
        int64_t m_constant;
    };

    union {
        Link m_link;
        Info m_info;
    };
};

JTDependency::JTDependency() : m_kind(JTDepKind::kNone)
{ }

sstring
to_string(const JTDependency &dep)
{
    sstring result = "dep: ";
    if (dep.is_link()) {
        result +=
            "link, n @ " + to_hex(dep.node()->address()) + " p @ " +
            (dep.parent() == nullptr ? "null" : to_hex(dep.parent()->address()));
        return result;
    }

    if (dep.is_base()) {
        result += "base ";
    } else if (dep.is_cond_jump()) {
        result += "cond-jump ";
    } else if (dep.is_cond_comp()) {
        result += "cond-comp ";
    } else {
        result += "other ";
    }
    if (!is_temp_dep(dep.kind())) {
        result += "(fixed) ";
    }
    result += to_string(*dep.instruction());
    return result;
}

//==============================================================================

class MicroExecSlice {
    friend class JumpTabAnalyzerImpl;

    static constexpr int64_t kDefaultConstIndexValue = -1;

public:

    MicroExecSlice();

    ~MicroExecSlice() = default;

    const MCInstPtrVec &instructions() const noexcept
    {
        return m_instructions;
    }

    addr_t bound_cond_jump_addr() const noexcept
    {
        return m_cond_jump_addr;
    }

    addr_t bound_cond_target_addr() const noexcept
    {
        return m_cond_jump_target;
    }

    int64_t bound_condition_constant() const noexcept
    {
        return m_cond_cmp_constant;
    }

    void add_instruction(MCInstPtr inst);

    bool has_bound_condition() const noexcept
    {
        return m_cond_jump_addr != 0;
    }

    addr_t jump_inst_address() const noexcept
    {
        return m_jump_inst_addr;
    }

    int64_t max_constant_index_value() const noexcept
    {
        return m_max_const_index_value;
    }

    bool is_index_set_to_constants() const noexcept
    {
        return m_max_const_index_value != kDefaultConstIndexValue;
    }

private:
    addr_t m_jump_inst_addr;
    addr_t m_cond_jump_addr;
    int64_t m_cond_cmp_constant;
    addr_t m_cond_jump_target;
    MCInstPtrVec m_instructions;
    int64_t m_max_const_index_value;
};

MicroExecSlice::MicroExecSlice() : m_cond_jump_addr(0),
                                   m_max_const_index_value(kDefaultConstIndexValue)
{ }

void
MicroExecSlice::add_instruction(MCInstPtr inst)
{
    m_instructions.push_back(inst);
}

sstring
to_string(const MicroExecSlice &slice)
{
    sstring result = to_string(*slice.instructions().front());
    for (auto inst_ptr_it = slice.instructions().begin() + 1;
         inst_ptr_it != slice.instructions().end(); ++inst_ptr_it) {
        result += " | " + to_string(*(*inst_ptr_it));
    }
    return result;
}

//==============================================================================

class BackwardDataFlowSlicer {

public:
    using OpndVec = std::vector<MCOpnd>;
    using RegBitSet = std::bitset<X64_CANONICAL_REG_COUNT>;

    BackwardDataFlowSlicer();

    BackwardDataFlowSlicer(const BackwardDataFlowSlicer &other);

    BackwardDataFlowSlicer &operator=(const BackwardDataFlowSlicer &other);

    ~BackwardDataFlowSlicer() = default;

    bool is_reg_var_alive(X64Reg reg) const noexcept;

    bool
    is_mem_var_alive(const x86_op_mem &mem, const cs_insn *inst) const noexcept;

    bool defines_live_var(const cs_insn *inst) const noexcept;

    const MCOpnd *get_defined_live_var(const cs_insn *inst) const noexcept;

    void update_defined_values(const cs_insn *inst) noexcept;

    bool uses_live_var(const cs_insn *inst) const noexcept;

    const MCOpnd *get_used_live_var(const cs_insn *inst) const noexcept;

    void add_instruction(const cs_insn *inst) noexcept;

    void kill_defined_var(const cs_insn *inst) noexcept;

    void kill_used_var(const cs_insn *inst) noexcept;

    void base_slicing_on(const BackwardDataFlowSlicer *slicer);

    size_t live_reg_var_count() const noexcept;

    size_t live_mem_var_count() const noexcept;

    size_t live_var_count() const noexcept;

    addr_t
    eval_direct_target(const x86_op_mem &mem, const cs_insn *inst) const noexcept;

    bool valid() const;

    void init(ValueIdx *value_idx);

    void reset() noexcept;

    void kill_reg_var(X64Reg reg) noexcept;

    ValueIdx *value_index() const noexcept;

protected:

    void fix_mov_value_ids(const cs_insn *inst) noexcept;

    void remove_mem_var_idx(unsigned opnd_idx) noexcept;

    RegBitSet get_live_mem_args(unsigned mem_opnd_idx) const noexcept;

    void kill_live_mem_args(unsigned mem_opnd_idx) noexcept;

    void kill_mem_var(const x86_op_mem &mem, const cs_insn *inst) noexcept;

    void make_live_reg_var(MCOpndKind kind, X64Reg reg) noexcept;

    void make_live_mem_var(const cs_insn *inst,
                           const cs_x86_op &opnd) noexcept;

    void make_live_mem_arg_var(MCOpndKind kind, X64Reg reg) noexcept;

    bool is_mem_var_equal(unsigned mem_opnd_idx, const x86_op_mem &mem,
                          const cs_insn *inst) const noexcept;

    bool is_mem_arg_alive(const MCOpnd &mem_arg) const noexcept;

    bool base_is_reg_var_alive(X64Reg reg) const noexcept;

    bool
    base_is_mem_var_alive(const x86_op_mem &mem, const cs_insn *inst) const noexcept;

    bool base_slicer_is_mem_arg_alive(const MCOpnd &mem_arg) const noexcept;

    const MCOpnd &get_reg_opnd(X64Reg reg) const;

    static X64Reg get_reg(x86_reg reg) noexcept;

    static bool is_irrelevant_inst(const cs_insn *inst) noexcept;

private:
    MCOpnd::ValueId *m_value_index_ptr;
    const BackwardDataFlowSlicer *m_base_slicer;
    RegBitSet m_live_reg_opnds;
    std::vector<unsigned> m_live_mem_opnds;
    OpndVec m_reg_opnds;
    OpndVec m_mem_opnds;
    bool m_update_value_id;
};

BackwardDataFlowSlicer::BackwardDataFlowSlicer()
    : m_value_index_ptr(nullptr), m_base_slicer(nullptr)
{ }

BackwardDataFlowSlicer::BackwardDataFlowSlicer(const BackwardDataFlowSlicer &other)
{
    m_value_index_ptr = other.m_value_index_ptr;
    m_base_slicer = other.m_base_slicer;
    m_live_reg_opnds = other.m_live_reg_opnds;
    m_live_mem_opnds = other.m_live_mem_opnds;
    m_reg_opnds = other.m_reg_opnds;
    m_mem_opnds = other.m_mem_opnds;
}

BackwardDataFlowSlicer &
BackwardDataFlowSlicer::operator=(const BackwardDataFlowSlicer &other)
{
    m_value_index_ptr = other.m_value_index_ptr;
    m_base_slicer = other.m_base_slicer;
    m_live_reg_opnds = other.m_live_reg_opnds;
    m_live_mem_opnds = other.m_live_mem_opnds;
    m_reg_opnds = other.m_reg_opnds;
    m_mem_opnds = other.m_mem_opnds;
    return *this;
}

bool
BackwardDataFlowSlicer::valid() const
{
    return !m_reg_opnds.empty();
}

void
BackwardDataFlowSlicer::init(ValueIdx *value_idx)
{
    m_value_index_ptr = value_idx;
    m_reg_opnds.resize(X64_CANONICAL_REG_COUNT);
}

void
BackwardDataFlowSlicer::base_slicing_on(const BackwardDataFlowSlicer *slicer)
{
    m_base_slicer = slicer;
}

X64Reg
BackwardDataFlowSlicer::get_reg(x86_reg reg) noexcept
{
    return get_canonical(get_x64_reg(reg));
}

void
BackwardDataFlowSlicer::reset() noexcept
{
    if (m_live_reg_opnds.none()) {
        return;
    }
    m_live_reg_opnds.reset();
    for (auto &reg_opnd : m_reg_opnds) {
        reg_opnd.invalidate();
    }
    m_live_mem_opnds.clear();
    m_mem_opnds.clear();
}

BackwardDataFlowSlicer::RegBitSet
BackwardDataFlowSlicer::get_live_mem_args(unsigned mem_opnd_idx) const noexcept
{
    if (m_live_mem_opnds.size() <= mem_opnd_idx) {
        return {};
    }
    RegBitSet result;
    for (auto mem_arg_it = m_mem_opnds.cbegin() + mem_opnd_idx + 1;
         mem_arg_it != m_mem_opnds.cend() &&
         mem_arg_it->is_reg_type(); ++mem_arg_it) {

        auto index = get_canonical_index(mem_arg_it->reg());
        if (m_reg_opnds[index] == *mem_arg_it) {
            result[index] = true;
        }
    }

    return result;
}

void
BackwardDataFlowSlicer::kill_live_mem_args(unsigned mem_opnd_idx) noexcept
{
    if (m_mem_opnds.size() <= mem_opnd_idx) {
        return;
    }

    for (auto mem_arg_it = m_mem_opnds.cbegin() + mem_opnd_idx + 1;
         mem_arg_it != m_mem_opnds.cend() &&
         mem_arg_it->is_reg_type(); ++mem_arg_it) {

        auto index = get_canonical_index(mem_arg_it->reg());
        if (m_reg_opnds[index] == *mem_arg_it) {
            kill_reg_var(mem_arg_it->reg());
        }
    }
}

ValueIdx *
BackwardDataFlowSlicer::value_index() const noexcept
{
    return m_value_index_ptr;
}

size_t
BackwardDataFlowSlicer::live_reg_var_count() const noexcept
{
    return m_live_reg_opnds.count();
}

size_t
BackwardDataFlowSlicer::live_mem_var_count() const noexcept
{
    return m_live_mem_opnds.size();
}

size_t
BackwardDataFlowSlicer::live_var_count() const noexcept
{
    return m_live_reg_opnds.count() + m_live_mem_opnds.size();
}

const MCOpnd &
BackwardDataFlowSlicer::get_reg_opnd(X64Reg reg) const
{
    return m_reg_opnds[get_canonical_index(reg)];
}

addr_t
BackwardDataFlowSlicer::eval_direct_target(const x86_op_mem &mem,
                                           const cs_insn *inst) const noexcept
{
    if (mem.base == X86_REG_RIP) {
        // [RIP + displacement]  index reg not allowed
        return inst->address + inst->size + mem.disp;
    }

    if (is_invalid(mem.base) && is_invalid(mem.index)) {
        // absolute address, should not be zero!
        return (addr_t) mem.disp;
    }

    return 0;
}

void
BackwardDataFlowSlicer::kill_reg_var(const X64Reg reg) noexcept
{
    m_live_reg_opnds[get_canonical_index(reg)] = false;
    m_reg_opnds[get_canonical_index(reg)].invalidate();
}

bool
BackwardDataFlowSlicer::is_mem_arg_alive(const MCOpnd &mem_arg) const noexcept
{
    return mem_arg == get_reg_opnd(mem_arg.reg());
}

bool
BackwardDataFlowSlicer::is_reg_var_alive(const X64Reg reg) const noexcept
{
    return m_live_reg_opnds[get_canonical_index(reg)];
}

bool
BackwardDataFlowSlicer::base_slicer_is_mem_arg_alive(
    const MCOpnd &mem_arg) const noexcept
{
    return m_base_slicer != nullptr && m_base_slicer->is_mem_arg_alive(mem_arg);
}

bool
BackwardDataFlowSlicer::base_is_reg_var_alive(X64Reg reg) const noexcept
{
    return m_base_slicer != nullptr && m_base_slicer->is_reg_var_alive(reg);
}

bool
BackwardDataFlowSlicer::base_is_mem_var_alive(const x86_op_mem &mem,
                                              const cs_insn *inst) const noexcept
{
    return m_base_slicer != nullptr && m_base_slicer->is_mem_var_alive(mem, inst);
}

bool
BackwardDataFlowSlicer::is_mem_var_equal(unsigned mem_opnd_idx,
                                         const x86_op_mem &mem,
                                         const cs_insn *inst) const noexcept
{
    const auto &opnd = m_mem_opnds[mem_opnd_idx];
    if (!opnd.valid() || !opnd.is_mem_type()) {
        return false;
    }
    if (opnd.is_direct_mem()) {
        return opnd.target() == eval_direct_target(mem, inst);
    }
    // XXX: check access size for better memory aliasing detection?
    // TODO: value id comparison for registers
    auto other_arg_count = get_arg_count(mem);
    for (unsigned i = mem_opnd_idx + 1;
         i < m_mem_opnds.size() && m_mem_opnds[i].is_mem_arg(); ++i) {

        switch (m_mem_opnds[i].kind()) {
        case MCOpndKind::kSegment:
            if (m_mem_opnds[i].reg() != get_reg(mem.segment)) {
                return false;
            }
            break;
        case MCOpndKind::kBase:
            if (m_mem_opnds[i].value_id() !=
                m_reg_opnds[get_canonical_index(get_x64_reg(mem.base))].value_id()) {
                return false;
            }
            break;
        case MCOpndKind::kIndex:
            if (m_mem_opnds[i].value_id() !=
                m_reg_opnds[get_canonical_index(
                    get_x64_reg(mem.index))].value_id()) {
                return false;
            }
            break;
        case MCOpndKind::kScale:
            if (m_mem_opnds[i].imm() != mem.scale) {
                return false;
            }
            break;
        case MCOpndKind::kDisp:
            if (m_mem_opnds[i].imm() != mem.disp) {
                return false;
            }
            break;
        default:break;
        }
        --other_arg_count;
    }
    return other_arg_count == 0;
}

bool
BackwardDataFlowSlicer::is_mem_var_alive(const x86_op_mem &mem,
                                         const cs_insn *inst) const noexcept
{
    for (const auto opnd_idx : m_live_mem_opnds) {
        if (is_mem_var_equal(opnd_idx, mem, inst)) {
            return true;
        }
    }
    return false;
}

void
BackwardDataFlowSlicer::kill_mem_var(const x86_op_mem &mem,
                                     const cs_insn *inst) noexcept
{
    for (const auto opnd_idx : m_live_mem_opnds) {
        if (is_mem_var_equal(opnd_idx, mem, inst)) {
            kill_live_mem_args(opnd_idx);
            remove_mem_var_idx(opnd_idx);
        }
    }
}

void
BackwardDataFlowSlicer::remove_mem_var_idx(unsigned opnd_idx) noexcept
{
    auto it = std::remove(m_live_mem_opnds.begin(), m_live_mem_opnds.end(),
                          opnd_idx);
    m_live_mem_opnds.erase(it, m_live_mem_opnds.end());
}

void
BackwardDataFlowSlicer::make_live_reg_var(MCOpndKind kind, X64Reg reg) noexcept
{
    m_live_reg_opnds[get_canonical_index(reg)] = true;
    m_reg_opnds[get_canonical_index(reg)] = MCOpnd(kind, reg, MCAccMode::kRead);
    m_reg_opnds[get_canonical_index(reg)].value_id((*m_value_index_ptr)++);
}

void
BackwardDataFlowSlicer::make_live_mem_arg_var(MCOpndKind kind, X64Reg reg) noexcept
{
    m_mem_opnds.emplace_back(MCOpnd(kind, reg, MCAccMode::kRead));
    if (is_reg_var_alive(reg)) {
        m_mem_opnds.back().value_id(get_reg_opnd(reg).value_id());
        // reg kind should be properly set
        m_reg_opnds[get_canonical_index(reg)] = m_mem_opnds.back();
    } else if (m_base_slicer != nullptr &&
               m_base_slicer->is_reg_var_alive(reg)) {
        m_mem_opnds.back().value_id(m_base_slicer->get_reg_opnd(reg).value_id());
        m_reg_opnds[get_canonical_index(reg)] = m_mem_opnds.back();
    } else {
        m_mem_opnds.back().value_id((*m_value_index_ptr)++);
        m_live_reg_opnds[get_canonical_index(reg)] = true;
        m_reg_opnds[get_canonical_index(reg)] = m_mem_opnds.back();
    }
}

void
BackwardDataFlowSlicer::make_live_mem_var(const cs_insn *inst,
                                          const cs_x86_op &opnd) noexcept
{
    // precondition: operand is memory
    m_live_mem_opnds.push_back((unsigned) m_mem_opnds.size());
    auto direct_target = eval_direct_target(opnd.mem, inst);
    if (direct_target != 0) {
        m_mem_opnds.emplace_back(MCOpnd(direct_target, opnd.size, MCAccMode::kRead));
        return;
    }
    m_mem_opnds.emplace_back(
        MCOpnd(X64_DEFAULT_MEM_TARGET, opnd.size, MCAccMode::kRead));
    m_mem_opnds.back().value_id((*m_value_index_ptr)++);

    if (!is_invalid(opnd.mem.segment)) {
        auto reg = get_reg(opnd.mem.segment);
        make_live_mem_arg_var(MCOpndKind::kSegment, reg);
    }
    if (!is_invalid(opnd.mem.base)) {
        auto reg = get_reg(opnd.mem.base);
        make_live_mem_arg_var(MCOpndKind::kBase, reg);
    }
    if (!is_invalid(opnd.mem.index) && opnd.mem.scale != 0) {
        auto reg = get_reg(opnd.mem.index);
        make_live_mem_arg_var(MCOpndKind::kIndex, reg);
        m_mem_opnds.emplace_back(MCOpnd(MCOpndKind::kScale, opnd.mem.scale));
        m_mem_opnds.back().value_id((*m_value_index_ptr)++);
    }
    if (opnd.mem.disp != 0) {
        m_mem_opnds.emplace_back(MCOpnd(MCOpndKind::kDisp, opnd.mem.disp));
        m_mem_opnds.back().value_id((*m_value_index_ptr)++);
    }
}

void
BackwardDataFlowSlicer::update_defined_values(const cs_insn *inst) noexcept
{
    auto details = inst->detail;
    for (int i = 0; i < details->x86.op_count; ++i) {
        if (details->x86.operands[i].type != X86_OP_REG ||
            !is_write((MCAccMode) details->x86.operands[i].access)) {
            continue;
        }
        auto reg = get_x64_reg(details->x86.operands[i].reg);
        auto id = (*m_value_index_ptr)++;
        m_reg_opnds[get_canonical_index(reg)].value_id(id);
    }
}

bool
BackwardDataFlowSlicer::is_irrelevant_inst(const cs_insn *inst) noexcept
{
    // XXX: capstone's data flow information for SSE and AVX instructions has bugs.
    // encountered example "repne movsd	xmm3, xmmword ptr [rdx + 8]" (hex f2 0f 10 5a 08)
    // this instruction reads and modifies rcx as reported by capstone!

    // SSE and AVX instructions are irrelevant anyway for jumptable analysis

    for (int i = 0; i < inst->detail->groups_count; ++i) {
        auto grp = inst->detail->groups[i];
        if (X86_GRP_SSE1 <= grp && grp <= X86_GRP_SSSE3) {
            return true;
        }
        if (X86_GRP_AVX <= grp && grp <= X86_GRP_AVX512) {
            return true;
        }
    }
    return false;
}

bool
BackwardDataFlowSlicer::defines_live_var(const cs_insn *inst) const noexcept
{
    return get_defined_live_var(inst) != nullptr;
}

const MCOpnd *
BackwardDataFlowSlicer::get_defined_live_var(const cs_insn *inst) const noexcept
{
    auto detail_p = inst->detail;
    if (is_irrelevant_inst(inst)) {
        return nullptr;
    }
    for (unsigned i = 0; i < detail_p->regs_write_count; ++i) {
        auto reg = get_reg((x86_reg) detail_p->regs_write[i]);
        if (is_reg_var_alive(reg) && reg != x64::X64Reg::RSP) {
            // instructions that implicitly defines rsp like call, push and pop,
            // will introduce false dependencies for stack variables
            return &m_reg_opnds[get_canonical_index(reg)];
        }
    }
    for (int i = 0; i < detail_p->x86.op_count; ++i) {
        if (!is_write((MCAccMode) detail_p->x86.operands[i].access)) {
            continue;
        }
        if (detail_p->x86.operands[i].type == X86_OP_REG) {
            if (is_reg_var_alive(get_reg(detail_p->x86.operands[i].reg))) {
                auto reg = get_reg(detail_p->x86.operands[i].reg);
                return &m_reg_opnds[get_canonical_index(reg)];
            }
        }
        if (detail_p->x86.operands[i].type == X86_OP_MEM) {
            for (const auto idx : m_live_mem_opnds) {
                if (is_mem_var_equal(idx, detail_p->x86.operands[i].mem, inst)) {
                    return &m_mem_opnds[idx];
                }
            }
        }
    }
    return nullptr;
}

bool
BackwardDataFlowSlicer::uses_live_var(const cs_insn *inst) const noexcept
{
    auto details = inst->detail;
    for (unsigned i = 0; i < details->regs_read_count; ++i) {
        if (is_reg_var_alive(get_reg((x86_reg) details->regs_read[i]))) {
            return true;
        }
    }

    for (int i = 0; i < details->x86.op_count; ++i) {
        if (!is_read_acc(details->x86.operands[i].access)) {
            continue;
        }
        if (details->x86.operands[i].type == X86_OP_REG) {
            if (is_reg_var_alive(get_reg(details->x86.operands[i].reg))) {
                return true;
            }
        }
        if (details->x86.operands[i].type == X86_OP_MEM) {
            if (is_mem_var_alive(details->x86.operands[i].mem, inst)) {
                return true;
            }
        }
    }
    return false;
}

const MCOpnd *
BackwardDataFlowSlicer::get_used_live_var(const cs_insn *inst) const noexcept
{
    auto details = inst->detail;
    for (unsigned i = 0; i < details->regs_read_count; ++i) {
        auto reg = get_reg((x86_reg) details->regs_read[i]);
        if (is_reg_var_alive(reg)) {
            return &m_reg_opnds[get_index(reg)];
        }
    }

    for (int i = 0; i < details->x86.op_count; ++i) {
        if (!is_read_acc(details->x86.operands[i].access)) {
            continue;
        }
        if (details->x86.operands[i].type == X86_OP_REG) {
            auto reg = get_reg(details->x86.operands[i].reg);
            if (is_reg_var_alive(reg)) {
                return &m_reg_opnds[get_index(reg)];
            }
        }
        if (details->x86.operands[i].type == X86_OP_MEM) {
            if (is_mem_var_alive(details->x86.operands[i].mem, inst)) {
                // FIXME
                return &m_mem_opnds[m_live_mem_opnds[0]];
            }
        }
    }
    return nullptr;
}

void
BackwardDataFlowSlicer::kill_defined_var(const cs_insn *inst) noexcept
{
    auto details = inst->detail;
    for (unsigned i = 0; i < details->regs_write_count; ++i) {
        auto reg = get_reg((x86_reg) details->regs_write[i]);
        if (is_reg_var_alive(reg)) {
            kill_reg_var(reg);
        }
    }

    for (unsigned i = 0; i < details->x86.op_count; ++i) {
        if (!is_write((MCAccMode) details->x86.operands[i].access)) {
            continue;
        }
        if (details->x86.operands[i].type == X86_OP_REG) {
            auto reg = get_reg(details->x86.operands[i].reg);
            if (is_reg_var_alive(reg)) {
                kill_reg_var(reg);
            }
        }
        if (details->x86.operands[i].type == X86_OP_MEM) {
            kill_mem_var(details->x86.operands[i].mem, inst);
        }
    }
}

void
BackwardDataFlowSlicer::kill_used_var(const cs_insn *inst) noexcept
{
    auto details = inst->detail;
    for (unsigned i = 0; i < details->regs_read_count; ++i) {
        auto reg = get_reg((x86_reg) details->regs_read[i]);
        if (is_reg_var_alive(reg)) {
            kill_reg_var(reg);
        }
    }

    for (int i = 0; i < details->x86.op_count; ++i) {
        if (!is_read_acc(details->x86.operands[i].access)) {
            continue;
        }
        if (details->x86.operands[i].type == X86_OP_REG) {
            auto reg = get_reg(details->x86.operands[i].reg);
            if (is_reg_var_alive(reg)) {
                kill_reg_var(reg);
            }
        }
        if (details->x86.operands[i].type == X86_OP_MEM) {
            kill_mem_var(details->x86.operands[i].mem, inst);
        }
    }
}

void
BackwardDataFlowSlicer::add_instruction(const cs_insn *inst) noexcept
{
    auto details = inst->detail;
    if (is_lea_inst(inst)) {
        // handle the awkward LEA
        kill_reg_var(get_reg(details->x86.operands[0].reg));
        auto &mem = details->x86.operands[1].mem;
        if (mem.base == X86_REG_RIP) {
            // ignore immediate operands
            return;
        }

        auto reg = get_reg(mem.base);
        if (!is_invalid(mem.base) && !is_reg_var_alive(reg) &&
            !base_is_reg_var_alive(reg)) {
            make_live_reg_var(MCOpndKind::kReg, reg);
        }

        reg = get_reg(mem.index);
        if (!is_invalid(mem.index) && !is_reg_var_alive(reg) &&
            !base_is_reg_var_alive(reg)) {
            make_live_reg_var(MCOpndKind::kReg, get_reg(mem.index));
        }

        return;
    }

    // for each defined operand, kill if alive
    kill_defined_var(inst);

    if (is_constant_xor(inst)) {
        return;
    }

    // for each used operand, make alive with new value id
    for (unsigned i = 0; i < details->regs_read_count; ++i) {
        auto reg = get_reg((x86_reg) details->regs_read[i]);
        if (!is_reg_var_alive(reg) && !base_is_reg_var_alive(reg)) {
            make_live_reg_var(MCOpndKind::kReg, reg);
        }
    }

    for (unsigned i = 0; i < details->x86.op_count; ++i) {
        if (!is_read_acc(details->x86.operands[i].access)) {
            continue;
        }
        if (details->x86.operands[i].type == X86_OP_REG) {
            auto reg = get_reg(details->x86.operands[i].reg);
            if (!is_reg_var_alive(reg) && !base_is_reg_var_alive(reg)) {
                make_live_reg_var(MCOpndKind::kReg, reg);
            }
        } else if (details->x86.operands[i].type == X86_OP_MEM) {
            if (!is_mem_var_alive(details->x86.operands[i].mem, inst) &&
                !base_is_mem_var_alive(details->x86.operands[i].mem, inst)) {
                make_live_mem_var(inst, details->x86.operands[i]);
            }
        }
    }

    if (is_mov_inst(inst)) {
        fix_mov_value_ids(inst);
    }
}

void
BackwardDataFlowSlicer::fix_mov_value_ids(const cs_insn *inst) noexcept
{
    auto details = inst->detail;
    DCHECK(details->x86.op_count == 2);

    MCOpnd::ValueId original_value_id = 0;
    if (details->x86.operands[0].type == X86_OP_REG) {
        auto reg_idx = get_canonical_index(
            get_x64_reg(details->x86.operands[0].reg));
        original_value_id = m_reg_opnds[reg_idx].value_id();
    } else if (details->x86.operands[0].type == X86_OP_MEM) {
        /// FIXME
        auto mem_opnd = std::find_if(m_mem_opnds.rbegin(), m_mem_opnds.rend(),
                                     [](const MCOpnd &opnd) { return opnd.is_mem_type(); }
        );
        original_value_id = mem_opnd->value_id();
    }

    if (details->x86.operands[1].type == X86_OP_REG) {
        auto reg_idx = get_canonical_index(
            get_x64_reg(details->x86.operands[1].reg));
        m_reg_opnds[reg_idx].value_id(original_value_id);
    } else if (details->x86.operands[1].type == X86_OP_MEM) {
        auto result = std::find_if(m_mem_opnds.rbegin(), m_mem_opnds.rend(),
                                   [](const MCOpnd &opnd) { return opnd.is_mem_type(); }
        );
        if (result != m_mem_opnds.rend()) {
            result->value_id(original_value_id);
        }
    }
}

//==============================================================================

class BaseSlicingVisitor : public GraphVisitorBase<CFG::Node> {
public:
    using JTDependencyVec = std::vector<JTDependency>;

    explicit BaseSlicingVisitor(const IFunction &function,
                                const BackwardDataFlowSlicer &slicer);

    ~BaseSlicingVisitor() = default;

    void visit_preorder(const CFG::Node &vertex, const CFG::Node *parent) override;

    bool is_finished() const noexcept override;

    JTDependencySpan dependencies() const noexcept;

    void identify_base_register(const CFG::Node &vertex);

    bool does_modify_base_register(const cs_insn *inst) const noexcept;

private:
    void set_base_dependency(const MCInst &node, int64_t constant);

    void add_dependency(const MCInst &node);

    x64::X64Reg get_read_register(const cs_insn *inst) const noexcept;

private:
    const IFunction &m_function;
    BackwardDataFlowSlicer m_base_slicer;
    x64::X64Reg m_base_register;
    JTDependencyVec m_base_deps;
    CSInstWrapper m_cs_inst;
    Disassembler m_disasm;
};

BaseSlicingVisitor::BaseSlicingVisitor(const IFunction &function,
                                       const BackwardDataFlowSlicer &slicer)
    : m_function(function), m_base_slicer(slicer),
      m_base_register(x64::X64Reg::Invalid)
{
    m_disasm.init(DisasmArch::kX86, DisasmMode::k64);
}

bool
BaseSlicingVisitor::does_modify_base_register(const cs_insn *inst) const noexcept
{
    auto &opnds = inst->detail->x86.operands;
    return m_base_register != x64::X64Reg::Invalid && inst->id == X86_INS_MOV &&
           m_base_register == get_canonical(get_x64_reg(opnds[0].reg));
}

void
BaseSlicingVisitor::identify_base_register(const CFG::Node &vertex)
{
    for (auto inst_it = vertex.instructions().rbegin();
         inst_it != vertex.instructions().rend(); ++inst_it) {

        disasm_inst(m_function, *inst_it, m_disasm, m_cs_inst.get());
        if (check_reads_mem(m_cs_inst.get())) {
            // analyze only jump-table access
            auto &opnd = *get_mem_opnd(m_cs_inst.get());
            // TODO: base register might be modified in pivot bb
            m_base_register = get_canonical(get_x64_reg(opnd.mem.base));
            break;
        }
    }
}

x64::X64Reg
BaseSlicingVisitor::get_read_register(const cs_insn *inst) const noexcept
{
    for (unsigned i = 0; i < inst->detail->x86.op_count; ++i) {
        auto &opnd = inst->detail->x86.operands[i];
        if (opnd.type == X86_OP_REG && is_read_acc(opnd.access) &&
            !is_write_acc(opnd.access)) {
            return get_canonical(get_x64_reg(opnd.reg));
        }
    }
    return x64::X64Reg::Invalid;
}

void
BaseSlicingVisitor::visit_preorder(const CFG::Node &vertex, const CFG::Node *parent)
{
    if (parent == nullptr) {
        identify_base_register(vertex);
        return;
    }
    if (vertex.is_virtual()) {
        DVLOG(4) << "jumptab: base search reached virtual entry";
        return;
    }
    DVLOG(5) << "jumptab: visiting n @ " << std::hex << vertex.address() << " p @ "
             << parent->address();
    for (auto inst_it = vertex.instructions().rbegin();
         inst_it != vertex.instructions().rend(); ++inst_it) {

        disasm_inst(m_function, *inst_it, m_disasm, m_cs_inst.get());

        auto defined_opnd = m_base_slicer.get_defined_live_var(m_cs_inst.get());
        if (defined_opnd == nullptr) {
            continue;
        }
        if (get_canonical(defined_opnd->reg()) != m_base_register &&
            m_base_deps.empty()) {
            continue;
        }
        if (m_base_deps.empty()) {
            m_base_slicer.reset();
        }
        add_dependency(*inst_it);
        auto base = check_sets_jumptab_base(m_cs_inst.get());
        // XXX: quick & effective heuristic to counter small constants
        // Generally, jump-table base should be in a read-only section located after
        // code section.
        if (base > m_function.address()) {
            set_base_dependency(*inst_it, base);
            VLOG(3) << "jumptab: found constant base @ "
                    << to_string(m_cs_inst);
            break;
        }
        // TODO: handle assignment to base register on different paths
        m_base_slicer.add_instruction(m_cs_inst.get());
        DVLOG(4) << "jumptab: base register modified @ " << m_cs_inst.get()->address;
    }
}

bool
BaseSlicingVisitor::is_finished() const noexcept
{
    return !m_base_deps.empty() && m_base_deps.back().is_base();
}

void
BaseSlicingVisitor::set_base_dependency(const MCInst &node, int64_t constant)
{
    m_base_deps.back().m_kind = JTDepKind::kBase;
    m_base_deps.back().m_info.m_inst = &node;
    m_base_deps.back().m_info.m_constant = constant;
}

void
BaseSlicingVisitor::add_dependency(const MCInst &node)
{
    m_base_deps.emplace_back(JTDependency());
    m_base_deps.back().m_kind = JTDepKind::kMerge;
    m_base_deps.back().m_info.m_inst = &node;
}

JTDependencySpan
BaseSlicingVisitor::dependencies() const noexcept
{
    return m_base_deps;
}

//==============================================================================

class BoundConditionSlicingVisitor : public GraphVisitorBase<CFG::Node> {
public:

    using ConstantIndexValueVec = std::vector<int>;

    explicit BoundConditionSlicingVisitor(const IFunction &function,
                                          const BackwardDataFlowSlicer &slicer);

    void visit_preorder(const CFG::Node &vertex, const CFG::Node *parent) override;

    void visit_peek(const CFG::Node &vertex, const CFG::Node &parent) override;

    bool is_path_finished(const CFG::Node &vertex) const noexcept override;

    bool is_path_complex(const CFG::Node &node) const noexcept;

    bool is_finished() const noexcept override;

    JTDependencySpan dependencies() const noexcept;

    JTConstantIndexValueSpan constant_index_values() const noexcept;

    unsigned cond_dependency_count() const noexcept;

    bool is_virtual_entry_reachable() const noexcept;

protected:

    void reset_conditions_and_finish_traversal();

    void analyze_path_bound_condition(const CFG::Node &cond_node,
                                      const CFG::Node &target_node,
                                      const CFG::Node &target_parent);

    static bool increases_dataflow_complexity(const cs_insn *inst);

    static bool bound_condition_mergeable(const BackwardDataFlowSlicer &slicer);

    BackwardDataFlowSlicer *
    get_or_make_slicer(const CFG::Node &node, const CFG::Node &parent);

    void set_path_finished(const CFG::Node &node);

    void set_path_complex(const CFG::Node &node);

    void set_found_bound_condition(const CFG::Node &node);

    void add_link_dep(const CFG::Node &vertex, const CFG::Node *parent);

    void add_info_dep(JTDepKind kind, const MCInst &inst, int64_t constant = 0);

    bool check_many_live_vars(const BackwardDataFlowSlicer &slicer) const;

    bool check_few_live_vars(const BackwardDataFlowSlicer &slicer) const;

    void collect_constant_index_values();

    void merge_conditional_deps(const CFG::Node &vertex);

    void set_head_link(JTDependency &dep);

    void merge_temp_conditional_deps(const CFG::Node &cond_node);

    void path_init_cond_slicer(JTDependencyVec::reverse_iterator cond_link_it,
                               JTDependencyVec::reverse_iterator vertex_link_it);

    bool is_bound_cond_found(const CFG::Node &vertex) const noexcept
    {
        auto status = get_path_status(vertex);
        return (status & JTSlicerPathStatus::kHasCond) ==
               JTSlicerPathStatus::kHasCond;
    }

    bool defines_bound_condition(const CFG::Node &vertex) const
    {
        return m_slicer_path_status[vertex.id()] == JTSlicerPathStatus::kSetsCond;
    }

    JTSlicerPathStatus get_path_status(const CFG::Node &vertex) const
    {
        return m_slicer_path_status[vertex.id()] & JTSlicerPathStatus::kHasCond;
    }

    void set_path_status(const CFG::Node &vertex, JTSlicerPathStatus a)
    {
        m_slicer_path_status[vertex.id()] = a;
    }

    BackwardDataFlowSlicer *get_slicer(const CFG::Node &vertex)
    {
        return m_slicer_ptrs[vertex.id()];
    }

    void set_slicer(const CFG::Node &vertex, BackwardDataFlowSlicer *slicer)
    {
        m_slicer_ptrs[vertex.id()] = slicer;
    }

    void find_bound_condition_in_successors();

    JTDependencyVec::iterator
    get_successor(JTDependencyVec::iterator link_it);

    JTDependencyVec::reverse_iterator
    get_predecessor(JTDependencyVec::reverse_iterator link_it);

    JTDependencyVec::reverse_iterator get_last_link_dep();

private:
    const IFunction &m_function;
    BackwardDataFlowSlicer m_pivot_slicer;
    int m_cond_dep_count;
    JTDependencyVec m_found_deps;
    ConstantIndexValueVec m_found_constant_indices;
    std::vector<std::pair<JTDepKind, const MCInst *>> m_temp_found_deps;
    bool m_virtual_entry_reachable;
    BackwardDataFlowSlicer m_cond_slicer;
    std::vector<BackwardDataFlowSlicer *> m_slicer_ptrs;
    std::vector<JTSlicerPathStatus> m_slicer_path_status;
    std::forward_list<BackwardDataFlowSlicer> m_df_slicers;
    CSInstWrapper m_cs_inst;
    Disassembler m_disasm;
};

BoundConditionSlicingVisitor::BoundConditionSlicingVisitor(const IFunction &function,
                                                           const BackwardDataFlowSlicer &slicer)
    : m_function(function), m_pivot_slicer(slicer), m_cond_dep_count(0),
      m_virtual_entry_reachable(false)
{
    m_cond_slicer.init(m_pivot_slicer.value_index());
    m_slicer_ptrs.resize(m_function.cfg().size(), nullptr);
    m_slicer_path_status.resize(m_function.cfg().size(), JTSlicerPathStatus::kNone);
    m_disasm.init(DisasmArch::kX86, DisasmMode::k64);
}

void
BoundConditionSlicingVisitor::set_found_bound_condition(const CFG::Node &node)
{
    m_slicer_path_status[node.id()] = JTSlicerPathStatus::kSetsCond;
}

bool
BoundConditionSlicingVisitor::check_many_live_vars(
    const BackwardDataFlowSlicer &slicer) const
{
    return slicer.live_mem_var_count() > 2 || slicer.live_reg_var_count() > 3;
}

bool
BoundConditionSlicingVisitor::check_few_live_vars(
    const BackwardDataFlowSlicer &slicer) const
{
    return slicer.live_var_count() < 2;
}

void
BoundConditionSlicingVisitor::collect_constant_index_values()
{
    auto link_it = get_forward_iter(m_found_deps, get_last_link_dep());
    for (auto dep_it = link_it + 1; dep_it < m_found_deps.end(); ++dep_it) {
        auto inst_p = m_cs_inst.get();
        disasm_inst(m_function, *dep_it->instruction(), m_disasm, inst_p);
        if (is_mov_inst(inst_p) && has_constant_opnd(inst_p)) {
            m_found_constant_indices.push_back(get_constant_opnd(inst_p));
            break;
        }
        if (is_constant_xor(inst_p)) {
            m_found_constant_indices.push_back(0);
        }
    }
    // dependencies that set index to a constant are not needed anymore
    m_found_deps.erase(link_it + 1, m_found_deps.end());
}

void
BoundConditionSlicingVisitor::add_link_dep(const CFG::Node &vertex,
                                           const CFG::Node *parent)
{
    m_found_deps.emplace_back(JTDependency());
    m_found_deps.back().m_kind = JTDepKind::kLink;
    m_found_deps.back().m_link.m_node = &vertex;
    m_found_deps.back().m_link.m_parent = parent;
    DVLOG(5) << "jumptab: add " << to_string(m_found_deps.back());
}

void
BoundConditionSlicingVisitor::add_info_dep(JTDepKind kind, const MCInst &inst,
                                           int64_t constant)
{
    m_found_deps.emplace_back(JTDependency());
    m_found_deps.back().m_kind = kind;
    m_found_deps.back().m_info.m_inst = &inst;
    m_found_deps.back().m_info.m_constant = constant;
    DVLOG(5) << "jumptab: add " << to_string(m_found_deps.back());
}

void
BoundConditionSlicingVisitor::merge_temp_conditional_deps(const CFG::Node &cond_node)
{
    DCHECK(m_found_deps.back().is_link());
    auto link_it = m_found_deps.rbegin();
    set_head_link(*link_it);
    while (*link_it->node() != cond_node) {
        set_path_status(*link_it->node(), JTSlicerPathStatus::kHasCond);
        set_path_finished(*link_it->node());
        link_it = get_predecessor(link_it);
    }

    set_path_status(*link_it->node(), JTSlicerPathStatus::kSetsCond);
    set_path_finished(cond_node);

    for (auto dep_it = link_it - 1; !dep_it->is_link(); --dep_it) {
        dep_it->m_kind = make_fixed(dep_it->m_kind);
    }

    // caution: adding dependencies can invalidate iterators!
    for (const auto &temp_dep_pair : m_temp_found_deps) {
        add_info_dep(make_fixed(temp_dep_pair.first), *temp_dep_pair.second);
    }
}

void
BoundConditionSlicingVisitor::merge_conditional_deps(const CFG::Node &vertex)
{
    set_head_link(*get_last_link_dep());

    for (auto dep_it = m_found_deps.rbegin();
         !dep_it->is_link() && dep_it != m_found_deps.rend(); ++dep_it) {

        dep_it->m_kind = make_fixed(dep_it->m_kind);
    }
    set_found_bound_condition(vertex);
    set_path_finished(vertex);
}

void
BoundConditionSlicingVisitor::set_head_link(JTDependency &dep)
{
    dep.m_kind = JTDepKind::kHeadLink;
}

unsigned
BoundConditionSlicingVisitor::cond_dependency_count() const noexcept
{
    return m_cond_dep_count < 0 ? 0 : m_cond_dep_count;
}

bool
BoundConditionSlicingVisitor::is_virtual_entry_reachable() const noexcept
{
    return m_virtual_entry_reachable;
}

bool
BoundConditionSlicingVisitor::is_path_finished(
    const CFG::Node &vertex) const noexcept
{
    return m_slicer_ptrs[vertex.id()] == nullptr;
}

void
BoundConditionSlicingVisitor::set_path_finished(const CFG::Node &node)
{
    m_slicer_ptrs[node.id()] = nullptr;
}

bool
BoundConditionSlicingVisitor::is_path_complex(const CFG::Node &node) const noexcept
{
    return m_slicer_ptrs[node.id()] == (BackwardDataFlowSlicer *) 1;
}

void
BoundConditionSlicingVisitor::set_path_complex(const CFG::Node &node)
{
    m_slicer_ptrs[node.id()] = (BackwardDataFlowSlicer *) 1;
}

JTDependencySpan
BoundConditionSlicingVisitor::dependencies() const noexcept
{
    return m_found_deps;
}

JTConstantIndexValueSpan
BoundConditionSlicingVisitor::constant_index_values() const noexcept
{
    return m_found_constant_indices;
}

BackwardDataFlowSlicer *
BoundConditionSlicingVisitor::get_or_make_slicer(const CFG::Node &node,
                                                 const CFG::Node &parent)
{
    if (m_slicer_ptrs[node.id()] != nullptr) {
        return &(*m_slicer_ptrs[node.id()]);
    }
    m_df_slicers.emplace_front(*m_slicer_ptrs[parent.id()]);
    m_slicer_ptrs[node.id()] = &m_df_slicers.front();
    return &m_df_slicers.front();
}

void
BoundConditionSlicingVisitor::path_init_cond_slicer(
    JTDependencyVec::reverse_iterator cond_link_it,
    JTDependencyVec::reverse_iterator vertex_link_it)
{
    // SmallVector optimization here
    std::vector<const BasicBlock *> path_basic_blocks;

    m_cond_slicer.reset();
    m_cond_slicer.base_slicing_on(get_slicer(*cond_link_it->parent()));
    for (auto dep_it = cond_link_it - 1; !dep_it->is_link(); --dep_it) {
        disasm_inst(m_function, *dep_it->instruction(), m_disasm, m_cs_inst.get());
        m_cond_slicer.add_instruction(m_cs_inst.get());
    }

    auto predecessor_it = get_predecessor(vertex_link_it);
    while (predecessor_it != cond_link_it && predecessor_it != m_found_deps.rend()) {
        path_basic_blocks.push_back(predecessor_it->node());
        predecessor_it = get_predecessor(predecessor_it);
    }

    DCHECK(predecessor_it == cond_link_it);

    for (auto rev_bb_it = path_basic_blocks.rbegin();
         rev_bb_it != path_basic_blocks.rend(); ++rev_bb_it) {
        auto bb_p = *rev_bb_it;
        m_cond_slicer.base_slicing_on(get_slicer(*bb_p));
        for (auto inst_it = bb_p->instructions().rbegin();
             inst_it != bb_p->instructions().rend(); ++inst_it) {
            disasm_inst(m_function, *inst_it, m_disasm, m_cs_inst.get());
            if (!m_cond_slicer.defines_live_var(m_cs_inst.get())) {
                continue;
            }
            m_cond_slicer.add_instruction(m_cs_inst.get());
            m_temp_found_deps.emplace_back(
                std::make_pair(make_temp(JTDepKind::kMerge), &(*inst_it)));
        }
    }
}

void
BoundConditionSlicingVisitor::find_bound_condition_in_successors()
{
    std::vector<JTDependencyVec::reverse_iterator> bound_cond_links;
    auto rev_last_link_it = get_last_link_dep();
    auto predecessor_it = get_predecessor(rev_last_link_it);
    while (predecessor_it != m_found_deps.rend()) {
        for (auto dep_it = predecessor_it - 1; !dep_it->is_link(); --dep_it) {
            if (make_fixed(dep_it->kind()) == JTDepKind::kCondComp) {
                bound_cond_links.push_back(predecessor_it);
            }
        }
        predecessor_it = get_predecessor(predecessor_it);
    }

    if (bound_cond_links.empty()) {
        VLOG(4) << "jumptab: no bound condition found in successors!";
        return;
    }

    auto fwd_last_link_it = get_forward_iter<JTDependencyVec>(m_found_deps,
                                                              rev_last_link_it);

    for (auto cond_link_it = bound_cond_links.rbegin();
         !is_bound_cond_found(*fwd_last_link_it->node()) &&
         cond_link_it != bound_cond_links.rend(); ++cond_link_it) {

        DVLOG(4) << "jumptab: analyzing bound condition of bb @ "
                 << std::hex << (*cond_link_it)->node()->address()
                 << " for bb @ " << fwd_last_link_it->node()->address();

        // using m_temp_found_deps here instead of m_found_deps. This is needed
        // to guarantee that vector iterators used here remain valid
        m_temp_found_deps.clear();
        m_found_deps.erase(fwd_last_link_it + 1, m_found_deps.end());

        path_init_cond_slicer(*cond_link_it, rev_last_link_it);
        auto cond_node = (*cond_link_it)->node();
        analyze_path_bound_condition(*cond_node, *fwd_last_link_it->node(),
                                     *fwd_last_link_it->parent());
    }

    if (!is_bound_cond_found(*fwd_last_link_it->node())) {
        for (const auto &temp_dep_pair : m_temp_found_deps) {
            if (!is_temp_dep(temp_dep_pair.first)) {
                add_info_dep(temp_dep_pair.first, *temp_dep_pair.second);
            }
        }
    }
}

JTDependencyVec::iterator
BoundConditionSlicingVisitor::get_successor(JTDependencyVec::iterator link_it)
{
    return std::find_if(link_it + 1, m_found_deps.end(),
                        [link_it](const JTDependency &dep) {
                            return dep.parent() == link_it->node();
                        });
}

JTDependencyVec::reverse_iterator
BoundConditionSlicingVisitor::get_predecessor(
    JTDependencyVec::reverse_iterator link_it)
{
    return std::find_if(link_it + 1, m_found_deps.rend(),
                        [link_it](const JTDependency &dep) {
                            return dep.node() == link_it->parent();
                        });
}

JTDependencyVec::reverse_iterator
BoundConditionSlicingVisitor::get_last_link_dep()
{
    return std::find_if(m_found_deps.rbegin(), m_found_deps.rend(),
                        [](const JTDependency &dep) {
                            return dep.is_link();
                        });
}

bool
BoundConditionSlicingVisitor::increases_dataflow_complexity(const cs_insn *inst)
{
    uint reg_rd_count = 0;
    uint reg_wr_count = 0;
    uint mem_reg_read_count = 0;
    for (unsigned i = 0; i < inst->detail->x86.op_count; ++i) {
        auto &opnd = inst->detail->x86.operands[i];
        if (opnd.type == X86_OP_REG && is_read_acc(opnd.access)) {
            ++reg_rd_count;
        }
        if (opnd.type == X86_OP_REG && is_write_acc(opnd.access)) {
            ++reg_wr_count;
        }
        if (opnd.type == X86_OP_MEM && is_read_acc(opnd.access)) {
            mem_reg_read_count = get_reg_arg_count(opnd.mem);
        }
    }
    return (reg_rd_count > 1 && reg_wr_count > 0) || mem_reg_read_count > 1;
}

bool
BoundConditionSlicingVisitor::bound_condition_mergeable(
    const BackwardDataFlowSlicer &slicer)
{
    // index variable must either be a register - or a memory operand which uses
    // a single register as base.
    bool mergeable = slicer.live_reg_var_count() < 2;
    VLOG_IF(!mergeable, 4) << "jumptab: unmergeable bound condition!";
    return mergeable;
}

void
BoundConditionSlicingVisitor::analyze_path_bound_condition(
    const CFG::Node &cond_node, const CFG::Node &target_node,
    const CFG::Node &target_parent)
{
    set_slicer(target_node, nullptr);
    BackwardDataFlowSlicer *cur_slicer = get_slicer(target_parent);
    set_path_status(target_node, get_path_status(target_parent));
    auto inst_it = target_node.instructions().rbegin();

    for (; inst_it != target_node.instructions().rend(); ++inst_it) {
        disasm_inst(m_function, *inst_it, m_disasm, m_cs_inst.get());

        if (m_cond_slicer.defines_live_var(m_cs_inst.get()) &&
            increases_dataflow_complexity(m_cs_inst.get())) {
            m_cond_slicer.reset();
        }
        if (m_cond_slicer.defines_live_var(m_cs_inst.get())) {
            m_cond_slicer.add_instruction(m_cs_inst.get());

            m_temp_found_deps.emplace_back(
                std::make_pair(make_temp(JTDepKind::kMerge), &(*inst_it)));

            if (cur_slicer->uses_live_var(m_cs_inst.get()) &&
                bound_condition_mergeable(*cur_slicer)) {
                ++m_cond_dep_count;
                merge_temp_conditional_deps(cond_node);
                VLOG(5) << "jumptab: merged bound condition @ "
                        << std::hex << m_cs_inst.get()->address;
                break;
            }
            continue;
        }

        if (!cur_slicer->defines_live_var(m_cs_inst.get())) {
            continue;
        }
        if (increases_dataflow_complexity(m_cs_inst.get())) {
            break;
        }
        cur_slicer = get_or_make_slicer(target_node, target_parent);
        m_cond_slicer.base_slicing_on(cur_slicer);
        cur_slicer->add_instruction(m_cs_inst.get());
        m_temp_found_deps.emplace_back(
            std::make_pair(JTDepKind::kMerge, &(*inst_it)));

        if (m_cond_slicer.uses_live_var(m_cs_inst.get()) &&
            bound_condition_mergeable(*cur_slicer)) {
            ++m_cond_dep_count;
            merge_temp_conditional_deps(cond_node);
            VLOG(3) << "jumptab: merged bound condition @ "
                    << std::hex << m_cs_inst.get()->address;
            break;
        }
    }
}

void
BoundConditionSlicingVisitor::visit_preorder(const CFG::Node &vertex,
                                             const CFG::Node *parent)
{
    if (parent == nullptr) {
        // this is the pivot bb
        set_slicer(vertex, &m_pivot_slicer);
        add_link_dep(vertex, parent);
        return;
    }

    if (vertex.is_virtual()) {
        m_virtual_entry_reachable = true;
        DVLOG(3) << "jumptab: reached virtual entry node";
        return;
    }

    if (is_path_finished(*parent) || is_path_complex(*parent)) {
        return;
    }

    add_link_dep(vertex, parent);

    BackwardDataFlowSlicer *cur_slicer = get_slicer(*parent);

    bool bound_comp_with_const = false;
    bool exists_valid_bound_jmp = false;
    bool is_live_var_def_or_use = false;

    m_cond_slicer.reset();

    if (vertex.instructions().back().is_conditional() &&
        vertex.instructions().back().is_jump()) {

        disasm_inst(m_function, vertex.instructions().back(), m_disasm,
                    m_cs_inst.get());
        exists_valid_bound_jmp = is_valid_bound_jmp(m_cs_inst.get());
        if (exists_valid_bound_jmp) {
            m_cond_slicer.base_slicing_on(cur_slicer);
            m_cond_slicer.add_instruction(m_cs_inst.get());
            add_info_dep(make_temp(JTDepKind::kCondJump),
                         vertex.instructions().back(), parent->address());
        }
    }

    for (auto inst_it = vertex.instructions().rbegin();
         inst_it != vertex.instructions().rend(); ++inst_it) {

        disasm_inst(m_function, *inst_it, m_disasm, m_cs_inst.get());

        if (cur_slicer->uses_live_var(m_cs_inst.get()) ||
            cur_slicer->defines_live_var(m_cs_inst.get())) {
            is_live_var_def_or_use = true;
        }

        if (m_cond_slicer.defines_live_var(m_cs_inst.get())) {
            m_cond_slicer.add_instruction(m_cs_inst.get());
            if (bound_comp_with_const) {
                add_info_dep(make_temp(JTDepKind::kMerge), *inst_it);
            } else if (exists_valid_bound_jmp &&
                       has_constant_opnd(m_cs_inst.get())) {
                bound_comp_with_const = true;
                add_info_dep(make_temp(JTDepKind::kCondComp), *inst_it,
                             get_constant_opnd(m_cs_inst.get()));

            }

            if (cur_slicer->uses_live_var(m_cs_inst.get())) {
                if (bound_comp_with_const && exists_valid_bound_jmp) {
                    find_bound_condition_in_successors();
                    if (is_bound_cond_found(vertex)) {
                        // prefer bound conditions closer to jumptable
                        return;
                    }
                    ++m_cond_dep_count;
                    merge_conditional_deps(vertex);
                    VLOG(3) << "jumptab: found bound condition @ "
                            << std::hex << m_cs_inst.get()->address;
                    return;
                } else {
                    VLOG(3) << "jumptab: invalid bound condition @ "
                            << std::hex << m_cs_inst.get()->address;
                    exists_valid_bound_jmp = false;
                }
            }
            continue;
        }

        if (!cur_slicer->defines_live_var(m_cs_inst.get())) {
            cur_slicer->update_defined_values(m_cs_inst.get());
            continue;
        }

        cur_slicer = get_or_make_slicer(vertex, *parent);
        m_cond_slicer.base_slicing_on(cur_slicer);
        cur_slicer->add_instruction(m_cs_inst.get());
        add_info_dep(JTDepKind::kMerge, *inst_it);

        VLOG(3) << "jumptab: live variable killed @ "
                << std::hex << m_cs_inst.get()->address;

        if (m_cond_slicer.uses_live_var(m_cs_inst.get())) {
            if (bound_comp_with_const && exists_valid_bound_jmp) {
                find_bound_condition_in_successors();
                if (is_bound_cond_found(vertex)) {
                    // prefer bound conditions closer to jumptable
                    return;
                }
                ++m_cond_dep_count;
                merge_conditional_deps(vertex);
                VLOG(3) << "jumptab: merged bound condition @ "
                        << std::hex << m_cs_inst.get()->address;
                return;
            } else {
                VLOG(3) << "jumptab: invalid bound condition @ "
                        << std::hex << m_cs_inst.get()->address;
            }
        }
    }

    if (check_few_live_vars(*cur_slicer)) {
        VLOG(3) << "jumptab: insufficient live variables in bb @ "
                << std::hex << vertex.address();
        collect_constant_index_values();
        set_path_finished(vertex);
        return;
    }
    if (is_live_var_def_or_use) {
        VLOG(3) << "jumptab: searching for bound condition in successors @ "
                << std::hex << vertex.address();
        find_bound_condition_in_successors();
    }
    if (is_bound_cond_found(vertex)) {
        return;
    }
    if (check_many_live_vars(*cur_slicer)) {
        VLOG(3) << "jumptab: too many live variables in bb @ "
                << std::hex << vertex.address();
        set_path_complex(vertex);
        return;
    }

    if (get_slicer(vertex) == nullptr) {
        // new slicer was not created, propagate parent's slicer
        set_slicer(vertex, get_slicer(*parent));
    }
}

void
BoundConditionSlicingVisitor::visit_peek(const CFG::Node &vertex,
                                         const CFG::Node &parent)
{
    if (defines_bound_condition(vertex) || vertex.is_virtual()) {
        return;
    }

    if (is_bound_cond_found(vertex) && !is_bound_cond_found(parent)) {
        VLOG(4) << "jumptab: non-dominator bound condition for "
                << std::hex << vertex.address() << " reached from "
                << parent.address();
        // TODO: handle the case where we have multiple equivalent bound conditions
        // for instance, we might undesirably consider a bound condition invalid if
        // we visit an upper node from node that have an equivalent bound condition
        reset_conditions_and_finish_traversal();
    }
}

bool
BoundConditionSlicingVisitor::is_finished() const noexcept
{
    return m_cond_dep_count < 0;
}

void
BoundConditionSlicingVisitor::reset_conditions_and_finish_traversal()
{
    m_cond_dep_count = -1;
}

//==============================================================================

enum class JTMicroXVisitorState : uint8_t {
    kNone = 0x0,
    kRunFinished = 0x1,
    kFinished = 0x3,
    kRunning = 0x4,
    kBoundCondMissed = 0x5,   // stops current run
    kInvalidMemAccess = 0x7,  // stop visitor altogether
    kBoundCondReached = 0x8,  // check next inst address is bound condition target
    kInvalidCodeAccess = 0xa,
    kJumpInstReached = 0x10,   // check next inst is within function, otherwise fail
    kEmulationError = 0xc
};

static inline JTMicroXVisitorState
operator&(JTMicroXVisitorState a, JTMicroXVisitorState b)
{
    return (JTMicroXVisitorState) ((uint8_t) a & (uint8_t) b);
}

static inline JTMicroXVisitorState
operator|(JTMicroXVisitorState a, JTMicroXVisitorState b)
{
    return (JTMicroXVisitorState) ((uint8_t) a | (uint8_t) b);
}

enum class JTMicroXAnalyzerResult : uint8_t {
    kNone,
    kFinished = 0x1,
    kMissedBoundCond = 0x2,
    kIndexError = 0x4,
    kNotLocalTarget = 0x8,
    kNotReadOnlyAccess = 0xa
};

static inline bool
is_successful(JTMicroXAnalyzerResult a)
{
    return a == JTMicroXAnalyzerResult::kFinished;
}

//==============================================================================

class JumpTabMicroXVisitor;

class MicroXMemoryAccessManager {
    static constexpr int kMaxTrialNum = 8;

public:
    MicroXMemoryAccessManager() = default;

    ~MicroXMemoryAccessManager() = default;

    void make_valid_access(const cs_insn *inst, flax::FlaxManager &mgr);

    bool is_valid(addr_t address) const noexcept;

    void set_memory_region(addr_t start, size_t size);

    addr_t evaluate_operand(const x86_op_mem &opnd);

    bool is_assigned_value(x86_reg reg);

    uint64_t get_assigned_value(x86_reg reg);

    void assign_value(x86_reg reg, uint64_t value);

    void hold_assigned_value(addr_t target);

    bool valid() const noexcept
    { return m_mem_region_start != 0; }

private:
    addr_t m_mem_region_start = 0;
    size_t m_mem_region_size = 0;
    addr_t m_last_assigned_addr;
    std::bitset<X64_GPR_REG_COUNT> m_assigned_regs;
    std::array<uint64_t, X64_GPR_REG_COUNT> m_assigned_values;
    std::unordered_set<addr_t> m_assigned_addrs;
};

bool
MicroXMemoryAccessManager::is_assigned_value(x86_reg reg)
{
    return m_assigned_regs[get_canonical_index(get_x64_reg(reg))];
}

uint64_t
MicroXMemoryAccessManager::get_assigned_value(x86_reg reg)
{
    return !is_assigned_value(reg) ? 0 :
           m_assigned_values[get_canonical_index(get_x64_reg(reg))];
}

void
MicroXMemoryAccessManager::assign_value(x86_reg reg, uint64_t value)
{
    m_assigned_values[get_canonical_index(get_x64_reg(reg))] = value;
    m_assigned_regs[get_canonical_index(get_x64_reg(reg))] = true;
}

void
MicroXMemoryAccessManager::hold_assigned_value(addr_t target)
{
    m_assigned_addrs.insert(target);
    m_last_assigned_addr = target;
}

addr_t
MicroXMemoryAccessManager::evaluate_operand(const x86_op_mem &opnd)
{
    addr_t target = 0;
    if (opnd.base != X86_REG_INVALID) {
        target = get_assigned_value(opnd.base);
    }
    if (opnd.index != X86_REG_INVALID) {
        target += get_assigned_value(opnd.index) * opnd.scale;
    }
    return target + opnd.disp;
}

void
MicroXMemoryAccessManager::set_memory_region(addr_t start, size_t size)
{
    m_mem_region_start = start;
    m_mem_region_size = size;
    m_last_assigned_addr = start + size / 2;
}

bool
MicroXMemoryAccessManager::is_valid(addr_t address) const noexcept
{
    return address > m_mem_region_start &&
           address < m_mem_region_start + m_mem_region_size;
}

void
MicroXMemoryAccessManager::make_valid_access(const cs_insn *inst,
                                             flax::FlaxManager &mgr)
{
    for (unsigned i = 0; i < inst->detail->x86.op_count; ++i) {

        auto &opnd = inst->detail->x86.operands[i];
        if (opnd.type != X86_OP_MEM || opnd.mem.base == X86_REG_RIP) {
            continue;
        }

        // TODO: improve memory access management
        if (opnd.mem.index != X86_REG_INVALID &&
            !is_assigned_value(opnd.mem.index)) {
            assign_value(opnd.mem.index, 0);
            auto reg = get_uc_reg(get_x64_reg(opnd.mem.index));
            addr_t zero_index = 0;
            auto err = uc_reg_write(mgr.engine().get(), reg, &zero_index);
            log_fatal_if(err != UC_ERR_OK, uc_strerror(err));
        }
        if (opnd.mem.base == X86_REG_INVALID || is_assigned_value(opnd.mem.base)) {
            continue;
        }

        bool success = false;
        for (int j = 1; j < kMaxTrialNum; ++j) {
            // we need base + disp to be inside the allocated region
            assign_value(opnd.mem.base,
                         m_last_assigned_addr - opnd.mem.disp + j * sizeof(void *));
            auto target = evaluate_operand(opnd.mem);
            if (is_valid(target) &&
                m_assigned_addrs.find(target) == m_assigned_addrs.end()) {
                hold_assigned_value(target);
                auto value = get_assigned_value(opnd.mem.base);
                auto reg = get_uc_reg(get_x64_reg(opnd.mem.base));
                auto err = uc_reg_write(mgr.engine().get(), reg, &value);
                log_fatal_if(err != UC_ERR_OK, uc_strerror(err));
                success = true;
                break;
            }
        }
        LOG_IF(!success, ERROR) << "jumptab: memory manager could not handle inst @ "
                                << to_hex(inst->address);
    }
}

//==============================================================================

class JumpTabMicroXAnalyzer {
public:

    static constexpr unsigned kFlaxRunCount = 24;
    static constexpr unsigned kConstIndexValueIdx = 8;

    JumpTabMicroXAnalyzer(flax::FlaxManager *mgr, const IFunction &function,
                          Disassembler &disas, CSInstWrapper &cs_inst);

    void analyze(const MicroExecSlice &slice, JumpTable &result);

    void try_fix_jumptab_index(const MicroExecSlice &inst_slice,
                               JumpTabMicroXVisitor &microx_visitor,
                               std::vector<addr_t> &inst_addr_slice);

    void mutate_jumptab_index(flax::FlaxManager *mgr, unsigned run_num) const;

    JTMicroXVisitorState
    evaluate_run(const JumpTabMicroXVisitor &visitor, flax::FlaxManager *mgr,
                 unsigned run_num);

    JTMicroXAnalyzerResult compute_run_result_summary();

    static bool
    is_read_only_mem_access(flax::FlaxManager *mgr, addr_t address);

    static void reset_rflags(flax::FlaxManager *mgr);

protected:

    void analyze_jumptab_index(const MicroExecSlice &slice);

    void generate_control_bounded_index_values(int64_t bound_constant);

    void generate_data_bounded_index_values();

    void generate_constant_index_values(int64_t max_index_value);

    void fill_slice_inst_addrs(const MicroExecSlice &slice,
                               std::vector<addr_t> &addresses);

    void identify_jumptab_targets(JumpTable &result);

    std::pair<const JumpTabEntryReader *, addr_t>
    get_entry_reader(buffer_t base_p, uint8_t entry_size,
                     addr_t fst_jumptab_target,
                     JumpTabKind &jumptab_kind);

private:
    flax::FlaxManager *m_microx_mgr;
    const IFunction &m_function;
    Disassembler &m_disasm;
    CSInstWrapper &m_cs_inst;
    addr_t m_fst_target_addr;
    addr_t m_jumptab_base_addr;
    addr_t m_jumptab_end_addr;
    uint8_t m_jumptab_entry_size;
    uc_x86_reg m_index_reg;
    addr_t m_index_addr;
    uint8_t m_index_size;
    std::array<JTMicroXAnalyzerResult, kFlaxRunCount> m_run_results;
    std::array<uint64_t, kFlaxRunCount> m_index_values;
    flax::EmulatorContext m_reg_context;
};

JumpTabMicroXAnalyzer::JumpTabMicroXAnalyzer(flax::FlaxManager *mgr,
                                             const IFunction &function,
                                             Disassembler &disasm,
                                             CSInstWrapper &cs_inst)
    : m_microx_mgr(mgr), m_function(function), m_disasm(disasm), m_cs_inst(cs_inst),
      m_fst_target_addr(0), m_jumptab_base_addr(m_microx_mgr->data_segment().end()),
      m_jumptab_end_addr(0), m_index_reg(UC_X86_REG_INVALID), m_index_addr(0)
{ }

bool
JumpTabMicroXAnalyzer::is_read_only_mem_access(flax::FlaxManager *mgr,
                                               addr_t address)
{
    return !mgr->is_writable(address) && mgr->is_readable(address);
}

//==============================================================================

class JumpTabMicroXVisitor : public flax::FlaxVisitorBase {
public:

    JumpTabMicroXVisitor(const MicroExecSlice &slice,
                         JumpTabMicroXAnalyzer &analyzer);

    void visit_instruction(flax::FlaxManager *mgr, addr_t address,
                           uint32_t size) override;

    void visit_valid_mem_access(flax::FlaxManager *mgr, uc_mem_type type,
                                uint64_t address, int size,
                                int64_t value) override;

    bool visit_invalid_mem_access(flax::FlaxManager *mgr, uc_mem_type type,
                                  uint64_t address, int size,
                                  int64_t value) override;

    void visit_start(flax::FlaxManager *mgr) override;

    void visit_run_start(flax::FlaxManager *mgr, unsigned run_num) override;

    void visit_run_finish(flax::FlaxManager *mgr, unsigned run_num) override;

    bool visit_invalid_code_access(flax::FlaxManager *mgr, uc_mem_type type,
                                   uint64_t address, int size,
                                   int64_t value) override;

    bool visit_emulation_error(flax::FlaxManager *mgr, uc_err error) override;

    bool is_finished() const noexcept override;

    addr_t last_accessed_mem_address() const noexcept
    { return m_last_mem_access; }

    JTMicroXVisitorState state() const noexcept
    { return m_state; }

    bool is_run_finished() const noexcept override;

private:
    JTMicroXVisitorState m_state;
    const MicroExecSlice &m_slice;
    JumpTabMicroXAnalyzer &m_analyzer;
    addr_t m_bound_cond_addr;
    addr_t m_bound_cond_target_addr;
    addr_t m_jump_inst_addr;
    addr_t m_last_mem_access;
};

JumpTabMicroXVisitor::JumpTabMicroXVisitor(const MicroExecSlice &slice,
                                           JumpTabMicroXAnalyzer &analyzer)
    : FlaxVisitorBase(), m_slice(slice), m_analyzer(analyzer)
{ }

void
JumpTabMicroXVisitor::visit_instruction(flax::FlaxManager *mgr, addr_t address,
                                        uint32_t size)
{
    UNUSED(size);
    log_rip_value(mgr);
    switch (m_state) {
    case JTMicroXVisitorState::kRunning:
        if (m_bound_cond_addr == address) {
            m_state = JTMicroXVisitorState::kBoundCondReached;
        } else if (m_jump_inst_addr == address) {
            m_state = JTMicroXVisitorState::kJumpInstReached;
        }
        break;

    case JTMicroXVisitorState::kBoundCondReached:
        if (m_bound_cond_target_addr != mgr->last_reachable_address()) {
            m_state = JTMicroXVisitorState::kBoundCondMissed;
            mgr->stop();
        } else if (m_jump_inst_addr == address) {
            m_state = JTMicroXVisitorState::kJumpInstReached;
        } else {
            m_state = JTMicroXVisitorState::kRunning;
        }
        break;
    default: break;
    }
}

void
JumpTabMicroXVisitor::visit_valid_mem_access(flax::FlaxManager *mgr,
                                             uc_mem_type type, uint64_t address,
                                             int size, int64_t value)
{
    UNUSED(mgr);
    UNUSED(type);
    UNUSED(value);
    UNUSED(size);
    m_last_mem_access = address;
}

bool
JumpTabMicroXVisitor::visit_invalid_mem_access(flax::FlaxManager *mgr,
                                               uc_mem_type type, uint64_t address,
                                               int size, int64_t value)
{
    log_rip_value(mgr);
    UNUSED(mgr);
    UNUSED(type);
    UNUSED(address);
    UNUSED(size);
    UNUSED(value);
    m_state = JTMicroXVisitorState::kInvalidMemAccess;
    m_last_mem_access = address;
    mgr->stop();
    return false;
}

void
JumpTabMicroXVisitor::visit_start(flax::FlaxManager *mgr)
{
    m_bound_cond_addr = mgr->get_mapped(m_slice.bound_cond_jump_addr());
    m_bound_cond_target_addr = mgr->get_mapped(m_slice.bound_cond_target_addr());
    m_jump_inst_addr = mgr->get_mapped(m_slice.jump_inst_address());
    m_state = JTMicroXVisitorState::kNone;
}

void
JumpTabMicroXVisitor::visit_run_start(flax::FlaxManager *mgr, unsigned run_num)
{
    m_analyzer.mutate_jumptab_index(mgr, run_num);
    m_analyzer.reset_rflags(mgr);
    m_state = JTMicroXVisitorState::kRunning;
}

void
JumpTabMicroXVisitor::visit_run_finish(flax::FlaxManager *mgr, unsigned run_num)
{
    UNUSED(run_num);
    m_state = m_analyzer.evaluate_run(*this, mgr, run_num);
}

bool
JumpTabMicroXVisitor::is_run_finished() const noexcept
{
    return (m_state & JTMicroXVisitorState::kRunFinished) ==
           JTMicroXVisitorState::kRunFinished;
}

bool
JumpTabMicroXVisitor::is_finished() const noexcept
{
    return (m_state & JTMicroXVisitorState::kFinished) ==
           JTMicroXVisitorState::kFinished;
}

bool
JumpTabMicroXVisitor::visit_invalid_code_access(flax::FlaxManager *mgr,
                                                uc_mem_type type, uint64_t address,
                                                int size, int64_t value)
{
    UNUSED(mgr);
    UNUSED(type);
    UNUSED(value);
    UNUSED(size);
    VLOG(3) << std::hex << "flax: invalid code access @ " << address;
    m_state = JTMicroXVisitorState::kInvalidCodeAccess;
    return false;
}

bool
JumpTabMicroXVisitor::visit_emulation_error(flax::FlaxManager *mgr, uc_err error)
{
    UNUSED(mgr);
    VLOG(3) << "flax: emulation error - " << uc_strerror(error);
    m_state = JTMicroXVisitorState::kEmulationError;
    return false;
}

//==============================================================================

void
JumpTabMicroXAnalyzer::analyze_jumptab_index(const MicroExecSlice &slice)
{
    x86_reg base_reg = X86_REG_INVALID;
    MicroXMemoryAccessManager mem_access_mgr;
    mem_access_mgr.set_memory_region(m_microx_mgr->get_stack_base(),
                                     m_microx_mgr->get_stack_size());
    auto inst_it = slice.instructions().begin();
    for (; inst_it != slice.instructions().end(); ++inst_it) {
        disasm_inst(m_function, *(*inst_it), m_disasm, m_cs_inst.get());
        if (!check_reads_mem(m_cs_inst.get())) {
            continue;
        }
        // skip jump-table access
        auto &opnd = *get_mem_opnd(m_cs_inst.get());
        base_reg = opnd.mem.base;
        m_jumptab_entry_size = opnd.size;
        break;
    }

    auto jumptab_mem_acc_inst_it = inst_it++;
    for (; inst_it != slice.instructions().end(); ++inst_it) {

        disasm_inst(m_function, *(*inst_it), m_disasm, m_cs_inst.get());
        if (get_mem_opnd(m_cs_inst.get()) != nullptr) {
            mem_access_mgr.make_valid_access(m_cs_inst.get(), *m_microx_mgr);
        }
    }

    const auto &last_modified_opnd = m_cs_inst.get()->detail->x86.operands[0];
    if (last_modified_opnd.reg == base_reg &&
        check_sets_jumptab_base(m_cs_inst.get()) != 0) {
        // skip instruction setting base register
        inst_it = slice.instructions().end() - 2;
        disasm_inst(m_function, *(*inst_it), m_disasm, m_cs_inst.get());
    }

    if (jumptab_mem_acc_inst_it == inst_it) {
        auto &opnd = *get_mem_opnd(m_cs_inst.get());
        m_index_reg = get_uc_reg(get_canonical(get_x64_reg(opnd.mem.index)));
        DVLOG(4) << "jumptab: fuzzing register index = "
                 << to_string(get_x64_reg(m_index_reg));
        return;
    }

    for (unsigned i = 0; i < m_cs_inst.get()->detail->x86.op_count; ++i) {

        auto &opnd = m_cs_inst.get()->detail->x86.operands[i];
        if (opnd.type == X86_OP_MEM && is_read_acc(opnd.access)) {
            if (opnd.mem.base == X86_REG_RIP) {
                m_index_addr = m_microx_mgr->get_mapped(m_cs_inst.get()->address) +
                               m_cs_inst.get()->size + opnd.mem.disp;
            } else {
                m_index_addr = mem_access_mgr.evaluate_operand(opnd.mem);
            }

            if (!m_microx_mgr->is_writable(m_index_addr)) {
                m_index_addr = 0;
                DLOG(ERROR) << "jumptab: invalid memory index!";
                break;
            }
            m_index_size = opnd.size;
            DVLOG(4) << "jumptab: fuzzing memory index @ " << std::hex
                     << m_index_addr << " , orig @"
                     << m_microx_mgr->get_original(m_index_addr)
                     << " , size " << (unsigned) m_index_size;
            break;
        }
        if (opnd.type == X86_OP_REG && is_read_acc(opnd.access)) {
            auto reg = get_x64_reg(opnd.reg);
            m_index_reg = get_uc_reg(get_canonical(reg));
            DVLOG(4) << "jumptab: fuzzing register index = " << to_string(reg);
            break;
        }
    }
}

void
JumpTabMicroXAnalyzer::mutate_jumptab_index(flax::FlaxManager *mgr,
                                            unsigned run_num) const
{
    DVLOG(4) << "starting run " << std::dec << run_num << " with index value="
             << m_index_values[run_num];
    mgr->engine().restore_context(m_reg_context);
    if (m_index_reg == UC_X86_REG_INVALID) {
        // memory index
        auto err = uc_mem_write(mgr->engine().get(), m_index_addr,
                                &m_index_values[run_num], m_index_size);
        log_fatal_if(err != UC_ERR_OK, uc_strerror(err));
    } else {
        // XXX: index register needs to be canonical i.e. 64-bit, because unicorn does
        // not zero upper 32-bit on writing!
        auto err = uc_reg_write(mgr->engine().get(), m_index_reg,
                                &m_index_values[run_num]);
        log_fatal_if(err != UC_ERR_OK, uc_strerror(err));
    }
}

void
JumpTabMicroXAnalyzer::reset_rflags(flax::FlaxManager *mgr)
{
    int64_t value = 0;
    auto err = uc_reg_write(mgr->engine().get(), UC_X86_REG_EFLAGS, &value);
    log_fatal_if(err != UC_ERR_OK, uc_strerror(err));
}

void
JumpTabMicroXAnalyzer::fill_slice_inst_addrs(const MicroExecSlice &slice,
                                             std::vector<addr_t> &addresses)
{
    addresses.reserve(slice.instructions().size());
    for (auto inst_ptr_it = slice.instructions().rbegin();
         inst_ptr_it != slice.instructions().rend(); ++inst_ptr_it) {
        addresses.push_back(m_microx_mgr->get_mapped((*inst_ptr_it)->address()));
    }
}

void
JumpTabMicroXAnalyzer::generate_control_bounded_index_values(int64_t bound_constant)
{
    m_index_values[0] = 0;
    m_index_values[kConstIndexValueIdx - 1] = bound_constant - 1;
    for (unsigned i = 1; i < kConstIndexValueIdx - 1; ++i) {
        m_index_values[i] = (i * bound_constant) / kConstIndexValueIdx;
    }
    m_index_values[kConstIndexValueIdx] = bound_constant;
    m_index_values[kConstIndexValueIdx + 1] = bound_constant + 1;

    unsigned shift_amount = 1;
    for (unsigned i = kConstIndexValueIdx + 2;
         i < kFlaxRunCount - 8; ++i, ++shift_amount) {
        auto step = (1U << shift_amount);
        m_index_values[i] = (bound_constant + step) | (step - 1);
    }

    // XXX: avoid large negative index values as they might make bound condition valid!
    shift_amount = 10;
    for (unsigned i = kFlaxRunCount - 8;
         i < kFlaxRunCount - 4; ++i, ++shift_amount) {
        m_index_values[i] = (1U << shift_amount) - 1;
    }

    std::fill(m_index_values.end() - 4, m_index_values.end(), 0);
}

void
JumpTabMicroXAnalyzer::generate_data_bounded_index_values()
{
    m_index_values = {0x0, 0x1, 0x3, 0x7, 0xF, 0x1F, 0x3F, 0x7F, 0xFF, 0x1FF,
                      0x3FF, 0x7FF, 0xFFF, 0x1FFF, 0x3FFF, 0x7FFF,
                      0x000000007FFFFFFF, 0x00000000FFFFFFFF, 0x3333333333333333,
                      0x4444444444444444, 0x8888888888888888, 0xCCCCCCCCCCCCCCCC,
                      0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF};
}

void
JumpTabMicroXAnalyzer::generate_constant_index_values(int64_t max_index_value)
{
    DVLOG(4) << "jumptab: generating index values with max " << std::dec
             << max_index_value;

    m_index_values[kFlaxRunCount - 1] = max_index_value;
    for (unsigned i = 0; i < kFlaxRunCount - 1; ++i) {
        m_index_values[i] = (i * max_index_value) / kFlaxRunCount;
    }
}

std::pair<const JumpTabEntryReader *, addr_t>
JumpTabMicroXAnalyzer::get_entry_reader(buffer_t base_p, uint8_t entry_size,
                                        addr_t fst_jumptab_target,
                                        JumpTabKind &jumptab_kind)
{
    uint64_t target;
    const JumpTabEntryReader *reader;
    addr_t base;
    buffer_t p;
    switch (entry_size) {
    case 1:reader = bcov::get_jumptab_reader(JumpTabKind::kOffsetU8);
        base = fst_jumptab_target - *reinterpret_cast<const uint8_t *>(base_p);
        target = reader->read(base_p, base);
        if (m_function.is_inside(m_microx_mgr->get_original(target))) {
            jumptab_kind = JumpTabKind::kOffsetU8;
            return std::make_pair(reader, base);
        }
        break;

    case 2: reader = bcov::get_jumptab_reader(JumpTabKind::kOffsetI16);
        base = fst_jumptab_target - *reinterpret_cast<const int16_t *>(base_p);
        target = reader->read(base_p, base);
        if (m_function.is_inside(m_microx_mgr->get_original(target))) {
            jumptab_kind = JumpTabKind::kOffsetI16;
            return std::make_pair(reader, base);
        }
        break;

    case 4: reader = bcov::get_jumptab_reader(JumpTabKind::kOffsetI32);
        target = reader->read(base_p, m_jumptab_base_addr);
        if (m_function.is_inside(m_microx_mgr->get_original(target))) {
            jumptab_kind = JumpTabKind::kOffsetI32;
            return std::make_pair(reader, m_jumptab_base_addr);
        }
        if (!m_function.is_inside(m_microx_mgr->get_original(fst_jumptab_target))) {
            p = base_p;
            for (; p < base_p + (m_jumptab_end_addr - m_jumptab_base_addr);
                   p += m_jumptab_entry_size) {
                target = reader->read(p, m_jumptab_base_addr);
                if (m_function.is_inside(m_microx_mgr->get_original(target))) {
                    jumptab_kind = JumpTabKind::kOffsetI32;
                    return std::make_pair(reader, m_jumptab_base_addr);
                }
            }
        }
        reader = bcov::get_jumptab_reader(JumpTabKind::kAbsAddr32);
        target = reader->read(base_p, 0);
        if (m_function.is_inside(m_microx_mgr->get_original(target))) {
            jumptab_kind = JumpTabKind::kAbsAddr32;
            return std::make_pair(reader, 0);
        }
        break;

    case 8: reader = bcov::get_jumptab_reader(JumpTabKind::kAbsAddr64);
        target = reader->read(base_p, 0);
        if (m_function.is_inside(m_microx_mgr->get_original(target))) {
            jumptab_kind = JumpTabKind::kAbsAddr64;
            return std::make_pair(reader, 0);
        }
        break;

    default: break;
    }
    jumptab_kind = JumpTabKind::kInvalid;
    return std::make_pair(nullptr, 0);
}

void
JumpTabMicroXAnalyzer::identify_jumptab_targets(JumpTable &result)
{
    DLOG_IF(m_jumptab_end_addr + m_jumptab_entry_size <= m_jumptab_base_addr, ERROR)
            << std::dec << "jumptab: invalid combination of base and end address";

    auto jumbtab_size =
        m_jumptab_end_addr - m_jumptab_base_addr + m_jumptab_entry_size;
    auto jumptab_buf = std::make_unique<uint8_t[]>(jumbtab_size);

    auto err = uc_mem_read(m_microx_mgr->engine().get(), m_jumptab_base_addr,
                           jumptab_buf.get(), jumbtab_size);
    log_fatal_if(err != UC_ERR_OK, uc_strerror(err));

    auto kind = (JumpTabKind) 0xFFU;
    auto reader_result = get_entry_reader(jumptab_buf.get(),
                                          m_jumptab_entry_size, m_fst_target_addr,
                                          kind);
    auto reader = reader_result.first;
    auto identified_base = reader_result.second;

    DCHECK(kind != (JumpTabKind) 0xFFU);
    result.kind(kind);
    if (kind == JumpTabKind::kInvalid) {
        DLOG(WARNING) << "jumptab: unknown kind detected @ " << std::hex
                      << result.jump_address();
        return;
    }
    JumpTable::Targets targets;
    auto orig_identified_base = m_microx_mgr->get_original(identified_base);
    for (buffer_t buf = jumptab_buf.get();
         buf < jumptab_buf.get() + jumbtab_size; buf += m_jumptab_entry_size) {

        auto target = reader->read(buf, orig_identified_base);

        if (m_microx_mgr->is_executable(m_microx_mgr->get_mapped(target))) {
            targets.push_back(target);
            LOG_IF(!m_function.is_inside(target), INFO)
                << "jumptab: non-local entry found " << to_hex(target);
        } else {
            LOG(WARNING) << "jumptab: invalid entry found " << to_hex(target);
            result.kind(JumpTabKind::kInvalid);
            break;
        }
    }
    if (targets.size() <= 2) {
        LOG(WARNING) << "jumptab: targets are too few";
        result.kind(JumpTabKind::kInvalid);
    }
    result.targets(targets);
}

JTMicroXVisitorState
JumpTabMicroXAnalyzer::evaluate_run(const JumpTabMicroXVisitor &visitor,
                                    flax::FlaxManager *mgr, unsigned run_num)
{
    switch (visitor.state()) {
    case JTMicroXVisitorState::kBoundCondMissed :m_run_results[run_num] = JTMicroXAnalyzerResult::kMissedBoundCond;
        return JTMicroXVisitorState::kRunFinished;
    case JTMicroXVisitorState::kInvalidMemAccess:m_run_results[run_num] = JTMicroXAnalyzerResult::kIndexError;
        DLOG(WARNING) << "jumptab: index caused invalid memory access @ "
                      << std::hex << mgr->get_original(mgr->last_reachable_address())
                      << " address "
                      << mgr->get_original(visitor.last_accessed_mem_address());
        return JTMicroXVisitorState::kFinished;
    case JTMicroXVisitorState::kInvalidCodeAccess:
    case JTMicroXVisitorState::kEmulationError:
        // we tolerate emulation errors as it might be caused by the partial nature
        // of backward slicing
        m_run_results[run_num] = JTMicroXAnalyzerResult::kNotLocalTarget;
        return JTMicroXVisitorState::kRunFinished;
    case JTMicroXVisitorState::kJumpInstReached :m_run_results[run_num] = JTMicroXAnalyzerResult::kFinished;
        break;
    default:m_run_results[run_num] = JTMicroXAnalyzerResult::kNone;
    }

    // jump table conditions:
    // - last memory access, presumingly to jump table, must be to read-only memory
    // - last instruction reached after finishing the slice must be inside the function
    // - jump table is bounded

    if (!is_read_only_mem_access(mgr, visitor.last_accessed_mem_address())) {
        VLOG(3) << "jumptab: jump table is not in read-only segment @ "
                << std::hex << visitor.last_accessed_mem_address();
        m_run_results[run_num] = JTMicroXAnalyzerResult::kNotReadOnlyAccess;
        return JTMicroXVisitorState::kFinished;
    }
    if (!m_function.is_inside(mgr->get_original(mgr->last_reachable_address()))) {
        m_run_results[run_num] = JTMicroXAnalyzerResult::kNotLocalTarget;
    }

    if (visitor.last_accessed_mem_address() > m_jumptab_end_addr) {
        m_jumptab_end_addr = visitor.last_accessed_mem_address();
    }
    if (visitor.last_accessed_mem_address() < m_jumptab_base_addr) {
        m_jumptab_base_addr = visitor.last_accessed_mem_address();
    }
    if (m_fst_target_addr == 0) {
        m_fst_target_addr = mgr->last_reachable_address();
    }

    return JTMicroXVisitorState::kRunning;
}

JTMicroXAnalyzerResult
JumpTabMicroXAnalyzer::compute_run_result_summary()
{
    bool exists_run_finish = false;
    for (const auto &result : m_run_results) {
        if (result == JTMicroXAnalyzerResult::kFinished) {
            exists_run_finish = true;
            continue;
        }
        if (result == JTMicroXAnalyzerResult::kMissedBoundCond ||
            result == JTMicroXAnalyzerResult::kNotLocalTarget) {
            continue;
        }
        return result;
    }
    return exists_run_finish ? JTMicroXAnalyzerResult::kFinished
                             : JTMicroXAnalyzerResult::kNone;
}

void
JumpTabMicroXAnalyzer::analyze(const MicroExecSlice &slice, JumpTable &result)
{
    analyze_jumptab_index(slice);
    if (m_index_addr == 0 && m_index_reg == UC_X86_REG_INVALID) {
        LOG(ERROR) << "jumptab: index variable was not found!";
        return;
    }

    if (slice.has_bound_condition()) {
        generate_control_bounded_index_values(slice.bound_condition_constant());
    } else if (slice.is_index_set_to_constants()) {
        generate_constant_index_values(slice.max_constant_index_value());
    } else {
        generate_data_bounded_index_values();
    }

    m_microx_mgr->engine().make_context(m_reg_context);
    m_microx_mgr->engine().save_context(m_reg_context);
    result.kind(JumpTabKind::kInvalid);
    result.jump_address(slice.jump_inst_address());
    result.base_address(0);
    JumpTabMicroXVisitor microx_visitor(slice, *this);
    std::vector<addr_t> slice_inst_addrs;
    fill_slice_inst_addrs(slice, slice_inst_addrs);

    m_microx_mgr->run_instructions(&microx_visitor, &slice_inst_addrs[0],
                                   kFlaxRunCount, slice_inst_addrs.size());

    auto summary = compute_run_result_summary();

    if (is_successful(summary)) {
        result.base_address(m_microx_mgr->get_original(m_jumptab_base_addr));
        identify_jumptab_targets(result);
        return;
    }
    if (summary != JTMicroXAnalyzerResult::kIndexError) {
        // we try to recover from index errors only
        return;
    }

    try_fix_jumptab_index(slice, microx_visitor, slice_inst_addrs);

    summary = compute_run_result_summary();

    if (is_successful(summary)) {
        result.base_address(m_microx_mgr->get_original(m_jumptab_base_addr));
        identify_jumptab_targets(result);
    } else {
        DVLOG(3) << "jumptab: recovery from index error failed - bad result";
    }
}

void
JumpTabMicroXAnalyzer::try_fix_jumptab_index(const MicroExecSlice &inst_slice,
                                             JumpTabMicroXVisitor &microx_visitor,
                                             std::vector<addr_t> &inst_addr_slice)
{
    unsigned i = 0;
    for (; i < inst_addr_slice.size() &&
           inst_addr_slice[i] != m_microx_mgr->last_reachable_address(); ++i) {
    }

    if (i >= inst_addr_slice.size()) {
        DVLOG(3) << "jumptab: recovery from index error failed - address not found";
        return;
    }

    MicroXMemoryAccessManager mem_access_mgr;
    mem_access_mgr.set_memory_region(m_microx_mgr->get_stack_base(),
                                     m_microx_mgr->get_stack_size());

    auto inst_it = inst_slice.instructions().begin();
    for (; inst_it != inst_slice.instructions().end() &&
           m_microx_mgr->get_mapped((*inst_it)->address()) !=
           inst_addr_slice[i]; ++inst_it) { }

    if (inst_it == inst_slice.instructions().end()) {
        DVLOG(3) << "jumptab: attempt to fix memory index failed!";
        return;
    }

    disasm_inst(m_function, *(*inst_it), m_disasm, m_cs_inst.get());
    auto mem_opnd_p = get_mem_opnd(m_cs_inst.get());
    if (mem_opnd_p == nullptr) {
        return;
    }

    mem_access_mgr.make_valid_access(m_cs_inst.get(), *m_microx_mgr);
    m_index_reg = UC_X86_REG_INVALID;
    m_index_addr = mem_access_mgr.evaluate_operand(mem_opnd_p->mem);
    m_microx_mgr->run_instructions(&microx_visitor, &inst_addr_slice[i],
                                   kFlaxRunCount, inst_addr_slice.size() - i);

}
//==============================================================================

class JumpTabAnalyzerImpl {
    friend class JumpTabAnalyzer;

public:

    JumpTabAnalyzerImpl() = default;

    ~JumpTabAnalyzerImpl() = default;

    void analyze_pivot_bb(const BasicBlock &pivot_bb,
                          BackwardDataFlowSlicer &df_slicer);

    void evaluate(const BoundConditionSlicingVisitor &slicing_visitor);

    void add_jumptab_value_bound_deps(JTDependencySpan dependencies);

    void add_jumptab_cond_bound_deps(JTDependencySpan dependencies);

    MCInstPtrVec::iterator
    find_ptr_modifying_inst(MCInstPtrVec &instructions) noexcept;

    void sanitize_data_bound_slice() noexcept;

    void sanitize_condition_bound_slice() noexcept;

    bool check_mem_read_valid(const MCInst &inst) const noexcept;

    void add_single_link_deps(JTDependencySpan::reverse_iterator link_it,
                              JTDependencySpan dependencies);

    static bool check_valid_bound_condition_exists(
        const BoundConditionSlicingVisitor &slicing_visitor) noexcept;

    bool valid_jumptab_address(int64_t value);

    static void invalidate_bound_condition(MicroExecSlice &slice) noexcept;

private:
    const IFunction *m_function = nullptr;
    flax::FlaxManager *m_microx_mgr = nullptr;
    ValueIdx m_value_idx = 0;
    bool m_pivot_has_constant_base = false;
    bool m_pivot_has_data_bounds = false;
    bool m_jumptab_does_match = true;
    MicroExecSlice m_microx_slice;
    mutable CSInstWrapper m_cs_inst;
    Disassembler m_disasm;
};

void
JumpTabAnalyzerImpl::analyze_pivot_bb(const BasicBlock &pivot_bb,
                                      BackwardDataFlowSlicer &df_slicer)
{
    // TODO: pivot bb analysis should not be this hackishy!
    disasm_inst(*m_function, pivot_bb.instructions().back(), m_disasm,
                m_cs_inst.get());
    df_slicer.add_instruction(m_cs_inst.get());
    m_microx_slice.add_instruction(&pivot_bb.instructions().back());
    m_microx_slice.m_jump_inst_addr = pivot_bb.instructions().back().address();

    bool jumptab_mem_access_analyzed = false;
    int64_t const_base_value = 0;
    int64_t mem_disp_value = 0;
    uint mem_reg_arg_count = 0;

    if (check_reads_mem(m_cs_inst.get())) {
        auto &mem_opnd = get_mem_opnd(m_cs_inst.get())->mem;
        mem_reg_arg_count = get_reg_arg_count(mem_opnd);
        mem_disp_value = mem_opnd.disp;
        jumptab_mem_access_analyzed = true;
        if (mem_reg_arg_count == 1 && valid_jumptab_address(mem_disp_value)) {
            const_base_value = mem_disp_value;
        }
    }

    for (auto inst_it = pivot_bb.instructions().rbegin() + 1;
         inst_it != pivot_bb.instructions().rend(); ++inst_it) {

        disasm_inst(*m_function, *inst_it, m_disasm, m_cs_inst.get());

        if (df_slicer.defines_live_var(m_cs_inst.get())) {
            df_slicer.add_instruction(m_cs_inst.get());
            m_microx_slice.add_instruction(&(*inst_it));
            if (!jumptab_mem_access_analyzed && check_reads_mem(m_cs_inst.get())) {
                auto &mem_opnd = get_mem_opnd(m_cs_inst.get())->mem;
                mem_reg_arg_count = get_reg_arg_count(mem_opnd);
                mem_disp_value = mem_opnd.disp;
                jumptab_mem_access_analyzed = true;
            }

            if (!has_constant_opnd(m_cs_inst.get())) {
                continue;

            }

            auto value = get_constant_opnd(m_cs_inst.get());
            if (const_base_value == 0 && valid_jumptab_address(value)) {
                const_base_value = value;
            }
            if (inst_it->cs_id() == X86_INS_AND &&
                is_plausible_data_bound_constant(value)) {
                m_pivot_has_data_bounds = true;
            }
        }
    }

    if (df_slicer.live_mem_var_count() == 0) {
        m_jumptab_does_match = false;
        VLOG(3) << "jumptab: pivot bb does not access memory!";
        return;
    }

    if (df_slicer.live_reg_var_count() > 3) {
        m_jumptab_does_match = false;
        VLOG(3) << "jumptab: pivot bb has too much dependencies!";
        return;
    }

    if (df_slicer.live_mem_var_count() > 0 && df_slicer.live_reg_var_count() == 1 &&
        const_base_value != 0) {
        // jumptab has reg index
        m_pivot_has_constant_base = true;
        VLOG(3) << "jumptab: pivot has constant base and register index";
        return;
    }

    if ((mem_reg_arg_count == 2 && const_base_value != 0) ||
        (mem_reg_arg_count == 1 && valid_jumptab_address(mem_disp_value))) {

        m_pivot_has_constant_base = true;
        VLOG(3) << "jumptab: pivot has constant base and memory index";
    }
}

bool
JumpTabAnalyzerImpl::valid_jumptab_address(int64_t value)
{
    if ((addr_t) value < 0x1000) {
        // useful to remove small constants
        return false;
    }
    auto mapped_addr = m_microx_mgr->get_mapped((addr_t) value);
    return !m_microx_mgr->is_writable(mapped_addr) &&
           m_microx_mgr->is_readable(mapped_addr);
}

void
JumpTabAnalyzerImpl::invalidate_bound_condition(MicroExecSlice &slice) noexcept
{
    slice.m_cond_jump_addr = 0;
    slice.m_cond_jump_target = 0;
}

void
JumpTabAnalyzer::build(const IFunction &func, const BasicBlock &pivot_bb,
                       flax::FlaxManager *microx_mgr, JumpTable &result)
{
    auto &exit_inst = pivot_bb.instructions().back();
    if (!exit_inst.is_jump() || exit_inst.is_direct()) {
        return;
    }

    JumpTabAnalyzerImpl impl;
    impl.m_function = &func;
    impl.m_microx_mgr = microx_mgr;
    impl.m_disasm.init(DisasmArch::kX86, DisasmMode::k64);

    BackwardDataFlowSlicer pivot_slicer;
    pivot_slicer.init(&impl.m_value_idx);
    impl.analyze_pivot_bb(pivot_bb, pivot_slicer);
    if (!impl.m_jumptab_does_match) {
        VLOG(3) << "jumptab: pivot bb does not match";
        return;
    }
    VLOG(3) << "jumptab: proceeding with backward slicing ...";

    if (!impl.m_pivot_has_constant_base) {
        BaseSlicingVisitor base_visitor(func, pivot_slicer);
        func.cfg().backward().traverse_depth_first(base_visitor, pivot_bb);

        if (base_visitor.dependencies().empty()) {
            VLOG(3) << "jumptab: constant base not found!";
            return;
        }
        auto &base_dep = base_visitor.dependencies().back();
        if (!base_dep.is_base() ||
            !impl.valid_jumptab_address(base_dep.constant())) {
            VLOG(3) << "jumptab: constant base not valid!";
            return;
        }
        for (const auto &dep : base_visitor.dependencies()) {
            impl.m_microx_slice.add_instruction(dep.instruction());
            disasm_inst(*impl.m_function, *dep.instruction(), impl.m_disasm,
                        impl.m_cs_inst.get());
            pivot_slicer.add_instruction(impl.m_cs_inst.get());
        }
    }

    VLOG_IF(impl.m_pivot_has_data_bounds, 3)
        << "jumptab: index is data-bounded in pivot bb";

    BoundConditionSlicingVisitor bound_cond_visitor(func, pivot_slicer);
    func.cfg().backward().traverse_depth_first(bound_cond_visitor, pivot_bb);
    impl.evaluate(bound_cond_visitor);

    if (impl.m_microx_slice.instructions().size() == 1) {
        LOG(WARNING) << "jumptab: slice too small - "
                     << to_string(impl.m_microx_slice);
        return;
    }
    DVLOG(4) << "jumptab: slice - " << to_string(impl.m_microx_slice);

    JumpTabMicroXAnalyzer microx_analyzer(microx_mgr, func, impl.m_disasm,
                                          impl.m_cs_inst);
    microx_analyzer.analyze(impl.m_microx_slice, result);
    if (!result.valid() && impl.m_pivot_has_data_bounds &&
        impl.m_microx_slice.has_bound_condition()) {
        result.reset();
        JumpTabAnalyzerImpl::invalidate_bound_condition(impl.m_microx_slice);
        microx_analyzer.analyze(impl.m_microx_slice, result);
        DVLOG(3) << "jumptab: retry with data bound is "
                 << (result.valid() ? "success" : "fail");
    }
}

void
JumpTabAnalyzerImpl::evaluate(const BoundConditionSlicingVisitor &slicing_visitor)
{
    bool bound_cond_exists = check_valid_bound_condition_exists(slicing_visitor);
    VLOG_IF(!bound_cond_exists, 3) << "jumptab: valid bound condition not found";

    if (bound_cond_exists) {
        DCHECK(!slicing_visitor.is_virtual_entry_reachable());
        add_jumptab_cond_bound_deps(slicing_visitor.dependencies());
        sanitize_condition_bound_slice();
    } else {
        add_jumptab_value_bound_deps(slicing_visitor.dependencies());
        sanitize_data_bound_slice();
    }

    if (!slicing_visitor.is_virtual_entry_reachable() &&
        !slicing_visitor.constant_index_values().empty()) {
        auto max_const =
            *std::max_element(slicing_visitor.constant_index_values().begin(),
                              slicing_visitor.constant_index_values().end());

        // XXX: heuristic to avoid incremental jumptable recovery. For example, having 
        // few constants does not mean that the jumptable is constant-bounded. It 
        // can be the case that jumptable is data-bounded but we need first to update CFG
        // with the few constants we already have.
        if (max_const > 0 &&
            slicing_visitor.constant_index_values().size() >
            (unsigned) max_const / 2) {
            m_microx_slice.m_max_const_index_value = max_const;
        }
    }
}

bool
JumpTabAnalyzerImpl::check_valid_bound_condition_exists(
    const BoundConditionSlicingVisitor &slicing_visitor) noexcept
{
    if (slicing_visitor.cond_dependency_count() == 0 ||
        slicing_visitor.is_virtual_entry_reachable()) {
        return false;
    }

    int64_t const_bound = 0;
    for (const auto &dep : slicing_visitor.dependencies()) {
        if (!dep.is_cond_comp()) {
            continue;
        }
        // handle conditional comparison
        if (const_bound == 0) {
            if (is_plausible_cond_bound_constant(dep.constant())) {
                const_bound = dep.constant();
            } else {
                VLOG(1) << "jumptab: bound condition ignored @ "
                        << to_string(*dep.instruction());
            }
        } else if (const_bound != dep.constant()) {
            LOG(WARNING) << "jumptab: bound conditions might not be equivalent "
                         << to_string(*dep.instruction());
            const_bound = std::min(const_bound, dep.constant());
        }
    }
    return const_bound != 0;
}

void
JumpTabAnalyzerImpl::add_jumptab_value_bound_deps(JTDependencySpan dependencies)
{
    bool proceed = true;
    auto link_it = dependencies.cbegin();
    while (link_it != dependencies.end() && proceed) {
        auto dep_it = link_it + 1;
        for (; proceed && !dep_it->is_link() &&
               dep_it != dependencies.end(); ++dep_it) {
            if (!dep_it->is_merge()) {
                continue;
            }
            disasm_inst(*m_function, *dep_it->instruction(), m_disasm,
                        m_cs_inst.get());

            // XXX: a bit fragile heuristic for ending value-bounded slice
            if (check_reads_single_byte(m_cs_inst.get()) ||
                check_reads_mem(m_cs_inst.get())) {
                proceed = false;
            }
            m_microx_slice.add_instruction(dep_it->instruction());
        }
        link_it = std::find_if(dep_it, dependencies.end(),
                               [link_it](const JTDependency &node) {
                                   return node.parent() == link_it->node();
                               });
    }
}

MCInstPtrVec::iterator
JumpTabAnalyzerImpl::find_ptr_modifying_inst(MCInstPtrVec &instructions) noexcept
{
    auto get_canonical_x64 = [](const x86_reg reg) {
        return get_canonical(get_x64_reg(reg));
    };

    auto inst_p_it = instructions.begin();
    auto jumptab_base_reg = X64Reg::Invalid;
    for (; inst_p_it < instructions.end(); ++inst_p_it) {
        disasm_inst(*m_function, *(*inst_p_it), m_disasm, m_cs_inst.get());
        auto opnd = get_mem_opnd(m_cs_inst.get());
        if (opnd != nullptr && is_read_acc(opnd->access)) {
            // skip jumptab access
            if (opnd->mem.base != X86_REG_INVALID) {
                jumptab_base_reg = get_canonical_x64(opnd->mem.base);
            } else {
                jumptab_base_reg = get_canonical_x64(opnd->mem.index);
            }
            ++inst_p_it;
            break;
        }
    }

    using namespace bcov::x64;
    auto other_base_reg = X64Reg::Invalid;
    for (; inst_p_it < instructions.end(); ++inst_p_it) {
        disasm_inst(*m_function, *(*inst_p_it), m_disasm, m_cs_inst.get());
        if (has_constant_opnd(m_cs_inst.get())) {
            continue;
        }
        if (m_cs_inst.get()->detail->x86.op_count != 2) {
            continue;
        }
        auto reg_opnd = &m_cs_inst.get()->detail->x86.operands[0];
        if (reg_opnd->type == X86_OP_REG &&
            get_canonical_x64(reg_opnd->reg) == jumptab_base_reg &&
            is_read_acc(reg_opnd->access) && is_write_acc(reg_opnd->access)) {
            // we are interested in instructions that increase data-flow dependencies
            // based on base register e.g shr edx, cl where edx is jumptab base
            return ++inst_p_it;
        }
        auto mem_opnd = get_mem_opnd(m_cs_inst.get());
        if (mem_opnd != nullptr && is_read_acc(mem_opnd->access)) {
            // now lets see if the base of this memory operand is manipulated
            other_base_reg = get_canonical_x64(mem_opnd->mem.base);
            ++inst_p_it;
            break;
        }
    }

    auto detail = m_cs_inst.get()->detail;
    bool finish = false;
    for (; !finish && inst_p_it < instructions.end(); ++inst_p_it) {
        disasm_inst(*m_function, *(*inst_p_it), m_disasm, m_cs_inst.get());
        for (unsigned i = 0; i < detail->x86.op_count; ++i) {
            auto &opnd = detail->x86.operands[i];
            if (opnd.type == X86_OP_REG &&
                get_canonical_x64(opnd.reg) == other_base_reg &&
                is_write_acc(opnd.access)) {
                finish = true;
            }
        }
    }
    return inst_p_it;
}

void
JumpTabAnalyzerImpl::sanitize_condition_bound_slice() noexcept
{
    auto &instructions = m_microx_slice.m_instructions;
    if (find_ptr_modifying_inst(instructions) == instructions.end()) {
        return;
    }
    VLOG(5) << "jumptab: invalid slice: " << to_string(m_microx_slice);
    addr_t cond_addr = m_microx_slice.m_cond_jump_addr;
    auto inst_p_it = std::find_if(instructions.begin(),
                                  instructions.end(),
                                  [cond_addr](MCInstPtr inst_p) {
                                      return inst_p->address() == cond_addr;
                                  });
    DCHECK(inst_p_it != instructions.end());
    VLOG(2) << "jumptab: slice sanitizer removed instructions from @ "
            << to_hex((*inst_p_it)->address());
    instructions.erase(inst_p_it, instructions.end());
    m_microx_slice.m_cond_jump_addr = 0;
}

void
JumpTabAnalyzerImpl::sanitize_data_bound_slice() noexcept
{
    auto &instructions = m_microx_slice.m_instructions;
    auto &last_inst = *instructions.back();
    if (!check_mem_read_valid(last_inst)) {
        VLOG(2) << "jumptab: potentially non-writable rip-rel index @ "
                << to_string(last_inst);
        instructions.pop_back();
    }
    auto inst_p_it = find_ptr_modifying_inst(instructions);
    if (inst_p_it != instructions.end()) {
        --inst_p_it;
        VLOG(5) << "jumptab: invalid slice: " << to_string(m_microx_slice);
        VLOG(2) << "jumptab: slice sanitizer removed instructions from @ "
                << to_hex((*inst_p_it)->address());
        instructions.erase(inst_p_it, instructions.end());
    }
}

void
JumpTabAnalyzerImpl::add_single_link_deps(JTDependencySpan::reverse_iterator link_it,
                                          JTDependencySpan dependencies)
{
    for (auto dep_it = link_it - 1;
         dep_it >= dependencies.rbegin() && !dep_it->is_link(); --dep_it) {
        if (dep_it->is_merge()) {
            m_microx_slice.add_instruction(dep_it->instruction());
            continue;
        }
        if (dep_it->is_cond_comp()) {
            m_microx_slice.m_cond_cmp_constant = dep_it->constant();
            m_microx_slice.add_instruction(dep_it->instruction());
            continue;
        }
        if (dep_it->is_cond_jump()) {
            m_microx_slice.m_cond_jump_addr = dep_it->instruction()->address();
            m_microx_slice.m_cond_jump_target = link_it->parent()->address();
            m_microx_slice.add_instruction(dep_it->instruction());
        }
    }
}

void
JumpTabAnalyzerImpl::add_jumptab_cond_bound_deps(JTDependencySpan dependencies)
{
    auto head_link_it =
        std::find_if(dependencies.rbegin(), dependencies.rend(),
                     [](const JTDependency &dep) { return dep.is_head_link(); });

    DCHECK(head_link_it != dependencies.rbegin());
    std::vector<JTDependencySpan::reverse_iterator> rev_links;
    for (auto link_it = head_link_it; link_it != dependencies.rend();) {
        rev_links.push_back(link_it);
        link_it = std::find_if(link_it, dependencies.rend(),
                               [link_it](const JTDependency &dep) {
                                   return dep.node() == link_it->parent();
                               });
    }
    for (auto link_it = rev_links.crbegin();
         link_it != rev_links.crend(); ++link_it) {

        add_single_link_deps(*link_it, dependencies);
    }
}

bool
JumpTabAnalyzerImpl::check_mem_read_valid(const MCInst &inst) const noexcept
{
    disasm_inst(*m_function, inst, m_disasm, m_cs_inst.get());
    auto opnd = get_mem_opnd(m_cs_inst.get());
    if (opnd == nullptr || !is_read_acc(opnd->access) ||
        opnd->mem.base != X86_REG_RIP) {
        return true;
    }
    return m_microx_mgr->is_writable(inst.address() + inst.size() + opnd->mem.disp);
}

} // x64
} // bcov
