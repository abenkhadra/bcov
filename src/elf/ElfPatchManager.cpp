/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 *
 * ****************************************************************************/
/**
 *  \brief
 */

#include <fcntl.h>
#include <fstream>
#include <set>
#include <iomanip>
#include "easylogging/easylogging++.h"
#include "x64/Asm.hpp"
#include "graph/SuperBlock.hpp"
#include "elf/ElfExtender.hpp"
#include "core/FileLoader.hpp"
#include "core/Region.hpp"
#include "core/Disassembler.hpp"
#include "core/Function.hpp"
#include "dump/patch.h"
#include "ElfPatchManager.hpp"

#define OUT_HEX(x) std::hex << x
#define OUT_DEC(x) std::dec << x
#define LOG_PREFIX kLogPrefix <<


namespace bcov {

static const char *kLogPrefix = "patch: ";

static const char *kPatchManagerModeNames[5] =
    {"none", "all-node", "any-node", "all-node-jumptab", "any-node-jumptab"};

static constexpr unsigned kSBShortJmpByteSize = 2U;

static constexpr unsigned kSBLongJmpCCByteSize = 6U;

static constexpr unsigned kSBLongJmpCCRewriteByteSize =
    kSBLongJmpCCByteSize + kSBDetourByteSize;

// worst case and only because of JCXZ and Co.
static constexpr unsigned kSBShortJmpCCRewriteByteSize =
    kSBShortJmpByteSize + 2 * kSBDetourByteSize;

static constexpr unsigned kLargeHostPadSize = kSBDetourByteSize;

czstring
to_string(SBProbeKind a)
{
    switch (a) {
    case SBProbeKind::kLink: return "link";
    case SBProbeKind::kReturn: return "return";
    case SBProbeKind::kLongCall: return "long-call";
    case SBProbeKind::kShortCall: return "short-call";
    case SBProbeKind::kLongJmp: return "long-jmp";
    case SBProbeKind::kJumpTab: return "jumptab";
    case SBProbeKind::kShortJmp: return "short-jmp";
    case SBProbeKind::kInnerBB: return "inner-bb";
    case SBProbeKind::kLongCondJmp: return "long-cond";
    case SBProbeKind::kShortCondJmp: return "short-cond";
    case SBProbeKind::kGuest: return "guest";
    case SBProbeKind::kNoHost: return "nohost";
    case SBProbeKind::kPlainHost: return "plain-host";
    default: return "unknown";
    }
}

czstring
to_string(PatchManagerMode mode)
{
    auto index = (uint8_t) get_effective(mode);
    if (supports_jumptab_patch(mode)) {
        index += 2;
    }
    return kPatchManagerModeNames[index];
}

static bool
requires_restore_jump(const BasicBlock *bb)
{
    return !bb->instructions().back().is_branch();
}

static unsigned
estimate_restore_overhead_size(const MCInst &exit_inst)
{
    if (!exit_inst.is_branch()) {
        return kSBDetourByteSize;
    }
    if (!exit_inst.is_jump() || !exit_inst.is_direct()) {
        // call, return, or indirect jumps
        return 0;
    }
    bool is_short_jmp = exit_inst.size() == kSBShortJmpByteSize;
    if (exit_inst.is_conditional()) {
        return is_short_jmp ? kSBShortJmpCCRewriteByteSize - kSBShortJmpByteSize :
               kSBLongJmpCCRewriteByteSize - kSBLongJmpCCByteSize;
    }
    return is_short_jmp ? kSBDetourByteSize - kSBShortJmpByteSize : 0;
}

static const MCInst *
find_one_detour_fitting_instruction(const BasicBlock *bb)
{
    const MCInst *result = nullptr;
    for (const auto &instruction : bb->instructions()) {
        if (instruction.size() < kSBDetourByteSize) {
            continue;
        }
        if (result == nullptr || instruction.size() < result->size()) {
            result = &instruction;
        }
    }
    return result;
}

static const MCInst *
find_few_detour_fitting_instructions(const BasicBlock *bb)
{
    auto inst_it = bb->instructions().begin();
    auto total = 0U;
    for (; total < kSBDetourByteSize &&
           inst_it != bb->instructions().end(); ++inst_it) {
        total += inst_it->size();
    }
    return total < kSBDetourByteSize ? nullptr : &(*(inst_it - 1));
}

static unsigned int
estimate_host_code_size(const BasicBlock *bb, unsigned offset)
{
    if (offset == 0) {
        return bb->byte_size() +
               estimate_restore_overhead_size(bb->instructions().back());
    } else {
        return offset + kSBDetourByteSize;
    }
}

static unsigned int
get_resume_offset(const SuperBlockProbe &probe)
{
    return probe.is_attr_set(SBProbeAttr::kLargeHost) ? probe.padding() : 0;
}

static unsigned
get_resume_offset(const BasicBlock *bb, size_t offset)
{
    auto &exit_inst = bb->instructions().back();
    if (bb->address() + offset > exit_inst.address()) {
        return 0;
    }

    if (exit_inst.is_return() &&
        (bb->address() + offset + kLargeHostPadSize > exit_inst.address())) {
        return 0;
    }

    auto hosting_end_addr = bb->address() + offset;
    for (auto &inst: bb->instructions()) {
        if (hosting_end_addr <= inst.address()) {
            return inst.address() - bb->address();
        }
    }
    return 0;
}

static void
log_estimate_diff(const SuperBlockProbe &probe, size_t estimate, size_t actual)
{
    DVLOG(4) << "estimate diff = " << std::dec << estimate - actual
             << " @ " << std::hex << probe.basic_block()->address();
}

static unsigned
get_function_padding(const ElfModule &module, const IFunction &function)
{
    const auto elf_func = module.get_static_function_at(function.address());
    DVLOG_IF(elf_func->padding() != 0, 5)
            << LOG_PREFIX "might use function padding @ " << std::hex
            << elf_func->address() + elf_func->size() << " size "
            << OUT_DEC((unsigned) elf_func->padding());
    return elf_func->padding();
}

static bool
is_tiny_guest_probe(const SuperBlockProbe &probe)
{
    return probe.basic_block()->byte_size() + probe.padding() < kSBShortJmpByteSize;
}

static bool
is_instrumentable_guest_probe(const SuperBlockProbe &probe)
{
    return probe.kind() == SBProbeKind::kGuest &&
           probe.basic_block()->byte_size() + probe.padding() >= kSBDetourByteSize;
}

static bool
short_jump_reachable(addr_t src, addr_t dst)
{
    // reachable addresses from a short jump instruction
    //
    // - forwards:  address + 0x2 + 0x7f = address + 0x81
    // - backwards: address + 0x2 - 0x80 = address - 0x7e
    //

    if (src < dst) {
        return dst <= (src + 0x81);
    } else {
        return (src - 0x7e) <= dst;
    }
}

static void
update_coverage_data(const SuperBlockStore &sb_store, const SuperBlock &cov_sb,
                     std::vector<bool> &cov_data)
{
    if (cov_data[cov_sb.idx()]) {
        return;
    }
    cov_data[cov_sb.idx()] = true;
    for (const auto &pred_p : sb_store.get_dominators(cov_sb)) {
        update_coverage_data(sb_store, *pred_p, cov_data);
    }
}

static bool
is_patchable_jumptab(const JumpTable &jumptab)
{
    return jumptab.kind() == JumpTabKind::kOffsetI32 ||
           jumptab.kind() == JumpTabKind::kAbsAddr32 ||
           jumptab.kind() == JumpTabKind::kAbsAddr64;
}

static void
disasm_inst(const Disassembler &disasm, const MCInst &inst, buffer_t buf,
            cs_insn *result)
{
    auto address = inst.address();
    size_t byte_size = inst.size();
    auto data = buf;
    auto success = cs_disasm_iter(disasm.get(), &data, &byte_size, &address, result);
    DCHECK(success);
}

//==============================================================================
// this code is based on
// https://github.com/embeddedartistry/embedded-resources/blob/master/examples/cpp/circular_buffer.cpp

template<class T, uint8_t TSize>
class SmallRingBuffer {
public:
    typedef T value_type;
    typedef value_type *pointer;
    typedef value_type *iterator;
    typedef const value_type *const_iterator;
    typedef std::size_t size_type;

    static constexpr unsigned kMaxSize = 128;
    static_assert(TSize < kMaxSize, "size too big for a small ring buffer!");

    SmallRingBuffer() = default;

    ~SmallRingBuffer() = default;

    void push(T item)
    {
        m_buf[m_head] = item;
        m_head = (m_head + 1) % TSize;

        if (m_full) {
            m_tail = (m_tail + 1) % TSize;
        }

        m_full = m_head == m_tail;
    }

    T pop()
    {
        if (empty()) {
            return T();
        }
        auto val = m_buf[m_tail];
        m_full = false;
        m_tail = (m_tail + 1) % TSize;

        return val;
    }

    T peek()
    {
        if (empty()) {
            return T();
        }
        return m_buf[m_tail];
    }

    iterator begin() noexcept
    {
        return &m_buf[m_tail];
    }

    iterator next(iterator current) noexcept
    {
        return ++current == &m_buf[TSize] ? &m_buf[0] : current;
    }

    const_iterator cbegin() const noexcept
    {
        return &m_buf[m_tail];
    }

    const_iterator cnext(const_iterator current) const noexcept
    {
        return ++current == &m_buf[TSize] ? &m_buf[0] : current;
    }

    void reset()
    {
        m_head = m_tail;
        m_full = false;
    }

    bool empty() const noexcept
    {
        return (!m_full && (m_head == m_tail));
    }

    bool full() const noexcept
    {
        return m_full;
    }

    size_t capacity() const noexcept
    {
        return TSize;
    }

    size_t size() const noexcept
    {
        size_t total_size = TSize;

        if (!m_full) {
            if (m_head >= m_tail) {
                total_size = m_head - m_tail;
            } else {
                total_size = TSize + m_head - m_tail;
            }
        }
        return total_size;
    }

private:
    bool m_full = false;
    uint8_t m_head = 0;
    uint8_t m_tail = 0;
    std::array<T, TSize> m_buf;
};

//==============================================================================

SuperBlockProbe::SuperBlockProbe() : m_link()
{ }

SBProbeKind
SuperBlockProbe::kind() const noexcept
{
    return m_kind;
}

const IFunction *
SuperBlockProbe::function() const noexcept
{
    DCHECK(m_kind == SBProbeKind::kLink);
    return m_link.m_function;
}

size_t
SuperBlockProbe::probe_count() const noexcept
{
    DCHECK(m_kind == SBProbeKind::kLink);
    return m_link.m_probe_count;
}

const SuperBlockStore *
SuperBlockProbe::super_block_store() const noexcept
{
    DCHECK(m_kind == SBProbeKind::kLink);
    return m_link.m_sb_store;
}

const BasicBlock *
SuperBlockProbe::basic_block() const noexcept
{
    DCHECK(m_kind != SBProbeKind::kLink);
    return m_default.m_detour_bb;
}

const JumpTable *
SuperBlockProbe::jump_table() const noexcept
{
    DCHECK(m_kind == SBProbeKind::kJumpTab);
    return m_jumptab.m_jumptab;
}

const BasicBlock *
SuperBlockProbe::host() const noexcept
{
    DCHECK(m_kind == SBProbeKind::kGuest);
    return m_default.m_host_bb;
}

bool
SuperBlockProbe::valid() const noexcept
{
    return m_kind != SBProbeKind::kLink || m_link.m_probe_count != 0;
}

bool
SuperBlockProbe::is_link() const noexcept
{
    return m_kind == SBProbeKind::kLink;
}

uint8_t
SuperBlockProbe::padding() const noexcept
{
    return m_default.m_padding;
}

size_t
SuperBlockProbe::super_block_idx() const noexcept
{
    DCHECK(!is_link());
    return m_default.m_sb_id;
}

bool
SuperBlockProbe::is_replaced() const noexcept
{
    return m_kind == SBProbeKind::kNoHost &&
           m_default.m_detour_bb == m_default.m_host_bb;
}

bool
SuperBlockProbe::is_attr_set(SBProbeAttr attr) const noexcept
{
    return (m_default.m_attr & attr) == attr;
}

//==============================================================================

struct HostBasicBlock {

    static constexpr unsigned kCondCostOverhead = 10;

    HostBasicBlock() = default;

    ~HostBasicBlock() = default;

    explicit HostBasicBlock(const BasicBlock *bb) : m_bb(bb)
    { };

    size_t restore_overhead();

    unsigned padding() const noexcept
    { return m_padding; };

    unsigned guest_offset() const noexcept
    { return m_guest_offset; };

    const BasicBlock *bb() const noexcept
    { return m_bb; }

    const BasicBlock *m_bb = nullptr;
    uint8_t m_guest_offset = 0;
    uint8_t m_padding = 0;
};

size_t
HostBasicBlock::restore_overhead()
{
    auto &exit_inst = bb()->instructions().back();
    size_t result;
    if (guest_offset() > exit_inst.address()) {
        result = bb()->byte_size();
        if (exit_inst.is_conditional() && exit_inst.is_jump()) {
            result += kCondCostOverhead;
        }
        return result;
    }
    auto restore_inst = std::find_if(bb()->instructions().begin(),
                                     bb()->instructions().end(),
                                     [this](const MCInst &inst) {
                                         return inst.address() >= guest_offset();
                                     });
    return restore_inst->address() - bb()->address();
}

//==============================================================================

class X64ElfPatcher {
public:
    enum class RegionKind : uint8_t {
        kOrigCode,
        kOrigData,
        kPatchCode,
        kPatchData,
        kROData1,
        kROData2,
    };

    static constexpr unsigned kMaxLoadableSegCount = 6U;
    static constexpr unsigned kMinLoadableSegCount = 4U;
    static constexpr unsigned kMaxGuestProbeCount = 8U;

    using HostBBPatchMap = std::map<const BasicBlock *, addr_t>;

    X64ElfPatcher();

    bool can_instrument_bb_at_end(const SuperBlockProbe &probe);

    void patch(const ElfPatchManager::SBProbeVec &probes, elf::elf &patch_file);

    void set_module(const ElfModule *module) noexcept;

    unsigned estimate_code_size(const SuperBlockProbe &probe) noexcept;

protected:

    bool reads_rsp_register(const MCInst &inst) const noexcept;

    void patch_probe(const SuperBlockProbe &probe);

    void patch_host_probe(const SuperBlockProbe &probe);

    void rewrite_basic_block(const BasicBlock *bb, addr_t restore_off = 0);

    void patch_return_probe(const SuperBlockProbe &probe);

    void patch_long_call_probe(const SuperBlockProbe &probe);

    void patch_long_jump_probe(const SuperBlockProbe &probe);

    void patch_short_call_probe(const SuperBlockProbe &probe);

    void patch_jumptab_probe(const SuperBlockProbe &probe);

    void patch_long_cond_jump_probe(const SuperBlockProbe &probe);

    void patch_short_cond_jump_probe(const SuperBlockProbe &probe);

    void patch_short_jump_probe(const SuperBlockProbe &probe);

    bool try_patch_one_instruction(const SuperBlockProbe &probe);

    bool try_patch_few_instructions(const SuperBlockProbe &probe);

    void patch_basic_block_end(const SuperBlockProbe &probe);

    void patch_inner_probe(const SuperBlockProbe &probe);

    void mark_guest_probe(const SuperBlockProbe &probe);

    void patch_one_guest_probe(const SuperBlockProbe &probe, addr_t detour_addr);

    void patch_guest_probes();

    void write_coverage_update();

    void fixup_short_call_rsp_disp(uint8_t *buf);

    static void fixup_long_call_rsp_disp(uint8_t *buf);

    void write_rsp_adjust_return(addr_t current, addr_t target);

    void write_restore_jump(addr_t target);

    void write_long_detour(addr_t src, addr_t dst);

    void write_call_detour(addr_t src, addr_t dst);

    void write_short_detour(addr_t src, addr_t dst);

    MMappedFileRegion &get_region(RegionKind region);

    void init_memory_regions(const elf::elf &patch_file);

    void init_patch_data_header(size_t probe_count);

protected:
    MMappedFileRegion *get_jumptab_region(addr_t base_address);

    struct GuestProbeAddrPair {
        GuestProbeAddrPair() = default;

        GuestProbeAddrPair(const SuperBlockProbe *probe, addr_t mem_addr)
            : m_probe(probe), m_mem_addr(mem_addr)
        { }

        ~ GuestProbeAddrPair() = default;

        const SuperBlockProbe *m_probe = nullptr;
        addr_t m_mem_addr;
    };

private:
    const ElfModule *m_module = nullptr;
    std::array<MMappedFileRegion, kMaxLoadableSegCount> m_regions = {};
    X64InstRewriter m_rewriter;
    std::vector<GuestProbeAddrPair> m_guest_addr_pair_vec;
    CSInstWrapper m_cs_inst;
    Disassembler m_disasm;
};

X64ElfPatcher::X64ElfPatcher()
{
    m_disasm.init(DisasmArch::kX86, DisasmMode::k64);
}

bool
X64ElfPatcher::can_instrument_bb_at_end(const SuperBlockProbe &probe)
{
    DCHECK(probe.kind() == SBProbeKind::kShortCall);
    DCHECK(probe.basic_block()->byte_size() >= kSBDetourByteSize);
    auto inst_it = probe.basic_block()->instructions().rbegin();
    auto rewrite_size = inst_it->size();
    while (rewrite_size < x64::kInstJMPRel32Size &&
           inst_it != probe.basic_block()->instructions().rend()) {
        ++inst_it;
        rewrite_size += inst_it->size();
        if (reads_rsp_register(*inst_it)) {
            return false;
        }
    }
    return rewrite_size >= x64::kInstJMPRel32Size;
}

void
X64ElfPatcher::init_memory_regions(const elf::elf &patch_file)
{
    using namespace elf;
    static auto init_region_from_seg =
        [](const segment &seg, MMappedFileRegion &region) {
            region.init(const_cast<void *>(seg.data()), seg.get_hdr().vaddr,
                        seg.get_hdr().memsz);
        };
    unsigned seg_count = 0;
    // TODO: the layout and number of supported elf segments is fixed. This can
    //  be improved upon.
    for (const auto &seg: patch_file.segments()) {
        if (!is_loadable(seg)) {
            continue;
        }
        ++seg_count;
        if (is_executable(seg)) {
            if (!get_region(RegionKind::kOrigCode).valid()) {
                init_region_from_seg(seg, get_region(RegionKind::kOrigCode));
            } else {
                DCHECK(!get_region(RegionKind::kPatchCode).valid());
                init_region_from_seg(seg, get_region(RegionKind::kPatchCode));
            }
            continue;
        }

        if (is_writable(seg)) {
            if (!get_region(RegionKind::kOrigData).valid()) {
                init_region_from_seg(seg, get_region(RegionKind::kOrigData));
            } else {
                DCHECK(!get_region(RegionKind::kPatchData).valid());
                init_region_from_seg(seg, get_region(RegionKind::kPatchData));
            }
            continue;
        }

        if (!get_region(RegionKind::kROData1).valid()) {
            init_region_from_seg(seg, get_region(RegionKind::kROData1));
        } else {
            init_region_from_seg(seg, get_region(RegionKind::kROData2));
        }
    }
    get_region(RegionKind::kPatchData).seekp(BCOV_DATA_HDR_SIZE);

    if (seg_count > kMaxLoadableSegCount || seg_count < kMinLoadableSegCount) {
        throw std::invalid_argument("malformed or corrupted patch file");
    }
}

MMappedFileRegion *
X64ElfPatcher::get_jumptab_region(addr_t base_address)
{
    if (get_region(RegionKind::kOrigData).is_inside(base_address)) {
        return &get_region(RegionKind::kOrigData);
    }
    if (get_region(RegionKind::kOrigCode).is_inside(base_address)) {
        return &get_region(RegionKind::kOrigCode);
    }
    if (get_region(RegionKind::kROData1).is_inside(base_address)) {
        return &get_region(RegionKind::kROData1);
    }
    if (get_region(RegionKind::kROData2).is_inside(base_address)) {
        return &get_region(RegionKind::kROData2);
    }

    return nullptr;
}

void
X64ElfPatcher::init_patch_data_header(size_t probe_count)
{
    auto &patch_data = get_region(RegionKind::kPatchData);
    bcov_write_magic(patch_data.base_pos());
    bcov_write_probe_count(patch_data.base_pos(), probe_count);
    bcov_write_base_address(patch_data.base_pos(), (uint64_t) -1);
}

MMappedFileRegion &
X64ElfPatcher::get_region(RegionKind region)
{
    return m_regions[(unsigned) region];
}

bool
X64ElfPatcher::reads_rsp_register(const MCInst &inst) const noexcept
{
    static auto does_match = [](uint16_t cs_reg) {
        auto reg = x64::get_x64_reg(cs_reg);
        if (x64::get_canonical(reg) == x64::X64Reg::RSP) {
            DCHECK(reg == get_canonical(reg));
            return true;
        }
        return false;
    };

    using namespace x64;
    auto buf = m_module->code_region().get_buffer(inst.address());
    disasm_inst(m_disasm, inst, buf, m_cs_inst.get());
    auto details = m_cs_inst.get()->detail;
    for (unsigned i = 0; i < details->regs_read_count && !inst.is_call(); ++i) {
        if (does_match(details->regs_read[i])) {
            return true;
        }
    }

    for (int i = 0; i < details->x86.op_count; ++i) {
        if (details->x86.operands[i].type == X86_OP_REG &&
            is_read_acc(details->x86.operands[i].access)) {
            if (does_match(details->x86.operands[i].reg)) {
                return true;
            }
        }
        if (details->x86.operands[i].type == X86_OP_MEM) {
            if (does_match(details->x86.operands[i].mem.base)) {
                return true;
            }
            if (does_match(details->x86.operands[i].mem.index)) {
                return true;
            }
        }
    }
    return false;
}

void
X64ElfPatcher::write_coverage_update()
{
    auto &patch_code = get_region(RegionKind::kPatchCode);
    auto &patch_data = get_region(RegionKind::kPatchData);

    VLOG(3) << LOG_PREFIX "writing coverage update @ "
            << OUT_HEX(patch_code.current_address()) << " to @ "
            << patch_data.current_address();

    X64Asm::mov_rip_mem_imm8(patch_code.current_pos(),
                             patch_code.current_address(),
                             patch_data.current_address(), 1);

    patch_code.seekp(x64::kInstRIPRelMoveSize);
    patch_data.seekp(1);
}

void
X64ElfPatcher::write_rsp_adjust_return(addr_t current, addr_t target)
{
    auto &patch_code = get_region(RegionKind::kPatchCode);

    auto diff = (int8_t) (current - target);
    DVLOG(3) << LOG_PREFIX "writing rsp adjust @ "
             << OUT_HEX(patch_code.current_address()) << " from "
             << current << " to " << target << " diff " << OUT_DEC((int) diff);

    DCHECK(current == (target + diff));
    X64Asm::sub_rsp_mem_imm8(patch_code.current_pos(), diff);
    patch_code.seekp(x64::kRSPAdjustByteSize);
}

void
X64ElfPatcher::write_restore_jump(addr_t target)
{
    auto &patch_code = get_region(RegionKind::kPatchCode);
    VLOG(3) << LOG_PREFIX "writing restore jmp @ "
            << OUT_HEX(patch_code.current_address()) << " to @ " << target;
    X64Asm::jmp_rel_32(patch_code.current_pos(),
                       patch_code.current_address(), target);
    patch_code.seekp(x64::kInstJMPRel32Size);
}

void
X64ElfPatcher::write_long_detour(addr_t src, addr_t dst)
{
    VLOG(3) << LOG_PREFIX "writing detour @ " << OUT_HEX(src) << " to @ " << dst;
    auto &orig_code = get_region(RegionKind::kOrigCode);
    orig_code.seekp(orig_code.get_pos(src));
    X64Asm::jmp_rel_32(orig_code.current_pos(),
                       orig_code.current_address(), dst);
    DCHECK(orig_code.is_inside(src) &&
           get_region(RegionKind::kPatchCode).is_inside(dst));
}

void
X64ElfPatcher::write_call_detour(addr_t src, addr_t dst)
{
    VLOG(3) << LOG_PREFIX "writing call detour @ " << OUT_HEX(src) << " to @"
            << dst;
    auto &orig_code = get_region(RegionKind::kOrigCode);
    orig_code.seekp(orig_code.get_pos(src));
    X64Asm::call_rel_32(orig_code.current_pos(),
                        orig_code.current_address(), dst);
    DCHECK(orig_code.is_inside(src) &&
           get_region(RegionKind::kPatchCode).is_inside(dst));
}

void
X64ElfPatcher::write_short_detour(addr_t src, addr_t dst)
{
    VLOG(3) << LOG_PREFIX "write short detour @ "
            << OUT_HEX(src) << " to @ " << dst;
    auto &orig_code = get_region(RegionKind::kOrigCode);
    orig_code.seekp(orig_code.get_pos(src));
    X64Asm::jmp_rel_8(orig_code.current_pos(),
                      orig_code.current_address(), dst);
    DCHECK(orig_code.is_inside(src) && orig_code.is_inside(dst));
}

void
X64ElfPatcher::patch_one_guest_probe(const SuperBlockProbe &probe,
                                     addr_t detour_addr)
{
    auto &orig_code = get_region(RegionKind::kOrigCode);
    auto &patch_code = get_region(RegionKind::kPatchCode);
    addr_t orig_address = patch_code.current_address();
    auto &exit_inst = probe.basic_block()->instructions().back();
    X64Asm::fill_nop(orig_code.get_pos(probe.basic_block()->address()),
                     probe.basic_block()->byte_size());
    write_short_detour(probe.basic_block()->address(), detour_addr);

    if (exit_inst.is_call()) {
        write_call_detour(detour_addr, patch_code.current_address());
    } else {
        write_long_detour(detour_addr, patch_code.current_address());
    }

    write_coverage_update();
    if (exit_inst.is_call()) {
        write_rsp_adjust_return(detour_addr + kSBDetourByteSize,
                                probe.basic_block()->end());
    }
    rewrite_basic_block(probe.basic_block());
    auto actual_size = patch_code.current_address() - orig_address;
    auto estimated_size = estimate_code_size(probe);
    DCHECK(actual_size <= estimated_size);
    log_estimate_diff(probe, estimated_size, actual_size);
}

void
X64ElfPatcher::patch_guest_probes()
{
    if (m_guest_addr_pair_vec.empty()) {
        return;
    }
    std::sort(m_guest_addr_pair_vec.begin(), m_guest_addr_pair_vec.end(),
              [](const auto &a, const auto &b) {
                  if (a.m_probe->host() != b.m_probe->host())
                      return a.m_probe->host() < b.m_probe->host();
                  return a.m_probe->basic_block()->address() <
                         b.m_probe->basic_block()->address();
              });

    auto &patch_data = get_region(RegionKind::kPatchData);
    auto cur_data_address = patch_data.current_address();
    auto cur_guest = m_guest_addr_pair_vec.begin();
    while (cur_guest != m_guest_addr_pair_vec.end()) {
        auto end_guest =
            std::find_if(cur_guest, m_guest_addr_pair_vec.end(),
                         [cur_guest](const GuestProbeAddrPair &pair) {
                             return pair.m_probe->host() !=
                                    cur_guest->m_probe->host();
                         });

        DVLOG(4) << LOG_PREFIX "patching guests for host @ "
                 << OUT_HEX(cur_guest->m_probe->host()->address())
                 << " guest count " << OUT_DEC(end_guest - cur_guest);

        for (; cur_guest != end_guest; ++cur_guest) {
            DCHECK(patch_data.is_inside(cur_guest->m_mem_addr));
            DCHECK(cur_guest->m_mem_addr < cur_data_address);
            patch_data.seekp(patch_data.get_pos(cur_guest->m_mem_addr));
            auto detour_addr = cur_guest->m_probe->host()->address() +
                               cur_guest->m_probe->padding();
            patch_one_guest_probe(*cur_guest->m_probe, detour_addr);
        }
    }

    patch_data.seekp(patch_data.get_pos(cur_data_address));
    m_guest_addr_pair_vec.clear();
}

void
X64ElfPatcher::patch_host_probe(const SuperBlockProbe &probe)
{
    auto &patch_code = get_region(RegionKind::kPatchCode);
    auto &orig_code = get_region(RegionKind::kOrigCode);

    addr_t orig_address = patch_code.current_address();
    auto offset = get_resume_offset(probe);
    auto estimated_size = estimate_host_code_size(probe.basic_block(), offset);

    auto pad_size =
        offset != 0 ? offset : probe.basic_block()->byte_size() + probe.padding();
    auto pad_buf = orig_code.get_pos(probe.basic_block()->address());

    X64Asm::fill_nop(pad_buf, pad_size);
    write_long_detour(probe.basic_block()->address(), patch_code.current_address());
    if (probe.kind() == SBProbeKind::kPlainHost) {
        auto &patch_data = get_region(RegionKind::kPatchData);
        patch_data.seekp(1);
    } else {
        estimated_size += kSBProbeCovInstSize;
        write_coverage_update();
    }

    auto &exit_inst = probe.basic_block()->instructions().back();
    if (offset != 0) {
        VLOG(3) << LOG_PREFIX "patch large host probe @ "
                << OUT_HEX(probe.basic_block()->address());
        DCHECK(exit_inst.address() >= probe.basic_block()->address() + offset);
        rewrite_basic_block(probe.basic_block(), offset);
    } else {
        VLOG(3) << LOG_PREFIX "patch normal host probe @ "
                << OUT_HEX(probe.basic_block()->address());
        DCHECK(!exit_inst.is_call());
        rewrite_basic_block(probe.basic_block());
    }
    auto actual_size = patch_code.current_address() - orig_address;
    DCHECK(actual_size <= estimated_size);
    log_estimate_diff(probe, estimated_size, actual_size);
}

void
X64ElfPatcher::rewrite_basic_block(const BasicBlock *bb, addr_t restore_off)
{
    auto &patch_code = get_region(RegionKind::kPatchCode);

    VLOG(4) << LOG_PREFIX "rewriting bb @ " << OUT_HEX(bb->address()) << " to @ "
            << patch_code.current_address();

    addr_t restore_addr = restore_off != 0 ? bb->address() + restore_off : bb->end();

    for (const auto &inst: bb->instructions()) {
        if (inst.address() >= restore_addr) {
            break;
        }
        VLOG(5) << LOG_PREFIX "rewriting inst @ " << OUT_HEX(inst.address())
                << " to @ " << patch_code.current_address();
        auto p = patch_code.current_pos();
        m_rewriter.rewrite(inst, m_module->get_buffer(inst.address()),
                           patch_code.current_address(), &p);
        patch_code.seekp(p);
    }
    if (restore_off != 0 || requires_restore_jump(bb)) {
        DCHECK(restore_off == 0 ||
               restore_addr <= bb->instructions().back().address());
        write_restore_jump(restore_addr);
    }
}

void
X64ElfPatcher::patch_long_call_probe(const SuperBlockProbe &probe)
{
    auto &patch_code = get_region(RegionKind::kPatchCode);
    auto &exit_inst = probe.basic_block()->instructions().back();
    DCHECK(exit_inst.is_call() && exit_inst.size() >= x64::kInstJMPRel32Size);
    if (exit_inst.size() > x64::kInstJMPRel32Size) {
        auto &orig = get_region(RegionKind::kOrigCode);
        X64Asm::fill_nop(orig.get_pos(exit_inst.address()), exit_inst.size());
    }
    write_call_detour(exit_inst.address() + exit_inst.size() - kSBDetourByteSize,
                      patch_code.current_address());
    write_coverage_update();
    auto p = patch_code.current_pos();
    m_rewriter.rewrite(exit_inst, m_module->get_buffer(exit_inst.address()),
                       patch_code.current_address(), &p);
    patch_code.seekp(p);
    if (reads_rsp_register(exit_inst)) {
        fixup_long_call_rsp_disp(p - x64::kJmpRSPMemDisp32InstSize);
    }
}

void
X64ElfPatcher::patch_long_jump_probe(const SuperBlockProbe &probe)
{
    auto &patch_code = get_region(RegionKind::kPatchCode);
    auto &exit_inst = probe.basic_block()->instructions().back();
    DCHECK(exit_inst.is_jump() && exit_inst.size() >= x64::kInstJMPRel32Size);

    if (exit_inst.size() > x64::kInstJMPRel32Size) {
        auto &orig = get_region(RegionKind::kOrigCode);
        X64Asm::fill_nop(orig.get_pos(exit_inst.address()), exit_inst.size());
    }
    write_long_detour(exit_inst.address(), patch_code.current_address());
    write_coverage_update();
    auto p = patch_code.current_pos();
    m_rewriter.rewrite(exit_inst, m_module->get_buffer(exit_inst.address()),
                       patch_code.current_address(), &p);
    patch_code.seekp(p);
}

void
X64ElfPatcher::patch_jumptab_probe(const SuperBlockProbe &probe)
{
    // update jumptab data to point to current patch code address
    DCHECK(is_patchable_jumptab(*probe.jump_table()));
    auto &patch_code = get_region(RegionKind::kPatchCode);
    auto jumptab_p = probe.jump_table();
    auto region_p = get_jumptab_region(jumptab_p->base_address());

    auto entry_reader = get_jumptab_reader(jumptab_p->kind());
    auto entry_writer = get_jumptab_writer(jumptab_p->kind());
    auto base_p = region_p->get_pos(jumptab_p->base_address());
    for (auto *buf = base_p; buf < base_p + jumptab_p->byte_size();
         buf += entry_size(jumptab_p->kind())) {

        auto target = entry_reader->read(buf, jumptab_p->base_address());
        if (target != probe.basic_block()->address()) {
            continue;
        }
        entry_writer->write(patch_code.current_address(),
                            jumptab_p->base_address(), buf);
        DVLOG(5) << LOG_PREFIX "patch jumptab @ "
                 << OUT_HEX(jumptab_p->jump_address())
                 << " entry @ " << region_p->get_address(buf)
                 << " target @ " << patch_code.current_address();
        DCHECK(patch_code.current_address() ==
               entry_reader->read(buf, jumptab_p->base_address()));
    }

    write_coverage_update();
    write_restore_jump(probe.basic_block()->address());
}

void
X64ElfPatcher::patch_long_cond_jump_probe(const SuperBlockProbe &probe)
{
    auto &patch_code = get_region(RegionKind::kPatchCode);
    auto &orig_code = get_region(RegionKind::kOrigCode);
    auto &exit_inst = probe.basic_block()->instructions().back();
    DCHECK(exit_inst.is_jump() && exit_inst.size() == x64::kInstJccRel32Size);
    X64Asm::fill_nop(orig_code.get_pos(exit_inst.address()), exit_inst.size());
    write_long_detour(exit_inst.address(), patch_code.current_address());
    write_coverage_update();
    auto p = patch_code.current_pos();
    m_rewriter.rewrite(exit_inst, m_module->get_buffer(exit_inst.address()),
                       patch_code.current_address(), &p);
    patch_code.seekp(p);
}

void
X64ElfPatcher::fixup_long_call_rsp_disp(uint8_t *buf)
{
    if (*buf == 0x42) {
        // skip prefix for e.g. jmp  QWORD PTR [rsp+r8*imm+disp]
        ++buf;
    }
    DCHECK((*reinterpret_cast<uint16_t *>(buf) & 0xA4FF) == 0xA4FF);
    auto off_p = reinterpret_cast<int32_t *>(buf + 3);
    *off_p += x64::kQWORD;
}

void
X64ElfPatcher::fixup_short_call_rsp_disp(uint8_t *buf)
{
    using namespace x64;
    auto &patch_code = get_region(RegionKind::kPatchCode);
    auto disp_p = reinterpret_cast<int8_t *>(buf + 3);
    auto *inst_bytes = reinterpret_cast<uint32_t *>(buf);
    if ((*inst_bytes & 0x00FFFFFFU) == kJmpRSPMemDisp0Inst) {
        // assuming: call   QWORD PTR [rsp]
        *reinterpret_cast<uint32_t *>(buf) = kJmpRSPMemDisp8Inst;
        patch_code.seekp(buf + kJmpRSPMemDisp8InstSize);
    }
    // assuming: call   QWORD PTR [rsp+disp]
    DCHECK((*inst_bytes & 0x00FFFFFFU) == kJmpRSPMemDisp8Inst);
    DCHECK(patch_code.current_pos() - kJmpRSPMemDisp8InstSize == buf);
    if (*disp_p < 120) {
        *disp_p += x64::kQWORD;
    } else {
        X64Asm::jmp_rsp_mem_disp32(buf, *disp_p + x64::kQWORD);
        patch_code.seekp(buf + kJmpRSPMemDisp32InstSize);
    }
}

void
X64ElfPatcher::patch_short_call_probe(const SuperBlockProbe &probe)
{
    auto &exit_inst = probe.basic_block()->instructions().back();
    DCHECK(exit_inst.is_call() && exit_inst.size() < x64::kInstJMPRel32Size);
    if (can_instrument_bb_at_end(probe)) {
        patch_basic_block_end(probe);
        if (reads_rsp_register(exit_inst)) {
            auto &patch_code = get_region(RegionKind::kPatchCode);
            fixup_short_call_rsp_disp(patch_code.current_pos() - exit_inst.size());
        }
        return;
    }
    if (try_patch_one_instruction(probe)) {
        return;
    }
    auto success = try_patch_few_instructions(probe);
    DCHECK(success);
}

void
X64ElfPatcher::patch_return_probe(const SuperBlockProbe &probe)
{
    auto &exit_inst = probe.basic_block()->instructions().back();
    DCHECK(exit_inst.is_return());
    patch_basic_block_end(probe);
}

bool
X64ElfPatcher::try_patch_one_instruction(const SuperBlockProbe &probe)
{
    auto &orig_code = get_region(RegionKind::kOrigCode);
    auto &patch_code = get_region(RegionKind::kPatchCode);
    auto detour_inst = find_one_detour_fitting_instruction(probe.basic_block());
    if (detour_inst == nullptr) {
        return false;
    }
    X64Asm::fill_nop(orig_code.get_pos(detour_inst->address()),
                     detour_inst->size());
    write_long_detour(detour_inst->address(), patch_code.current_address());
    write_coverage_update();
    auto p = patch_code.current_pos();
    m_rewriter.rewrite(*detour_inst, m_module->get_buffer(detour_inst->address()),
                       patch_code.current_address(), &p);
    patch_code.seekp(p);
    write_restore_jump(detour_inst->end());
    return true;
}

bool
X64ElfPatcher::try_patch_few_instructions(const SuperBlockProbe &probe)
{
    auto &orig_code = get_region(RegionKind::kOrigCode);
    auto &patch_code = get_region(RegionKind::kPatchCode);
    auto detour_inst = find_few_detour_fitting_instructions(probe.basic_block());
    if (detour_inst == nullptr) {
        return false;
    }

    auto start_address = probe.basic_block()->address();
    auto pad_size = detour_inst->end() - start_address;
    X64Asm::fill_nop(orig_code.get_pos(start_address), pad_size);
    write_long_detour(start_address, patch_code.current_address());
    write_coverage_update();
    for (const auto &inst : probe.basic_block()->instructions()) {
        if (inst.address() >= detour_inst->end()) {
            break;
        }
        auto p = patch_code.current_pos();
        m_rewriter.rewrite(inst, m_module->get_buffer(inst.address()),
                           patch_code.current_address(), &p);
        patch_code.seekp(p);
    }
    write_restore_jump(detour_inst->end());
    return true;
}

void
X64ElfPatcher::patch_basic_block_end(const SuperBlockProbe &probe)
{
    auto &orig_code = get_region(RegionKind::kOrigCode);
    auto &patch_code = get_region(RegionKind::kPatchCode);
    auto inst_it = probe.basic_block()->instructions().rbegin();
    unsigned rewrite_size = inst_it->size() + probe.padding();
    while (rewrite_size < kSBDetourByteSize &&
           inst_it != probe.basic_block()->instructions().rend()) {
        ++inst_it;
        rewrite_size += inst_it->size();
    }

    X64Asm::fill_nop(orig_code.get_pos(inst_it->address()), rewrite_size);

    auto detour_addr =
        probe.basic_block()->end() + probe.padding() - kSBDetourByteSize;
    if (probe.kind() == SBProbeKind::kShortCall) {
        write_call_detour(detour_addr, patch_code.current_address());
    } else {
        write_long_detour(detour_addr, patch_code.current_address());
    }
    write_coverage_update();
    for (; inst_it >= probe.basic_block()->instructions().rbegin(); --inst_it) {
        auto p = patch_code.current_pos();
        m_rewriter.rewrite(*inst_it, m_module->get_buffer(inst_it->address()),
                           patch_code.current_address(), &p);
        patch_code.seekp(p);
    }
}

void
X64ElfPatcher::patch_short_jump_probe(const SuperBlockProbe &probe)
{
    auto &exit_inst = probe.basic_block()->instructions().back();
    DCHECK(exit_inst.is_jump() && !exit_inst.is_conditional() &&
           exit_inst.size() < x64::kInstJMPRel32Size);
    patch_basic_block_end(probe);
}

void
X64ElfPatcher::patch_short_cond_jump_probe(const SuperBlockProbe &probe)
{
    auto &exit_inst = probe.basic_block()->instructions().back();
    DCHECK(exit_inst.is_jump() && exit_inst.is_conditional() &&
           exit_inst.size() < x64::kInstJMPRel32Size);
    DLOG_IF(probe.padding() != 0, WARNING)
            << LOG_PREFIX "padded short-cond probe, UB possible"
            << OUT_HEX(probe.basic_block()->address());
    if (!try_patch_one_instruction(probe)) {
        patch_basic_block_end(probe);
    }
}

void
X64ElfPatcher::patch_inner_probe(const SuperBlockProbe &probe)
{
    auto &exit_inst = probe.basic_block()->instructions().back();
    DCHECK(probe.padding() == 0 && !exit_inst.is_branch());
    if (!try_patch_one_instruction(probe)) {
        patch_basic_block_end(probe);
        write_restore_jump(probe.basic_block()->end());
    }
}

void
X64ElfPatcher::mark_guest_probe(const SuperBlockProbe &probe)
{
    auto &patch_data = get_region(RegionKind::kPatchData);
    VLOG(3) << LOG_PREFIX "marking guest @ "
            << OUT_HEX(probe.basic_block()->address())
            << " with data @ " << patch_data.current_address();

    m_guest_addr_pair_vec.emplace_back(&probe, patch_data.current_address());
    patch_data.seekp(1);
}

void
X64ElfPatcher::patch_probe(const SuperBlockProbe &probe)
{
    auto &patch_code = get_region(RegionKind::kPatchCode);
    auto &patch_data = get_region(RegionKind::kPatchData);
    addr_t prev_code_addr = patch_code.current_address();
    switch (probe.kind()) {
    case SBProbeKind::kReturn: patch_return_probe(probe);
        break;
    case SBProbeKind::kLongCall: patch_long_call_probe(probe);
        break;
    case SBProbeKind::kLongJmp: patch_long_jump_probe(probe);
        break;
    case SBProbeKind::kShortCall: patch_short_call_probe(probe);
        break;
    case SBProbeKind::kJumpTab: patch_jumptab_probe(probe);
        break;
    case SBProbeKind::kLongCondJmp: patch_long_cond_jump_probe(probe);
        break;
    case SBProbeKind::kShortJmp:patch_short_jump_probe(probe);
        break;
    case SBProbeKind::kShortCondJmp: patch_short_cond_jump_probe(probe);
        break;
    case SBProbeKind::kInnerBB: patch_inner_probe(probe);
        break;
    case SBProbeKind::kGuest: mark_guest_probe(probe);
        break;
    default:DVLOG(3) << LOG_PREFIX "skipping coverage update @ "
                     << OUT_HEX(patch_code.current_address()) << " to @ "
                     << patch_data.current_address();
        patch_data.seekp(1);
        DCHECK(probe.kind() == SBProbeKind::kNoHost);
    }

    auto used_code_size = patch_code.current_address() - prev_code_addr;
    if (probe.kind() != SBProbeKind::kGuest) {
        log_estimate_diff(probe, estimate_code_size(probe), used_code_size);
    }
    DCHECK(used_code_size <= estimate_code_size(probe));
    DCHECK(patch_code.is_inside(patch_code.current_pos()));
    DCHECK(patch_data.is_inside(patch_data.current_pos()));
}

void
X64ElfPatcher::set_module(const ElfModule *module) noexcept
{
    m_module = module;
}

unsigned
X64ElfPatcher::estimate_code_size(const SuperBlockProbe &probe) noexcept
{
    static auto compute_rewritten_insts_size =
        [](const SuperBlockProbe &probe, unsigned &size) {
            auto inst_it = probe.basic_block()->instructions().rbegin();
            size = inst_it->size();
            ++inst_it;
            for (; size + probe.padding() < kSBDetourByteSize &&
                   inst_it !=
                   probe.basic_block()->instructions().rend(); ++inst_it) {

                size += inst_it->size();
            }
        };

    const auto &exit_inst = probe.basic_block()->instructions().back();
    unsigned rewrite_size = 0;
    unsigned size = kSBProbeCovInstSize;
    const MCInst *detour_inst = nullptr;
    switch (probe.kind()) {
    case SBProbeKind::kReturn:compute_rewritten_insts_size(probe, rewrite_size);
        return size + rewrite_size;
    case SBProbeKind::kLongCall:return size + exit_inst.size();
    case SBProbeKind::kLongJmp:return size + exit_inst.size();
    case SBProbeKind::kShortCall:
        if (can_instrument_bb_at_end(probe)) {
            compute_rewritten_insts_size(probe, rewrite_size);
            if (!reads_rsp_register(exit_inst)) {
                return size + rewrite_size;
            }
            if (exit_inst.size() == x64::kJmpRSPMemDisp8InstSize) {
                size += x64::kJmpRSPMemDisp32InstSize - x64::kJmpRSPMemDisp8InstSize;
            } else if (exit_inst.size() == x64::kJmpRSPMemDisp0InstSize) {
                size += x64::kJmpRSPMemDisp8InstSize - x64::kJmpRSPMemDisp0InstSize;
            }
            return size + rewrite_size;
        }
        detour_inst = find_one_detour_fitting_instruction(probe.basic_block());
        if (detour_inst != nullptr) {
            return size + detour_inst->size() + kSBDetourByteSize;
        }
        detour_inst = find_few_detour_fitting_instructions(probe.basic_block());
        return size + detour_inst->end() - probe.basic_block()->address() +
               kSBDetourByteSize;

    case SBProbeKind::kJumpTab:return size + kSBDetourByteSize;
    case SBProbeKind::kLongCondJmp:return size + kSBLongJmpCCRewriteByteSize;
    case SBProbeKind::kShortJmp:compute_rewritten_insts_size(probe, rewrite_size);
        return size + rewrite_size + estimate_restore_overhead_size(exit_inst);
    case SBProbeKind::kInnerBB:
    case SBProbeKind::kShortCondJmp:
        detour_inst = find_one_detour_fitting_instruction(probe.basic_block());
        if (detour_inst != nullptr) {
            return size + detour_inst->size() + kSBDetourByteSize;
        } else {
            compute_rewritten_insts_size(probe, rewrite_size);
            return size + rewrite_size + estimate_restore_overhead_size(exit_inst);
        }
    case SBProbeKind::kGuest:
        size += probe.basic_block()->byte_size() +
                estimate_restore_overhead_size(exit_inst);
        return exit_inst.is_call() ? size + x64::kRSPAdjustByteSize : size;
    default: return 0;
    }
}

void
X64ElfPatcher::patch(const ElfPatchManager::SBProbeVec &probes,
                     elf::elf &patch_file)
{
    init_memory_regions(patch_file);
    init_patch_data_header(probes.size() - m_module->probed_functions().size());
    for (const auto &probe : probes) {
        if (probe.is_link()) {
            // patch guest probes of the previous function
            patch_guest_probes();
            VLOG(2) << LOG_PREFIX "writing probes for function @ "
                    << OUT_HEX(probe.function()->address());
            continue;
        }

        VLOG(3) << LOG_PREFIX "patching probe @ "
                << OUT_HEX(probe.basic_block()->address()) << " type "
                << to_string(probe.kind());

        if (probe.is_attr_set(SBProbeAttr::kHostProbe)) {
            patch_host_probe(probe);
        } else {
            patch_probe(probe);
        }
    }
    // patch guest probes of last function
    patch_guest_probes();
}

//==============================================================================

struct ElfPatchManager::Impl {
    using PtrUnderlyingType = uint64_t;
    static constexpr PtrUnderlyingType kGuestProbePtrTag = 1UL;
    static constexpr PtrUnderlyingType kGuestProbePtrMask = ~(kGuestProbePtrTag);
    static constexpr unsigned kProbeIdxRingBufSize = X64ElfPatcher::kMaxGuestProbeCount;

    using AddrJumpTabPair = std::pair<addr_t, const JumpTable *>;
    using AddrJumpTabVec = std::vector<AddrJumpTabPair>;
    using BBIdxRingBuffer = SmallRingBuffer<BasicBlock::Idx, kProbeIdxRingBufSize>;

    Impl();

    ~Impl() = default;

    void validate_coverage_file(const FileLoader::MMapedFile &file);

    size_t probe_count() const noexcept;

    void
    report_coverage_data(const IFunction &func,
                         const SuperBlockStore &sb_store,
                         const std::vector<bool> &sb_cov_data,
                         CoverageReporterBase *reporter);

    void populate_address_to_jumptab_map(const IFunction &function);

    void add_function_probes(const IFunction &function,
                             const SuperBlockStore &sb_store);

    void add_probe(const SuperBlock &sb);

    void merge_plain_host_probes();

    void add_jumptab_probe(const SuperBlock &sb, const BasicBlock *bb);

    std::pair<SBProbeKind, const BasicBlock *>
    find_best_basic_block(const SuperBlock &sb);

    void set_probe_padding(SuperBlockProbe &probe, const IFunction &func);

    void promote_guest_probe(SuperBlockProbe &probe);

    uint8_t compute_bb_padding(const BasicBlock &bb, const IFunction &func);

    bool has_compatible_kind(SuperBlockKind kind) const noexcept;

    static bool is_ignorable(const SuperBlock &sb) noexcept;

    void reset_address_to_jumptab_map();

    auto get_jumptab_targeting_bb(const BasicBlock *bb);

    void add_link_probe(const IFunction &function, const SuperBlockStore &sb_store);

    static void set_host_probe(SuperBlockProbe &probe, unsigned resume_offset);

    // probe-host analysis functions

    void map_basic_blocks_to_probes(const IFunction &function);

    bool is_bb_mapped_to_guest_probe(unsigned int bb_idx);

    void find_hosts_for_guest_probes(const IFunction &function);

    void find_host_for_one_guest_probe(const IFunction &function,
                                       SuperBlockProbe &guest_probe);

    void update_host_probe(const HostBasicBlock &host_bb);

    HostBasicBlock
    evaluate(const IFunction &function, const BasicBlock *guest_bb,
             const BasicBlock *host_bb) noexcept;

    HostBasicBlock
    pick_best_host(const BasicBlock *guest_bb, HostBasicBlock &current,
                   HostBasicBlock &candidate);

    void handle_nohost_probe(SuperBlockProbe &probe, const SuperBlock &sb,
                             const SuperBlockStore &sb_store);

    void handle_short_call_probe(SuperBlockProbe &probe);

    SuperBlockProbe *get_probe(unsigned int bb_idx);

    void set_probe(unsigned int bb_idx, SuperBlockProbe *probe);

    static inline PtrUnderlyingType to_underlying(SuperBlockProbe *ptr)
    {
        return (PtrUnderlyingType) (ptr);
    }

    PatchManagerMode m_patch_mode;
    const ElfModule *m_module;
    size_t m_patch_code_size;
    std::vector<SuperBlockStore> m_sb_stores;
    std::vector<SuperBlockProbe> m_probes;
    std::vector<SuperBlockProbe> m_plain_probes;
    unsigned m_total_plain_probe_count;
    unsigned m_cur_func_pad_size;
    std::vector<SuperBlockProbe *> m_bb_to_probe_map;
    std::map<const BasicBlock *, uint8_t> m_host_bb_off_map;
    std::set<BasicBlock::Idx> m_replacement_bb_set;
    AddrJumpTabVec m_addr_jumptab_vec;
    std::vector<bool> m_bb_cov_data;
    X64ElfPatcher m_patcher;
};

ElfPatchManager::Impl::Impl()
    : m_patch_mode(PatchManagerMode::kLeafNode), m_module(nullptr)
{ }

void
ElfPatchManager::Impl::populate_address_to_jumptab_map(const IFunction &function)
{
    for (const auto &jumptab : function.jump_tables()) {
        if (!is_patchable_jumptab(jumptab)) {
            continue;
        }
        for (const auto &target_addr : jumptab.targets()) {
            m_addr_jumptab_vec.emplace_back(std::make_pair(target_addr, &jumptab));
        }
    }
    std::sort(m_addr_jumptab_vec.begin(), m_addr_jumptab_vec.end(),
              [](const AddrJumpTabPair &a, const AddrJumpTabPair &b) {
                  return a.first < b.first;
              });
}

void
ElfPatchManager::Impl::reset_address_to_jumptab_map()
{
    m_addr_jumptab_vec.clear();
}

auto
ElfPatchManager::Impl::get_jumptab_targeting_bb(const BasicBlock *bb)
{
    auto iter = std::lower_bound(m_addr_jumptab_vec.begin(),
                                 m_addr_jumptab_vec.end(),
                                 bb->address(),
                                 [](const AddrJumpTabPair &item, addr_t addr) {
                                     return item.first < addr;
                                 });
    return iter != m_addr_jumptab_vec.end() &&
           iter->first == bb->address() ? iter : m_addr_jumptab_vec.end();
}

bool
ElfPatchManager::Impl::has_compatible_kind(const SuperBlockKind kind) const noexcept
{
    return kind != SuperBlockKind::kNone &&
           (uint8_t) (kind) <= (uint8_t) (get_effective(m_patch_mode));
}

bool
ElfPatchManager::Impl::is_ignorable(const SuperBlock &sb) noexcept
{
    if (sb.basic_blocks().size() > 1) {
        return false;
    }
    auto *bb = sb.basic_blocks().front();
    if (bb->kind() == BasicBlockKind::kDangling) {
        DVLOG(5) << LOG_PREFIX "ignoring dangling probe @ "
                 << OUT_HEX(bb->address());
        return true;
    }
    auto &exit_inst = bb->instructions().back();
    if (!exit_inst.is_interrupt()) {
        return false;
    }
    DCHECK(!exit_inst.is_direct());
    DVLOG(5) << LOG_PREFIX "ignoring probe with interrupt @ "
             << OUT_HEX(exit_inst.address());

    return true;
}

uint8_t
ElfPatchManager::Impl::compute_bb_padding(const BasicBlock &bb,
                                          const IFunction &func)
{
    auto next_bb_it = func.basic_blocks().begin() + bb.id() + 1;
    if (next_bb_it == func.basic_blocks().end()) {
        return (uint8_t) m_cur_func_pad_size;
    }
    if (bb.instructions().back().is_call()) {
        // TODO: add option to enable call padding instrumentation
        return 0;
    }
    return next_bb_it->is_padding() ? (uint8_t) next_bb_it->byte_size() : 0;
}

void
ElfPatchManager::Impl::promote_guest_probe(SuperBlockProbe &probe)
{
    const auto &exit_inst = probe.basic_block()->instructions().back();
    if (exit_inst.is_jump()) {
        probe.m_kind = exit_inst.is_conditional() ? SBProbeKind::kShortCondJmp
                                                  : SBProbeKind::kShortJmp;
        return;
    }

    if (exit_inst.is_return()) {
        probe.m_kind = SBProbeKind::kReturn;
        return;
    }

    if (exit_inst.is_call()) {
        probe.m_kind = SBProbeKind::kShortCall;
        return;
    }
    probe.m_kind = SBProbeKind::kInnerBB;
}

void
ElfPatchManager::Impl::set_probe_padding(SuperBlockProbe &probe,
                                         const IFunction &func)
{
    probe.m_default.m_padding = compute_bb_padding(*probe.basic_block(), func);
    DVLOG_IF(probe.padding() != 0, 5)
            << LOG_PREFIX "might use bb padding @ " << std::hex
            << probe.basic_block()->end() << " size "
            << OUT_DEC((unsigned) probe.padding());
}

std::pair<SBProbeKind, const BasicBlock *>
ElfPatchManager::Impl::find_best_basic_block(const SuperBlock &sb)
{
    auto probe_bb = sb.basic_blocks().front();
    SBProbeKind probe_kind = SBProbeKind::kGuest;

    for (auto bb_ptr : sb.basic_blocks()) {
        const auto &exit_inst = bb_ptr->instructions().back();
        if (exit_inst.is_jump() && is_instrumentable(exit_inst)) {
            if (SBProbeKind::kLongCondJmp < probe_kind &&
                exit_inst.is_conditional()) {
                probe_kind = SBProbeKind::kLongCondJmp;
                probe_bb = bb_ptr;
            } else if (SBProbeKind::kLongJmp < probe_kind &&
                       !exit_inst.is_conditional()) {
                probe_kind = SBProbeKind::kLongJmp;
                probe_bb = bb_ptr;
            }
        }
        if (exit_inst.is_jump() && !is_instrumentable(exit_inst) &&
            is_instrumentable(*bb_ptr)) {
            if (SBProbeKind::kShortCondJmp < probe_kind &&
                exit_inst.is_conditional()) {
                probe_kind = SBProbeKind::kShortCondJmp;
                probe_bb = bb_ptr;
            } else if (SBProbeKind::kShortJmp < probe_kind &&
                       !exit_inst.is_conditional()) {
                probe_kind = SBProbeKind::kShortJmp;
                probe_bb = bb_ptr;
            }
        } else if (exit_inst.is_call()) {
            if (SBProbeKind::kLongCall < probe_kind &&
                is_instrumentable(exit_inst)) {
                probe_kind = SBProbeKind::kLongCall;
                probe_bb = bb_ptr;

            } else if (SBProbeKind::kShortCall < probe_kind &&
                       is_instrumentable(*bb_ptr)) {
                probe_kind = SBProbeKind::kShortCall;
                probe_bb = bb_ptr;
            }
        } else if (exit_inst.is_return()) {
            if (SBProbeKind::kReturn < probe_kind && is_instrumentable(*bb_ptr)) {
                probe_kind = SBProbeKind::kReturn;
                probe_bb = bb_ptr;
            }
        }
        if (SBProbeKind::kInnerBB < probe_kind && !exit_inst.is_branch() &&
            is_instrumentable(*bb_ptr)) {
            probe_kind = SBProbeKind::kInnerBB;
            probe_bb = bb_ptr;
        }
        if (SBProbeKind::kJumpTab < probe_kind && !m_addr_jumptab_vec.empty()) {
            auto addr_jumptab_it = get_jumptab_targeting_bb(bb_ptr);
            if (addr_jumptab_it != m_addr_jumptab_vec.end()) {
                probe_kind = SBProbeKind::kJumpTab;
                probe_bb = bb_ptr;
            }
        }
    }

    return {probe_kind, probe_bb};
}

void
ElfPatchManager::Impl::add_probe(const SuperBlock &sb)
{
    auto result_pair = find_best_basic_block(sb);
    auto probe_kind = result_pair.first;
    auto probe_bb = result_pair.second;

    if (probe_kind == SBProbeKind::kJumpTab) {
        add_jumptab_probe(sb, probe_bb);
        return;
    }
    m_probes.emplace_back(SuperBlockProbe());
    m_probes.back().m_kind = probe_kind;
    m_probes.back().m_default.m_detour_bb = probe_bb;
    m_probes.back().m_default.m_host_bb = nullptr;
    m_probes.back().m_default.m_sb_id = sb.idx();
    // check for potential overflow
    DCHECK(m_probes.back().m_default.m_sb_id == sb.idx());
}

void
ElfPatchManager::Impl::merge_plain_host_probes()
{
    DVLOG_IF(!m_plain_probes.empty(), 3) << LOG_PREFIX "merging plain probes "
                                         << OUT_DEC(m_plain_probes.size());
    m_probes.insert(m_probes.end(), m_plain_probes.begin(), m_plain_probes.end());
    m_total_plain_probe_count += m_plain_probes.size();
    m_plain_probes.clear();
}

void
ElfPatchManager::Impl::add_jumptab_probe(const SuperBlock &sb,
                                         const BasicBlock *bb)
{
    auto addr_jumptab_it = get_jumptab_targeting_bb(bb);
    DCHECK(addr_jumptab_it != m_addr_jumptab_vec.end());
    for (; addr_jumptab_it != m_addr_jumptab_vec.end() &&
           addr_jumptab_it->first == bb->address(); ++addr_jumptab_it) {

        m_probes.emplace_back(SuperBlockProbe());
        m_probes.back().m_kind = SBProbeKind::kJumpTab;
        m_probes.back().m_jumptab.m_detour_bb = bb;
        m_probes.back().m_jumptab.m_jumptab = addr_jumptab_it->second;
        m_probes.back().m_jumptab.m_sb_id = sb.idx();
        DCHECK(m_probes.back().m_jumptab.m_sb_id == sb.idx());
    }
}

void
ElfPatchManager::Impl::handle_short_call_probe(SuperBlockProbe &probe)
{

    auto &exit_inst = probe.basic_block()->instructions().back();
    if (probe.basic_block()->byte_size() - exit_inst.size() < kSBDetourByteSize &&
        !m_patcher.can_instrument_bb_at_end(probe)) {
        probe.m_kind = SBProbeKind::kNoHost;
        DVLOG(4) << LOG_PREFIX "downgraded short-call probe to nohost @ "
                 << OUT_HEX(probe.basic_block()->address());
    }
}

void
ElfPatchManager::Impl::handle_nohost_probe(SuperBlockProbe &probe,
                                           const SuperBlock &sb,
                                           const SuperBlockStore &sb_store)
{
    // try to find a replacement for tiny probe, e.g 1-byte size without padding
    probe.m_kind = SBProbeKind::kNoHost;
    // modifying this signals that tiny probe replaced successfully
    probe.m_default.m_host_bb = probe.m_default.m_detour_bb;
    for (const SuperBlock *pred_sb : sb_store.get_dominators(sb)) {
        if (pred_sb->is_virtual_root()) {
            continue;
        }
        if (get_effective(m_patch_mode) == PatchManagerMode::kLeafNode &&
            sb_store.forward_dom_graph().get_edges(*pred_sb).size() > 1) {
            // we are cool here, other successors take over
            continue;
        }

        if (get_effective(m_patch_mode) == PatchManagerMode::kAnyNode &&
            pred_sb->kind() == SuperBlockKind::kAnyNode) {
            // we are cool here, already handled
            continue;
        }
        add_probe(*pred_sb);
        auto repl_bb = m_probes.back().basic_block();
        if (m_probes.back().kind() == SBProbeKind::kGuest) {
            LOG(WARNING) << LOG_PREFIX "will not replace nohost probe @ "
                         << OUT_HEX(probe.basic_block()->address())
                         << " with guest @ " << repl_bb->address();
            m_probes.pop_back();
            continue;
        }
        auto result =
            m_replacement_bb_set.insert(m_probes.back().basic_block()->id());
        if (!result.second) {
            DVLOG(5) << LOG_PREFIX "ignoring redundant replacement @ "
                     << OUT_HEX(probe.basic_block()->address());
            DLOG_IF(m_probes.back().kind() == SBProbeKind::kJumpTab, WARNING)
                    << LOG_PREFIX "possible redundant replacement probe @ "
                    << OUT_HEX(repl_bb->address());
            m_probes.pop_back();
            continue;
        }

        VLOG(2) << LOG_PREFIX "replacing nohost probe @ "
                << OUT_HEX(probe.basic_block()->address())
                << " with @ " << repl_bb->address();

        m_probes.back().m_default.m_attr =
            m_probes.back().m_default.m_attr | SBProbeAttr::kReplacement;
        for (auto probe_it = m_probes.rbegin();
             probe_it->kind() == SBProbeKind::kJumpTab &&
             probe_it->basic_block()->address() == repl_bb->address(); ++probe_it) {
            probe_it->m_default.m_attr =
                probe_it->m_default.m_attr | SBProbeAttr::kReplacement;
        }
    }
}

void
ElfPatchManager::Impl::map_basic_blocks_to_probes(const IFunction &function)
{
    m_bb_to_probe_map.clear();
    m_bb_to_probe_map.resize(function.basic_blocks().size(), nullptr);

    for (auto rev_probe_it = m_probes.rbegin();
         !rev_probe_it->is_link(); ++rev_probe_it) {

        // multiple jumptab probes can be mapped to same bb
        DCHECK(get_probe(rev_probe_it->basic_block()->id()) == nullptr ||
               rev_probe_it->kind() == SBProbeKind::kJumpTab);
        set_probe(rev_probe_it->basic_block()->id(), &(*rev_probe_it));
    }
}

HostBasicBlock
ElfPatchManager::Impl::pick_best_host(const BasicBlock *guest_bb,
                                      HostBasicBlock &current,
                                      HostBasicBlock &candidate)
{
    static auto get_hosting_diff =
        [](const BasicBlock *guest_bb, const BasicBlock *host_bb) {
            return host_bb->address() < guest_bb->address() ?
                   guest_bb->address() - host_bb->address() :
                   host_bb->address() - guest_bb->address();
        };

    if (candidate.guest_offset() == 0 ||
        candidate.guest_offset() < current.guest_offset()) {
        return current;
    }

    if (candidate.guest_offset() > current.guest_offset()) {
        return candidate;
    }

    auto candidate_probe = get_probe(candidate.bb()->id());
    auto current_probe = get_probe(current.bb()->id());

    if (candidate_probe == nullptr && current_probe != nullptr) {
        return current;
    }

    if (candidate_probe != nullptr && current_probe == nullptr) {
        return candidate;
    }

    return get_hosting_diff(guest_bb, candidate.bb()) <
           get_hosting_diff(guest_bb, current.bb()) ? candidate : current;
}

void
ElfPatchManager::Impl::find_hosts_for_guest_probes(const IFunction &function)
{
    // find a host for guest probes. A guest probe has size (together with padding)
    // satisfying 2 <= size && size < 5

    map_basic_blocks_to_probes(function);
    m_host_bb_off_map.clear();

    for (unsigned i = 0; i < function.basic_blocks().size(); ++i) {
        if (is_bb_mapped_to_guest_probe(i)) {
            auto *guest_probe = get_probe(i);
            find_host_for_one_guest_probe(function, *guest_probe);
        }
    }
}

void
ElfPatchManager::Impl::find_host_for_one_guest_probe(const IFunction &function,
                                                     SuperBlockProbe &guest_probe)
{
    HostBasicBlock current_host;
    // search forward
    auto bb_idx = guest_probe.basic_block()->id();
    for (size_t j = bb_idx + 1; j < m_bb_to_probe_map.size(); ++j) {
        auto candidate_bb = &function.basic_blocks()[j];
        if (!short_jump_reachable(guest_probe.basic_block()->address(),
                                  candidate_bb->address() + kSBDetourByteSize)) {
            break;
        }
        if (candidate_bb->is_padding()) {
            continue;
        }
        auto candidate_host = evaluate(function, guest_probe.basic_block(),
                                       candidate_bb);
        current_host = pick_best_host(guest_probe.basic_block(), current_host,
                                      candidate_host);
    }

    // search backward
    for (int j = (int) bb_idx - 1; j >= 0; --j) {
        auto candidate_bb = &function.basic_blocks()[j];
        // check for padding reachability
        if (!short_jump_reachable(guest_probe.basic_block()->address(),
                                  candidate_bb->end() + 2 * kSBDetourByteSize)) {
            break;
        }
        if (candidate_bb->is_padding()) {
            continue;
        }
        auto candidate_host = evaluate(function, guest_probe.basic_block(),
                                       candidate_bb);

        current_host = pick_best_host(guest_probe.basic_block(), current_host,
                                      candidate_host);
    }

    if (current_host.guest_offset() == 0) {
        VLOG(3) << LOG_PREFIX "could not find host for guest probe @ "
                << OUT_HEX(guest_probe.basic_block()->address());
        guest_probe.m_kind = SBProbeKind::kNoHost;
        guest_probe.m_default.m_host_bb = nullptr;
        return;
    }

    update_host_probe(current_host);

    guest_probe.m_default.m_host_bb = current_host.bb();
    guest_probe.m_default.m_padding = current_host.guest_offset();

    auto diff = (int) (guest_probe.host()->address() -
                       guest_probe.basic_block()->address());

    DVLOG(4) << LOG_PREFIX "found host @ "
             << OUT_HEX(guest_probe.host()->address())
             << " for guest @ "
             << OUT_HEX(guest_probe.basic_block()->address())
             << " diff " << OUT_DEC(diff);
}

void
ElfPatchManager::Impl::update_host_probe(const HostBasicBlock &host_bb)
{
    if (m_host_bb_off_map.find(host_bb.bb()) == m_host_bb_off_map.end()) {
        m_host_bb_off_map[host_bb.bb()] = kSBDetourByteSize;
    } else {
        m_host_bb_off_map[host_bb.bb()] = host_bb.guest_offset();
    }

    unsigned resume_off = get_resume_offset(host_bb.bb(),
                                            m_host_bb_off_map[host_bb.bb()] +
                                            kSBDetourByteSize);

    auto host_probe = get_probe(host_bb.bb()->id());
    if (host_probe == nullptr &&
        m_host_bb_off_map[host_bb.bb()] != kSBDetourByteSize) {
        auto plain_probe_it =
            std::find_if(m_plain_probes.begin(), m_plain_probes.end(),
                         [&host_bb](const SuperBlockProbe &probe) {
                             return probe.basic_block()->address() ==
                                    host_bb.bb()->address();
                         }
            );
        DCHECK(plain_probe_it != m_plain_probes.end());
        host_probe = &(*plain_probe_it);
    }

    if (host_probe != nullptr) {
        host_probe->m_default.m_padding = host_bb.padding();
        set_host_probe(*host_probe, resume_off);
        return;
    }

    DVLOG(4) << LOG_PREFIX "add plain probe @ " << OUT_HEX(host_bb.bb()->address());
    m_plain_probes.emplace_back(SuperBlockProbe());
    auto &plain_probe = m_plain_probes.back();
    plain_probe.m_kind = SBProbeKind::kPlainHost;
    plain_probe.m_default.m_detour_bb = host_bb.bb();
    plain_probe.m_default.m_host_bb = nullptr;
    plain_probe.m_default.m_padding = host_bb.padding();
    set_host_probe(plain_probe, resume_off);
}

HostBasicBlock
ElfPatchManager::Impl::evaluate(const IFunction &function,
                                const BasicBlock *guest_bb,
                                const BasicBlock *host_bb) noexcept
{
    static auto is_rsp_adjustable = [](const BasicBlock *guest_bb,
                                       addr_t hosting_addr) {
        if (hosting_addr < guest_bb->address()) {
            return true;
        }
        auto &guest_exit_inst = guest_bb->instructions().back();
        return hosting_addr + kSBDetourByteSize - guest_exit_inst.end() <= 0x7F;
    };

    HostBasicBlock candidate(host_bb);
    auto &preds = function.cfg().backward().get_edges(*host_bb);
    if (preds.front()->is_virtual() && !host_bb->is_landing_pad()) {
        // XXX: workaround for the case of missing jump-tables
        return candidate;
    }

    candidate.m_padding = compute_bb_padding(*host_bb, function);
    if (host_bb->byte_size() + candidate.padding() < 2 * kSBDetourByteSize) {
        return candidate;
    }

    unsigned detour_offset = kSBDetourByteSize;
    if (m_host_bb_off_map.find(host_bb) != m_host_bb_off_map.end()) {
        detour_offset += m_host_bb_off_map[host_bb];
    }

    size_t avail_size;
    auto &host_exit_inst = host_bb->instructions().back();
    if (host_exit_inst.is_call()) {
        avail_size = host_bb->byte_size() - host_exit_inst.size();
    } else {
        avail_size = host_bb->byte_size() + candidate.padding();
    }

    if (avail_size < kSBDetourByteSize + detour_offset) {
        return candidate;
    }

    auto hosting_addr = host_bb->address() + detour_offset;
    if (!short_jump_reachable(guest_bb->address(), hosting_addr)) {
        return candidate;
    }
    if (!guest_bb->instructions().back().is_call() ||
        is_rsp_adjustable(guest_bb, hosting_addr)) {
        candidate.m_guest_offset = detour_offset;
    }
    return candidate;
}

bool
ElfPatchManager::Impl::is_bb_mapped_to_guest_probe(unsigned int bb_idx)
{
    return ((to_underlying(m_bb_to_probe_map[bb_idx])) & kGuestProbePtrTag) != 0;
}

SuperBlockProbe *
ElfPatchManager::Impl::get_probe(unsigned int bb_idx)
{
    return (SuperBlockProbe *)
        ((to_underlying(m_bb_to_probe_map[bb_idx])) & kGuestProbePtrMask);
}

void
ElfPatchManager::Impl::set_probe(unsigned int bb_idx, SuperBlockProbe *probe)
{
    if (probe->kind() != SBProbeKind::kGuest) {
        m_bb_to_probe_map[bb_idx] = probe;
    } else {
        m_bb_to_probe_map[bb_idx] =
            (SuperBlockProbe *) (to_underlying(probe) | kGuestProbePtrTag);
    }
}

void
ElfPatchManager::Impl::add_function_probes(const IFunction &function,
                                           const SuperBlockStore &sb_store)
{
    auto link_idx = m_probes.size();
    add_link_probe(function, sb_store);
    m_cur_func_pad_size = get_function_padding(*m_module, function);
    m_replacement_bb_set.clear();
    int guest_probe_count = 0;
    for (const auto &sb: sb_store.super_blocks()) {
        if (!has_compatible_kind(sb.kind()) || is_ignorable(sb)) {
            continue;
        }
        DCHECK(!sb.is_virtual_root());
        add_probe(sb);

        auto &probe = m_probes.back();
        set_probe_padding(probe, function);

        if (is_instrumentable_guest_probe(probe)) {
            promote_guest_probe(probe);
            DVLOG(4) << LOG_PREFIX "promoted guest probe @ "
                     << OUT_HEX(probe.basic_block()->address());
        }

        if (probe.kind() == SBProbeKind::kShortCall) {
            handle_short_call_probe(probe);
        }

        if (probe.kind() != SBProbeKind::kGuest) {
            DVLOG(4) << LOG_PREFIX "probing bb @ "
                     << OUT_HEX(probe.basic_block()->address())
                     << " type " << to_string(probe.kind())
                     << " padding " << (int) probe.padding();
            continue;
        }

        // handle guest probes
        if (is_tiny_guest_probe(probe)) {
            handle_nohost_probe(probe, sb, sb_store);
        } else {
            ++guest_probe_count;
        }
    }
    if (guest_probe_count > 0) {
        find_hosts_for_guest_probes(function);
        merge_plain_host_probes();
    }
    m_probes[link_idx].m_link.m_probe_count = m_probes.size() - link_idx - 1;
    // now compute code size estimation
    for (auto probe_it = m_probes.begin() + link_idx + 1;
         probe_it != m_probes.end(); ++probe_it) {

        if (probe_it->kind() == SBProbeKind::kNoHost) {
            // TODO: handle guest probes which are later discovered to be nohost
            continue;
        }
        if (probe_it->is_attr_set(SBProbeAttr::kHostProbe)) {
            if (probe_it->kind() != SBProbeKind::kPlainHost) {
                m_patch_code_size += kSBProbeCovInstSize;
            }
            auto offset = get_resume_offset(*probe_it);
            m_patch_code_size += estimate_host_code_size(probe_it->basic_block(),
                                                         offset);
            continue;
        }
        m_patch_code_size += m_patcher.estimate_code_size(*probe_it);
    }
}

void
ElfPatchManager::Impl::set_host_probe(SuperBlockProbe &probe, unsigned resume_offset)
{
    if (resume_offset == 0) {
        probe.m_default.m_attr = SBProbeAttr::kHostProbe;
    } else {
        probe.m_default.m_attr =
            SBProbeAttr::kHostProbe | SBProbeAttr::kLargeHost;
        probe.m_default.m_padding = resume_offset;
        DCHECK(probe.m_default.m_padding == resume_offset);
    }
}

void
ElfPatchManager::Impl::add_link_probe(const IFunction &function,
                                      const SuperBlockStore &sb_store)
{
    m_probes.emplace_back(SuperBlockProbe());
    m_probes.back().m_kind = SBProbeKind::kLink;
    m_probes.back().m_link.m_function = &function;
    m_probes.back().m_link.m_sb_store = &sb_store;
}

//==============================================================================

ElfPatchManager::ElfPatchManager() : m_impl(std::make_shared<Impl>())
{ }

void
ElfPatchManager::set_mode(PatchManagerMode mode)
{
    m_impl->m_patch_mode = mode;
}

PatchManagerMode
ElfPatchManager::mode() const noexcept
{
    return m_impl->m_patch_mode;
}

bool
ElfPatchManager::patch(sstring_view infile_path, sstring_view outfile_path)
{
    ElfExtender elf_extender(patch_code_seg_size(), patch_data_seg_size());

    LOG(INFO) << LOG_PREFIX "patching input file " << infile_path << " to "
              << outfile_path;

    if (!elf_extender.extend(infile_path, outfile_path)) {
        return false;
    }
    ::elf::elf patch_file(FileLoader::create(outfile_path, FileAccess::kRW));

    m_impl->m_patcher.patch(m_impl->m_probes, patch_file);
    return true;
}

ElfPatchManager::SBProbeVec &
ElfPatchManager::probes() const noexcept
{
    return m_impl->m_probes;
}

void
ElfPatchManager::build_probes(const ElfModule &module)
{
    if (module.probed_functions().empty()) {
        return;
    }
    DCHECK(m_impl->m_probes.empty());
    LOG(INFO) << LOG_PREFIX "started probe analysis for "
              << module.probed_functions().size() << " functions";

    m_impl->m_patch_code_size = 0;
    m_impl->m_total_plain_probe_count = 0;
    m_impl->m_module = &module;
    m_impl->m_sb_stores.reserve(module.probed_functions().size());
    m_impl->m_patcher.set_module(&module);
    for (const auto &function : module.probed_functions()) {
        m_impl->m_sb_stores.emplace_back(SuperBlockStoreBuilder::build(&function));
    }

    auto sb_store_it = m_impl->m_sb_stores.begin();
    for (const auto &function : module.probed_functions()) {
        if (supports_jumptab_patch(m_impl->m_patch_mode)) {
            m_impl->populate_address_to_jumptab_map(function);
        }
        m_impl->add_function_probes(function, *sb_store_it);
        if (supports_jumptab_patch(m_impl->m_patch_mode)) {
            m_impl->reset_address_to_jumptab_map();
        }
        ++sb_store_it;
    }
    VLOG(1) << LOG_PREFIX "required code size "
            << (double) patch_code_seg_size() / 0x400 << " kb";
    VLOG(1) << LOG_PREFIX "required data size "
            << (double) patch_data_seg_size() / 0x400 << " kb";
    LOG(INFO) << LOG_PREFIX "finished probe analysis";
}

size_t
ElfPatchManager::Impl::probe_count() const noexcept
{
    return m_probes.size() - m_module->probed_functions().size();
}

void
ElfPatchManager::Impl::validate_coverage_file(const FileLoader::MMapedFile &file)
{
    auto data_hdr_buf = (const uint8_t *) file->load(0, BCOV_DATA_MAGIC_SIZE);
    if (!bcov_has_valid_magic(data_hdr_buf)) {
        throw std::invalid_argument("invalid file magic!");
    }

    auto probe_count = bcov_read_probe_count(data_hdr_buf);

    if (probe_count != file->size() - BCOV_DATA_HDR_SIZE) {
        throw std::invalid_argument("coverage data might be corrupted!");
    }

    if (probe_count != this->probe_count()) {
        throw std::invalid_argument("coverage data does not match module!");
    }
}

void
ElfPatchManager::Impl::report_coverage_data(const IFunction &func,
                                            const SuperBlockStore &sb_store,
                                            const std::vector<bool> &sb_cov_data,
                                            CoverageReporterBase *reporter)
{
    m_bb_cov_data.resize(func.basic_blocks().size(), false);

    for (unsigned i = 0; i < sb_store.super_blocks().size(); ++i) {
        if (!sb_cov_data[i]) {
            continue;
        }

        for (const auto bb_ptr : sb_store.super_blocks()[i].basic_blocks()) {
            m_bb_cov_data[bb_ptr->id()] = true;
        }
    }

    reporter->report(func, m_bb_cov_data);
    m_bb_cov_data.clear();
}

//==============================================================================

size_t
ElfPatchManager::patch_code_seg_size() const noexcept
{
    return m_impl->m_patch_code_size + BCOV_PATCH_SEG_PAD;
}

size_t
ElfPatchManager::patch_data_seg_size() const noexcept
{
    return BCOV_DATA_HDR_SIZE + probe_count() + BCOV_PATCH_SEG_PAD;
}

size_t
ElfPatchManager::probe_count() const noexcept
{
    return m_impl->probe_count();
}

void
ElfPatchManager::report(sstring_view data_file_name,
                        CoverageReporterBase *reporter)
{
    auto bcov_file = FileLoader::create(data_file_name, FileAccess::kRO);
    m_impl->validate_coverage_file(bcov_file);
    std::vector<bool> sb_cov_data;
    auto buf = (buffer_t) bcov_file->load(0, BCOV_DATA_HDR_SIZE);
    reporter->init(bcov_read_base_address(buf),
                   m_impl->m_module->is_position_independent_code());
    buf += BCOV_DATA_HDR_SIZE;
    auto buf_end = (buffer_t) bcov_file->base() + bcov_file->size();
    auto link_it = m_impl->m_probes.begin();
    for (; link_it < m_impl->m_probes.end() && buf < buf_end;) {
        auto cur_func = link_it->function();
        auto cur_store = link_it->super_block_store();
        sb_cov_data.clear();
        sb_cov_data.resize(cur_store->super_blocks().size(), false);
        auto probe_it = link_it + 1;
        auto next_buf = buf + link_it->probe_count();
        link_it += link_it->probe_count() + 1;
        for (; !probe_it->is_link(); ++probe_it) {
            if (probe_it->kind() == SBProbeKind::kPlainHost) {
                DVLOG(4) << "cov-report: plain host @ "
                         << OUT_HEX(probe_it->basic_block()->address());
                ++buf;
                continue;
            }
            if (*buf != 0) {
                LOG_IF(*buf != 1, WARNING) << "report: coverage data corrupted";
                auto &sb = cur_store->super_blocks()[probe_it->super_block_idx()];
                update_coverage_data(*cur_store, sb, sb_cov_data);
            }
            ++buf;
        }
        DCHECK(next_buf == buf);
        m_impl->report_coverage_data(*cur_func, *cur_store, sb_cov_data, reporter);
    }
    DCHECK(link_it == m_impl->m_probes.end() && buf == buf_end);
}

void
LogCoverageReporter::report(const IFunction &function,
                            const CoverageVec &covered_basic_blocks)
{
    VLOG(1) << "cov-func @ " << OUT_HEX(function.address() + m_base_addr);
    DCHECK(function.basic_blocks().size() == covered_basic_blocks.size());
    for (unsigned i = 0; i < function.basic_blocks().size(); ++i) {
        if (!covered_basic_blocks[i]) {
            continue;
        }
        auto &bb = function.basic_blocks()[i];
        VLOG(1) << "cov-bb @ " << OUT_HEX(bb.address() + m_base_addr);
        for (const auto &inst : bb.instructions()) {
            VLOG(1) << "cov-insn @ " << OUT_HEX(inst.address() + m_base_addr);
        }
    }
}

void
LogCoverageReporter::init(addr_t mem_base_addr, bool position_independent_code)
{
    if (m_report_actual_address && position_independent_code) {
        m_base_addr = mem_base_addr;
        VLOG(1) << "cov-base set @ " << OUT_HEX(mem_base_addr);
    }
}

void
LogCoverageReporter::set_report_actual_address()
{
    m_report_actual_address = true;
}

OStreamCoverageReporter::OStreamCoverageReporter(std::ostream &os) :
    m_ostream(os), m_base_addr(0)
{
    m_ostream << std::hex;
}

void
OStreamCoverageReporter::report(const IFunction &function,
                                const CoverageVec &covered_basic_blocks)
{
    unsigned covered_bb_count = 0;
    unsigned total_bb_count = 0;
    unsigned covered_insts_count = 0;
    unsigned total_insts_count = 0;

    DCHECK(function.basic_blocks().size() == covered_basic_blocks.size());
    for (unsigned i = 0; i < function.basic_blocks().size(); ++i) {
        auto &bb = function.basic_blocks()[i];
        auto bb_inst_count = bb.is_padding() ? 0 : bb.instructions().size();
        m_ostream << std::hex << m_base_addr + bb.address() << ","
                  << std::dec << bb_inst_count;

        if (!bb.is_padding()) {
            total_insts_count += bb.instructions().size();
            ++total_bb_count;
        }

        if(bb.is_fallthrough()) {
            m_ostream << ",1";
        } else {
            m_ostream << ",0";
        }

        if (!covered_basic_blocks[i]) {
            m_ostream << ",0\n";
            continue;
        }

        DCHECK(!bb.is_padding());
        ++covered_bb_count;
        covered_insts_count += bb_inst_count;
        m_ostream << ",1\n";
    }

    m_ostream << std::setprecision(4)
              << "func:" << std::hex << function.address() << ","
              << m_base_addr + function.address() << std::dec
              << "," << (double) covered_bb_count / total_bb_count
              << "," << covered_bb_count << "," << total_bb_count
              << "," << (double) covered_insts_count / total_insts_count
              << "," << covered_insts_count << "," << total_insts_count
              << "\n";
}

void
OStreamCoverageReporter::init(addr_t mem_base_addr, bool position_independent_code)
{
    if (m_report_actual_address && position_independent_code) {
        m_base_addr = mem_base_addr;
    }
}

void
OStreamCoverageReporter::set_report_actual_address()
{
    m_report_actual_address = true;
}

} // bcov
