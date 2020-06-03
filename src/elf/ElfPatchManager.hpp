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
#include "elf/ElfModule.hpp"
#include "dump/patch.h"

#define BCOV_PATCH_SEG_PAD (1U)

namespace bcov {

class SuperBlockStore;

// minimum cost for all is a rip-relative mov instruction to update coverage data
// c6 05 1e 06 38 00 01  mov	byte ptr [rip + 0x38061e], 1
static constexpr unsigned kSBProbeCovInstSize = 7U;
static constexpr unsigned kSBDetourByteSize = 5U;

enum class SBProbeKind : uint8_t {
    kLink,          // marker for function
    kReturn,        // cost = prev inst (varies) + 1 (ret)
    kLongJmp,       // cost = 5 (long jmp) (direct + indirect)
    kLongCall,      // cost = call (varies) + 5 (uncond jmp )
    kJumpTab,       // cost = modify jump table - 5 (uncond jmp)
    kShortCall,     // cost = prev inst (varies) + call (varies)
    kShortJmp,
    kInnerBB,       // cost = varies + 5 (uncond jmp)
    kLongCondJmp,   // cost = 2 (short cond jmp) + 2 * 5 (uncond jmp)
    kShortCondJmp,
    kGuest,         // cost = host bb needs to be moved + 5 (uncond jmp)
    kNoHost,        // failed instrumentation as no host bb found
    kPlainHost,     // (partially) relocated host without coverage update
    kDummyCount
};

static constexpr auto kSBProbeKindCount = (unsigned) SBProbeKind::kDummyCount;

static inline bool operator<(SBProbeKind a, SBProbeKind b)
{
    return (uint8_t) a < (uint8_t) b;
}

static inline SBProbeKind min(SBProbeKind a, SBProbeKind b)
{
    return (SBProbeKind) (std::min((uint8_t) a, (uint8_t) b));
}

enum class SBProbeAttr : uint8_t {
    kNone = 0x0,
    kReplacement = 0x1,   // original guest is nohost, this probe is a replacement
    kHostProbe = 0x2,     // probe is host
    kLargeHost = 0x4      // probe is host with large bb or probe is guest with large host probe
};

static inline SBProbeAttr operator&(SBProbeAttr a, SBProbeAttr b)
{
    return SBProbeAttr((uint8_t) a & (uint8_t) b);
}

static inline SBProbeAttr operator|(SBProbeAttr a, SBProbeAttr b)
{
    return SBProbeAttr((uint8_t) a | (uint8_t) b);
}

static inline bool fits_detour(size_t size)
{
    return size >= kSBDetourByteSize;
}

static inline bool is_instrumentable(const BasicBlock &bb)
{
    return kSBDetourByteSize <= bb.byte_size();
}

static inline bool is_instrumentable(const MCInst &inst)
{
    return kSBDetourByteSize <= inst.size();
}

czstring to_string(SBProbeKind a);

enum class PatchManagerMode : uint8_t {
    kNone = 0x0,
    kLeafNode = 0x1,
    kAnyNode = 0x2,
    kJumpTab = 0x10
};

czstring to_string(PatchManagerMode mode);

static inline PatchManagerMode
operator|(PatchManagerMode a, PatchManagerMode b)
{
    return (PatchManagerMode) ((uint8_t) a | (uint8_t) b);
}

static inline PatchManagerMode
operator&(PatchManagerMode a, PatchManagerMode b)
{
    return (PatchManagerMode) ((uint8_t) a & (uint8_t) b);
}

static inline PatchManagerMode
get_effective(PatchManagerMode mode)
{
    return (PatchManagerMode) ((uint8_t) mode & 0x0F);
}

static inline bool
supports_jumptab_patch(PatchManagerMode mode)
{
    return (mode & PatchManagerMode::kJumpTab) == PatchManagerMode::kJumpTab;
}

//==============================================================================

class SuperBlockProbe {
    friend class ElfPatchManager;

public:
    SuperBlockProbe();

    ~SuperBlockProbe() = default;

    SBProbeKind kind() const noexcept;

    const IFunction *function() const noexcept;

    size_t probe_count() const noexcept;

    const SuperBlockStore *super_block_store() const noexcept;

    const BasicBlock *basic_block() const noexcept;

    const JumpTable *jump_table() const noexcept;

    const BasicBlock *host() const noexcept;

    bool valid() const noexcept;

    bool is_link() const noexcept;

    uint8_t padding() const noexcept;

    size_t super_block_idx() const noexcept;

    bool is_replaced() const noexcept;

    bool is_attr_set(SBProbeAttr attr) const noexcept;

private:

    struct Link {
        const IFunction *m_function;
        const SuperBlockStore *m_sb_store;
        uint32_t m_probe_count = 0;
    };

    struct Default {
        const BasicBlock *m_detour_bb;
        const BasicBlock *m_host_bb;
        uint8_t m_padding;
        SBProbeAttr m_attr;
        uint16_t m_sb_id;
    };

    struct JumpTab {
        const BasicBlock *m_detour_bb;
        const JumpTable *m_jumptab;
        uint8_t m_padding;
        SBProbeAttr m_attr;
        uint16_t m_sb_id;
    };

private:
    SBProbeKind m_kind = SBProbeKind::kLink;
    union {
        Default m_default;
        JumpTab m_jumptab;
        Link m_link;
    };
};

//==============================================================================

class CoverageReporterBase {
public:
    using CoverageVec = std::vector<bool>;

    virtual ~CoverageReporterBase() = default;

    virtual void
    report(const IFunction &function, const CoverageVec &covered_basic_blocks) = 0;

    virtual void init(addr_t mem_base_address, bool position_independent_code) = 0;
};

class LogCoverageReporter : public CoverageReporterBase {
public:
    ~LogCoverageReporter() override = default;

    void report(const IFunction &function,
                const CoverageVec &covered_basic_blocks) override;

    void init(addr_t mem_base_addr, bool position_independent_code) override;

    void set_report_actual_address();

private:
    bool m_report_actual_address = false;
    addr_t m_base_addr = 0;
};

class OStreamCoverageReporter : public CoverageReporterBase {
public:

    explicit OStreamCoverageReporter(std::ostream &os);

    ~OStreamCoverageReporter() override = default;

    void report(const IFunction &function,
                const CoverageVec &covered_basic_blocks) override;

    void init(addr_t mem_base_addr, bool position_independent_code) override;

    void set_report_actual_address();

private:
    std::ostream &m_ostream;
    bool m_report_actual_address = false;
    addr_t m_base_addr = 0;
};

//==============================================================================

class ElfPatchManager {
public:

    using SBProbeVec = std::vector<SuperBlockProbe>;

    ElfPatchManager();

    ElfPatchManager(const ElfPatchManager &other) = default;

    ElfPatchManager &operator=(const ElfPatchManager &other) = default;

    ElfPatchManager(ElfPatchManager &&other) noexcept = default;

    ElfPatchManager &operator=(ElfPatchManager &&other) noexcept = default;

    virtual ~ElfPatchManager() = default;

    void set_mode(PatchManagerMode mode);

    PatchManagerMode mode() const noexcept;

    void build_probes(const ElfModule &module);

    bool patch(sstring_view infile_path, sstring_view outfile_path);

    size_t patch_code_seg_size() const noexcept;

    size_t patch_data_seg_size() const noexcept;

    size_t probe_count() const noexcept;

    void report(sstring_view data_file_name, CoverageReporterBase *reporter);

    SBProbeVec &probes() const noexcept;

private:
    struct Impl;
    std::shared_ptr<Impl> m_impl;
};

} // bcov
