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
#include <cstring>
#include <array>

#define X64_PHY_REG_MASK        (0xFFF0U)
#define X64_SUB_REG_MASK        (0x000FU)
#define X64_SUB_REG_FIELD_WIDTH (0x4U)

#define X64_GPR_REG_COUNT       (18U)
#define X64_AVX512_REG_COUNT    (32U)
#define X64_AVX256_REG_COUNT    (16U)
#define X64_AVX128_REG_COUNT    (X64_AVX256_REG_COUNT)
#define X64_SEGMENT_REG_COUNT   (2)

#define X64_CANONICAL_REG_COUNT (61U)
#define X64_INDEX_FACTOR        (60U) // for compact indexing of registers
#define X64_REG_BASE_TYPE       uint16_t
#define X64_DEFAULT_MEM_TARGET  0


#define X64_GPR_REG_SIZE      (8U)
#define X64_AVX512_REG_SIZE   (64U)
#define X64_AVX256_REG_SIZE   (32U)
#define X64_AVX128_REG_SIZE   (16U)
#define X64_X87_REG_SIZE      (10U)

// buffer size for core general purpose registers
#define X64_GPR_REG_CONTEXT_SIZE       (0x90U)
// buffer size for AVX-512 registers
#define X64_AVX512_REG_CONTEXT_SIZE    (0x840U)
// buffer size for AVX-256 registers
#define X64_AVX256_REG_CONTEXT_SIZE    (0x200U)

#define X64_AVX128_REG_CONTEXT_SIZE    (0x100U)

namespace bcov {
namespace x64 {

enum class MCOpndKind : uint8_t {
    kNone = 0x0,
    kMem = 0x1,
    kImm = 0x2,
    kScale = 0x3,
    kDisp = 0x5,
    kReg = 0x10,
    kBase = 0x11,
    kIndex = 0x13,
    kSegment = 0x15
};

enum class MCAccMode : uint8_t {
    kNone = 0x0,
    kRead = 0x1,
    kWrite = 0x2,
};

static inline MCAccMode operator&(MCAccMode a, MCAccMode b)
{
    return (MCAccMode) (static_cast<unsigned>(a) & static_cast<unsigned>(b));
}

static inline MCAccMode operator|(MCAccMode a, MCAccMode b)
{
    return (MCAccMode) (static_cast<unsigned>(a) | static_cast<unsigned>(b));
}

static inline void operator|=(MCAccMode &a, const MCAccMode b)
{
    a = a | b;
}

static inline bool is_read(MCAccMode a)
{
    return (a & MCAccMode::kRead) == MCAccMode::kRead;
}

static inline bool is_write(MCAccMode a)
{
    return (a & MCAccMode::kWrite) == MCAccMode::kWrite;
}

static inline bool is_read_acc(uint8_t access)
{
    return is_read((MCAccMode) access);
}

static inline bool is_write_acc(uint8_t access)
{
    return is_write((MCAccMode) access);
}

enum class X64Reg : X64_REG_BASE_TYPE {
    Invalid = 0b000000000000,
    RAX = 0b000000010000,
    RBX = 0b000000100000,
    RCX = 0b000000110000,
    RDX = 0b000001000000,
    RSI = 0b000001010000,
    RDI = 0b000001100000,
    RBP = 0b000001110000,
    RSP = 0b000010000000,
    R8 = 0b000010010000,
    R9 = 0b000010100000,
    R10 = 0b000010110000,
    R11 = 0b000011000000,
    R12 = 0b000011010000,
    R13 = 0b000011100000,
    R14 = 0b000011110000,
    R15 = 0b000100000000,
    RFLAGS = 0b000100010000,
    RIP = 0b000100100000,
    GS = 0b000100110000,
    FS = 0b000101000000,
    ZMM0 = 0b000101010000,
    ZMM1 = 0b000101100000,
    ZMM2 = 0b000101110000,
    ZMM3 = 0b000110000000,
    ZMM4 = 0b000110010000,
    ZMM5 = 0b000110100000,
    ZMM6 = 0b000110110000,
    ZMM7 = 0b000111000000,
    ZMM8 = 0b000111010000,
    ZMM9 = 0b000111100000,
    ZMM10 = 0b000111110000,
    ZMM11 = 0b001000000000,
    ZMM12 = 0b001000010000,
    ZMM13 = 0b001000100000,
    ZMM14 = 0b001000110000,
    ZMM15 = 0b001001000000,
    ZMM16 = 0b001001010000,
    ZMM17 = 0b001001100000,
    ZMM18 = 0b001001110000,
    ZMM19 = 0b001010000000,
    ZMM20 = 0b001010010000,
    ZMM21 = 0b001010100000,
    ZMM22 = 0b001010110000,
    ZMM23 = 0b001011000000,
    ZMM24 = 0b001011010000,
    ZMM25 = 0b001011100000,
    ZMM26 = 0b001011110000,
    ZMM27 = 0b001100000000,
    ZMM28 = 0b001100010000,
    ZMM29 = 0b001100100000,
    ZMM30 = 0b001100110000,
    ZMM31 = 0b001101000000,
    K0 = 0b001101010000,           // avx-512 opmask regs
    K1 = 0b001101100000,
    K2 = 0b001101110000,
    K3 = 0b001110000000,
    K4 = 0b001110010000,
    K5 = 0b001110100000,
    K6 = 0b001110110000,
    K7 = 0b001111000000,

    AL = RAX | 0x1U,            // sub-registers
    AX = RAX | 0x2U,
    AH = RAX | 0x3U,
    EAX = RAX | 0xFU,
    BL = RBX | 0x1U,
    BX = RBX | 0x2U,
    BH = RBX | 0x3U,
    EBX = RBX | 0xFU,
    CL = RCX | 0x1U,
    CX = RCX | 0x2U,
    CH = RCX | 0x3U,
    ECX = RCX | 0xFU,
    DL = RDX | 0x1U,
    DX = RDX | 0x2U,
    DH = RDX | 0x3U,
    EDX = RDX | 0xFU,
    SIL = RSI | 0x1U,
    SI = RSI | 0x2U,
    ESI = RSI | 0xFU,
    DIL = RDI | 0x1U,
    DI = RDI | 0x2U,
    EDI = RDI | 0xFU,
    BPL = RBP | 0x1U,
    BP = RBP | 0x2U,
    EBP = RBP | 0xFU,
    SPL = RSP | 0x1U,
    SP = RSP | 0x2U,
    ESP = RSP | 0xFU,
    R8B = R8 | 0x1U,
    R8W = R8 | 0x2U,
    R8D = R8 | 0xFU,
    R9B = R9 | 0x1U,
    R9W = R9 | 0x2U,
    R9D = R9 | 0xFU,
    R10B = R10 | 0x1U,
    R10W = R10 | 0x2U,
    R10D = R10 | 0xFU,
    R11B = R11 | 0x1U,
    R11W = R11 | 0x2U,
    R11D = R11 | 0xFU,
    R12B = R12 | 0x1U,
    R12W = R12 | 0x2U,
    R12D = R12 | 0xFU,
    R13B = R13 | 0x1U,
    R13W = R13 | 0x2U,
    R13D = R13 | 0xFU,
    R14B = R14 | 0x1U,
    R14W = R14 | 0x2U,
    R14D = R14 | 0xFU,
    R15B = R15 | 0x1U,
    R15W = R15 | 0x2U,
    R15D = R15 | 0xFU,
    EIP = RIP | 0xFU,
    EFLAGS = RFLAGS | 0xFU,
    XMM0 = ZMM0 | 0x1U,
    XMM1 = ZMM1 | 0x1U,
    XMM2 = ZMM2 | 0x1U,
    XMM3 = ZMM3 | 0x1U,
    XMM4 = ZMM4 | 0x1U,
    XMM5 = ZMM5 | 0x1U,
    XMM6 = ZMM6 | 0x1U,
    XMM7 = ZMM7 | 0x1U,
    XMM8 = ZMM8 | 0x1U,
    XMM9 = ZMM9 | 0x1U,
    XMM10 = ZMM10 | 0x1U,
    XMM11 = ZMM11 | 0x1U,
    XMM12 = ZMM12 | 0x1U,
    XMM13 = ZMM13 | 0x1U,
    XMM14 = ZMM14 | 0x1U,
    XMM15 = ZMM15 | 0x1U,
    YMM0 = ZMM0 | 0x2U,
    YMM1 = ZMM1 | 0x2U,
    YMM2 = ZMM2 | 0x2U,
    YMM3 = ZMM3 | 0x2U,
    YMM4 = ZMM4 | 0x2U,
    YMM5 = ZMM5 | 0x2U,
    YMM6 = ZMM6 | 0x2U,
    YMM7 = ZMM7 | 0x2U,
    YMM8 = ZMM8 | 0x2U,
    YMM9 = ZMM9 | 0x2U,
    YMM10 = ZMM10 | 0x2U,
    YMM11 = ZMM11 | 0x2U,
    YMM12 = ZMM12 | 0x2U,
    YMM13 = ZMM13 | 0x2U,
    YMM14 = ZMM14 | 0x2U,
    YMM15 = ZMM15 | 0x2U,

    DS = 0b110000000000,      // compatiblity with x86
    ES = 0b110000010000,
    SS = 0b110000100000,
    CS = 0b110000110000,
    ST0 = 0b110001000000,
    ST1 = 0b110001010000,
    ST2 = 0b110001100000,
    ST3 = 0b110001110000,
    ST4 = 0b110010000000,
    ST5 = 0b110010010000,
    ST6 = 0b110010100000,
    ST7 = 0b110010110000,
    FP_CS = 0b110011000000,
    FPCW = 0b110011010000,
    FPSW = 0b110011100000,
    FPTW = 0b110011110000,
    FP_IP = 0b110100000000,
    FP_DP = 0b110100010000,
    MM0 = ST0 | 0x1U,
    MM1 = ST1 | 0x1U,
    MM2 = ST2 | 0x1U,
    MM3 = ST3 | 0x1U,
    MM4 = ST4 | 0x1U,
    MM5 = ST5 | 0x1U,
    MM6 = ST6 | 0x1U,
    MM7 = ST7 | 0x1U,
    TR = 0b110100100000,        // some system registers
    GDTR = 0b110100110000,
    IDTR = 0b110101000000,
    LDTR = 0b110101010000,
    MXCSR = 0b110101100000,
    CR0 = 0b110101110000,       // only a subset is writable
    CR1 = 0b110110000000,
    CR2 = 0b110110010000,
    CR3 = 0b110110100000,
    CR4 = 0b110110110000,
    CR5 = 0b110111000000,
    CR6 = 0b110111010000,
    CR7 = 0b110111100000,
    CR8 = 0b110111110000,
    CR9 = 0b111000000000,
    CR10 = 0b111000010000,
    CR11 = 0b111000100000,
    CR12 = 0b111000110000,
    CR13 = 0b111001000000,
    CR14 = 0b111001010000,
    CR15 = 0b111001100000,
    DR0 = 0b111001110000,
    DR1 = 0b111010000000,
    DR2 = 0b111010010000,
    DR3 = 0b111010100000,
    DR4 = 0b111010110000,
    DR5 = 0b111011000000,
    DR6 = 0b111011010000,
    DR7 = 0b111011100000,
    DR8 = 0b111011110000,
    DR9 = 0b111100000000,
    DR10 = 0b111100010000,
    DR11 = 0b111100100000,
    DR12 = 0b111100110000,
    DR13 = 0b111101000000,
    DR14 = 0b111101010000,
    DR15 = 0b111101100000
};

static inline bool is_invalid(X64Reg reg)
{
    return reg == X64Reg::Invalid;
}

static inline bool operator<(const X64Reg a, const X64Reg b)
{
    return (X64_REG_BASE_TYPE) a < (X64_REG_BASE_TYPE) b;
}

static inline X64Reg
get_canonical(X64Reg reg)
{
    return (X64Reg) ((X64_REG_BASE_TYPE) reg & X64_PHY_REG_MASK);
}

static inline X64Reg
get_subreg_32(X64Reg reg)
{
    return (X64Reg) ((X64_REG_BASE_TYPE) get_canonical(reg) | X64_SUB_REG_MASK);
}

static inline uint8_t
get_subreg_id(X64Reg reg)
{
    return ((X64_REG_BASE_TYPE) reg & X64_SUB_REG_MASK);
}

/**
 * @brief  Returns true if register is AH, BH, CH, or DH, false otherwise.
 * @param reg
 * @return
 */
static inline bool
is_high_byte_reg(X64Reg reg)
{
    return ((X64_REG_BASE_TYPE) reg & X64_SUB_REG_MASK) == 0x3;
}

static inline X64Reg
get_canonical_reg_at(X64_REG_BASE_TYPE index)
{
    // assumes index < X64_CANONICAL_REG_COUNT
    return (X64Reg) (index << X64_SUB_REG_FIELD_WIDTH);
}

static inline X64_REG_BASE_TYPE
get_canonical_index(X64Reg reg)
{
    return ((X64_REG_BASE_TYPE) (reg)) >> X64_SUB_REG_FIELD_WIDTH;
}

static inline X64Reg
get_reg_at(X64_REG_BASE_TYPE index)
{
    return (X64Reg) (((index % X64_INDEX_FACTOR) << X64_SUB_REG_FIELD_WIDTH) |
                     (index / X64_INDEX_FACTOR));
}

static inline X64_REG_BASE_TYPE
get_index(X64Reg reg)
{
    auto offset = ((X64_REG_BASE_TYPE) reg) & X64_SUB_REG_MASK;
    if (offset == X64_SUB_REG_MASK) {
        // as far as we are concerned in x64, eax == rax
        return get_canonical_index(reg);
    }
    return get_canonical_index(reg) + (offset * X64_INDEX_FACTOR);
}

static inline bool
is_flags_reg(X64Reg reg)
{
    return reg == X64Reg::RFLAGS || reg == X64Reg::FPSW;
}

constexpr X64_REG_BASE_TYPE kLastGPRRegIdx =
    ((X64_REG_BASE_TYPE) (X64Reg::RIP)) >> X64_SUB_REG_FIELD_WIDTH;

constexpr X64_REG_BASE_TYPE kFirstAVXRegIdx =
    ((X64_REG_BASE_TYPE) (X64Reg::ZMM0)) >> X64_SUB_REG_FIELD_WIDTH;

constexpr X64_REG_BASE_TYPE kLastAVXRegIdx =
    ((X64_REG_BASE_TYPE) (X64Reg::ZMM31)) >> X64_SUB_REG_FIELD_WIDTH;

static inline bool
is_gpr_reg(X64Reg reg)
{
    auto idx = get_canonical_index(reg);
    return idx != 0 && idx <= kLastGPRRegIdx;
}

static inline bool
is_avx_reg(X64Reg reg)
{
    auto idx = get_canonical_index(reg);
    return kFirstAVXRegIdx <= idx && idx <= kLastAVXRegIdx;
}

const char *to_string(X64Reg reg) __attribute__((const));

uint8_t get_reg_size(X64Reg reg) __attribute__((const));

/// @brief converts capstone x86_reg to our reg
X64Reg get_x64_reg(uint16_t cs_reg) __attribute__((const));

/// @brief converts capstone access mode to ours
MCAccMode get_access_mode(uint8_t ac_mode) __attribute__((const));

class MCOpnd {
public:

    using ValueId = unsigned;

    MCOpnd();

    // register
    MCOpnd(MCOpndKind kind, X64Reg reg, MCAccMode mode);

    // memory
    MCOpnd(addr_t target, uint8_t size, MCAccMode mode);

    // constant
    MCOpnd(MCOpndKind kind, int64_t imm);

    MCOpnd(const MCOpnd &other) = default;

    MCOpnd &operator=(const MCOpnd &other) = default;

    MCOpnd(MCOpnd &&other) = default;

    MCOpnd &operator=(MCOpnd &&other) = default;

    ~MCOpnd() = default;

    inline ValueId value_id() const noexcept
    { return m_value_id; }

    inline void value_id(ValueId id) noexcept
    { m_value_id = id; }

    inline MCOpndKind kind() const noexcept
    { return m_kind; }

    inline MCAccMode mode() const noexcept
    { return m_mode; }

    inline X64Reg reg() const noexcept
    { return m_reg; }

    inline int64_t imm() const noexcept
    { return m_imm; }

    inline uint8_t size() const noexcept
    { return m_size; }

    inline bool valid() const noexcept
    { return m_kind != MCOpndKind::kNone; }

    inline void invalidate()
    { m_kind = MCOpndKind::kNone; }

    inline bool is_reg_type() const noexcept
    { return ((uint8_t) m_kind & 0xF0) != 0; }

    inline bool is_mem_type() const noexcept
    { return m_kind == MCOpndKind::kMem; }

    inline bool is_imm_type() const noexcept
    {
        return (uint8_t) m_kind >= 2 && !is_reg_type();
    }

    inline bool is_direct_mem() const noexcept
    {
        return is_mem_type() && m_target != X64_DEFAULT_MEM_TARGET;
    }

    // precondition: is_direct_mem
    inline addr_t target() const noexcept
    { return m_target; }

    inline bool is_mem_arg() const noexcept
    {
        return ((uint8_t) m_kind & 0x1) != 0 && !is_mem_type();
    }

    inline bool is_use() const noexcept
    {
        return (m_mode & MCAccMode::kRead) == MCAccMode::kRead;
    }

    inline bool is_def() const noexcept
    {
        return (m_mode & MCAccMode::kWrite) == MCAccMode::kWrite;
    }

private:
    MCOpndKind m_kind;
    ValueId m_value_id;
    MCAccMode m_mode;
    uint8_t m_size;
    union {
        X64Reg m_reg;
        int64_t m_imm;
        addr_t m_target;
    };
};

// user is responsible for setting unique value ids based on a data flow analysis
static inline bool operator==(const MCOpnd &a, const MCOpnd &b)
{
    if (!a.valid() || !b.valid()) {
        return false;
    }
    return a.is_imm_type() && b.is_imm_type() ?
           a.imm() == b.imm() : a.value_id() == b.value_id();
}

static inline bool operator!=(const MCOpnd &a, const MCOpnd &b)
{
    return !(a == b);
}

//==============================================================================

enum class RegisterContextType : uint8_t {
    kGPR,
    kAVX128,
    kAVX256,
    kAVX512,
    kSSE = kAVX128
};

constexpr unsigned kRegisterCount(RegisterContextType type)
{
    switch (type) {
    case RegisterContextType::kGPR : return X64_GPR_REG_COUNT;
    case RegisterContextType::kAVX128 :
    case RegisterContextType::kAVX256 :
        return X64_GPR_REG_COUNT + X64_AVX256_REG_COUNT + X64_SEGMENT_REG_COUNT;

    case RegisterContextType::kAVX512 :
        return X64_GPR_REG_COUNT + X64_AVX512_REG_COUNT + X64_SEGMENT_REG_COUNT;
    }
}

constexpr unsigned kContextSize(RegisterContextType type)
{
    switch (type) {
    case RegisterContextType::kGPR : return X64_GPR_REG_CONTEXT_SIZE;
    case RegisterContextType::kAVX128 :
        return X64_GPR_REG_CONTEXT_SIZE + X64_AVX128_REG_CONTEXT_SIZE +
               X64_SEGMENT_REG_COUNT * X64_GPR_REG_SIZE;
    case RegisterContextType::kAVX256 :
        return X64_GPR_REG_CONTEXT_SIZE + X64_AVX256_REG_CONTEXT_SIZE +
               X64_SEGMENT_REG_COUNT * X64_GPR_REG_SIZE;
    case RegisterContextType::kAVX512 :
        return X64_GPR_REG_CONTEXT_SIZE + X64_AVX512_REG_CONTEXT_SIZE +
               X64_SEGMENT_REG_COUNT * X64_GPR_REG_SIZE;
    }
}

constexpr unsigned kAVXRegSize(RegisterContextType type)
{
    switch (type) {
    case RegisterContextType::kGPR : return 0;
    case RegisterContextType::kAVX128 : return X64_AVX128_REG_SIZE;
    case RegisterContextType::kAVX256 : return X64_AVX256_REG_SIZE;
    case RegisterContextType::kAVX512 : return X64_AVX512_REG_SIZE;
    }
}

template<RegisterContextType context_type = RegisterContextType::kAVX256>
class RegisterContext {
public:

    static_assert(context_type != RegisterContextType::kAVX512,
                  "unicorn does not currently support avx-512!");

    static constexpr RegisterContextType type = context_type;

    static constexpr unsigned context_size = kContextSize(context_type);

    static constexpr unsigned register_count = kRegisterCount(context_type);

    static constexpr unsigned avx_reg_size = kAVXRegSize(context_type);

    RegisterContext();

    RegisterContext(const RegisterContext &other) = delete;

    RegisterContext &operator=(const RegisterContext &other) = delete;

    RegisterContext(RegisterContext &&other) noexcept;

    RegisterContext &operator=(RegisterContext &&other) noexcept;

    ~RegisterContext();

    uint8_t read_reg8(X64Reg reg) const noexcept;

    uint16_t read_reg16(X64Reg reg) const noexcept;

    uint32_t read_reg32(X64Reg reg) const noexcept;

    uint64_t read_reg64(X64Reg reg) const noexcept;

    void write_reg8(X64Reg reg, uint8_t value) noexcept;

    void write_reg16(X64Reg reg, uint16_t value) noexcept;

    void write_reg32(X64Reg reg, uint32_t value) noexcept;

    void write_reg64(X64Reg reg, uint64_t value) noexcept;

    buffer_t get_buffer(X64Reg reg) const noexcept;

    void write_reg(X64Reg reg, buffer_t src) noexcept;

    uint8_t **get_reg_ptrs() const noexcept;

    /**
     * @brief copies only the core general purpose registers
     * @param other register context
     */
    void copy_gpr_only(const RegisterContext &other) noexcept;

    void copy_all(const RegisterContext &other) noexcept;

protected:
    uint8_t *get_reg_data_ex(X64Reg reg) noexcept;

    uint8_t *get_data_buf() const noexcept;

private:
    uint8_t *m_context;
};

template<RegisterContextType context_type>
uint8_t *RegisterContext<context_type>::get_data_buf() const noexcept
{
    return m_context + register_count * sizeof(uint8_t *);
}

template<RegisterContextType context_type>
RegisterContext<context_type>::RegisterContext() : m_context(nullptr)
{
    auto reg_ptrs_buf_size = register_count * sizeof(uint8_t *);
    m_context = (uint8_t *) malloc(reg_ptrs_buf_size + context_size);
    auto reg_ptrs = reinterpret_cast<uint8_t **>(m_context);
    uint8_t *cur_reg_buf = m_context + reg_ptrs_buf_size;
    for (uint16_t i = 1; i <= register_count; ++i) {
        reg_ptrs[i - 1] = cur_reg_buf;
        if (is_avx_reg(get_canonical_reg_at(i))) {
            cur_reg_buf += avx_reg_size;
        } else {
            cur_reg_buf += X64_GPR_REG_SIZE;
        }
    }
}

template<RegisterContextType context_type>
RegisterContext<context_type>::~RegisterContext()
{
    if (m_context != nullptr)
        free(m_context);
}

template<RegisterContextType context_type>
RegisterContext<context_type>::RegisterContext(RegisterContext &&other) noexcept
{
    m_context = other.m_context;
    other.m_context = nullptr;
}

template<RegisterContextType context_type>
uint8_t **RegisterContext<context_type>::get_reg_ptrs() const noexcept
{
    return reinterpret_cast<uint8_t **>(m_context);
}

template<RegisterContextType context_type>
RegisterContext<context_type> &
RegisterContext<context_type>::operator=(RegisterContext &&other) noexcept
{
    this->m_context = other.m_context;
    other.m_context = nullptr;
    return *this;
}

template<RegisterContextType context_type>
uint8_t
RegisterContext<context_type>::read_reg8(X64Reg reg) const noexcept
{
    if (is_high_byte_reg(reg)) {
        return *(get_buffer(reg) + 1);
    } else {
        return *(get_buffer(reg));
    }
}

template<RegisterContextType context_type>
uint16_t
RegisterContext<context_type>::read_reg16(X64Reg reg) const noexcept
{
    return *(reinterpret_cast<const uint16_t *>(get_buffer(reg)));
}

template<RegisterContextType context_type>
uint32_t
RegisterContext<context_type>::read_reg32(X64Reg reg) const noexcept
{
    return *(reinterpret_cast<const uint32_t *>(get_buffer(reg)));
}

template<RegisterContextType context_type>
uint64_t
RegisterContext<context_type>::read_reg64(X64Reg reg) const noexcept
{
    return *(reinterpret_cast<const uint64_t *>(get_buffer(reg)));
}

template<RegisterContextType context_type>
void
RegisterContext<context_type>::write_reg8(X64Reg reg, uint8_t value) noexcept
{
    if (is_high_byte_reg(reg)) {
        *(get_reg_data_ex(reg) + 1) = value;
    } else {
        *(get_reg_data_ex(reg)) = value;
    }
}

template<RegisterContextType context_type>
void
RegisterContext<context_type>::write_reg16(X64Reg reg, uint16_t value) noexcept
{
    *(reinterpret_cast<uint16_t *>(get_reg_data_ex(reg))) = value;
}

template<RegisterContextType context_type>
void
RegisterContext<context_type>::write_reg32(X64Reg reg, uint32_t value) noexcept
{
    // write to 32-bit registers is zero extended in x64
    *(reinterpret_cast<uint64_t *>(get_reg_data_ex(reg))) = value;
}

template<RegisterContextType context_type>
void
RegisterContext<context_type>::write_reg64(X64Reg reg, uint64_t value) noexcept
{
    *(reinterpret_cast<uint64_t *>(get_reg_data_ex(reg))) = value;
}

template<RegisterContextType context_type>
void
RegisterContext<context_type>::write_reg(X64Reg reg, buffer_t src) noexcept
{
    std::memcpy(get_reg_data_ex(reg), src, get_reg_size(reg));
}

template<RegisterContextType context_type>
void
RegisterContext<context_type>::copy_gpr_only(const RegisterContext &other) noexcept
{
    std::memcpy(this->get_data_buf(), other.get_data_buf(),
                X64_GPR_REG_CONTEXT_SIZE);
}

template<RegisterContextType context_type>
void
RegisterContext<context_type>::copy_all(const RegisterContext &other) noexcept
{
    std::memcpy(this->get_data_buf(), other.get_data_buf(),
                X64_GPR_REG_CONTEXT_SIZE);
}

template<RegisterContextType context_type>
buffer_t
RegisterContext<context_type>::get_buffer(X64Reg reg) const noexcept
{
    return get_reg_ptrs()[get_canonical_index(reg) - 1];
}

template<RegisterContextType context_type>
uint8_t *
RegisterContext<context_type>::get_reg_data_ex(X64Reg reg) noexcept
{
    return get_reg_ptrs()[get_canonical_index(reg) - 1];
}

} // x64
} // bcov
