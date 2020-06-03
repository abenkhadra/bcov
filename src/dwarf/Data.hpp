/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include <core/Common.hpp>

#define MAX_LEB128_SIZE (16)

namespace bcov {
namespace dwarf {

static inline bool
skip_leb128(buffer_t *pp, buffer_t end, size_t *len = nullptr)
{
    if (*pp == nullptr) {
        return false;
    }
    bool result = false;
    buffer_t st_pp = *pp;
    for (auto cur_pp = *pp; cur_pp < end; ++cur_pp) {
        if ((*cur_pp & 0x80) == 0x0) {
            *pp = cur_pp + 1;
            result = true;
            break;
        }
    }
    if (len != nullptr) {
        *len = *pp - st_pp;
    }
    return result;
}

static inline bool
skip_leb128(buffer_t *pp, size_t *len = nullptr)
{
    const uint8_t *end = *pp + MAX_LEB128_SIZE;
    return skip_leb128(pp, end, len);
}

enum class Endianness {
    kBig,
    kLittle
};

enum DwarfPointerEncoding {
    DW_EH_PE_absptr = 0x00,
    DW_EH_PE_omit = 0xff,

    DW_EH_PE_uleb128 = 0x01,
    DW_EH_PE_udata2 = 0x02,
    DW_EH_PE_udata4 = 0x03,
    DW_EH_PE_udata8 = 0x04,
    DW_EH_PE_signed = 0x08,
    DW_EH_PE_sleb128 = 0x09,
    DW_EH_PE_sdata2 = 0x0a,
    DW_EH_PE_sdata4 = 0x0b,
    DW_EH_PE_sdata8 = 0x0c,

    DW_EH_PE_pcrel = 0x10,
    DW_EH_PE_textrel = 0x20,
    DW_EH_PE_datarel = 0x30,
    DW_EH_PE_funcrel = 0x40,
    DW_EH_PE_aligned = 0x50,

    DW_EH_PE_indirect = 0x80
};

class DwarfPointerEncodingTy {
public:

    DwarfPointerEncodingTy() = default;

    ~DwarfPointerEncodingTy() = default;

    implicit DwarfPointerEncodingTy(DwarfPointerEncoding encoding)
    {
        value = (uint8_t) encoding;
    }

    implicit DwarfPointerEncodingTy(uint8_t encoding)
    {
        value = encoding;
    }

    DwarfPointerEncodingTy &operator=(DwarfPointerEncoding encoding)
    {
        value = encoding;
        return *this;
    }

    DwarfPointerEncodingTy &operator=(uint8_t encoding)
    {
        value = encoding;
        return *this;
    }

    inline friend bool operator==(DwarfPointerEncodingTy a, DwarfPointerEncoding b)
    { return a.value == b; }

    inline friend bool operator!=(DwarfPointerEncodingTy a, DwarfPointerEncoding b)
    { return !(a.value == b); }

    operator DwarfPointerEncoding() const
    { return (DwarfPointerEncoding) value; }

private:
    uint8_t value;
};

static inline bool
is_leb128(DwarfPointerEncoding encoding) noexcept
{
    return (encoding & 0x0f) == DW_EH_PE_sleb128 ||
           (encoding & 0x0f) == DW_EH_PE_uleb128;
}

static inline DwarfPointerEncoding
absolute(DwarfPointerEncoding encoding) noexcept
{
    return DwarfPointerEncodingTy(encoding & 0x0f);
}

size_t
size_of_encoded_value(DwarfPointerEncoding encoding,
                      buffer_t pp) noexcept  __attribute__ ((const));

static inline bool
is_valid_encoding(DwarfPointerEncoding encoding)
{
    if (encoding == DW_EH_PE_omit) return true;
    if (encoding == DW_EH_PE_aligned) return true;
    if ((encoding & 0x7) > DW_EH_PE_udata8)
        return false;
    return !((encoding & 0x70) > DW_EH_PE_funcrel);
}

static inline bool
is_indirect(DwarfPointerEncoding encoding)
{
    return ((encoding & 0x80) == DW_EH_PE_indirect);
}

inline uint64_t
round_to_aligned_lower(uint64_t value, uint64_t alignment = sizeof(void *)) noexcept
{
    return (value & ~(alignment - 1));
}

inline uint64_t
round_to_aligned_higher(uint64_t value, uint64_t alignment = sizeof(void *)) noexcept
{
    return round_to_aligned_lower(value + alignment - 1, alignment);
}

sstring to_string(DwarfPointerEncoding encoding);

} // dwarf
} // bcov
