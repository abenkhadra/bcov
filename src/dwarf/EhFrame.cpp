/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/

//
// DwarfPointerReader is based on code of ByteReader. ByteReader code is part
// of "breakpad" project. ByteReader is distributed under the following license:
//
// Copyright (c) 2010 Google Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

/**
 *  \brief
 */

#include "EhFrame.hpp"
#include "LEB128.hpp"
#include "easylogging/easylogging++.h"
#include <cstring>

#define CIE_VERSION_SIZE (1)
#define EH_RECORD_ID_SIZE (4)

#define EH_FORMAT_CHECK(X, Y) if (!(X)) throw EhFrameFormatException(Y)

namespace bcov {
namespace dwarf {

static bool
skip_str(buffer_t *pp, buffer_t end)
{
    for (auto cur_p = *pp; cur_p < end; ++cur_p) {
        if (*cur_p == 0x0) {
            *pp = cur_p + 1;
            return true;
        }
    }
    return false;
}

static inline void
fde_skip_code_pointer(buffer_t *pp, const CIEAugmentation &augm)
{
    if (!augm.has_code_encoding()) {
        // TODO: breaks for 32-bit machines, cie augmentation should provide the size
        *pp += sizeof(void *);
    }
    *pp += size_of_encoded_value(augm.code_enc(), *pp);
}

static inline buffer_t
lsda_get_type_table_enc_buf(buffer_t data)
{
    // skip lpstart encoding
    DwarfPointerEncoding lpstart_enc = DwarfPointerEncodingTy(*data);
    auto pp = data + 1;
    // skip lpstart
    pp += size_of_encoded_value(lpstart_enc, pp);
    return pp;
}

EHRecord::EHRecord() : m_data(nullptr)
{

}

EHRecord::EHRecord(const uint8_t *buffer, size_t offset)
    : m_data(buffer), m_offset(offset)
{

}

size_t
EHRecord::content_length() const noexcept
{
    uint32_t len = *reinterpret_cast<const uint32_t *>(m_data);
    return (len != 0xFFFFFFFFU) ? len :
           *reinterpret_cast<const uint64_t *>(m_data + sizeof(len));
}

size_t
EHRecord::header_length() const noexcept
{
    uint32_t len = *reinterpret_cast<const uint32_t *>(m_data);
    return (len != 0xFFFFFFFF) ? 4 : 12;
}

size_t
EHRecord::record_length() const noexcept
{
    return header_length() + content_length();
}

uint32_t
EHRecord::id() const noexcept
{
    return *reinterpret_cast<const uint32_t *>(m_data + header_length());
}

buffer_t
EHRecord::record_start() const noexcept
{ return m_data; }

buffer_t
EHRecord::record_end() const noexcept
{ return record_start() + record_length(); }

bool
EHRecord::is_cie() const noexcept
{ return id() == 0; }

bool
EHRecord::is_terminator() const noexcept
{ return content_length() == 0; }

size_t
EHRecord::record_offset() const noexcept
{ return m_offset; }

bool
EHRecord::valid() const noexcept
{ return record_start() != nullptr; }

//===============================================

CIE::CIE() : EHRecord()
{}

CIE::CIE(const uint8_t *buffer, size_t offset) : EHRecord(buffer, offset)
{}

uint8_t
CIE::version() const noexcept
{
    size_t offset = header_length() + EH_RECORD_ID_SIZE;
    return *(record_start() + offset);
}

czstring
CIE::augmentation_str() const
{
    size_t offset = header_length() + EH_RECORD_ID_SIZE + CIE_VERSION_SIZE;
    return reinterpret_cast<const char *>(record_start() + offset);
}

uint64_t
CIE::code_align_factor() const
{
    auto pp = reinterpret_cast<buffer_t >(augmentation_str());
    EH_FORMAT_CHECK(skip_str(&pp, record_end()), "invalid augmentation string");
    return decodeULEB128(pp);
}

int64_t
CIE::data_align_factor() const
{
    auto pp = reinterpret_cast<buffer_t >(augmentation_str());
    EH_FORMAT_CHECK(skip_str(&pp, record_end()),
                    "cie: invalid augmentation string!");
    EH_FORMAT_CHECK(skip_leb128(&pp, record_end()),
                    "cie: invalid code align factor!");
    return decodeSLEB128(pp);
}

uint64_t
CIE::ret_address_reg() const
{
    auto pp = reinterpret_cast<buffer_t >(augmentation_str());
    EH_FORMAT_CHECK(skip_str(&pp, record_end()),
                    "cie: invalid augmentation string!");
    EH_FORMAT_CHECK(skip_leb128(&pp, record_end()),
                    "cie: invalid code align factor!");
    EH_FORMAT_CHECK(skip_leb128(&pp, record_end()),
                    "cie: invalid data align factor!");
    return (version() == 1) ? *(pp) : decodeULEB128(pp);
}

uint64_t
CIE::augmentation_len() const
{

    if (!augmentation_exists()) {
        return 0;
    }
    auto pp = reinterpret_cast<buffer_t >(augmentation_str());
    EH_FORMAT_CHECK(skip_str(&pp, record_end()),
                    "cie: invalid augmentation string!");
    EH_FORMAT_CHECK(skip_leb128(&pp, record_end()),
                    "cie: invalid code align factor!");
    EH_FORMAT_CHECK(skip_leb128(&pp, record_end()),
                    "cie: invalid data align factor!");
    if (version() == 1) {
        pp++;
    } else {
        EH_FORMAT_CHECK(skip_leb128(&pp, record_end()),
                        "cie: invalid return address!");
    }
    return decodeULEB128(pp);
}

buffer_t
CIE::augmentation_data() const
{
    if (!augmentation_exists()) {
        return nullptr;
    }
    auto pp = reinterpret_cast<buffer_t >(augmentation_str());
    EH_FORMAT_CHECK(skip_str(&pp, record_end()),
                    "cie: invalid augmentation string!");
    EH_FORMAT_CHECK(skip_leb128(&pp, record_end()),
                    "cie: invalid code align factor!");
    EH_FORMAT_CHECK(skip_leb128(&pp, record_end()),
                    "cie: invalid data align factor!");
    if (version() == 1) {
        pp++;
    } else {
        EH_FORMAT_CHECK(skip_leb128(&pp, record_end()),
                        "cie: invalid return address");
    }
    EH_FORMAT_CHECK(skip_leb128(&pp, record_end()),
                    "cie: invalid augmentation length");
    return pp;
}

bool
CIE::augmentation_exists() const
{
    return augmentation_str()[0] == 'z';
}

buffer_t
CIE::instructions() const
{
    if (augmentation_exists()) {
        return augmentation_data() + augmentation_len();
    }
    auto pp = reinterpret_cast<buffer_t >(augmentation_str());
    EH_FORMAT_CHECK(skip_str(&pp, record_end()), "cie: invalid augmentation string");
    EH_FORMAT_CHECK(skip_leb128(&pp, record_end()),
                    "cie: invalid code align factor");
    EH_FORMAT_CHECK(skip_leb128(&pp, record_end()),
                    "cie: invalid data align factor");
    if (version() == 1) {
        pp++;
    } else {
        EH_FORMAT_CHECK(skip_leb128(&pp, record_end()),
                        "cie: invalid return address");
    }
    return pp;
}

//===============================================

FDE::FDE() : EHRecord()
{

}

FDE::FDE(buffer_t buffer, size_t offset) : EHRecord(buffer, offset)
{

}

CIE
FDE::get_cie() const noexcept
{
    if (is_cie()) {
        // this should not happen, return invalid cie
        return CIE();
    }
    return CIE(record_start() + header_length() - id(),
               record_offset() + header_length() - id());
}

buffer_t
FDE::location() const
{
    return record_start() + header_length() + EH_RECORD_ID_SIZE;
}

buffer_t
FDE::range(const CIEAugmentation &augm) const
{
    auto pp = location();
    fde_skip_code_pointer(&pp, augm);
    return pp;
}

uint64_t
FDE::augmentation_len(const CIEAugmentation &augm) const
{
    CHECK(augm.valid());
    auto pp = range(augm);
    // skip function range
    fde_skip_code_pointer(&pp, augm);
    return decodeULEB128(pp);
}

buffer_t
FDE::augmentation_data(const CIEAugmentation &augm) const
{
    CHECK(augm.valid());
    auto pp = range(augm);
    // skip function range
    fde_skip_code_pointer(&pp, augm);
    // skip augmentation length
    EH_FORMAT_CHECK(skip_leb128(&pp, record_end()), "fde: invalid augmentation");
    return pp;
}

buffer_t
FDE::instructions(const CIEAugmentation &augm) const
{
    if (augm.valid()) {
        return augmentation_data(augm) + augmentation_len(augm);
    }
    auto pp = range(augm);
    fde_skip_code_pointer(&pp, augm);
    return pp;
}

//===============================================

CIEAugmentation::CIEAugmentation()
    : m_code_enc(DW_EH_PE_omit), m_lsda_enc(DW_EH_PE_omit),
      m_personality_enc(DW_EH_PE_omit), m_personality_data(nullptr)
{}

CIEAugmentation::CIEAugmentation(czstring augm_str, buffer_t augm_data)
    : m_code_enc(DW_EH_PE_omit), m_lsda_enc(DW_EH_PE_omit),
      m_personality_enc(DW_EH_PE_omit), m_personality_data(nullptr), m_valid(false)
{
    if (*augm_str != 'z') {
        return;
    }
    const char *cc = augm_str;
    buffer_t pp = augm_data;

    while (*cc != 0x0) {
        switch (*cc) {
        case 'P': m_personality_enc = *pp;
            pp++;
            m_personality_data = pp;
            pp += size_of_encoded_value(m_personality_enc, pp);
            break;
        case 'R': m_code_enc = *pp;
            pp++;
            break;
        case 'L': m_lsda_enc = *pp;
            pp++;
            break;
        default:break;
        }
        cc++;
    }
    m_valid = true;
}

bool
CIEAugmentation::valid() const noexcept
{ return m_valid; }

bool
CIEAugmentation::has_code_encoding() const noexcept
{ return m_code_enc != DW_EH_PE_omit; }

bool
CIEAugmentation::has_lsda_encoding() const noexcept
{ return m_lsda_enc != DW_EH_PE_omit; }

bool
CIEAugmentation::has_personality_encoding() const noexcept
{ return m_personality_enc != DW_EH_PE_omit; }

DwarfPointerEncoding
CIEAugmentation::code_enc() const noexcept
{ return m_code_enc; }

DwarfPointerEncoding
CIEAugmentation::lsda_enc() const noexcept
{ return m_lsda_enc; }

DwarfPointerEncoding
CIEAugmentation::personality_enc() const noexcept
{ return m_personality_enc; }

buffer_t
CIEAugmentation::personality() const noexcept
{ return m_personality_data; }

//===============================================

LSDA::LSDA()
    : m_data(nullptr)
{}

LSDA::LSDA(buffer_t data) : m_data(data)
{}

DwarfPointerEncoding
LSDA::landing_pad_start_enc() const
{
    return DwarfPointerEncodingTy(*m_data);
}

bool
LSDA::has_landing_pad_start_address() const noexcept
{
    return landing_pad_start_enc() != DW_EH_PE_omit;
}

buffer_t
LSDA::landing_pad_start_address() const
{
    CHECK(has_landing_pad_start_address());
    return m_data + 1;
}


DwarfPointerEncoding
LSDA::type_table_enc() const
{
    return DwarfPointerEncodingTy(*lsda_get_type_table_enc_buf(m_data));
}

bool
LSDA::has_type_table() const noexcept
{
    return type_table_enc() != DW_EH_PE_omit;
}

buffer_t
LSDA::header_start() const noexcept
{
    return m_data;
}

buffer_t
LSDA::header_end() const
{
    auto pp = lsda_get_type_table_enc_buf(m_data);
    if (DwarfPointerEncodingTy(*pp) == DW_EH_PE_omit) {
        return ++pp;
    } else {
        ++pp;
        skip_leb128(&pp);
        return pp;
    }
}

uoffset_t
LSDA::type_table_offset() const
{
    CHECK(has_type_table());
    auto pp = lsda_get_type_table_enc_buf(m_data) + 1;
    return decodeULEB128(pp);
}

buffer_t
LSDA::call_site_tbl_start() const
{
    auto pp = header_end() + 1;
    skip_leb128(&pp);
    return pp;
}

buffer_t
LSDA::call_site_tbl_end() const
{
    auto pp = header_end() + 1;
    unsigned len;
    auto call_site_tbl_size = decodeULEB128(pp, &len);
    return pp + len + call_site_tbl_size;
}

DwarfPointerEncoding
LSDA::call_site_encoding() const
{
    return DwarfPointerEncodingTy(*header_end());
}

bool
LSDA::valid() const noexcept
{
    return m_data != nullptr;
}

//==============================================================================

LSDACallSiteEntry::LSDACallSiteEntry() : m_data(nullptr)
{}

LSDACallSiteEntry::LSDACallSiteEntry(buffer_t data,
                                     DwarfPointerEncoding callsite_enc)
    : m_data(data), m_callsite_encoding(callsite_enc)
{}

buffer_t
LSDACallSiteEntry::start() const noexcept
{
    return m_data;
}

buffer_t
LSDACallSiteEntry::range() const noexcept
{
    auto pp = m_data;
    // skip start
    pp += size_of_encoded_value(m_callsite_encoding, pp);
    return pp;
}

buffer_t
LSDACallSiteEntry::landing_pad() const noexcept
{
    auto pp = range();
    // skip range
    pp += size_of_encoded_value(m_callsite_encoding, pp);
    return pp;
}

bool
LSDACallSiteEntry::landing_pad_exists() const noexcept
{
    return *(landing_pad()) != 0;
}

uoffset_t
LSDACallSiteEntry::action_table_offset() const noexcept
{
    auto pp = landing_pad();
    pp += size_of_encoded_value(m_callsite_encoding, pp);
    return decodeULEB128(pp);
}

buffer_t
LSDACallSiteEntry::next() const noexcept
{
    auto pp = landing_pad();
    // skip landing pad
    pp += size_of_encoded_value(m_callsite_encoding, pp);
    // skip action table offset
    skip_leb128(&pp);
    return pp;
}

DwarfPointerEncoding
LSDACallSiteEntry::encoding() const noexcept
{
    return m_callsite_encoding;
}

bool
LSDACallSiteEntry::valid() const noexcept
{
    return m_data != nullptr;
}

bool
LSDACallSiteEntry::is_terminal() const noexcept
{
    return *m_data == 0;
}

//==============================================================================

EhFrame::EhFrame()
    : m_data(nullptr), m_virtual_address(0), m_size(0)
{}

bool
EhFrame::valid() const noexcept
{
    return m_data != nullptr;
}

void
EhFrame::parse(buffer_t buffer, addr_t address, size_t size)
{
    m_data = buffer;
    m_virtual_address = address;
    m_size = size;
    auto pp = buffer;
    size_t offset = 0;
    do {
        EHRecord record(pp, offset);
        if (record.is_terminator()) {
            break;
        }
        if (record.is_cie()) {
            bool success;
            CIEMap::iterator last_cie_it;
            std::tie(last_cie_it, success) =
                m_cie_map.insert(std::make_pair(CIE(pp, offset), FDEVec()));
            CHECK(success);
        } else {
            FDE fde(pp, offset);
            auto cie_it = m_cie_map.find(fde.get_cie());
            EH_FORMAT_CHECK(cie_it != m_cie_map.end(),
                            "found fde with no matching cie");
            cie_it->second.push_back(fde);
        }
        pp += record.record_length();
        offset += record.record_length();
    } while (pp < buffer + size);
}

buffer_t
EhFrame::data() const noexcept
{
    return m_data;
}

addr_t
EhFrame::virtual_address() const noexcept
{
    return m_virtual_address;
}

size_t
EhFrame::size() const noexcept
{
    return m_size;
}

const EhFrame::CIEMap &
EhFrame::map() const noexcept
{
    return m_cie_map;
}

//===============================================

DwarfPointerReader::DwarfPointerReader()
    : m_address_size(sizeof(void *)), m_offset_size(m_address_size),
      m_endianess(Endianness::kLittle), m_buffer_base(nullptr), m_section_base(0),
      m_text_base(0), m_func_base(0), m_data_base(0),
      m_has_section_base(false), m_has_text_base(false),
      m_has_func_base(false), m_has_data_base(false)
{

}

bool
DwarfPointerReader::usable_encoding(DwarfPointerEncoding encoding) const noexcept
{
    switch (encoding & 0x70) {
    case DW_EH_PE_absptr: return true;
    case DW_EH_PE_pcrel: return m_has_section_base;
    case DW_EH_PE_textrel: return m_has_text_base;
    case DW_EH_PE_datarel: return m_has_data_base;
    case DW_EH_PE_funcrel: return m_has_func_base;
    default: return false;
    }
}

inline uint8_t
DwarfPointerReader::read_one_byte(buffer_t buffer) const
{
    return buffer[0];
}

inline uint16_t
DwarfPointerReader::read_two_bytes(buffer_t buffer) const
{
    const uint16_t buffer0 = buffer[0];
    const uint16_t buffer1 = buffer[1];
    if (m_endianess == Endianness::kLittle) {
        return buffer0 | buffer1 << 8;
    } else {
        return buffer1 | buffer0 << 8;
    }
}

inline uint64_t
DwarfPointerReader::read_four_bytes(buffer_t buffer) const
{
    const uint32_t buffer0 = buffer[0];
    const uint32_t buffer1 = buffer[1];
    const uint32_t buffer2 = buffer[2];
    const uint32_t buffer3 = buffer[3];
    if (m_endianess == Endianness::kLittle) {
        return buffer0 | buffer1 << 8 | buffer2 << 16 | buffer3 << 24;
    } else {
        return buffer3 | buffer2 << 8 | buffer1 << 16 | buffer0 << 24;
    }
}

inline uint64_t
DwarfPointerReader::read_eight_bytes(buffer_t buffer) const
{
    const uint64_t buffer0 = buffer[0];
    const uint64_t buffer1 = buffer[1];
    const uint64_t buffer2 = buffer[2];
    const uint64_t buffer3 = buffer[3];
    const uint64_t buffer4 = buffer[4];
    const uint64_t buffer5 = buffer[5];
    const uint64_t buffer6 = buffer[6];
    const uint64_t buffer7 = buffer[7];
    if (m_endianess == Endianness::kLittle) {
        return buffer0 | buffer1 << 8 | buffer2 << 16 | buffer3 << 24 |
               buffer4 << 32 | buffer5 << 40 | buffer6 << 48 | buffer7 << 56;
    } else {
        return buffer7 | buffer6 << 8 | buffer5 << 16 | buffer4 << 24 |
               buffer3 << 32 | buffer2 << 40 | buffer1 << 48 | buffer0 << 56;
    }
}

void
DwarfPointerReader::set_endianess(Endianness e) noexcept
{
    m_endianess = e;
}

void
DwarfPointerReader::set_cfi_base(uint64_t section_base,
                                 buffer_t buffer_base) noexcept
{
    m_section_base = section_base;
    m_buffer_base = buffer_base;
    m_has_section_base = true;
}

void
DwarfPointerReader::set_text_base(uint64_t text_base) noexcept
{
    m_text_base = text_base;
    m_has_text_base = true;
}

void
DwarfPointerReader::set_function_base(uint64_t function_base) noexcept
{
    m_func_base = function_base;
    m_has_func_base = true;
}

void
DwarfPointerReader::set_data_base(uint64_t data_base) noexcept
{
    m_data_base = data_base;
    m_has_data_base = true;
}

void
DwarfPointerReader::set_address_size(uint8_t size) noexcept
{
    CHECK(size == 4 || size == 8);
    m_address_size = size;
    if (size == 4) {
        m_address_reader = &DwarfPointerReader::read_four_bytes;
    } else {
        m_address_reader = &DwarfPointerReader::read_eight_bytes;
    }
}

void
DwarfPointerReader::set_offset_size(uint8_t size) noexcept
{
    CHECK(size == 4 || size == 8);
    m_offset_size = size;
    if (size == 4) {
        m_offset_reader = &DwarfPointerReader::read_four_bytes;
    } else {
        m_offset_reader = &DwarfPointerReader::read_eight_bytes;
    }
}

uint64_t
DwarfPointerReader::read_address(buffer_t buffer) const
{
    return (this->*m_address_reader)(buffer);
}

uint64_t
DwarfPointerReader::read(buffer_t buffer, DwarfPointerEncoding encoding,
                         unsigned *len) const
{
    // UsableEncoding doesn't approve of DW_EH_PE_omit, so we shouldn't
    // see it here.
    CHECK(encoding != DW_EH_PE_omit);

    // The Linux Standards Base 4.0 does not make this clear, but the
    // GNU tools (gcc/unwind-pe.h; readelf/dwarf.c; gdb/dwarf2-frame.c)
    // agree that aligned pointers are always absolute, machine-sized,
    // machine-signed pointers.
    if (encoding == DW_EH_PE_aligned) {
        CHECK(m_has_section_base);

        // We don't need to align BUFFER in *our* address space. Rather, we
        // need to find the next position in our buffer that would be aligned
        // when the .eh_frame section the buffer contains is loaded into the
        // program's memory. So align assuming that buffer_base_ gets loaded at
        // address section_base_, where section_base_ itself may or may not be
        // aligned.

        // First, find the offset to START from the closest prior aligned
        // address.
        uint64_t skew = m_section_base & (m_address_size - 1);
        // Now find the offset from that aligned address to buffer.
        uint64_t offset = skew + (buffer - m_buffer_base);
        // Round up to the next boundary.
        uint64_t aligned = (offset + m_address_size - 1) & -m_address_size;
        // Convert back to a pointer.
        const uint8_t *aligned_buffer = m_buffer_base + (aligned - skew);
        // Finally, store the length and actually fetch the pointer.
        *len = (unsigned) (aligned_buffer - buffer + m_address_size);
        return read_address(aligned_buffer);
    }

    // Extract the value first, ignoring whether it's a pointer or an
    // offset relative to some base.
    uint64_t offset;
    switch (encoding & 0x0f) {
    case DW_EH_PE_absptr:
        // DW_EH_PE_absptr is weird, as it is used as a meaningful value for
        // both the high and low nybble of encoding bytes. When it appears in
        // the high nybble, it means that the pointer is absolute, not an
        // offset from some base address. When it appears in the low nybble,
        // as here, it means that the pointer is stored as a normal
        // machine-sized and machine-signed address. A low nybble of
        // DW_EH_PE_absptr does not imply that the pointer is absolute; it is
        // correct for us to treat the value as an offset from a base address
        // if the upper nybble is not DW_EH_PE_absptr.
        offset = read_address(buffer);
        *len = m_address_size;
        break;

    case DW_EH_PE_uleb128:offset = decodeULEB128(buffer, len);
        break;

    case DW_EH_PE_udata2:offset = read_two_bytes(buffer);
        *len = 2;
        break;

    case DW_EH_PE_udata4:offset = read_four_bytes(buffer);
        *len = 4;
        break;

    case DW_EH_PE_udata8:offset = read_eight_bytes(buffer);
        *len = 8;
        break;

    case DW_EH_PE_sleb128:offset = decodeSLEB128(buffer, len);
        break;

    case DW_EH_PE_sdata2:offset = read_two_bytes(buffer);
        // Sign-extend from 16 bits.
        offset = (offset ^ 0x8000) - 0x8000;
        *len = 2;
        break;

    case DW_EH_PE_sdata4:offset = read_four_bytes(buffer);
        // Sign-extend from 32 bits.
        offset = (offset ^ 0x80000000ULL) - 0x80000000ULL;
        *len = 4;
        break;

    case DW_EH_PE_sdata8:
        // No need to sign-extend; this is the full width of our type.
        offset = read_eight_bytes(buffer);
        *len = 8;
        break;

    default:throw EhFrameFormatException("invalid pointer format");
    }

    // Find the appropriate base address.
    uint64_t base;
    switch (encoding & 0x70) {
    case DW_EH_PE_absptr:base = 0;
        break;

    case DW_EH_PE_pcrel:CHECK(m_has_section_base);
        base = m_section_base + (buffer - m_buffer_base);
        break;

    case DW_EH_PE_textrel:CHECK(m_has_text_base);
        base = m_text_base;
        break;

    case DW_EH_PE_datarel:CHECK(m_has_data_base);
        base = m_data_base;
        break;

    case DW_EH_PE_funcrel:CHECK(m_has_func_base);
        base = m_func_base;
        break;

    default:throw EhFrameFormatException("invalid pointer format");
    }

    uint64_t pointer = base + offset;

    // Remove inappropriate upper bits.
    if (m_address_size == 4)
        pointer = pointer & 0xffffffff;
    else CHECK(m_address_size == sizeof(uint64_t));

    return pointer;
}

//===============================================

EhFrameFormatException::EhFrameFormatException(const std::string &what_arg)
    : runtime_error(what_arg)
{

}

EhFrameFormatException::EhFrameFormatException(const char *what_arg)
    : runtime_error(what_arg)
{

}

} // dwarf
} // bcov
