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


#pragma once

#include "core/Common.hpp"
#include "Data.hpp"
#include <map>

namespace bcov {
namespace dwarf {

using Addr64 = uint64_t;
using Addr32 = uint32_t;

class EHRecord {
public:

    EHRecord();

    explicit EHRecord(buffer_t buffer, size_t offset = 0);

    EHRecord(const EHRecord &other) = default;

    EHRecord &operator=(const EHRecord &other) = default;

    EHRecord(EHRecord &&other) noexcept = default;

    EHRecord &operator=(EHRecord &&other) noexcept = default;

    virtual ~EHRecord() = default;

    size_t content_length() const noexcept;

    size_t header_length() const noexcept;

    uint32_t id() const noexcept;

    buffer_t record_start() const noexcept;

    buffer_t record_end() const noexcept;

    size_t record_length() const noexcept;

    size_t record_offset() const noexcept;

    bool is_cie() const noexcept;

    bool is_terminator() const noexcept;

    bool valid() const noexcept;

private:
    buffer_t m_data;
    size_t m_offset;
};

class CIE : public EHRecord {
public:

    CIE();

    CIE(buffer_t buffer, size_t offset);

    CIE(const CIE &other) = default;

    CIE &operator=(const CIE &other) = default;

    CIE(CIE &&other) noexcept = default;

    CIE &operator=(CIE &&other) noexcept = default;

    ~CIE() override = default;

    friend bool operator==(const CIE &a, const CIE &b)
    {
        return a.record_offset() == b.record_offset();
    }

    friend bool operator<(const CIE &a, const CIE &b)
    {
        return a.record_offset() < b.record_offset();
    }

    uint8_t version() const noexcept;

    czstring augmentation_str() const;

    uint64_t code_align_factor() const;

    int64_t data_align_factor() const;

    uint64_t ret_address_reg() const;

    uint64_t augmentation_len() const;

    buffer_t augmentation_data() const;

    bool augmentation_exists() const;

    buffer_t instructions() const;
};

class CIEAugmentation {
public:

    CIEAugmentation();

    CIEAugmentation(czstring augm_str, buffer_t augm_data);

    DwarfPointerEncoding code_enc() const noexcept;

    DwarfPointerEncoding lsda_enc() const noexcept;

    DwarfPointerEncoding personality_enc() const noexcept;

    buffer_t personality() const noexcept;

    bool has_code_encoding() const noexcept;

    bool has_lsda_encoding() const noexcept;

    bool has_personality_encoding() const noexcept;

    bool valid() const noexcept;

private:
    DwarfPointerEncodingTy m_code_enc;
    DwarfPointerEncodingTy m_lsda_enc;
    DwarfPointerEncodingTy m_personality_enc;
    buffer_t m_personality_data;
    bool m_valid;
};

class LSDA {
public:

    LSDA();

    explicit LSDA(buffer_t data);

    DwarfPointerEncoding landing_pad_start_enc() const;

    bool has_landing_pad_start_address() const noexcept;

    buffer_t landing_pad_start_address() const;

    DwarfPointerEncoding type_table_enc() const;

    bool has_type_table() const noexcept;

    buffer_t header_start() const noexcept;

    buffer_t header_end() const;

    uoffset_t type_table_offset() const;

    DwarfPointerEncoding call_site_encoding() const;

    buffer_t call_site_tbl_start() const;

    buffer_t call_site_tbl_end() const;

    bool valid() const noexcept;

private:
    buffer_t m_data;
};

/// @class LSDACallSiteEntry
/// @brief LSDA "table-based" entry
class LSDACallSiteEntry {
public:

    LSDACallSiteEntry();

    LSDACallSiteEntry(buffer_t data, DwarfPointerEncoding callsite_enc);

    buffer_t start() const noexcept;

    buffer_t next() const noexcept;

    buffer_t range() const noexcept;

    buffer_t landing_pad() const noexcept;

    bool landing_pad_exists() const noexcept;

    uoffset_t action_table_offset() const noexcept;

    DwarfPointerEncoding encoding() const noexcept;

    bool valid() const noexcept;

    bool is_terminal() const noexcept;

private:
    buffer_t m_data;
    DwarfPointerEncodingTy m_callsite_encoding;
};

class FDE : public EHRecord {
public:

    FDE();

    FDE(buffer_t buffer, size_t offset);

    FDE(const FDE &other) = default;

    FDE &operator=(const FDE &other) = default;

    FDE(FDE &&other) noexcept = default;

    FDE &operator=(FDE &&other) noexcept = default;

    ~FDE() override = default;

    friend inline bool operator==(const FDE &a, const FDE &b)
    {
        return a.record_offset() == b.record_offset();
    }

    friend inline bool operator<(const FDE &a, const FDE &b)
    {
        return a.record_offset() < b.record_offset();
    }

    CIE get_cie() const noexcept;

    buffer_t location() const;

    buffer_t range(const CIEAugmentation &augm) const;

    // assumes that augmentation exists in parent CIE
    uint64_t augmentation_len(const CIEAugmentation &augm) const;

    // assumes that augmentation exists in parent CIE
    buffer_t augmentation_data(const CIEAugmentation &augm) const;

    buffer_t instructions(const CIEAugmentation &augm) const;
};

class EhFrame {
public:

    using FDEVec = std::vector<FDE>;
    using CIEMap = std::map<CIE, FDEVec>;

    EhFrame();

    EhFrame(const EhFrame &other) = default;

    EhFrame &operator=(const EhFrame &other) = default;

    EhFrame(EhFrame &&other) noexcept = default;

    EhFrame &operator=(EhFrame &&other) noexcept = default;

    ~EhFrame() = default;

    void parse(buffer_t buffer, addr_t address, size_t size);

    const CIEMap &map() const noexcept;

    buffer_t data() const noexcept;

    addr_t virtual_address() const noexcept;

    size_t size() const noexcept;

    bool valid() const noexcept;

    CIE get_cie(uoffset_t offset) const;

    FDE get_fde(uoffset_t offset) const;

private:
    buffer_t m_data;
    addr_t m_virtual_address;
    size_t m_size;
    CIEMap m_cie_map;
};

class DwarfPointerReader {
public:

    DwarfPointerReader();

    uint64_t
    read(buffer_t buffer, DwarfPointerEncoding encoding, unsigned *len) const;

    bool usable_encoding(DwarfPointerEncoding encoding) const noexcept;

    void set_endianess(Endianness e) noexcept;

    void set_cfi_base(uint64_t section_base, buffer_t buffer_base) noexcept;

    void set_text_base(uint64_t text_base) noexcept;

    void set_function_base(uint64_t function_base) noexcept;

    void set_data_base(uint64_t data_base) noexcept;

    void set_address_size(uint8_t size) noexcept;

    void set_offset_size(uint8_t size) noexcept;

    uint8_t read_one_byte(buffer_t buffer) const;

    uint16_t read_two_bytes(buffer_t buffer) const;

    uint64_t read_four_bytes(buffer_t buffer) const;

    uint64_t read_eight_bytes(buffer_t buffer) const;

    uint64_t read_address(buffer_t buffer) const;

private:

    using AddressReader = decltype(&DwarfPointerReader::read_eight_bytes);

    // Read an offset from BUFFER and return it as an unsigned 64 bit
    // integer.  DWARF2/3 define offsets as either 4 or 8 bytes,
    // generally depending on the amount of DWARF2/3 info present.
    // This function pointer gets set by SetOffsetSize.
    AddressReader m_offset_reader;

    // Read an address from BUFFER and return it as an unsigned 64 bit
    // integer.  DWARF2/3 allow addresses to be any size from 0-255
    // bytes currently.  Internally we support 4 and 8 byte addresses,
    // and will CHECK on anything else.
    // This function pointer gets set by SetAddressSize.
    AddressReader m_address_reader;

    uint8_t m_address_size;
    uint8_t m_offset_size;
    Endianness m_endianess;
    buffer_t m_buffer_base;
    addr_t m_section_base, m_text_base, m_func_base, m_data_base;
    bool m_has_section_base, m_has_text_base, m_has_func_base, m_has_data_base;
};

class EhFrameFormatException : public std::runtime_error {
public:

    explicit EhFrameFormatException(const std::string &what_arg);

    explicit EhFrameFormatException(const char *what_arg);

    ~EhFrameFormatException() override = default;
};

} // dwarf
} // bcov
