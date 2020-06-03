/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include "PrettyPrint.hpp"
#include "easylogging/easylogging++.h"
#include <iomanip>

#define LSDA_MARGIN "   "
#define CIE_MARGIN "  "

namespace bcov {
namespace dwarf {

std::ostream &
write_cie(std::ostream &out, const CIE &cie)
{
    using namespace std;
    out << hex << setfill('0')
        << setw(8) << cie.record_offset() << " "
        << setw(16) << cie.content_length() << " "
        << setw(8) << cie.id() << " CIE\n";

    out << CIE_MARGIN << "Version: "
        << setfill(' ') << setw(16) << (unsigned) cie.version() << "\n"
        << CIE_MARGIN << "Augmentation:          "
        << cie.augmentation_str() << "\n" << dec
        << CIE_MARGIN << "Code alignment factor: "
        << cie.code_align_factor() << "\n"
        << CIE_MARGIN << "Data alignment factor: "
        << cie.data_align_factor() << "\n"
        << CIE_MARGIN << "Return address column: "
        << cie.ret_address_reg() << "\n"
        << CIE_MARGIN << "Augmentation data:     ";
    out << hex << setfill('0');
    for (auto pp = cie.augmentation_data();
         pp < cie.augmentation_data() + cie.augmentation_len(); ++pp) {
        out << hex << setw(2) << (unsigned) *pp << " ";
    }
    out << "\n\n";
    return out;
}

std::ostream &
write_fde(std::ostream &out, const FDE &fde, const DwarfPointerReader &reader,
          const CIEAugmentation &augm)
{
    using namespace std;
    addr_t pc;
    addr_t range;
    unsigned len;
    if (augm.has_code_encoding()) {
        pc = reader.read(fde.location(), augm.code_enc(), &len);
        range = reader.read(fde.range(augm), absolute(augm.code_enc()), &len);
    } else {
        pc = reader.read_address(fde.location());
        range = reader.read_address(fde.range(augm));
    }

    out << hex << setfill('0')
        << setw(8) << fde.record_offset() << " "
        << setw(16) << fde.content_length() << " "
        << setw(8) << fde.id() << " FDE cie="
        << setw(8) << fde.get_cie().record_offset() << " "
        << setw(16) << pc << ".." << setw(16) << (pc + range) << "\n";

    return out;
}

std::ostream &
write_lsda(std::ostream &out, const LSDA &lsda, const DwarfPointerReader &reader)
{
    out << LSDA_MARGIN << std::boolalpha
        << "LPStart: " << lsda.has_landing_pad_start_address()
        << ",TTable: " << lsda.has_type_table() << "\n";
    auto pp = lsda.call_site_tbl_start();
    const auto encoding = lsda.call_site_encoding();
    out << std::hex;
    while (pp < lsda.call_site_tbl_end()) {
        unsigned len;
        LSDACallSiteEntry entry(pp, encoding);
        out << LSDA_MARGIN << "---------------------------\n";
        out << LSDA_MARGIN << "St Offset: "
            << reader.read(entry.start(), absolute(encoding), &len) << "\n";
        out << LSDA_MARGIN << "Length   : "
            << reader.read(entry.range(), absolute(encoding), &len) << " \n";
        out << LSDA_MARGIN << "LP Offset: "
            << reader.read(entry.landing_pad(), absolute(encoding), &len) << " \n";
        pp = entry.next();
    }

    return out;
}

sstring
to_string(const CIE &cie)
{
    std::stringstream stream;
    write_cie(stream, cie);
    return stream.str();
}

sstring
to_string(const FDE &fde, const DwarfPointerReader &reader,
          const CIEAugmentation &augm)
{
    std::stringstream stream;
    write_fde(stream, fde, reader, augm);
    return stream.str();
}

sstring
to_string(const LSDA &lsda, const DwarfPointerReader &reader)
{
    std::stringstream stream;
    write_lsda(stream, lsda, reader);
    return stream.str();
}

} // dwarf
} // bcov
