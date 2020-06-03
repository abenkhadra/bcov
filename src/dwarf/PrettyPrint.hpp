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
#include "EhFrame.hpp"

namespace bcov {
namespace dwarf {

std::ostream &
write_cie(std::ostream &out, const CIE &cie);

std::ostream &
write_fde(std::ostream &out, const FDE &fde, const DwarfPointerReader &reader,
          const CIEAugmentation &augm);

std::ostream &
write_lsda(std::ostream &out, const LSDA &lsda, const DwarfPointerReader &reader);

sstring to_string(const CIE &cie);

sstring to_string(const LSDA &lsda, const DwarfPointerReader &reader);

sstring to_string(const FDE &fde, const DwarfPointerReader &reader,
                  const CIEAugmentation &augm);

} // dwarf
} // bcov
