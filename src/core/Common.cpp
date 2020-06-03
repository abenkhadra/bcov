/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include "Common.hpp"
#include <iomanip>

namespace bcov {

sstring
hex_dump(const void *a, size_t len)
{
    std::stringstream stream;
    for (unsigned i = 0; i < len; i++) {
        stream << std::setfill('0') << std::setw(2) << std::hex
               << int(*((uint8_t *) a + i)) << " ";
    }
    return stream.str();
}
} // bcov
