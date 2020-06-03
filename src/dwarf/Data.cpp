/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include "Data.hpp"

namespace bcov {
namespace dwarf {

sstring
to_string(DwarfPointerEncoding encoding)
{
    if (encoding == DW_EH_PE_omit) {
        return " omitted";
    }

    sstring result;
    switch (encoding & 0x70) {
    case DW_EH_PE_pcrel:   result = " rel-pc   |";   break;
    case DW_EH_PE_textrel: result = " rel-text |"; break;
    case DW_EH_PE_datarel: result = " rel-data |"; break;
    case DW_EH_PE_funcrel: result = " rel-func |"; break;
    case DW_EH_PE_aligned: result = " aligned  |"; break;
    default: break;
    }

    switch (encoding & 0x0f) {
    case DW_EH_PE_absptr  : result += " absolute";  break;
    case DW_EH_PE_uleb128 : result += " uleb128";   break;
    case DW_EH_PE_udata2  : result += " udata2";    break;
    case DW_EH_PE_udata4  : result += " udata4";    break;
    case DW_EH_PE_udata8  : result += " udata8";    break;
    case DW_EH_PE_signed  : result += " signed";    break;
    case DW_EH_PE_sleb128 : result += " sleb128";   break;
    case DW_EH_PE_sdata2  : result += " sdata2";    break;
    case DW_EH_PE_sdata4  : result += " sdata4";    break;
    case DW_EH_PE_sdata8  : result += " sdata8";    break;
    default: result = "unknown";                     break;
    }

    return ((encoding & 0x80) == DW_EH_PE_indirect)? result += " | indirect": result;
}

size_t
size_of_encoded_value(DwarfPointerEncoding encoding, buffer_t pp) noexcept
{
    {
        if (encoding == DW_EH_PE_omit) {
            return 0;
        }
        size_t len;
        switch (encoding & 0x0f) {
        case DW_EH_PE_uleb128:
        case DW_EH_PE_sleb128:skip_leb128(&pp, &len);
            return len;
        case DW_EH_PE_udata2:
        case DW_EH_PE_sdata2:return 2;
        case DW_EH_PE_udata4:
        case DW_EH_PE_sdata4:return 4;
        case DW_EH_PE_udata8:
        case DW_EH_PE_sdata8:return 8;
            // XXX: will not work for 32-bit machines
        default:return sizeof(void *);
        }
    }
}
} // dwarf
} // bcov
