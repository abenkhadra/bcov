/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include "core/Common.hpp"

namespace bcov {

static inline sstring
get_base_name(sstring_view path)
{
    sstring file_path(path.data());
    return file_path.substr(file_path.find_last_of('/') + 1);
}

static inline sstring
get_directory_name(sstring_view path)
{
    sstring file_path(path.data());
    return file_path.substr(0, file_path.find_last_of('/'));
}

} // bcov 
