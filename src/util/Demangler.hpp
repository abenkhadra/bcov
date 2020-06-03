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

namespace bcov {

class Demangler {
public:

    Demangler();

    Demangler(const Demangler &other) = default;

    Demangler &operator=(const Demangler &other) = default;

    Demangler(Demangler &&other) noexcept = default;

    Demangler &operator=(Demangler &&other) noexcept = default;

    virtual ~Demangler();

    bool is_success() const noexcept;

    static bool is_unmangled_name(sstring_view name) noexcept;

    const char *demangled_name() const noexcept;

    void demangle(sstring_view func_name) noexcept;

private:
    bool m_status;
    char *m_demangled_name;

};
} // bcov
