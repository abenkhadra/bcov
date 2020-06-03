/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include "Demangler.hpp"
#include <cstring>
#include <cxxabi.h>

#define CPP_MANGLED_NAME_PREFIX "_Z"
#define CPP_MANGLED_NAME_MAXSIZE (1024UL)

namespace bcov {

bool
Demangler::is_unmangled_name(sstring_view name) noexcept
{
    // to check whether a function name is mangled or not we need to
    // (1) check if the name is prefixed with _Z. According to
    //      Itanium C++ ABI, all mangled names should start with _Z.
    //      See http://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangling-structure
    // (2) use demangler API which would return success on mangled names.
    //      See https://itanium-cxx-abi.github.io/cxx-abi/abi.html#demangler
    //
    // here we do a quick check to see if the name is unmangled i.e. is not prefixed
    // with '_Z'
    return (std::strncmp(name.data(), CPP_MANGLED_NAME_PREFIX, 2)) != 0;
}

Demangler::Demangler() : m_status(false), m_demangled_name(nullptr)
{
    m_demangled_name = (char *) malloc(CPP_MANGLED_NAME_MAXSIZE);
}

Demangler::~Demangler()
{
    if (m_demangled_name != nullptr) {
        free(m_demangled_name);
    }
}

bool
Demangler::is_success() const noexcept
{
    return m_status;
}

const char *
Demangler::demangled_name() const noexcept
{
    return m_demangled_name;
}

void
Demangler::demangle(sstring_view func_name) noexcept
{
    int status;
    size_t size = CPP_MANGLED_NAME_MAXSIZE;
    m_demangled_name = abi::__cxa_demangle(func_name.data(), m_demangled_name, &size, &status);
    m_status = (status == 0);
}
} // bcov
