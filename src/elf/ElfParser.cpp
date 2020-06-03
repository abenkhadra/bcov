/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include "ElfParser.hpp"
#include "easylogging/easylogging++.h"
#include <fcntl.h>

namespace elf {
enum class machine : ElfTypes::Half {
    EM_SPARC = 2,
    EM_MIPS = 8,
    EM_ARM = 40,
    EM_X86_64 = 62
};
}

namespace bcov {

static inline bool
is_executable(const elf::elf &binary)
{
    return binary.get_hdr().type == elf::et::exec;
}

static inline bool
is_shared_obj(const elf::elf &binary)
{
    return binary.get_hdr().type == elf::et::dyn;
}

static bool
is_x64_binary(const elf::elf &binary)
{
    return binary.get_hdr().machine == to_integral(elf::machine::EM_X86_64) and
           binary.get_hdr().ei_class == elf::elfclass::_64;
}

elf::elf
ElfParser::parse(sstring_view file_name)
{
    sstring file_name_str = to_string(file_name);

    int fd = open(file_name_str.c_str(), O_RDONLY);
    if (fd < 0) {
        throw std::runtime_error("could not open input elf file!");
    }

    elf::elf binary(elf::create_mmap_loader(fd));

    if (not is_x64_binary(binary)) {
        throw ElfLogicException("error: we support x86-64 binaries only!");
    }
    if (not(is_executable(binary) or is_shared_obj(binary))) {
        throw ElfLogicException(
            "error: only executables and shared libraries are supported!");
    }
    return binary;
}

ElfLogicException::ElfLogicException(const std::string &what_arg) :
    std::logic_error(what_arg)
{
}

ElfLogicException::ElfLogicException(const char *what_arg) :
    std::logic_error(what_arg)
{
}

} //bcov
