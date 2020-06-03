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

#include "libelfin/elf/elf++.hh"
#include "Common.hpp"

namespace bcov {

enum class FileAccess {
    kRO,
    kRW,
};

class FileAccessor {
public:
    FileAccessor() = default;

    ~FileAccessor();

    void open(sstring_view file_path, FileAccess mode);

    int fd();

private:
    int m_fd = -1;
};

class FileLoader : public elf::loader {
public:

    using MMapedFile = std::shared_ptr<FileLoader>;

    ~FileLoader() override = default;

    const void *load(off_t offset, size_t size) override = 0;

    virtual size_t size() const noexcept = 0;

    virtual const void *base() const noexcept = 0;

    static MMapedFile create(sstring_view file_path, FileAccess mode);
};

} // bcov
