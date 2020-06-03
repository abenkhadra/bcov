/* ****************************************************************************
 * Copyright (c) 2013 Austin T. Clements. All rights reserved.
 *
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include <system_error>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include "FileLoader.hpp"

namespace bcov {

using namespace std;

class MMAPLoader : public FileLoader {
public:
    MMAPLoader(int fd, FileAccess access)
    {
        off_t end = lseek(fd, 0, SEEK_END);
        if (end == (off_t) -1)
            throw std::system_error(errno, system_category(),
                                    "finding file length");
        m_limit = (size_t) end;

        int prot = (access == FileAccess::kRO) ?
                   PROT_READ : PROT_READ | PROT_WRITE;

        m_base = mmap(nullptr, m_limit, prot, MAP_SHARED, fd, 0);
        if (m_base == MAP_FAILED)
            throw std::system_error(errno, system_category(),
                                    "mmap'ing file ");
    }

    ~MMAPLoader() override
    {
        munmap(m_base, m_limit);
    }

    const void *load(off_t offset, size_t size) override
    {
        if (offset + size > m_limit) {
            throw std::range_error("offset exceeds file size");
        }
        return (char *) (m_base) + offset;
    }

    size_t size() const noexcept override
    {
        return m_limit;
    }

    const void *base() const noexcept override
    {
        return m_base;
    }

private:
    void *m_base;
    size_t m_limit;
};

FileLoader::MMapedFile
FileLoader::create(sstring_view file_path, FileAccess mode)
{
    FileAccessor accessor;
    accessor.open(file_path, mode);
    return make_shared<MMAPLoader>(accessor.fd(), mode);
}

FileAccessor::~FileAccessor()
{
    if (m_fd >= 0) {
        ::close(m_fd);
    }
}

void FileAccessor::open(sstring_view file_path, FileAccess mode)
{
    int flags = (mode == FileAccess::kRO) ? O_RDONLY : O_RDWR;
    m_fd = ::open(file_path.data(), flags);
    if (m_fd < 0) {
        throw std::system_error(errno, system_category(),
                                "error opening file: " + to_string(file_path));
    }
}

int FileAccessor::fd()
{
    return m_fd;
}

} // bcov
