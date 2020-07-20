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

#include "Common.hpp"

namespace bcov {

// XXX permissions are consistent with that of unicorn, which deviates from the common
// Linux convention where, e.g., X = 1
enum class Permissions : uint8_t {
    None = 0x0,
    R = 0x1,
    W = 0x2,
    X = 0x4,
    All = 0x7
};

constexpr size_t kTaggedPermMaskSize = (sizeof(size_t) * 8 - 3);

constexpr size_t kTaggedPermMask = ((size_t) 7) << kTaggedPermMaskSize;

constexpr size_t kTaggedSizeMask = ~kTaggedPermMask;

static inline Permissions get_permissions(size_t tagged_size)
{
    return (Permissions) (tagged_size >> kTaggedPermMaskSize);
}

static inline size_t get_real_size(size_t tagged_size)
{
    return tagged_size & kTaggedSizeMask;
}

static inline size_t set_permissions(size_t size, Permissions perm)
{
    return get_real_size(size) | (((size_t) perm) << kTaggedPermMaskSize);
}

static inline size_t set_real_size(size_t tagged_size, size_t size)
{
    return (tagged_size & kTaggedPermMask) | size;
}

static inline Permissions operator&(Permissions a, Permissions b)
{
    return (Permissions) ((unsigned) a & ((unsigned) b));
}

static inline Permissions operator|(Permissions a, Permissions b)
{
    return (Permissions) ((unsigned) a | ((unsigned) b));
}

static inline bool has_read(Permissions perm)
{
    return (perm & Permissions::R) == Permissions::R;
}

static inline bool has_write(Permissions perm)
{
    return (perm & Permissions::W) == Permissions::W;
}

static inline bool has_exec(Permissions perm)
{
    return (perm & Permissions::X) == Permissions::X;
}

//==============================================================================

struct FileRegion {

    inline int64_t offset(const char *pos)
    {
        return pos - base_pos;
    }

    inline bool is_inside(const char *pos)
    {
        return base_pos <= pos && pos < (base_pos + size);
    }

    const char *base_pos = nullptr;
    size_t size = 0;
};

sstring to_string(const FileRegion &region);

//===============================================

struct MMappedFileRegion {

    using ptr_type = uint8_t *;
    using const_ptr_type = const uint8_t *;

    inline addr_t get_address(const_ptr_type pos) const
    {
        return m_base_address + (pos - m_base_pos);
    }

    inline ptr_type get_pos(addr_t address) const
    {
        return m_base_pos + (address - m_base_address);
    }

    inline int64_t offset(addr_t address) const
    {
        return address - m_base_address;
    }

    inline int64_t offset(const_ptr_type pos) const
    {
        return pos - m_base_pos;
    }

    inline bool is_inside(addr_t address) const
    {
        return m_base_address <= address && address < (m_base_address + m_size);
    }

    inline bool is_inside(const_ptr_type pos) const
    {
        return m_base_pos <= pos && pos < (m_base_pos + m_size);
    }

    inline addr_t current_address() const
    {
        return m_base_address + offset(m_cur_pos);
    }

    ptr_type current_pos() const
    {
        return m_cur_pos;
    }

    void seekp(soffset_t off)
    {
        m_cur_pos += off;
    }

    void seekp(ptr_type pos)
    {
        m_cur_pos = pos;
    }

    addr_t base_address() const
    {
        return m_base_address;
    }

    ptr_type base_pos() const
    {
        return m_base_pos;
    }

    bool valid() const noexcept
    {
        return m_base_pos != nullptr;
    }

    size_t size() const noexcept
    {
        return m_size;
    }

    void init(void *base_pos, addr_t base_addr, size_t size);

    void write(const void *buf, size_t size);

    friend sstring to_string(const MMappedFileRegion &region);

private:
    ptr_type m_base_pos = nullptr;
    ptr_type m_cur_pos;
    addr_t m_base_address;
    size_t m_size;
};

sstring to_string(const MMappedFileRegion &region);

//===============================================

class MemoryRegion {
public:
    MemoryRegion() = default;

    MemoryRegion(buffer_t pos, addr_t addr, size_t size);

    inline int64_t offset(buffer_t pos) const
    {
        return pos - m_base_pos;
    }

    inline bool is_inside(buffer_t pos) const
    {
        return m_base_pos <= pos and pos < (m_base_pos + size());
    }

    inline bool is_inside(addr_t address) const
    {
        return m_base_address <= address && address < (m_base_address + size());
    }

    inline buffer_t get_buffer(addr_t address) const
    {
        return m_base_pos + (address - m_base_address);
    }

    inline addr_t get_address(buffer_t pos) const
    {
        return m_base_address + (pos - m_base_pos);
    }

    inline buffer_t base_pos() const
    {
        return m_base_pos;
    }

    inline addr_t base_address() const
    {
        return m_base_address;
    }

    inline size_t size() const
    {
        return get_real_size(m_size);
    }

    inline Permissions permissions() const
    {
        return get_permissions(m_size);
    }

    inline bool valid() const
    {
        return m_base_pos != nullptr;
    }

    inline void base_pos(buffer_t buffer)
    {
        m_base_pos = buffer;
    }

    inline void base_address(addr_t address)
    {
        m_base_address = address;
    }

    inline void size(size_t size)
    {
        m_size = set_real_size(m_size, size);
    }

    inline void permissions(Permissions perm)
    {
        m_size = set_permissions(m_size, perm);
    }

private:
    buffer_t m_base_pos = nullptr;
    addr_t m_base_address;
    size_t m_size;
};

class MemoryArea {
public:
    MemoryArea() = default;

    inline addr_t start() const
    {
        return m_start_address;
    }

    inline addr_t end() const
    {
        return m_start_address + m_size;
    }

    inline size_t size() const
    {
        return m_size;
    }

    inline bool valid() const
    {
        return m_start_address != 0;
    }

    inline void start(addr_t address)
    {
        m_start_address = address;
    }

    inline void size(size_t size)
    {
        m_size = size;
    }

private:
    addr_t m_start_address = 0;
    size_t m_size;
};

static inline bool operator==(const MemoryRegion &a, const MemoryRegion &b)
{
    return a.base_address() == b.base_address() && a.size() == b.size();
}

static inline bool operator==(const MemoryArea &a, const MemoryArea &b)
{
    return a.start() == b.start() && a.end() == b.end();
}

sstring to_string(const MemoryRegion &region);

} // bcov

