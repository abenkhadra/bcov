/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include <unistd.h>
#include <string.h>
#include <assert.h>
#include "patch.h"

#ifdef __cplusplus
extern "C" {
namespace bcov {
#endif

#define BCOV_BASE_ADDR_OFFSET       (BCOV_DATA_MAGIC_SIZE)
#define BCOV_PROBE_COUNT_OFFSET     (BCOV_BASE_ADDR_OFFSET + 8)
#define BCOV_PID_OFFSET             (BCOV_PROBE_COUNT_OFFSET  + 4)

const uint8_t kBcovDataSegMagic[BCOV_DATA_MAGIC_SIZE] =
    {0x2E, 0x42, 0x43, 0x4F, 0x56, 0x55, 0x55, 0x55}; // ".BCOV***"

void
bcov_write_base_address(uint8_t *begin, uint64_t address)
{
    *((uint64_t *) (begin + BCOV_BASE_ADDR_OFFSET)) = address;
}

uint64_t
bcov_read_base_address(const uint8_t *begin)
{
    return *((const uint64_t *) (begin + BCOV_BASE_ADDR_OFFSET));
}

void
bcov_write_probe_count(uint8_t *begin, size_t probe_count)
{
    *((uint32_t *) (begin + BCOV_PROBE_COUNT_OFFSET)) = (uint32_t) probe_count;
    assert(probe_count == bcov_read_probe_count(begin));
}

size_t
bcov_read_probe_count(const uint8_t *begin)
{
    return *((const uint32_t *) (begin + BCOV_PROBE_COUNT_OFFSET));
}

void
bcov_write_magic(uint8_t *begin)
{
    memcpy(begin, kBcovDataSegMagic, BCOV_DATA_MAGIC_SIZE);
}

bool
bcov_has_valid_magic(const uint8_t *begin)
{
    return memcmp(begin, kBcovDataSegMagic, BCOV_DATA_MAGIC_SIZE) == 0;
}

const uint8_t *
bcov_get_magic_data()
{
    return kBcovDataSegMagic;
}

void
bcov_write_process_id(uint8_t *begin)
{
    int id = getpid();
    *((int32_t *) (begin + BCOV_PID_OFFSET)) = id;
}

int
bcov_read_process_id(const uint8_t *begin)
{
    return *((const int32_t *) (begin + BCOV_PID_OFFSET));
}

#ifdef __cplusplus
} // bcov
}
#endif
