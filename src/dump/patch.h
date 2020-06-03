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

#include <stdint.h>
#include <stdbool.h>

#define BCOV_DATA_HDR_SIZE      (24)
#define BCOV_DATA_MAGIC_SIZE    (8)

#ifdef __cplusplus
extern "C" {
namespace bcov {
#endif

/*
 * bcov header format.
 *  8 byte magic.
 *  8 byte base address
 *  4 byte probe count
 *  4 byte pid
 */

void bcov_write_base_address(uint8_t *begin, uint64_t address);

uint64_t bcov_read_base_address(const uint8_t *begin);

void bcov_write_probe_count(uint8_t *begin, size_t probe_count);

size_t bcov_read_probe_count(const uint8_t *begin);

void bcov_write_magic(uint8_t *begin);

bool bcov_has_valid_magic(const uint8_t *begin);

const uint8_t *bcov_get_magic_data();

void bcov_write_process_id(uint8_t *begin);

int bcov_read_process_id(const uint8_t *begin);

#ifdef __cplusplus
} // bcov
}
#endif
