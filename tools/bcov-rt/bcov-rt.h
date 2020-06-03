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


static void bcov_init(void) __attribute__((constructor (0x1000)));

static void bcov_fini(void) __attribute__((destructor (0x1000)));
