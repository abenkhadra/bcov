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

#include "easylogging/easylogging++.h"

void initialize_logging(const char *log_file, unsigned short verbosity_level);

void initialize_logging(int argc, const char **argv);
