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

struct ProgOptionName {
    static const char *kInputFile;
    static const char *kConfigFile;
    static const char *kDataFile;
    static const char *kOutputFile;
    static const char *kLogFile;
    static const char *kFuncName;
    static const char *kParameter;
    static const char *kMode;
    static const char *kVerbosity;
};

enum class ErrorCode : int {
    kOk = 0,
    kGeneric = -1,
    kInputFile = -3,
    kConfigFile = -4,
    kBadUsage = -5
};

enum class ProgramMode : uint8_t {
    kInvalid,
    kPatch,
    kReport,
    kDump
};

enum class OperationParams : uint32_t {
    kInvalid = 0x00,
    kAllNode = 0x01,
    kAnyNode = 0x02,
    kDumpCFG = 0x04,
    kDumpPreDom = 0x08,
    kDumpPostDom = 0x10,
    kDumpSBDom = 0x20
};

static inline OperationParams operator&(OperationParams a, OperationParams b)
{
    return (OperationParams)((unsigned) a & (unsigned) b);
}

static inline OperationParams operator|(OperationParams a, OperationParams b)
{
    return (OperationParams)((unsigned) a | (unsigned) b);
}

czstring to_string(ProgramMode mode);

std::string to_string(OperationParams params);

class ProgOptions {
public:

    ProgOptions();

    ProgOptions(const ProgOptions &other) = default;

    ProgOptions &operator=(const ProgOptions &other) = default;

    ProgOptions(ProgOptions &&other) noexcept = default;

    ProgOptions &operator=(ProgOptions &&other) noexcept = default;

    virtual ~ProgOptions() = default;

    static ProgOptions parse(int argc, const char **argv);

    sstring_view input_file() const noexcept;

    sstring_view output_file() const noexcept;

    sstring_view log_file() const noexcept;

    sstring_view data_file() const noexcept;

    sstring_view config_file() const noexcept;

    sstring_view selected_function() const noexcept;

    ProgramMode program_mode() const noexcept;

    OperationParams operation_params() const noexcept;

    int verbosity() const noexcept;

private:
    ProgramMode  m_mode;
    OperationParams m_params;
    sstring m_config_file;
    sstring m_output_file;
    sstring m_data_file;
    sstring m_input_file;
    sstring m_function;
    sstring m_log_file;
    int m_verbosity;
};

} // bcov
