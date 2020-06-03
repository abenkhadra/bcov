/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 * 
 * ****************************************************************************/
/**
 *  \brief
 */

#include "ProgOptions.hpp"
#include "cmdline/cmdline.hpp"
#include <fstream>

namespace bcov {

const char *ProgOptionName::kInputFile = "input";
const char *ProgOptionName::kConfigFile = "config";
const char *ProgOptionName::kDataFile = "data";
const char *ProgOptionName::kOutputFile = "output";
const char *ProgOptionName::kLogFile = "log-file";
const char *ProgOptionName::kFuncName = "function";
const char *ProgOptionName::kParameter = "parameter";
const char *ProgOptionName::kMode = "mode";
const char *ProgOptionName::kVerbosity = "verbosity";

static void
usage_error_exit(const cmdline::parser &parser, const std::string &msg,
                 ErrorCode error_code)
{
    std::cerr << "\n" << msg << "\n" << std::endl;
    std::cerr << parser.usage();
    std::exit((int) error_code);
}

static void
error_exit(const std::string &msg, ErrorCode error_code)
{
    std::cerr << msg << std::endl;
    std::exit((int) error_code);
}

static bool
file_exists(const std::string &file_name) noexcept
{
    std::ifstream file(file_name);
    return file.good();
}

static ProgramMode
parse_mode(const std::string &mode) noexcept
{
    if (mode == "patch") {
        return ProgramMode::kPatch;
    }
    if (mode == "report") {
        return ProgramMode::kReport;
    }
    if (mode == "dump") {
        return ProgramMode::kDump;
    }
    return ProgramMode::kInvalid;
}

static OperationParams
parse_dump_param(const std::string &param) noexcept
{
    if (param == "cfg") {
        return OperationParams::kDumpCFG;
    }
    if (param == "predom") {
        return OperationParams::kDumpPreDom;
    }

    if (param == "postdom") {
        return OperationParams::kDumpPostDom;
    }

    if (param == "sbdom") {
        return OperationParams::kDumpSBDom;
    }

    return OperationParams::kInvalid;
}

static inline bool is_dump_params(OperationParams params)
{
    return ((unsigned) params & 0x3) == 0;
}

static OperationParams
parse_params(ProgramMode mode, const std::string &params) noexcept
{
    if (mode == ProgramMode::kPatch || mode == ProgramMode::kReport) {
        if (params == "all") {
            return OperationParams::kAllNode;
        }
        if (params == "any") {
            return OperationParams::kAnyNode;
        }
        return OperationParams::kInvalid;
    }
    sstring delimiter = ",";
    size_t pos1 = 0;
    size_t pos2 = 0;
    OperationParams res = OperationParams::kInvalid;
    std::string token;
    while ((pos2 = params.find(delimiter, pos2)) != std::string::npos) {
        token = params.substr(pos1, pos2 - pos1);
        res = res | parse_dump_param(token);
        pos1 = ++pos2;
    }

    token = params.substr(pos1, params.size() - pos1);
    res = res | parse_dump_param(token);

    return res;
}

//==============================================================================

ProgOptions::ProgOptions()
    : m_mode(ProgramMode::kPatch), m_params(OperationParams::kAllNode),
      m_verbosity(0)
{ }

ProgOptions
ProgOptions::parse(int argc, const char **argv)
{
    cmdline::parser cmd_parser;
    cmd_parser.add<std::string>(ProgOptionName::kMode, 'm',
                                "operation mode [patch|report|dump]", true);

    cmd_parser.add<std::string>(ProgOptionName::kParameter, 'p',
                                "operation mode parameter", false);

    cmd_parser.add<std::string>(ProgOptionName::kInputFile, 'i',
                                "input elf file", true);

    cmd_parser.add<std::string>(ProgOptionName::kConfigFile, 'c',
                                "configuration file", false);

    cmd_parser.add<std::string>(ProgOptionName::kOutputFile, 'o',
                                "patched output file", false);

    cmd_parser.add<std::string>(ProgOptionName::kDataFile, 'd',
                                "coverage data file", false);

    cmd_parser.add<std::string>(ProgOptionName::kLogFile, 'l',
                                "log file", false);

    cmd_parser.add<std::string>(ProgOptionName::kFuncName, 'f',
                                "selected function name", false);

    cmd_parser.add<int>(ProgOptionName::kVerbosity, 'v', "verbosity level",
                        false, 0);

    cmd_parser.add("help", 'h', "print help");
    auto parsed_ok = cmd_parser.parse(argc, argv);
    if (!parsed_ok) {
        usage_error_exit(cmd_parser, "please check provided options!",
                         ErrorCode::kBadUsage);
    }

    ProgOptions options;
    options.m_mode = parse_mode(cmd_parser.get<std::string>(ProgOptionName::kMode));
    if (options.program_mode() == ProgramMode::kInvalid) {
        usage_error_exit(cmd_parser, "invalid operation mode!",
                         ErrorCode::kBadUsage);
    }
    options.m_input_file = cmd_parser.get<std::string>(ProgOptionName::kInputFile);
    if (options.program_mode() == ProgramMode::kPatch) {
        if (cmd_parser.exist(ProgOptionName::kOutputFile)) {
            options.m_output_file =
                cmd_parser.get<std::string>(ProgOptionName::kOutputFile);
        } else {
            error_exit("please specify an output file", ErrorCode::kBadUsage);
        }
    }

    if (options.program_mode() == ProgramMode::kReport) {
        if (cmd_parser.exist(ProgOptionName::kDataFile)) {
            options.m_data_file =
                cmd_parser.get<std::string>(ProgOptionName::kDataFile);
        } else {
            error_exit("please specify a coverage data file", ErrorCode::kBadUsage);
        }
    }

    if (cmd_parser.exist(ProgOptionName::kConfigFile)) {
        options.m_config_file =
            cmd_parser.get<std::string>(ProgOptionName::kConfigFile);
    }

    if (cmd_parser.exist(ProgOptionName::kOutputFile)) {
        options.m_output_file =
            cmd_parser.get<std::string>(ProgOptionName::kOutputFile);
    }

    if (cmd_parser.exist(ProgOptionName::kLogFile)) {
        options.m_log_file =
            cmd_parser.get<std::string>(ProgOptionName::kLogFile);
    } else {
        options.m_log_file = "bcov.log";
    }

    if (cmd_parser.exist(ProgOptionName::kFuncName)) {
        options.m_function = cmd_parser.get<std::string>(ProgOptionName::kFuncName);
    }

    if (cmd_parser.exist(ProgOptionName::kVerbosity)) {
        options.m_verbosity = cmd_parser.get<int>(ProgOptionName::kVerbosity);
    }

    if (cmd_parser.exist(ProgOptionName::kParameter)) {
        options.m_params =
            parse_params(options.program_mode(),
                         cmd_parser.get<std::string>(ProgOptionName::kParameter));

        if (options.operation_params() == OperationParams::kInvalid) {
            usage_error_exit(cmd_parser, "invalid parameters!",
                             ErrorCode::kBadUsage);
        }
    }

    return options;
}

sstring_view
ProgOptions::input_file() const noexcept
{
    return m_input_file;
}

sstring_view
ProgOptions::output_file() const noexcept
{
    return m_output_file;
}

sstring_view
ProgOptions::log_file() const noexcept
{
    return m_log_file;
}

sstring_view
ProgOptions::data_file() const noexcept
{
    return m_data_file;
}

sstring_view
ProgOptions::config_file() const noexcept
{
    return m_config_file;
}

sstring_view
ProgOptions::selected_function() const noexcept
{
    return m_function;
}

int
ProgOptions::verbosity() const noexcept
{
    return m_verbosity;
}

ProgramMode
ProgOptions::program_mode() const noexcept
{
    return m_mode;
}

OperationParams
ProgOptions::operation_params() const noexcept
{
    return m_params;
}

czstring
to_string(ProgramMode mode)
{
    switch (mode) {
    case ProgramMode::kPatch: return "patch";
    case ProgramMode::kReport: return "report";
    case ProgramMode::kDump: return "dump";
    default: return "invalid";
    }
}

std::string
to_string(OperationParams params)
{
    if (params == OperationParams::kInvalid) {
        return "invalid";
    }
    if ((params & OperationParams::kAllNode) == OperationParams::kAllNode) {
        return "all-node";
    }
    if ((params & OperationParams::kAnyNode) == OperationParams::kAnyNode) {
        return "any-node";
    }

    sstring res;
    if ((params & OperationParams::kDumpCFG) == OperationParams::kDumpCFG) {
        res += "cfg";
    }
    if ((params & OperationParams::kDumpPreDom) == OperationParams::kDumpPreDom) {
        res += res.empty() ? "predom" : "|predom";
    }
    if ((params & OperationParams::kDumpPostDom) == OperationParams::kDumpPostDom) {
        res += res.empty() ? "postdom" : "|postdom";
    }

    if ((params & OperationParams::kDumpSBDom) == OperationParams::kDumpSBDom) {
        res += res.empty() ? "sbdom" : "|sbdom";
    }

    return res.empty() ? "invalid" : res;
}
} // bcov
