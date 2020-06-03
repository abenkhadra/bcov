/* ****************************************************************************
 * Copyright (c) 2018 University of Kaiserslautern. All rights reserved.
 *
 * This file is distributed under MIT license. See LICENSE.txt for details.
 *
 * ****************************************************************************/


#include "Logging.hpp"

INITIALIZE_EASYLOGGINGPP

void initialize_logging_common()
{
    using namespace el;
    Loggers::reconfigureAllLoggers(ConfigurationType::Format, "%levshort | %msg");

    Loggers::reconfigureAllLoggers(ConfigurationType::ToStandardOutput, "false");

    Loggers::reconfigureAllLoggers(ConfigurationType::ToFile, "true");

    Configurations log_conf;
    log_conf.setToDefault();
    log_conf.set(Level::Info, ConfigurationType::PerformanceTracking,
                 "true");
    log_conf.set(Level::Info, ConfigurationType::SubsecondPrecision, "3");
    log_conf.set(Level::Info, ConfigurationType::MaxLogFileSize, "2097152");

    Loggers::reconfigureLogger("performance", log_conf);
}

void
initialize_logging(const char *log_file, unsigned short verbosity_level)
{
    using namespace el;
    if (log_file == nullptr) {
        Loggers::reconfigureAllLoggers(ConfigurationType::Filename, "bcov.log");
    } else {
        Loggers::reconfigureAllLoggers(ConfigurationType::Filename, log_file);
    }
    initialize_logging_common();
    Loggers::setVerboseLevel(verbosity_level);
}

void
initialize_logging(int argc, const char **argv)
{
    START_EASYLOGGINGPP(argc, argv);
    initialize_logging_common();
}
