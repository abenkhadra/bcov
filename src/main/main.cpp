#include <iostream>
#include <set>
#include "core/Disassembler.hpp"
#include "util/BcovConfigParser.hpp"
#include "util/ProgOptions.hpp"
#include "graph/SuperBlock.hpp"
#include "elf/ElfPatchManager.hpp"
#include "elf/ElfModule.hpp"
#include "util/Logging.hpp"


int main(int argc, const char **argv)
{
    using namespace bcov;
    ProgOptions options = ProgOptions::parse(argc, argv);
    initialize_logging(options.log_file().data(), options.verbosity());

    bcov::ElfModule module;
    if (options.config_file().empty() && options.selected_function().empty()) {
        LOG(INFO) << "bcov will probe all static functions";
        module = ElfModuleBuilder::build(options.input_file());
    } else {
        BcovConfigParser config_parser;
        BcovConfig config = config_parser.parse(options.config_file());
        if (config.functions().empty() && !options.selected_function().empty()) {
            config.add_function(options.selected_function());
        }
        module = ElfModuleBuilder::build(options.input_file(), config);
    }

    DCHECK(options.program_mode() == ProgramMode::kReport ||
           options.program_mode() == ProgramMode::kPatch);

    auto mgr_mode = options.operation_params() == OperationParams::kAllNode
                    ? PatchManagerMode::kLeafNode : PatchManagerMode::kAnyNode;

    ElfPatchManager patch_mgr;
    patch_mgr.set_mode(mgr_mode | PatchManagerMode::kJumpTab);
    patch_mgr.build_probes(module);

    if (patch_mgr.probes().empty()) {
        std::cout << "weird! no probes identified!";
        exit(EXIT_SUCCESS);
    }

    if (options.program_mode() == ProgramMode::kReport) {
        if (options.output_file().empty()) {
            OStreamCoverageReporter coverage_reporter(std::cout);
            coverage_reporter.set_report_actual_address();
            patch_mgr.report(options.data_file(), &coverage_reporter);
        } else {
            std::ofstream out_file;
            out_file.open(options.output_file().data(), std::ofstream::out);
            if (!out_file.good()) {
                std::cerr << "can not open output file: " << options.output_file();
                exit(EXIT_FAILURE);
            }
            OStreamCoverageReporter coverage_reporter(out_file);
            coverage_reporter.set_report_actual_address();
            patch_mgr.report(options.data_file(), &coverage_reporter);
        }
        exit(EXIT_SUCCESS);
    }

    try {
        auto success = patch_mgr.patch(options.input_file(), options.output_file());
        if (!success) {
            std::cout << "unsupported input!";
            exit(0);
        }
    } catch (const std::exception &exp) {
        std::cerr << "fatal error: " << exp.what();
        exit(1);
    }

    std::cout << "file patched successfully\n";
    return 0;
}
