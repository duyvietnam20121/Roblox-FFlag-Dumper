// ---------------------------------------------------------------------------
// RobloxFFlagDumper - dumps FFlag offsets from a running Roblox client.
//
// Usage:  RobloxFFlagDumper [--out <dir>] [--process <exe>] [--anchor Name=Value]
//                           [--verbose] [--no-pause] [--help]
//
// Exit codes: 0 ok | 1 cannot attach | 2 map not found | 3 dump/IO failure | 64 bad usage
// ---------------------------------------------------------------------------

#include <charconv>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>

#include "Memory.hpp"
#include "Output.hpp"
#include "Scanner.hpp"

namespace {

enum ExitCode : int { kOk = 0, kAttachFailed = 1, kMapNotFound = 2, kDumpFailed = 3, kBadUsage = 64 };

struct Options {
    std::string process = "RobloxPlayerBeta.exe";
    std::filesystem::path outDir = ".";
    Scanner::Config scan;
    bool pause = true;
    bool help = false;
};

void PrintUsage() {
    std::cout << "RobloxFFlagDumper [options]\n"
                 "  --out <dir>            output directory (default: current directory)\n"
                 "  --process <exe>        target process (default: RobloxPlayerBeta.exe)\n"
                 "  --anchor <Name=Value>  flag with a known value used to calibrate offsets\n"
                 "                         (default: BatchThumbnailMinWaitMs=15)\n"
                 "  --verbose              print scanning details\n"
                 "  --no-pause             do not wait for Enter before exiting\n"
                 "  --help                 show this help\n";
}

bool ParseArgs(int argc, char** argv, Options& options) {
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        const auto needValue = [&](std::string_view flag) -> const char* {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for " << flag << '\n';
                return nullptr;
            }
            return argv[++i];
        };

        if (arg == "--help" || arg == "-h") {
            options.help = true;
        } else if (arg == "--verbose") {
            options.scan.verbose = true;
        } else if (arg == "--no-pause") {
            options.pause = false;
        } else if (arg == "--out") {
            const char* value = needValue(arg);
            if (!value) return false;
            options.outDir = value;
        } else if (arg == "--process") {
            const char* value = needValue(arg);
            if (!value) return false;
            options.process = value;
        } else if (arg == "--anchor") {
            const char* value = needValue(arg);
            if (!value) return false;
            const std::string_view text = value;
            const auto eq = text.find('=');
            if (eq == std::string_view::npos || eq == 0) {
                std::cerr << "--anchor expects Name=Value\n";
                return false;
            }
            const std::string_view number = text.substr(eq + 1);
            int parsed = 0;
            const auto [end, ec] = std::from_chars(number.data(), number.data() + number.size(), parsed);
            if (ec != std::errc{} || end != number.data() + number.size()) {
                std::cerr << "--anchor value must be an integer\n";
                return false;
            }
            options.scan.anchorName = std::string(text.substr(0, eq));
            options.scan.anchorValue = parsed;
        } else {
            std::cerr << "Unknown argument: " << arg << '\n';
            return false;
        }
    }
    return true;
}

int Finish(int code, bool pause) {
    if (pause) {
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
    }
    return code;
}

}  // namespace

int main(int argc, char** argv) {
    Options options;
    if (!ParseArgs(argc, argv, options)) {
        PrintUsage();
        return kBadUsage;
    }
    if (options.help) {
        PrintUsage();
        return kOk;
    }

    // --- attach ------------------------------------------------------------
    const std::wstring processName(options.process.begin(), options.process.end());
    const DWORD pid = Memory::FindProcessId(processName);
    Memory::Process process;
    if (pid == 0 || !process.Attach(pid)) {
        std::cerr << "Could not attach to " << options.process
                  << (pid == 0 ? " (process not running)" : " (access denied? try an elevated prompt)") << '\n';
        return Finish(kAttachFailed, options.pause);
    }

    const auto module = process.FindModule(processName);
    if (!module) {
        std::cerr << "Could not find the main module of " << options.process << '\n';
        return Finish(kAttachFailed, options.pause);
    }
    std::cout << "PID        : " << std::dec << process.Pid() << '\n'
              << "Base       : " << Memory::ToHex(module->base) << '\n'
              << "Image size : " << Memory::ToHex(module->size) << '\n';

    // --- calibrate ---------------------------------------------------------
    std::cout << "Scanning for the FFlag map (anchor " << options.scan.anchorName << " = "
              << options.scan.anchorValue << ")...\n";
    Scanner::LayoutFinder finder(process, *module, options.scan);
    const auto layout = finder.Find();
    if (!layout) {
        std::cerr << "FFlag map not found. If Roblox changed the anchor flag's value, "
                     "pass a new one with --anchor Name=Value (see --verbose).\n";
        return Finish(kMapNotFound, options.pause);
    }
    std::cout << "Map slot    : " << Memory::ToHex(layout->mapGlobalRva) << '\n'
              << "ValueGetSet : " << Memory::ToHex(layout->valueGetSet) << '\n'
              << "FlagToValue : " << Memory::ToHex(layout->flagToValue) << '\n';

    // --- dump --------------------------------------------------------------
    const auto dump = Scanner::DumpFlags(process, *module, *layout, options.scan);
    if (!dump || dump->flags.empty()) {
        std::cerr << "Failed to walk the FFlag list.\n";
        return Finish(kDumpFailed, options.pause);
    }

    Output::Meta meta;
    meta.process = options.process;
    meta.generatedUtc = Output::UtcTimestamp();
    meta.imageSize = module->size;
    if (const auto path = process.ImagePath()) meta.robloxVersion = Output::QueryFileVersion(*path);

    std::error_code ec;
    std::filesystem::create_directories(options.outDir, ec);
    const auto jsonPath = options.outDir / "FFlags.json";
    const auto headerPath = options.outDir / "FFlags.hpp";
    if (!Output::WriteJson(jsonPath, meta, *layout, *dump) ||
        !Output::WriteHeader(headerPath, meta, *layout, *dump)) {
        std::cerr << "Could not write output files into " << options.outDir.string() << '\n';
        return Finish(kDumpFailed, options.pause);
    }

    const auto& s = dump->stats;
    std::cout << "\nDumped " << s.dumped << " flags (" << meta.robloxVersion << ") -> "
              << jsonPath.string() << ", " << headerPath.string() << '\n'
              << "Nodes visited: " << s.nodes << " | skipped: bad name " << s.badName << ", bad pointer "
              << s.badPointer << ", string-valued " << s.stringValued << ", duplicates " << s.duplicates << '\n';
    if (s.truncated) std::cout << "Warning: node limit reached - the list may be incomplete.\n";

    return Finish(kOk, options.pause);
}
