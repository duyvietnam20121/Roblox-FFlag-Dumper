// ---------------------------------------------------------------------------
// RobloxFFlagDumper - dumps FFlag offsets from a running Roblox client.
//
// Usage:  RobloxFFlagDumper [--out <dir>] [--process <exe>] [--anchor Name=Value]...
//                           [--no-verify] [--values]
//                           [--verbose] [--no-pause] [--help]
//
// Exit codes: 0 ok | 1 cannot attach | 2 map not found | 3 dump/IO failure | 64 bad usage
// ---------------------------------------------------------------------------

#include <charconv>
#include <filesystem>
#include <iostream>
#include <map>
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
    bool values = false;
    bool help = false;
};

void PrintUsage() {
    std::cout << "RobloxFFlagDumper [options]\n"
                 "  --out <dir>            output directory (default: current directory)\n"
                 "  --process <exe>        target process (default: RobloxPlayerBeta.exe)\n"
                 "  --anchor <Name=Value>  integer flag with a known value (landmark); repeatable.\n"
                 "                         Default: BatchThumbnailMinWaitMs=15, StreamingSafeMemWatermarkMB=100\n"
                 "                         (either one is enough). Your own landmarks replace the default.\n"
                 "                         Max 4. Any landmark can locate the layout. With 1-2 landmarks all\n"
                 "                         must match; with 3-4 one may differ. (--anchor2 is an alias.)\n"
                 "                         (default: BatchThumbnailMinWaitMs=15)\n"
                 "  --values               also store each flag's current int value in FFlags.json\n"
                 "                         (feed several dumps to pick_anchors.py to find stable anchors)\n"
                 "  --no-verify            skip the layout verification (coverage + landmark check)\n"
                 "  --verbose              print scanning details\n"
                 "  --no-pause             do not wait for Enter before exiting\n"
                 "  --help                 show this help\n";
}

// "Name=123" -> name + integer value.
bool ParseNameValue(std::string_view text, std::string& name, int& value) {
    const auto eq = text.find('=');
    if (eq == std::string_view::npos || eq == 0) {
        std::cerr << "Expected Name=Value, got: " << text << '\n';
        return false;
    }
    const std::string_view number = text.substr(eq + 1);
    int parsed = 0;
    const auto [end, ec] = std::from_chars(number.data(), number.data() + number.size(), parsed);
    if (ec != std::errc{} || end != number.data() + number.size()) {
        std::cerr << "Value must be an integer: " << text << '\n';
        return false;
    }
    name = std::string(text.substr(0, eq));
    value = parsed;
    return true;
}

bool ParseArgs(int argc, char** argv, Options& options) {
    bool anchorsFromUser = false;
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
        } else if (arg == "--anchor" || arg == "--anchor2") {
            const char* value = needValue(arg);
            Scanner::Anchor anchor;
            if (!value || !ParseNameValue(value, anchor.name, anchor.value)) return false;
            if (!anchorsFromUser) {  // user landmarks replace the built-in defaults
                options.scan.anchors.clear();
                options.scan.defaultAnchors = false;
            }
            if (options.scan.anchors.size() >= Scanner::kMaxAnchors) {
                std::cerr << "At most " << Scanner::kMaxAnchors << " --anchor landmarks are supported\n";
                return false;
            }
            anchorsFromUser = true;
            options.scan.anchors.push_back(std::move(anchor));
        } else if (arg == "--values") {
            options.values = true;
        } else if (arg == "--no-verify") {
            options.scan.verify = false;
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
    std::cout << "Scanning for the FFlag map (landmarks:";
    for (const auto& anchor : options.scan.anchors) std::cout << ' ' << anchor.name << '=' << anchor.value;
    std::cout << ")...\n";
    Scanner::LayoutFinder finder(process, *module, options.scan);
    const auto layout = finder.Find();
    if (!layout) {
        if (!finder.LastRejection().empty()) {
            std::cerr << "A map was found but its layout was rejected:\n";
            for (const auto& line : finder.LastRejection()) std::cerr << "  - " << line << '\n';
            std::cerr << "(use --no-verify to accept it anyway)\n\n";
        }
        std::cerr << "FFlag map not found. If Roblox changed a landmark's value, pass new ones with "
                     "--anchor Name=Value (repeatable, see --verbose).\n";
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
    meta.generatedAt = Output::Timestamp();
    meta.imageSize = module->size;
    if (const auto path = process.ImagePath()) meta.robloxVersion = Output::RobloxVersionFromPath(*path);

    std::error_code ec;
    std::filesystem::create_directories(options.outDir, ec);
    const auto jsonPath = options.outDir / "FFlags.json";
    const auto headerPath = options.outDir / "FFlags.hpp";
    std::map<std::string, int> values;
    if (options.values) {
        for (const auto& [name, rva] : dump->flags) {
            if (const auto value = process.Read<int>(module->base + rva)) values.emplace(name, *value);
        }
    }
    if (!Output::WriteJson(jsonPath, meta, *layout, *dump, options.values ? &values : nullptr) ||
        !Output::WriteHeader(headerPath, meta, *layout, *dump)) {
        std::cerr << "Could not write output files into " << options.outDir.string() << '\n';
        return Finish(kDumpFailed, options.pause);
    }

    const auto& s = dump->stats;
    std::cout << "\nDumped " << s.dumped << " flags (" << meta.robloxVersion << ") -> "
              << jsonPath.string() << ", " << headerPath.string() << '\n'
              << "Nodes visited: " << s.nodes << " | skipped: bad name " << s.badName << ", bad pointer "
              << s.badPointer << ", string-valued " << s.stringValued << ", duplicates " << s.duplicates << '\n'
              << "Layout coverage: " << static_cast<int>(Scanner::Coverage(s) * 100) << "%"
              << (options.scan.verify ? " (verified)" : " (verification skipped)") << '\n';
    if (s.truncated) std::cout << "Warning: node limit reached - the list may be incomplete.\n";

    return Finish(kOk, options.pause);
}
