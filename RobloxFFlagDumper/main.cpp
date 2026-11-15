// ---------------------------------------------------------------------------
// RobloxFFlagDumper - dumps FFlag offsets from a running Roblox client.
//
// Usage:  RobloxFFlagDumper [--out <dir>] [--process <exe>] [--anchor Name=Value]...
//                           [--no-verify] [--no-discover] [--values]
//                           [--dump-skipped] [--inspect <FlagName>]
//                           [--verbose] [--no-pause] [--help]
//
// Exit codes: 0 ok | 1 cannot attach | 2 map not found | 3 dump/IO failure | 64 bad usage
// ---------------------------------------------------------------------------

#include <cctype>
#include <charconv>
#include <fstream>
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
    bool dumpSkipped = false;
    std::string inspect;
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
                 "  --dump-skipped         also write FFlagsSkipped.json: every node that was NOT turned into an\n"
                 "                         offset (string-stored, bad pointer...) with raw data, to analyse them\n"
                 "  --inspect <FlagName>   print a hex report of one flag's node and value object (also saved to\n"
                 "                         Inspect_<FlagName>.txt); the F/DF/FInt... prefix is optional\n"
                 "  --no-discover          skip the name-based fallback (slow search of all process memory)\n"
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
        } else if (arg == "--dump-skipped") {
            options.dumpSkipped = true;
        } else if (arg == "--inspect") {
            const char* value = needValue(arg);
            if (!value) return false;
            options.inspect = value;
        } else if (arg == "--no-discover") {
            options.scan.discover = false;
        } else if (arg == "--no-verify") {
            options.scan.verify = false;
        } else {
            std::cerr << "Unknown argument: " << arg << '\n';
            return false;
        }
    }
    return true;
}

std::string Percent(double ratio) { return std::to_string(static_cast<int>(ratio * 100)) + "%"; }

std::string VerificationSummary(const Scanner::VerifyInfo& v, bool enabled) {
    if (!enabled || !v.performed) return "Verification: skipped (--no-verify)";
    std::string text = "Verification: coverage " + Percent(v.coverage) + " | unique addresses " + Percent(v.uniqueRvas);
    if (v.declaredSize) {
        text += " | list size " + std::to_string(*v.declaredSize) + " vs walked " + std::to_string(v.walkedNodes) +
                (*v.declaredSize == v.walkedNodes ? " (match)" : " (MISMATCH)");
    }
    text += " | landmarks " + std::to_string(v.anchorsMatched) + "/" + std::to_string(v.anchorsTotal);
    return text;
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
        const auto& st = finder.ScanStatistics();
        std::cerr << "Scan summary: read " << st.bytesRead / 1048576 << " MB (" << st.bytesUnreadable / 1048576
                  << " MB unreadable), " << st.pointersTested << " pointers tested, " << st.signatureHits
                  << " targets start with 1.0f (unordered_map signature)\n";
        if (st.bytesRead == 0)
            std::cerr << "-> No memory of the process could be read (permissions or protection).\n";
        else if (st.signatureHits == 0)
            std::cerr << "-> No unordered_map-like object found: the structure may have changed in this Roblox version.\n";
        const auto& d = finder.DiscoveryStatistics();
        if (d.attempted) {
            std::cerr << "Name-based search: " << d.nameHits << " text hit(s), " << d.references << " pointer(s) to it, "
                      << d.nodes << " valid node(s), " << d.circularLists << " circular list(s), " << d.mapObjects
                      << " map object(s)" << (d.probeFailed ? ", landmark value unreachable in " + std::to_string(d.probeFailed) : std::string())
                      << "\n";
            if (d.nodes == 0 && !d.firstReferenceDump.empty())
                std::cerr << "Memory around the first pointer to the landmark's name (send this if it keeps failing):\n"
                          << d.firstReferenceDump;
        }
        std::cerr << "FFlag map not found. If Roblox changed a landmark's value, pass new ones with "
                     "--anchor Name=Value (repeatable, see --verbose).\n";
        return Finish(kMapNotFound, options.pause);
    }
    std::cout << (layout->mapEmbedded ? "Map object  : " : "Map slot    : ") << Memory::ToHex(layout->mapGlobalRva) << '\n'
              << "ValueGetSet : " << Memory::ToHex(layout->valueGetSet) << '\n'
              << "FlagToValue : " << Memory::ToHex(layout->flagToValue) << '\n';

    // --- inspect (optional) ------------------------------------------------
    if (!options.inspect.empty()) {
        const auto report = Scanner::InspectFlag(process, *module, *layout, options.scan, options.inspect);
        if (!report) {
            std::cerr << "\n--inspect: flag '" << options.inspect << "' not found in the flag list.\n";
        } else {
            std::cout << "\n" << *report;
            std::string fileName = "Inspect_" + options.inspect + ".txt";
            for (char& c : fileName) if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '.') c = '_';
            std::error_code dirError;
            std::filesystem::create_directories(options.outDir, dirError);
            std::ofstream file(options.outDir / fileName, std::ios::binary | std::ios::trunc);
            if (file << *report) std::cout << "(saved to " << (options.outDir / fileName).string() << ")\n";
        }
    }

    // --- dump --------------------------------------------------------------
    Scanner::Config dumpConfig = options.scan;
    dumpConfig.collectSkipped = options.dumpSkipped;  // (verification dumps stay light)
    const auto dump = Scanner::DumpFlags(process, *module, *layout, dumpConfig);
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

    if (options.dumpSkipped) {
        const auto skippedPath = options.outDir / "FFlagsSkipped.json";
        if (Output::WriteSkipped(skippedPath, meta, dump->skipped))
            std::cout << "Skipped entries: " << dump->skipped.size() << " -> " << skippedPath.string() << '\n';
        else
            std::cerr << "Could not write " << skippedPath.string() << '\n';
    }

    const auto& s = dump->stats;
    std::cout << "\nDumped " << s.dumped << " flags (" << meta.robloxVersion << ") -> "
              << jsonPath.string() << ", " << headerPath.string() << '\n'
              << "Nodes visited: " << s.nodes << " | skipped: bad name " << s.badName << ", bad pointer "
              << s.badPointer << ", string-stored " << s.stringValued << ", duplicates " << s.duplicates << '\n'
              << VerificationSummary(finder.Verification(), options.scan.verify) << '\n';
    if (s.truncated) std::cout << "Warning: node limit reached - the list may be incomplete.\n";

    return Finish(kOk, options.pause);
}
