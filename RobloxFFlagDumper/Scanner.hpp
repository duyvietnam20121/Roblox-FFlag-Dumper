#pragma once
// ---------------------------------------------------------------------------
// Scanner.hpp - locates Roblox's FFlag hash-map and dumps it.
//
// Pseudocode
//   FindLayout():
//     for range in [legacy .data range, every writable non-exec PE section]:
//       for each 8-byte slot in range:
//         p = *slot                       -> must look like an aligned user pointer
//         if *p != 0x3F800000 (1.0f)      -> not an unordered_map object, skip
//         head  = *(p + 8)                -> list sentinel
//         node  = *head                   -> first element
//         walk the list; every node whose name is one of the anchors ("BatchThumbnailMinWaitMs", ...)
//         brute-force the two offsets so that  **(node+A + B) == that anchor's value
//         -> Layout{ slotRva, A (ValueGetSet), B (FlagToValue) }
//         VERIFY the layout before accepting it (see LayoutFinder::Verify):
//           a) coverage: walk the whole list with it; a wrong layout resolves almost
//              no value pointers into the module image, a right one resolves most
//           b) anchors: RequiredMatches(#anchors) of them must read back their expected value
//
//   DumpFlags(layout):
//     walk the circular list, for every node: name, value-pointer
//     keep only pointers that land inside the module image -> RVA
// ---------------------------------------------------------------------------

#include <algorithm>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

#include "Memory.hpp"

namespace Scanner {

// --- Roblox-specific layout constants (x64) --------------------------------
inline constexpr std::uintptr_t kLoadFactorSignature = 0x3F800000;  // float 1.0f
inline constexpr std::uintptr_t kMapHeadOffset = 0x8;               // list sentinel
inline constexpr std::uintptr_t kNodeNameOffset = 0x10;             // std::string in node
inline constexpr std::uintptr_t kMinMapPointer = 0x100000;
inline constexpr std::uintptr_t kMinValueRva = 0x10000;
inline constexpr std::size_t kPageSize = 0x1000;

inline constexpr std::size_t kMaxAnchors = 4;

// How many anchors must read back their expected value: all of them when 1-2 are given,
// all but one when 3-4 are given (so a single changed default does not break the dump).
[[nodiscard]] constexpr std::size_t RequiredMatches(std::size_t anchorCount) noexcept {
    return anchorCount <= 2 ? anchorCount : anchorCount - 1;
}

// An integer flag with a known value, used as a landmark in the flag map.
struct Anchor {
    std::string name;
    int value = 0;
};

struct Config {
    // Landmarks (--anchor Name=Value, repeatable). Any of them can locate the layout;
    // at most kMaxAnchors; see RequiredMatches() for how many must match.
    std::vector<Anchor> anchors = {{"BatchThumbnailMinWaitMs", 15}, {"StreamingSafeMemWatermarkMB", 100}};
    // True while the list above is the built-in default. Defaults are "soft": either one can
    // locate the layout and one matching value is enough, so a Roblox update that changes one
    // default does not break the tool. Landmarks given with --anchor are strict (RequiredMatches).
    bool defaultAnchors = true;
    bool verify = true;                                  // --no-verify disables the checks
    double minCoverage = 0.5;                            // share of usable entries required
    std::uintptr_t legacyStart = 0x7000000;              // proven range from v1
    std::uintptr_t legacyEnd = 0x12000000;
    std::size_t chunkSize = 0x10000;                     // multiple of kPageSize
    std::size_t maxListNodes = 2'000'000;                // hard stop against cycles
    bool verbose = false;
};

struct Layout {
    std::uintptr_t mapGlobalRva = 0;  // RVA of the global slot holding the map pointer
    std::uintptr_t valueGetSet = 0;   // node offset -> ValueGetSet object
    std::uintptr_t flagToValue = 0;   // ValueGetSet offset -> pointer to the value
};

struct Range {
    std::uintptr_t start = 0;  // RVA
    std::uintptr_t end = 0;    // RVA (exclusive)
};

struct DumpStats {
    std::size_t nodes = 0;
    std::size_t dumped = 0;
    std::size_t badName = 0;
    std::size_t badPointer = 0;
    std::size_t stringValued = 0;
    std::size_t duplicates = 0;
    bool truncated = false;  // hit Config::maxListNodes
};

struct DumpResult {
    std::map<std::string, std::uintptr_t> flags;  // name -> RVA, sorted => stable diffs
    DumpStats stats;
};

// Share of entries (with a valid name and non-string value) whose value pointer
// resolved into the module image. ~0 for a wrong layout, high for the right one.
[[nodiscard]] inline double Coverage(const DumpStats& s) {
    const std::size_t usable = s.dumped + s.duplicates + s.badPointer;
    return usable ? static_cast<double>(s.dumped + s.duplicates) / static_cast<double>(usable) : 0.0;
}

// Writable, non-executable PE sections (.data & friends) as RVA ranges.
[[nodiscard]] inline std::vector<Range> ReadDataSections(const Memory::Process& process,
                                                         const Memory::ModuleInfo& module) {
    std::vector<Range> ranges;

    const auto dos = process.Read<IMAGE_DOS_HEADER>(module.base);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || dos->e_lfanew > 0x1000)
        return ranges;

    const std::uintptr_t nt = module.base + static_cast<std::uintptr_t>(dos->e_lfanew);
    const auto signature = process.Read<DWORD>(nt);
    const auto file = process.Read<IMAGE_FILE_HEADER>(nt + sizeof(DWORD));
    if (!signature || *signature != IMAGE_NT_SIGNATURE || !file) return ranges;

    const std::uintptr_t table =
        nt + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + file->SizeOfOptionalHeader;

    for (WORD i = 0; i < file->NumberOfSections && i < 96; ++i) {
        const auto section = process.Read<IMAGE_SECTION_HEADER>(table + i * sizeof(IMAGE_SECTION_HEADER));
        if (!section) break;

        const DWORD flags = section->Characteristics;
        if ((flags & IMAGE_SCN_MEM_WRITE) && !(flags & IMAGE_SCN_MEM_EXECUTE)) {
            const std::uintptr_t size =
                section->Misc.VirtualSize ? section->Misc.VirtualSize : section->SizeOfRawData;
            ranges.push_back({section->VirtualAddress, section->VirtualAddress + size});
        }
    }
    return ranges;
}

// Walks the flag list and collects name -> RVA for every usable entry.
[[nodiscard]] inline std::optional<DumpResult> DumpFlags(const Memory::Process& process,
                                                         const Memory::ModuleInfo& module,
                                                         const Layout& layout, const Config& config) {
    const auto mapObject = process.Read<std::uintptr_t>(module.base + layout.mapGlobalRva);
    if (!mapObject || !Memory::IsUserPointer(*mapObject)) return std::nullopt;

    const auto head = process.Read<std::uintptr_t>(*mapObject + kMapHeadOffset);
    if (!head || !Memory::IsUserPointer(*head)) return std::nullopt;

    const auto first = process.Read<std::uintptr_t>(*head);
    if (!first) return std::nullopt;

    DumpResult result;
    DumpStats& stats = result.stats;

    std::uintptr_t node = *first;
    while (Memory::IsUserPointer(node) && node != *head) {
        if (stats.nodes >= config.maxListNodes) {
            stats.truncated = true;
            break;
        }
        ++stats.nodes;

        // Read the successor first so every `continue` below can still advance.
        const auto next = process.Read<std::uintptr_t>(node);

        [&] {
            const auto name = process.ReadMsvcString(node + kNodeNameOffset);
            if (!name) { ++stats.badName; return; }

            const auto getSet = process.Read<std::uintptr_t>(node + layout.valueGetSet);
            if (!getSet || !Memory::IsUserPointer(*getSet)) { ++stats.badPointer; return; }

            // Entries whose "value" is the text True/False are not offsets.
            if (const auto text = process.ReadMsvcString(*getSet + layout.flagToValue);
                text && (*text == "True" || *text == "False")) {
                ++stats.stringValued;
                return;
            }

            const auto valuePointer = process.Read<std::uintptr_t>(*getSet + layout.flagToValue);
            // The value must live inside the module image, otherwise the RVA is meaningless.
            if (!valuePointer || *valuePointer < module.base ||
                *valuePointer - module.base >= module.size ||
                *valuePointer - module.base < kMinValueRva) {
                ++stats.badPointer;
                return;
            }

            if (result.flags.emplace(*name, *valuePointer - module.base).second) ++stats.dumped;
            else ++stats.duplicates;
        }();

        if (!next || *next == node) break;
        node = *next;
    }
    return result;
}

class LayoutFinder {
public:
    LayoutFinder(const Memory::Process& process, const Memory::ModuleInfo& module, const Config& config)
        : process_(process), module_(module), config_(config) {}

    // Why the last layout candidate was rejected (empty if none was reached).
    [[nodiscard]] const std::vector<std::string>& LastRejection() const noexcept { return report_; }

    [[nodiscard]] std::optional<Layout> Find() {
        // 1) The range that is known to work - fast path.
        const Range legacy{config_.legacyStart, std::min<std::uintptr_t>(config_.legacyEnd, module_.size)};
        if (legacy.start < legacy.end) {
            if (auto layout = ScanRange(legacy)) return layout;
        }

        // 2) Fallback: every writable data section of the image.
        if (config_.verbose) std::cout << "[scan] legacy range failed, trying PE data sections\n";
        for (const Range& range : ReadDataSections(process_, module_)) {
            if (auto layout = ScanRange(range)) return layout;
        }
        return std::nullopt;
    }

private:
    std::optional<Layout> ScanRange(const Range& range) {
        const std::size_t chunk = std::max<std::size_t>(config_.chunkSize & ~std::size_t{7}, kPageSize);
        std::vector<std::uintptr_t> buffer(chunk / sizeof(std::uintptr_t));

        for (std::uintptr_t offset = range.start; offset < range.end; offset += chunk) {
            const std::size_t bytes =
                static_cast<std::size_t>(std::min<std::uintptr_t>(chunk, range.end - offset)) & ~std::size_t{7};
            if (bytes == 0) break;

            if (process_.ReadBytes(module_.base + offset, buffer.data(), bytes)) {
                if (auto layout = ScanBlock(buffer.data(), bytes / sizeof(std::uintptr_t), offset)) return layout;
                continue;
            }

            // The chunk contains unreadable pages: retry page by page.
            for (std::size_t page = 0; page < bytes; page += kPageSize) {
                const std::size_t n = std::min(kPageSize, bytes - page);
                if (!process_.ReadBytes(module_.base + offset + page, buffer.data(), n)) continue;
                if (auto layout = ScanBlock(buffer.data(), n / sizeof(std::uintptr_t), offset + page))
                    return layout;
            }
        }
        return std::nullopt;
    }

    std::optional<Layout> ScanBlock(const std::uintptr_t* slots, std::size_t count, std::uintptr_t blockRva) {
        for (std::size_t i = 0; i < count; ++i) {
            const std::uintptr_t candidate = slots[i];
            if (candidate < kMinMapPointer || !Memory::IsUserPointer(candidate) || (candidate & 7)) continue;
            if (!checked_.insert(candidate).second) continue;  // already validated

            const auto signature = process_.Read<std::uintptr_t>(candidate);
            if (!signature || *signature != kLoadFactorSignature) continue;

            const std::uintptr_t slotRva = blockRva + i * sizeof(std::uintptr_t);
            if (config_.verbose) std::cout << "[scan] map candidate, slot RVA " << Memory::ToHex(slotRva) << '\n';

            if (auto layout = TryCandidate(candidate, slotRva)) return layout;
        }
        return std::nullopt;
    }

    std::optional<Layout> TryCandidate(std::uintptr_t mapObject, std::uintptr_t slotRva) {
        const auto head = process_.Read<std::uintptr_t>(mapObject + kMapHeadOffset);
        if (!head || !Memory::IsUserPointer(*head)) {
            if (config_.verbose) std::cout << "[scan]   list head invalid\n";
            return std::nullopt;
        }
        const auto first = process_.Read<std::uintptr_t>(*head);
        if (!first || !Memory::IsUserPointer(*first)) {
            if (config_.verbose) std::cout << "[scan]   first node invalid\n";
            return std::nullopt;
        }

        // The list is circular: it ends when we are back at the sentinel.
        std::uintptr_t node = *first;
        for (std::size_t n = 0; n < config_.maxListNodes && Memory::IsUserPointer(node) && node != *head; ++n) {
            const auto name = process_.ReadMsvcString(node + kNodeNameOffset);
            if (name) {
                for (const Anchor& anchor : config_.anchors) {
                    if (*name != anchor.name) continue;
                    if (const auto layout = ProbeAnchor(node, slotRva, anchor.value)) {
                        if (Verify(*layout)) return layout;
                        if (config_.verbose)
                            std::cout << "[scan]   layout from anchor '" << anchor.name << "' rejected\n";
                    } else if (config_.verbose) {
                        std::cout << "[scan]   anchor '" << anchor.name << "' found but value offsets not matched\n";
                    }
                }
            }
            const auto next = process_.Read<std::uintptr_t>(node);
            if (!next || *next == node) break;
            node = *next;
        }
        return std::nullopt;
    }

    // Brute-forces the two offsets so that the anchor flag's value is reachable.
    std::optional<Layout> ProbeAnchor(std::uintptr_t node, std::uintptr_t slotRva, int expected) const {
        for (std::uintptr_t getSet = 0x20; getSet <= 0x100; getSet += 8) {
            const auto object = process_.Read<std::uintptr_t>(node + getSet);
            if (!object || !Memory::IsUserPointer(*object)) continue;

            for (std::uintptr_t toValue = 0; toValue < 0x300; toValue += 8) {
                const auto pointer = process_.Read<std::uintptr_t>(*object + toValue);
                if (!pointer || !Memory::IsUserPointer(*pointer)) continue;

                const auto value = process_.Read<int>(*pointer);
                if (value && *value == expected) return Layout{slotRva, getSet, toValue};
            }
        }
        return std::nullopt;
    }

    // Second opinion on a layout found with one anchor. The outcome is recorded in
    // report_ (always, not only with --verbose) so a failed run can explain itself.
    bool Verify(const Layout& layout) {
        if (!config_.verify) return true;
        report_.clear();

        const auto dump = DumpFlags(process_, module_, layout, config_);
        if (!dump) {
            Note("could not walk the flag list with this layout");
            return false;
        }

        const double coverage = Coverage(dump->stats);
        Note("coverage " + std::to_string(static_cast<int>(coverage * 100)) + "% (" +
             std::to_string(dump->stats.dumped) + " flags)");
        if (dump->flags.empty() || coverage < config_.minCoverage) {
            Note("rejected: coverage too low");
            return false;
        }

        if (!config_.anchors.empty()) {
            std::size_t matches = 0;
            for (const Anchor& anchor : config_.anchors) {
                const auto it = dump->flags.find(anchor.name);
                if (it == dump->flags.end()) {
                    Note("anchor " + anchor.name + ": not found in the dump");
                    continue;
                }
                const auto value = process_.Read<int>(module_.base + it->second);
                Note("anchor " + anchor.name + ": expected " + std::to_string(anchor.value) + ", read " +
                     (value ? std::to_string(*value) : std::string("(unreadable)")));
                if (value && *value == anchor.value) ++matches;
            }
            const std::size_t required =
                config_.defaultAnchors ? 1 : RequiredMatches(config_.anchors.size());
            Note("anchors matched " + std::to_string(matches) + "/" + std::to_string(config_.anchors.size()) +
                 " (need " + std::to_string(required) + ")");
            if (matches < required) return false;
        }
        return true;
    }

    void Note(const std::string& line) {
        report_.push_back(line);
        if (config_.verbose) std::cout << "[verify] " << line << '\n';
    }

    const Memory::Process& process_;
    const Memory::ModuleInfo& module_;
    const Config& config_;
    std::unordered_set<std::uintptr_t> checked_;
    std::vector<std::string> report_;
};

}  // namespace Scanner
