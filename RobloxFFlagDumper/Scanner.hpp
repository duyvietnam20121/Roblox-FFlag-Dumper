#pragma once
// ---------------------------------------------------------------------------
// Scanner.hpp - locates Roblox's FFlag hash-map and dumps it.
//
// Pseudocode
//   FindLayout():
//     for range in [legacy .data range, every writable non-exec PE section]:
//       for each 8-byte slot in range:
//         p = *slot                       -> must look like a (4-byte aligned) user pointer
//         if low dword of *p != 0x3F800000 (1.0f) -> not an unordered_map object, skip
//         head  = *(p + 8)                -> list sentinel
//         node  = *head                   -> first element
//         walk the list; every node whose name is one of the anchors ("BatchThumbnailMinWaitMs", ...)
//         brute-force the two offsets so that  **(node+A + B) == that anchor's value
//         -> Layout{ slotRva, A (ValueGetSet), B (FlagToValue) }
//         VERIFY the layout before accepting it (see LayoutFinder::Verify):
//           a) coverage: walk the whole list with it; a wrong layout resolves almost
//              no value pointers into the module image, a right one resolves most
//           b) unique addresses: every flag has its own storage, so (almost) no two entries
//              may resolve to the same value address
//           c) list size: nodes walked vs. the map's own element count (reported, soft)
//           d) anchors: RequiredMatches(#anchors) of them must read back their expected value
//
//   DumpFlags(layout):
//     walk the circular list, for every node: name, value-pointer
//     keep only pointers that land inside the module image -> RVA
// ---------------------------------------------------------------------------

#include <algorithm>
#include <cstdio>
#include <iostream>
#include <map>
#include <sstream>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

#include "Memory.hpp"
#include "MemoryScan.hpp"

namespace Scanner {

// --- Roblox-specific layout constants (x64) --------------------------------
inline constexpr std::uint32_t kLoadFactorSignature = 0x3F800000;   // float 1.0f (low dword; padding may be garbage)
inline constexpr std::uintptr_t kMapHeadOffset = 0x8;               // list sentinel
inline constexpr std::uintptr_t kMapSizeOffset = 0x10;             // element count (MSVC _List._Mysize)
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
    bool collectSkipped = false;                         // keep details of skipped entries (--dump-skipped)
    bool discover = true;                                // name-based fallback (--no-discover)
    bool verify = true;                                  // --no-verify disables the checks
    double minCoverage = 0.5;                            // share of usable entries required
    double minUniqueRvas = 0.8;                          // share of distinct value addresses required
    std::uintptr_t legacyStart = 0x7000000;              // proven range from v1
    std::uintptr_t legacyEnd = 0x12000000;
    std::size_t chunkSize = 0x10000;                     // multiple of kPageSize
    std::size_t maxListNodes = 2'000'000;                // hard stop against cycles
    bool verbose = false;
};

struct Layout {
    std::uintptr_t mapGlobalRva = 0;  // RVA of the global slot holding the map pointer
                                      // (or of the map object itself when mapEmbedded)
    std::uintptr_t valueGetSet = 0;   // node offset -> ValueGetSet object
    std::uintptr_t flagToValue = 0;   // ValueGetSet offset -> pointer to the value
    bool mapEmbedded = false;         // true: the map object lives directly in the module's data
};

struct Range {
    std::uintptr_t start = 0;  // RVA
    std::uintptr_t end = 0;    // RVA (exclusive)
};

// Address of the map object for a layout (direct, or through the global slot).
[[nodiscard]] inline std::optional<std::uintptr_t> ResolveMapObject(const Memory::Process& process,
                                                                    const Memory::ModuleInfo& module,
                                                                    const Layout& layout) {
    if (layout.mapEmbedded) return module.base + layout.mapGlobalRva;
    return process.Read<std::uintptr_t>(module.base + layout.mapGlobalRva);
}

struct Offsets {
    std::uintptr_t valueGetSet = 0;
    std::uintptr_t flagToValue = 0;
};

// Brute-forces the two offsets so that the node's value pointer leads to `expected`.
[[nodiscard]] inline std::optional<Offsets> ProbeOffsets(const Memory::Process& process, std::uintptr_t node,
                                                         int expected) {
    for (std::uintptr_t getSet = 0x20; getSet <= 0x100; getSet += 8) {
        const auto object = process.Read<std::uintptr_t>(node + getSet);
        if (!object || !Memory::IsUserPointer(*object)) continue;

        for (std::uintptr_t toValue = 0; toValue < 0x300; toValue += 8) {
            const auto pointer = process.Read<std::uintptr_t>(*object + toValue);
            if (!pointer || !Memory::IsUserPointer(*pointer)) continue;

            const auto value = process.Read<int>(*pointer);
            if (value && *value == expected) return Offsets{getSet, toValue};
        }
    }
    return std::nullopt;
}

// Hex dump of `size` bytes at `address` (16 per line), for diagnostics.
[[nodiscard]] inline std::string HexDump(const Memory::Process& process, std::uintptr_t address, std::size_t size) {
    std::vector<std::uint8_t> bytes(size);
    if (!process.ReadBytes(address, bytes.data(), size)) return "  (unreadable)\n";
    std::string out;
    char line[16];
    for (std::size_t i = 0; i < size; i += 16) {
        out += "  " + Memory::ToHex(address + i) + ":";
        for (std::size_t j = i; j < std::min(size, i + 16); ++j) {
            std::snprintf(line, sizeof(line), " %02x", bytes[j]);
            out += line;
        }
        out += '\n';
    }
    return out;
}

// What the name-based discovery fallback saw - printed when it fails, to tell *why*.
struct DiscoveryStats {
    bool attempted = false;
    std::size_t nameHits = 0;        // places where the landmark's name text exists
    std::size_t references = 0;      // pointers to that text
    std::size_t nodes = 0;           // ...that sit in a valid list node
    std::size_t circularLists = 0;   // ...whose list is circular and has a sentinel
    std::size_t mapObjects = 0;      // ...with a map object whose size field matches
    std::size_t probeFailed = 0;     // layouts whose landmark value could not be reached
    std::string firstReferenceDump;  // memory around the first reference (if no node matched)
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

// How the dumper classifies one list node.
enum class NodeStatus { Dumped, BadName, BadObject, StringStored, BadValuePointer };

[[nodiscard]] inline const char* ToString(NodeStatus status) noexcept {
    switch (status) {
        case NodeStatus::Dumped: return "dumped";
        case NodeStatus::BadName: return "bad-name";
        case NodeStatus::BadObject: return "bad-object";
        case NodeStatus::StringStored: return "string-stored";
        case NodeStatus::BadValuePointer: return "bad-value-pointer";
    }
    return "unknown";
}

// A node the dumper did not turn into an offset, with the raw data needed to understand why.
struct SkippedFlag {
    NodeStatus status = NodeStatus::BadName;
    std::string name;                // empty for bad-name
    std::uintptr_t node = 0;
    std::uintptr_t object = 0;       // node + ValueGetSet (0 if unreadable)
    std::uintptr_t valuePointer = 0; // 8 bytes at object + FlagToValue
    std::string text;                // std::string found at object + FlagToValue, if any
    std::string raw;                 // 32 raw bytes (hex) at object + FlagToValue (node + 0x10 for bad-name)
    std::uintptr_t vtableRva = 0;    // module RVA of the object's first qword (its class), 0 if not in the module
    std::uint64_t kind = 0;          // 8 bytes at object + 0x10 (type / size tag seen in --inspect)
};

struct DumpResult {
    std::map<std::string, std::uintptr_t> flags;  // name -> RVA, sorted => stable diffs
    std::vector<SkippedFlag> skipped;             // only filled with Config::collectSkipped
    DumpStats stats;
};

// What the scan saw - printed when no map is found, to tell *why*.
struct ScanStats {
    std::uint64_t bytesRead = 0;
    std::uint64_t bytesUnreadable = 0;
    std::uint64_t pointersTested = 0;  // distinct pointer-like values dereferenced
    std::uint64_t signatureHits = 0;   // ...whose target starts with 1.0f
};

// What the verification measured for the accepted layout (printed by main).
struct VerifyInfo {
    bool performed = false;
    double coverage = 0.0;                         // entries resolved into the module image
    double uniqueRvas = 0.0;                       // distinct value addresses / entries
    std::size_t walkedNodes = 0;                   // list nodes visited
    std::optional<std::uint64_t> declaredSize;     // element count stored in the map object
    std::size_t anchorsMatched = 0;
    std::size_t anchorsTotal = 0;
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

struct NodeInfo {
    NodeStatus status = NodeStatus::BadName;
    std::string name;
    std::uintptr_t object = 0;        // node + ValueGetSet
    std::uintptr_t valuePointer = 0;  // 8 bytes at object + FlagToValue
    std::string text;                 // std::string at object + FlagToValue, if it looks like one
    std::uintptr_t rva = 0;           // value address relative to the module (Dumped only)
};

// The single place that decides what a list node is (shared by the dump and --inspect).
[[nodiscard]] inline NodeInfo ClassifyNode(const Memory::Process& process, const Memory::ModuleInfo& module,
                                           const Layout& layout, std::uintptr_t node) {
    NodeInfo info;

    const auto name = process.ReadMsvcString(node + kNodeNameOffset);
    if (!name) return info;  // BadName
    info.name = *name;

    const auto object = process.Read<std::uintptr_t>(node + layout.valueGetSet);
    if (!object || !Memory::IsUserPointer(*object)) {
        info.status = NodeStatus::BadObject;
        return info;
    }
    info.object = *object;

    if (const auto text = process.ReadMsvcString(*object + layout.flagToValue)) info.text = *text;
    if (const auto pointer = process.Read<std::uintptr_t>(*object + layout.flagToValue)) info.valuePointer = *pointer;

    // Flags that only exist as text (remote / dynamic flags) keep their value as a std::string inside the
    // object, at object + FlagToValue: the value lives on the heap, so there is no module offset to record.
    if (process.LooksLikeMsvcString(*object + layout.flagToValue)) {
        info.status = NodeStatus::StringStored;
        return info;
    }

    // The value must live inside the module image, otherwise the RVA is meaningless.
    if (info.valuePointer < module.base || info.valuePointer - module.base >= module.size ||
        info.valuePointer - module.base < kMinValueRva) {
        info.status = NodeStatus::BadValuePointer;
        return info;
    }

    info.status = NodeStatus::Dumped;
    info.rva = info.valuePointer - module.base;
    return info;
}

// "00 1f ..." for `size` bytes at `address`, or "(unreadable)".
[[nodiscard]] inline std::string HexBytes(const Memory::Process& process, std::uintptr_t address, std::size_t size) {
    std::vector<std::uint8_t> bytes(size);
    if (!process.ReadBytes(address, bytes.data(), size)) return "(unreadable)";
    std::string out;
    char item[8];
    for (std::size_t i = 0; i < size; ++i) {
        std::snprintf(item, sizeof(item), i ? " %02x" : "%02x", bytes[i]);
        out += item;
    }
    return out;
}

// Walks the flag list and collects name -> RVA for every usable entry.
[[nodiscard]] inline std::optional<DumpResult> DumpFlags(const Memory::Process& process,
                                                         const Memory::ModuleInfo& module,
                                                         const Layout& layout, const Config& config) {
    const auto mapObject = ResolveMapObject(process, module, layout);
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

        // Read the successor first, then classify.
        const auto next = process.Read<std::uintptr_t>(node);
        const NodeInfo info = ClassifyNode(process, module, layout, node);

        switch (info.status) {
            case NodeStatus::Dumped:
                if (result.flags.emplace(info.name, info.rva).second) ++stats.dumped;
                else ++stats.duplicates;
                break;
            case NodeStatus::BadName: ++stats.badName; break;
            case NodeStatus::BadObject:
            case NodeStatus::BadValuePointer: ++stats.badPointer; break;
            case NodeStatus::StringStored: ++stats.stringValued; break;
        }

        if (info.status != NodeStatus::Dumped && config.collectSkipped) {
            SkippedFlag entry;
            entry.status = info.status;
            entry.name = info.name;
            entry.node = node;
            entry.object = info.object;
            entry.valuePointer = info.valuePointer;
            entry.text = info.text;
            if (info.object) {
                if (const auto vtable = process.Read<std::uintptr_t>(info.object);
                    vtable && *vtable >= module.base && *vtable < module.base + module.size)
                    entry.vtableRva = *vtable - module.base;
                entry.kind = process.Read<std::uint64_t>(info.object + 0x10).value_or(0);
            }
            entry.raw = info.status == NodeStatus::BadName ? HexBytes(process, node + kNodeNameOffset, 32)
                        : info.object ? HexBytes(process, info.object + layout.flagToValue, 32)
                                      : std::string();
            result.skipped.push_back(std::move(entry));
        }

        if (!next || *next == node) break;
        node = *next;
    }
    return result;
}

// --inspect: a human-readable report about one flag's node and value object.
// Accepts the name with or without its type prefix (FFlag, DFInt, ...).
[[nodiscard]] inline std::optional<std::string> InspectFlag(const Memory::Process& process,
                                                            const Memory::ModuleInfo& module,
                                                            const Layout& layout, const Config& config,
                                                            const std::string& wanted) {
    static const char* const kPrefixes[] = {"DFFlag", "DFInt", "DFString", "DFLog", "SFFlag", "FFlag",
                                            "FInt",   "FString", "FLog"};
    std::vector<std::string> names{wanted};
    for (const char* prefix : kPrefixes) {
        const std::string_view p(prefix);
        if (wanted.size() > p.size() && wanted.compare(0, p.size(), p) == 0) names.push_back(wanted.substr(p.size()));
    }

    const auto mapObject = ResolveMapObject(process, module, layout);
    if (!mapObject) return std::nullopt;
    const auto head = process.Read<std::uintptr_t>(*mapObject + kMapHeadOffset);
    if (!head) return std::nullopt;
    auto node = process.Read<std::uintptr_t>(*head);

    std::size_t visited = 0;
    while (node && Memory::IsUserPointer(*node) && *node != *head && visited++ < config.maxListNodes) {
        const auto name = process.ReadMsvcString(*node + kNodeNameOffset);
        if (name && std::find(names.begin(), names.end(), *name) != names.end()) break;
        const auto next = process.Read<std::uintptr_t>(*node);
        if (!next || *next == *node) return std::nullopt;
        node = next;
    }
    if (!node || !Memory::IsUserPointer(*node) || *node == *head) return std::nullopt;

    const NodeInfo info = ClassifyNode(process, module, layout, *node);
    const auto where = [&](std::uintptr_t address) {
        if (address >= module.base && address < module.base + module.size)
            return Memory::ToHex(address) + " (module RVA " + Memory::ToHex(address - module.base) + ")";
        return Memory::ToHex(address);
    };
    // Qwords inside [address, address + size) that point into the module, with the bytes they point at.
    const auto modulePointers = [&](std::uintptr_t address, std::size_t size) {
        std::string out;
        for (std::size_t off = 0; off + 8 <= size; off += 8) {
            const auto value = process.Read<std::uintptr_t>(address + off);
            if (value && *value >= module.base && *value < module.base + module.size)
                out += "  +" + Memory::ToHex(off) + " -> RVA " + Memory::ToHex(*value - module.base) + ", bytes there: " +
                       HexBytes(process, *value, 8) + "\n";
        }
        return out.empty() ? std::string("  (none)\n") : out;
    };

    std::ostringstream r;
    r << "Flag          : " << info.name << "  (searched as " << wanted << ")\n"
      << "Classified as : " << ToString(info.status) << '\n'
      << "Node          : " << where(*node) << '\n'
      << "Node bytes (+0x00, 0x60):\n" << HexDump(process, *node, 0x60)
      << "Node fields pointing into the module:\n" << modulePointers(*node, 0x60);
    if (info.object) {
        r << "ValueGetSet   : " << where(info.object) << "  (node + " << Memory::ToHex(layout.valueGetSet) << ")\n"
          << "Object bytes (+0x00, 0x100):\n" << HexDump(process, info.object, 0x100)
          << "Object fields pointing into the module:\n" << modulePointers(info.object, 0x100)
          << "At object + " << Memory::ToHex(layout.flagToValue) << " (FlagToValue):\n"
          << "  raw 32 bytes : " << HexBytes(process, info.object + layout.flagToValue, 32) << '\n'
          << "  as pointer   : " << where(info.valuePointer) << '\n'
          << "  as std::string: " << (info.text.empty() ? std::string("(not a valid string)") : "\"" + info.text + "\"") << '\n';
        if (Memory::IsUserPointer(info.valuePointer)) {
            r << "  target bytes : " << HexBytes(process, info.valuePointer, 32) << '\n';
            if (const auto i32 = process.Read<std::int32_t>(info.valuePointer)) r << "  int32 there  : " << *i32 << '\n';
            if (const auto i8 = process.Read<std::uint8_t>(info.valuePointer)) r << "  uint8 there  : " << static_cast<int>(*i8) << '\n';
        }
    } else {
        r << "(no valid ValueGetSet object at node + " << Memory::ToHex(layout.valueGetSet) << ")\n";
    }
    return r.str();
}

class LayoutFinder {
public:
    LayoutFinder(const Memory::Process& process, const Memory::ModuleInfo& module, const Config& config)
        : process_(process), module_(module), config_(config) {}

    // What the name-based fallback saw (attempted == false if it never ran).
    [[nodiscard]] const DiscoveryStats& DiscoveryStatistics() const noexcept { return discovery_; }

    // Counters of the scan so far (see ScanStats).
    [[nodiscard]] const ScanStats& ScanStatistics() const noexcept { return scanStats_; }

    // Measurements of the last accepted layout (performed == false if verification was off).
    [[nodiscard]] const VerifyInfo& Verification() const noexcept { return info_; }

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
        const auto sections = ReadDataSections(process_, module_);
        if (config_.verbose) std::cout << "[scan] " << sections.size() << " writable data section(s) found\n";
        for (const Range& range : sections) {
            if (config_.verbose)
                std::cout << "[scan] section RVA " << Memory::ToHex(range.start) << " - " << Memory::ToHex(range.end) << '\n';
            if (auto layout = ScanRange(range)) return layout;
        }

        // 3) Signature-free fallback: locate the map through the landmark flags' names.
        if (config_.discover) return Discover();
        return std::nullopt;
    }

private:
    // ---- name-based discovery ------------------------------------------------------------
    // Needs no structure signature. Landmark name text -> pointer to it (node + 0x10) -> circular list
    // -> sentinel -> map object (sentinel at +0x08, element count at +0x10) -> global slot in the module.
    std::optional<Layout> Discover() {
        discovery_.attempted = true;
        std::cout << "Signature scan found nothing - searching the process memory by flag name (can take a while)...\n";

        const auto regions = process_.ReadableRegions();
        const auto moduleRegions = MemoryScan::Clip(regions, module_.base, module_.size);

        for (const Anchor& anchor : config_.anchors) {
            std::string pattern = anchor.name;
            pattern.push_back('\0');
            const auto texts = MemoryScan::FindBytes(process_, regions, pattern, 64);
            discovery_.nameHits += texts.size();
            if (config_.verbose)
                std::cout << "[discover] '" << anchor.name << "': " << texts.size() << " text hit(s)\n";

            // Candidate nodes: names >= 16 chars live on the heap (node+0x10 points to the text),
            // shorter names are stored inline at node+0x10.
            std::vector<std::uintptr_t> nodes;
            if (anchor.name.size() < 16) {
                for (const auto text : texts)
                    if (text >= kNodeNameOffset) nodes.push_back(text - kNodeNameOffset);
            } else {
                const auto refs = MemoryScan::FindPointers(process_, regions, texts, 256);
                discovery_.references += refs.size();
                if (discovery_.firstReferenceDump.empty() && !refs.empty() && refs.front().first >= 0x40)
                    discovery_.firstReferenceDump = HexDump(process_, refs.front().first - 0x40, 0xA0);
                for (const auto& ref : refs)
                    if (ref.first >= kNodeNameOffset) nodes.push_back(ref.first - kNodeNameOffset);
            }

            for (const std::uintptr_t node : nodes) {
                if (auto layout = DiscoverFromNode(node, anchor, regions, moduleRegions)) return layout;
            }
        }
        return std::nullopt;
    }

    std::optional<Layout> DiscoverFromNode(std::uintptr_t node, const Anchor& anchor,
                                           const std::vector<Memory::Region>& regions,
                                           const std::vector<Memory::Region>& moduleRegions) {
        // 1) the node must really carry the landmark's name
        const auto name = process_.ReadMsvcString(node + kNodeNameOffset);
        if (!name || *name != anchor.name) return std::nullopt;
        ++discovery_.nodes;

        // 2) walk the circular list; nodes without a valid name are sentinel candidates
        std::vector<std::uintptr_t> sentinels;
        std::size_t length = 0;
        std::uintptr_t current = node;
        do {
            const auto next = process_.Read<std::uintptr_t>(current);
            if (!next || !Memory::IsUserPointer(*next) || ++length > config_.maxListNodes) return std::nullopt;
            if (sentinels.size() < 4 && !process_.ReadMsvcString(*next + kNodeNameOffset)) sentinels.push_back(*next);
            current = *next;
        } while (current != node);
        if (sentinels.empty()) return std::nullopt;
        ++discovery_.circularLists;

        // 3) the map object stores the sentinel at +0x08 and the element count at +0x10
        const auto probe = ProbeOffsets(process_, node, anchor.value);
        for (const std::uintptr_t sentinel : sentinels) {
            for (const auto& head : MemoryScan::FindPointers(process_, regions, {sentinel}, 64)) {
                if (head.first < kMapHeadOffset) continue;
                const std::uintptr_t mapObject = head.first - kMapHeadOffset;
                const auto declared = process_.Read<std::uint64_t>(mapObject + kMapSizeOffset);
                if (!declared || *declared != length - 1) continue;
                ++discovery_.mapObjects;
                if (!probe) {
                    ++discovery_.probeFailed;
                    continue;
                }

                // 4a) a global slot in the module points at the map object
                for (const auto& slot : MemoryScan::FindPointers(process_, moduleRegions, {mapObject}, 8)) {
                    const Layout layout{slot.first - module_.base, probe->valueGetSet, probe->flagToValue, false};
                    if (config_.verbose)
                        std::cout << "[discover] map via slot RVA " << Memory::ToHex(layout.mapGlobalRva) << '\n';
                    if (Verify(layout)) return layout;
                }
                // 4b) the map object itself lies inside the module (no pointer to it)
                if (mapObject >= module_.base && mapObject < module_.base + module_.size) {
                    const Layout layout{mapObject - module_.base, probe->valueGetSet, probe->flagToValue, true};
                    if (config_.verbose)
                        std::cout << "[discover] map embedded at RVA " << Memory::ToHex(layout.mapGlobalRva) << '\n';
                    if (Verify(layout)) return layout;
                }
            }
        }
        return std::nullopt;
    }

    std::optional<Layout> ScanRange(const Range& range) {
        const std::size_t chunk = std::max<std::size_t>(config_.chunkSize & ~std::size_t{7}, kPageSize);
        std::vector<std::uintptr_t> buffer(chunk / sizeof(std::uintptr_t));

        for (std::uintptr_t offset = range.start; offset < range.end; offset += chunk) {
            const std::size_t bytes =
                static_cast<std::size_t>(std::min<std::uintptr_t>(chunk, range.end - offset)) & ~std::size_t{7};
            if (bytes == 0) break;

            if (process_.ReadBytes(module_.base + offset, buffer.data(), bytes)) {
                scanStats_.bytesRead += bytes;
                if (auto layout = ScanBlock(buffer.data(), bytes / sizeof(std::uintptr_t), offset)) return layout;
                continue;
            }

            // The chunk contains unreadable pages: retry page by page.
            for (std::size_t page = 0; page < bytes; page += kPageSize) {
                const std::size_t n = std::min(kPageSize, bytes - page);
                if (!process_.ReadBytes(module_.base + offset + page, buffer.data(), n)) {
                    scanStats_.bytesUnreadable += n;
                    continue;
                }
                scanStats_.bytesRead += n;
                if (auto layout = ScanBlock(buffer.data(), n / sizeof(std::uintptr_t), offset + page))
                    return layout;
            }
        }
        return std::nullopt;
    }

    std::optional<Layout> ScanBlock(const std::uintptr_t* slots, std::size_t count, std::uintptr_t blockRva) {
        for (std::size_t i = 0; i < count; ++i) {
            const std::uintptr_t candidate = slots[i];
            if (candidate < kMinMapPointer || !Memory::IsUserPointer(candidate) || (candidate & 3)) continue;
            if (!checked_.insert(candidate).second) continue;  // already validated
            ++scanStats_.pointersTested;

            const auto signature = process_.Read<std::uint32_t>(candidate);
            if (!signature || *signature != kLoadFactorSignature) continue;
            ++scanStats_.signatureHits;

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

    // Landmark node -> Layout (offsets come from ProbeOffsets).
    std::optional<Layout> ProbeAnchor(std::uintptr_t node, std::uintptr_t slotRva, int expected) const {
        if (const auto offsets = ProbeOffsets(process_, node, expected))
            return Layout{slotRva, offsets->valueGetSet, offsets->flagToValue, false};
        return std::nullopt;
    }

    // Second opinion on a layout found with one anchor. The outcome is recorded in
    // report_ (always, not only with --verbose) so a failed run can explain itself.
    bool Verify(const Layout& layout) {
        if (!config_.verify) return true;
        report_.clear();
        VerifyInfo info;

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
        info.coverage = coverage;
        info.walkedNodes = dump->stats.nodes;

        // Every flag owns its storage: a wrong layout tends to funnel many entries to one address.
        std::unordered_set<std::uintptr_t> addresses;
        for (const auto& entry : dump->flags) addresses.insert(entry.second);
        info.uniqueRvas = static_cast<double>(addresses.size()) / static_cast<double>(dump->flags.size());
        Note("unique value addresses " + std::to_string(static_cast<int>(info.uniqueRvas * 100)) + "%");
        if (info.uniqueRvas < config_.minUniqueRvas) {
            Note("rejected: too many entries share one value address");
            return false;
        }

        // The map object stores its own element count: compare it with what we walked (soft check).
        if (const auto mapObject = ResolveMapObject(process_, module_, layout))
            info.declaredSize = process_.Read<std::uint64_t>(*mapObject + kMapSizeOffset);
        if (info.declaredSize) {
            Note("list size field " + std::to_string(*info.declaredSize) + ", walked " +
                 std::to_string(info.walkedNodes) +
                 (*info.declaredSize == info.walkedNodes ? " (match)" : " (differs - warning only)"));
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
            info.anchorsMatched = matches;
            info.anchorsTotal = config_.anchors.size();
        }
        info.performed = true;
        info_ = info;
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
    VerifyInfo info_;
    ScanStats scanStats_;
    DiscoveryStats discovery_;
};

}  // namespace Scanner
