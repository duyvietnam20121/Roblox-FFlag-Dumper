#pragma once
// ---------------------------------------------------------------------------
// MemoryScan.hpp - byte / pointer searches over the target's readable memory.
// Used by the name-based discovery fallback (no structure signature needed).
// ---------------------------------------------------------------------------

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include "Memory.hpp"

namespace MemoryScan {

inline constexpr std::size_t kChunk = std::size_t{1} << 20;
inline constexpr std::size_t kPage = 0x1000;

// visit(address, data, size, owned): `data` holds `size` bytes read at `address`; only the first
// `owned` bytes belong to this chunk (the rest is overlap with the next one). Return false to stop.
using Visitor = std::function<bool(std::uintptr_t, const std::uint8_t*, std::size_t, std::size_t)>;

inline void ForEachChunk(const Memory::Process& process, const std::vector<Memory::Region>& regions,
                         std::size_t overlap, const Visitor& visit) {
    std::vector<std::uint8_t> buffer(kChunk + overlap);
    for (const Memory::Region& region : regions) {
        for (std::size_t offset = 0; offset < region.size; offset += kChunk) {
            const std::size_t owned = std::min(kChunk, region.size - offset);
            const std::size_t total = std::min(kChunk + overlap, region.size - offset);
            const std::uintptr_t address = region.base + offset;

            if (process.ReadBytes(address, buffer.data(), total)) {
                if (!visit(address, buffer.data(), total, owned)) return;
                continue;
            }
            // Some page of the chunk is unreadable: go page by page (no overlap).
            for (std::size_t page = 0; page < owned; page += kPage) {
                const std::size_t n = std::min(kPage, owned - page);
                if (process.ReadBytes(address + page, buffer.data(), n) && !visit(address + page, buffer.data(), n, n))
                    return;
            }
        }
    }
}

// The parts of `regions` that lie inside [base, base + size).
[[nodiscard]] inline std::vector<Memory::Region> Clip(const std::vector<Memory::Region>& regions,
                                                      std::uintptr_t base, std::size_t size) {
    std::vector<Memory::Region> out;
    const std::uintptr_t end = base + size;
    for (const Memory::Region& r : regions) {
        const std::uintptr_t lo = std::max(r.base, base);
        const std::uintptr_t hi = std::min(r.base + r.size, end);
        if (lo < hi) out.push_back({lo, static_cast<std::size_t>(hi - lo)});
    }
    return out;
}

// Addresses where `pattern` occurs (at most `limit`).
[[nodiscard]] inline std::vector<std::uintptr_t> FindBytes(const Memory::Process& process,
                                                           const std::vector<Memory::Region>& regions,
                                                           std::string_view pattern, std::size_t limit) {
    std::vector<std::uintptr_t> hits;
    if (pattern.empty()) return hits;
    ForEachChunk(process, regions, pattern.size() - 1,
                 [&](std::uintptr_t base, const std::uint8_t* data, std::size_t size, std::size_t owned) {
                     const std::string_view view(reinterpret_cast<const char*>(data), size);
                     for (std::size_t pos = view.find(pattern); pos != std::string_view::npos && pos < owned;
                          pos = view.find(pattern, pos + 1)) {
                         hits.push_back(base + pos);
                         if (hits.size() >= limit) return false;
                     }
                     return true;
                 });
    return hits;
}

// 8-byte aligned slots whose value is one of `values`: (slot address, value). At most `limit`.
[[nodiscard]] inline std::vector<std::pair<std::uintptr_t, std::uintptr_t>> FindPointers(
    const Memory::Process& process, const std::vector<Memory::Region>& regions,
    const std::vector<std::uintptr_t>& values, std::size_t limit) {
    std::vector<std::pair<std::uintptr_t, std::uintptr_t>> hits;
    if (values.empty()) return hits;

    const std::unordered_set<std::uintptr_t> wanted(values.begin(), values.end());
    const auto [lo, hi] = std::minmax_element(values.begin(), values.end());
    const std::uintptr_t minValue = *lo;
    const std::uintptr_t maxValue = *hi;

    ForEachChunk(process, regions, 0,
                 [&](std::uintptr_t base, const std::uint8_t* data, std::size_t size, std::size_t) {
                     for (std::size_t i = 0; i + sizeof(std::uintptr_t) <= size; i += sizeof(std::uintptr_t)) {
                         std::uintptr_t value = 0;
                         std::memcpy(&value, data + i, sizeof(value));
                         if (value < minValue || value > maxValue || wanted.count(value) == 0) continue;
                         hits.emplace_back(base + i, value);
                         if (hits.size() >= limit) return false;
                     }
                     return true;
                 });
    return hits;
}

}  // namespace MemoryScan
