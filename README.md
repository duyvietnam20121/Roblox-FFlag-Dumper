# Roblox FFlag Dumper

Dumps the FFlag layout and offsets of a **running** Roblox client without any hardcoded offsets:

- the structure offsets (`Pointer`, `ToFlag`, `ToValue`), calibrated automatically from landmark flags
- every dumpable FFlag as an RVA, written to `FFlags.json` and `FFlags.hpp`

The tool is **read-only**: it opens the process with `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` only.

## Build

Visual Studio 2022 (toolset v143): open `RobloxFFlagDumper.sln`, choose `Release | x64` (or `ARM64`) and build.
C++17 is required. Win32 is not supported - the target process is 64-bit. Release builds link the C runtime
statically, so the exe runs without the Visual C++ Redistributable.

The binary ends up in `x64\Release\RobloxFFlagDumper.exe` (or `ARM64\Release\`). Run it from that folder, or
with its full path - `.\RobloxFFlagDumper.exe` only works when the exe is in the current directory.

GitHub Actions (`.github/workflows/build.yml`) builds x64 and ARM64 on every push / pull request and attaches
`RobloxFFlagDumper-x64.exe` and `RobloxFFlagDumper-ARM64.exe` to a release when you push a `v*` tag.

## Usage

Start Roblox first, then:

```
RobloxFFlagDumper [--out <dir>] [--process <exe>] [--anchor Name=Value]...
                  [--values] [--no-verify] [--verbose] [--no-pause] [--help]
```

| Option | Meaning |
| --- | --- |
| `--out <dir>` | Output directory (default: current directory) |
| `--process <exe>` | Target process (default `RobloxPlayerBeta.exe`) |
| `--anchor Name=Value` | Landmark: an **integer** flag with a known value. Repeatable, **max 4** (`--anchor2` is an alias). See [Landmarks](#landmarks). |
| `--values` | Also store each flag's current int value in `FFlags.json` (`Values` block) - input for `pick_anchors.py` |
| `--no-verify` | Skip layout verification |
| `--verbose` | Print scanning and verification details |
| `--no-pause` | Do not wait for Enter at the end (scripts / CI) |

Exit codes: `0` ok, `1` cannot attach, `2` map not found, `3` dump/IO failure, `64` bad usage.

## Landmarks

A landmark is an integer flag whose value you know. The tool finds the flag map by looking for it and
learns the two structure offsets from where its value lives.

- **Defaults:** `BatchThumbnailMinWaitMs=15` and `StreamingSafeMemWatermarkMB=100`. Either one is enough, so a
  Roblox update that changes one of them does not break the tool.
- **Your own:** the first `--anchor` replaces the defaults, and your landmarks are checked strictly: with 1-2
  landmarks all must read back their value, with 3-4 one may differ.
- Only integer flags work. Bool / `u8` flags occupy 1 byte (a 4-byte read picks up neighbouring bytes, e.g.
  `GfxClustersFull` reads as `768`) and string flags are not numbers at all. Values `0` / `1` are too common.
- Names in the map have no `F` / `DF` / `FInt` prefix: pass `BatchThumbnailMinWaitMs`, not `FIntBatchThumbnailMinWaitMs`.

## How it works

1. Scan the image's data (`0x7000000-0x12000000` first, then every writable non-executable PE section) for a
   pointer to an `unordered_map` object (first qword `0x3F800000` = load factor `1.0f`).
2. Walk its node list; at a node named like a landmark, brute-force the two offsets that lead from the node to
   the landmark's value.
3. **Verify** the layout (below). A rejected layout makes the scan continue with other candidates.
4. Walk the whole circular list again and keep every entry whose value pointer lies inside the module image.

### Verification

The accepted layout must pass all of these (disable with `--no-verify`):

| Check | What it catches |
| --- | --- |
| **Coverage** >= 50% | A wrong layout resolves almost no value pointers into the module image, a right one resolves most. |
| **Unique addresses** >= 80% | Every flag owns its storage; a wrong layout tends to point many entries at one address. |
| **Landmarks** | They must read back their expected value (see [Landmarks](#landmarks)). |
| **List size** (reported, soft) | Nodes walked vs. the element count stored in the map object itself. A mismatch is shown as a warning. |

The summary is printed after every run, for example:

```
Verification: coverage 93% | unique addresses 100% | list size 4521 vs walked 4521 (match) | landmarks 2/2
```

When a layout is rejected the tool says why, including the value it actually read for each landmark:

```
A map was found but its layout was rejected:
  - anchor BatchThumbnailMinWaitMs: expected 15, read 15
  - anchor StreamingSafeMemWatermarkMB: expected 100, read 150
  - anchors matched 1/2 (need 2)
```

The thresholds (50% / 80%) are empirical; if a correct layout is rejected, run with `--verbose` and
`--no-verify` and compare.

## Picking long-lived landmarks

A landmark only helps if its value survives Roblox updates. To find out which ones do:

1. For each Roblox version run `RobloxFFlagDumper --values --out dumps\<version>`.
2. With 2+ dumps from different versions: `python tools/pick_anchors.py dumps/*/FFlags.json`
3. Paste the suggested `--anchor Name=Value` arguments into the dumper.

The script keeps flags that have the same value in every dump (`--min-versions N` relaxes this), skips `0` / `1` / `-1`
and prefers uncommon values, since the offset probe matches by value.

## Output

`FFlags.json`:

| Block | Content |
| --- | --- |
| `Meta` | `Process`, `RobloxVersion` (e.g. `version-5a21b87bbc2641cf`, taken from the install folder name), `GeneratedAt` (UTC date/time), `ImageSize`, `FlagCount` |
| `FFlagOffsets` | `FFlagList`, `ValueGetSet`, `FlagToValue` |
| `FFlags` | flag name -> RVA, sorted by name so two dumps can be compared with a plain `diff` |
| `Values` | only with `--values`: flag name -> current int value |

`FFlags.hpp` starts with a comment line (version and UTC date/time) and uses `inline constexpr`, so it can be
included from several translation units:

```cpp
// Generated by RobloxFFlagDumper | version-5a21b87bbc2641cf | 2026-11-03 05:06:00 UTC
#pragma once
#include <cstdint>
#include <string_view>

namespace FFlagOffsets {
    inline constexpr std::string_view ClientVersion = "version-5a21b87bbc2641cf";

    namespace FFlagList {
        inline constexpr std::uintptr_t Pointer = 0x83eba48;  // JSON: FFlagList
        inline constexpr std::uintptr_t ToFlag = 0x30;        // JSON: ValueGetSet
        inline constexpr std::uintptr_t ToValue = 0x20;       // JSON: FlagToValue
    }

    namespace FFlags {
        inline constexpr std::uintptr_t SomeFlagName = 0x7fdce50;
        // ...
    }
}
```

Flag names that are not valid C++ identifiers are sanitised (non-alphanumerics become `_`, a leading digit gets
a `_` prefix); the JSON keeps the real names.

## Project layout

```
RobloxFFlagDumper.sln
RobloxFFlagDumper/
    main.cpp        CLI, orchestration, exit codes
    Memory.hpp      read-only process access (RAII), MSVC std::string reader
    Scanner.hpp     layout finder, verification, flag dump
    Output.hpp      FFlags.json / FFlags.hpp writers, version and timestamp
tools/pick_anchors.py
.github/workflows/build.yml
```

## Disclaimer

This repository is intended solely for educational and research purposes. Users are responsible for
ensuring compliance with all applicable laws and terms of service.
