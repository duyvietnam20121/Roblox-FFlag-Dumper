# Roblox FFlag Dumper

Dumps the FFlag layout and offsets of a **running** Roblox client without any hardcoded offsets:

- `FFlagList`, `ValueGetSet`, `FlagToValue` (the structure offsets, calibrated automatically)
- every dumpable FFlag as an RVA, to `FFlags.json` and `FFlags.hpp`

The tool is **read-only**: it opens the process with `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` only.

## Build

Visual Studio 2022 (toolset v143), open `RobloxFFlagDumper.sln`, pick `Release | x64`
(or `ARM64`). C++17 is required. Win32 is not supported - the target process is 64-bit.

## Usage

```
RobloxFFlagDumper [--out <dir>] [--process <exe>] [--anchor Name=Value]
                  [--verbose] [--no-pause] [--help]
```

| Option | Meaning |
| --- | --- |
| `--out <dir>` | Output directory (default: current directory) |
| `--process <exe>` | Target process (default `RobloxPlayerBeta.exe`) |
| `--anchor Name=Value` | Integer flag with a known value (landmark). **Repeatable**: `--anchor A=1 --anchor B=2`. Default landmarks: `BatchThumbnailMinWaitMs=15` and `StreamingSafeMemWatermarkMB=100` - either one is enough, so one changed default does not break the tool. The first `--anchor` replaces the defaults, and your own landmarks are checked strictly. Max 4. Any landmark can locate the layout. With 1-2 landmarks all must read back their value; with 3-4 one may differ, so a single changed default does not break the dump. |
| `--values` | Also store each flag's current int value in `FFlags.json` (`Values` block), to pick stable anchors |
| `--no-verify` | Skip layout verification (coverage check and landmark check) |
| `--verbose` | Print scanning details |
| `--no-pause` | Do not wait for Enter at the end (CI / scripts) |

Exit codes: `0` ok, `1` cannot attach, `2` map not found, `3` dump/IO failure, `64` bad usage.

## How it works

1. Scan the image's data (`0x7000000-0x12000000` first, then every writable non-executable PE section)
   for a pointer to an `unordered_map` object (first qword `0x3F800000` = load factor `1.0f`).
2. Walk its node list until the anchor flag is found, then brute-force the two offsets that lead from
   the node to the anchor's value.
3. **Verify** the layout: walking the list with it must resolve most entries to pointers inside the module
   (a wrong layout resolves almost none), and the landmarks must read back their expected values (all of them with 1-2 landmarks, all but one with 3-4). If the layout is rejected, the tool prints why, including the value it actually read for each landmark.
   A rejected layout makes the scan continue with other candidates.
4. Walk the whole list again and keep every entry whose value pointer lies inside the module image.

## Picking long-lived anchors

An anchor only helps if its value survives Roblox updates. To find out which ones do:

1. For each Roblox version run `RobloxFFlagDumper --values --out dumps\<version>`.
2. With 3+ dumps from different versions: `python tools/pick_anchors.py dumps/*/FFlags.json`
3. Paste the suggested `--anchor Name=Value` arguments into the dumper.

The script keeps flags that have the same value in every dump (`--min-versions N` relaxes this) and
prefers uncommon values, since the offset probe matches by value.

## Output

`FFlags.json` contains `Meta` (Roblox version taken from the `version-<hash>` install folder, UTC date/time, flag count), `FFlagOffsets` and `FFlags`.
Entries are sorted by name, so two dumps can be compared with a plain `diff`.
`FFlags.hpp` starts with a comment line (version + UTC date/time) and uses `inline constexpr`, so it can be included
from multiple translation units:

```cpp
namespace FFlagOffsets {
    inline constexpr std::string_view ClientVersion = "version-5a21b87bbc2641cf";
    namespace FFlagList { Pointer, ToFlag, ToValue }   // calibrated offsets
    namespace FFlags    { <FlagName> = <RVA>; ... }
}
```

## Disclaimer

This repository is intended solely for educational and research purposes. Users are responsible for
ensuring compliance with all applicable laws and terms of service.
