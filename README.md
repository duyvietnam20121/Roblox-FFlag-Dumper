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
| `--anchor Name=Value` | Flag with a known value used to calibrate offsets (default `BatchThumbnailMinWaitMs=15`). Change it if Roblox changes that default. |
| `--verbose` | Print scanning details |
| `--no-pause` | Do not wait for Enter at the end (CI / scripts) |

Exit codes: `0` ok, `1` cannot attach, `2` map not found, `3` dump/IO failure, `64` bad usage.

## How it works

1. Scan the image's data (`0x7000000-0x12000000` first, then every writable non-executable PE section)
   for a pointer to an `unordered_map` object (first qword `0x3F800000` = load factor `1.0f`).
2. Walk its node list until the anchor flag is found, then brute-force the two offsets that lead from
   the node to the anchor's value.
3. Walk the whole list again and keep every entry whose value pointer lies inside the module image.

## Output

`FFlags.json` contains `Meta` (Roblox version, UTC time, flag count), `FFlagOffsets` and `FFlags`.
Entries are sorted by name, so two dumps can be compared with a plain `diff`.
`FFlags.hpp` uses `inline constexpr std::uintptr_t`, so it can be included from multiple translation units.

## Disclaimer

This repository is intended solely for educational and research purposes. Users are responsible for
ensuring compliance with all applicable laws and terms of service.
