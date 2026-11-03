#!/usr/bin/env python3
"""pick_anchors.py - find long-lived anchor flags from several FFlags.json dumps.

Workflow
  1. For each Roblox version, run:   RobloxFFlagDumper --values --out dumps\\<version>
  2. Collect 3+ dumps (the more versions, the better), then run:
         python pick_anchors.py dumps/*/FFlags.json
  3. Paste the suggested  --anchor Name=Value  arguments into the dumper.

What makes a good anchor
  * present in every dump and with the SAME value in all of them (long-lived);
  * an uncommon value (not 0, 1, -1): the offset probe matches by value, so a value that
    many other fields share causes false matches. Rarer inside the dump = better;
  * integer flag. Bool flags only occupy 1 byte, so their 4-byte read picks up neighbouring
    bytes - they rarely stay identical across versions and drop out on their own.
"""
import argparse
import json
import sys
from collections import Counter


def load(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    values = data.get("Values")
    if not isinstance(values, dict) or not values:
        sys.exit(f"{path}: no 'Values' block - run the dumper with --values")
    version = data.get("Meta", {}).get("RobloxVersion", path)
    return version, values


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dumps", nargs="+", help="FFlags.json files, ideally oldest to newest")
    ap.add_argument("--min-versions", type=int, default=0,
                    help="minimum dumps a flag must be stable in (default: all of them)")
    ap.add_argument("--top", type=int, default=15, help="how many candidates to list (default 15)")
    args = ap.parse_args()

    dumps = [load(p) for p in args.dumps]
    if len(dumps) < 2:
        sys.exit("Need at least 2 dumps from different Roblox versions to judge stability.")
    need = args.min_versions or len(dumps)

    # How common is each value inside the newest dump? (rarer = safer anchor)
    newest_values = dumps[-1][1]
    value_freq = Counter(newest_values.values())

    names = set().union(*(set(v) for _, v in dumps))
    rows = []
    for name in names:
        seen = [v[name] for _, v in dumps if name in v]
        if len(seen) < need:
            continue
        value, count = Counter(seen).most_common(1)[0]
        if count < need or value in (0, 1, -1):
            continue
        rows.append((-count, value_freq.get(value, 0), name, value, count))

    rows.sort()
    if not rows:
        sys.exit("No flag kept the same value in enough dumps. Try --min-versions with a smaller number.")

    print(f"{len(dumps)} dumps: " + ", ".join(version for version, _ in dumps))
    print(f"{'flag':<55} {'value':>12} {'stable in':>10} {'same value in dump':>19}")
    for _, freq, name, value, count in rows[: args.top]:
        print(f"{name:<55} {value:>12} {count:>5}/{len(dumps):<4} {freq:>19}")

    best = rows[:3]
    print("\nSuggested arguments:")
    print("  " + " ".join(f"--anchor {name}={value}" for _, _, name, value, _ in best))


if __name__ == "__main__":
    main()