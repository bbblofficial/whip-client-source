#!/usr/bin/env python3
"""One-shot in-place patch: bump isGlobal=1 for every static object/array field
in the launcher JSONs the auto-generator (`generate_deobf_mappings.py`) emits.

Mirrors the source-side fix in `generate_deobf_mappings.py`: the auto-generator
used to hard-code `isGlobal: 0` for every field, which made `mappings->getObject(...)`
return null for enum singletons on Lunar/Forge/Vanilla and silently broke
break-block / autotool / anti-bot / trajectories / tick-locker. This script
brings the already-generated JSONs into line with the fixed generator without
needing to re-run the full auto-mapper pipeline.

Scope: only edits files we generate (lunar/forge/vanilla, both versions).
Skips cheatbreaker.json — that one is produced by a separate Java auto-mapper
and already emits isGlobal=1 where it matters.
"""
from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parent / "mappings"
TARGETS = [
    "v1_7_10/lunar.json",
    "v1_7_10/forge.json",
    "v1_7_10/vanilla.json",
    "v1_8_9/lunar.json",
    "v1_8_9/forge.json",
    "v1_8_9/vanilla.json",
]


def needs_global(field_entry: dict) -> bool:
    if field_entry.get("isGlobal", 0):
        return False
    if not field_entry.get("isStatic", 0):
        return False
    sig = field_entry.get("sig", "")
    return bool(sig) and sig[0] in ("L", "[")


def patch_file(path: Path) -> int:
    data = json.loads(path.read_text(encoding="utf-8"))
    flipped = 0
    for cls in data.values():
        for fv in cls.get("fields", {}).values():
            if needs_global(fv):
                fv["isGlobal"] = 1
                flipped += 1
    if flipped:
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return flipped


def main():
    total = 0
    for rel in TARGETS:
        p = ROOT / rel
        if not p.exists():
            print(f"[skip] {p} not found", file=sys.stderr)
            continue
        n = patch_file(p)
        total += n
        print(f"[patch] {rel}: bumped {n} static-object fields to isGlobal=1")
    print(f"[done] total: {total} fields updated")


if __name__ == "__main__":
    main()
