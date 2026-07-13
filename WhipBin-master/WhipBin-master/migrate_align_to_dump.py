#!/usr/bin/env python3
"""Reconcile WhipClient mapping keys with whatever the auto-mapper actually
emits — overload suffixes are determined by the real reference jar, not by
what lunar.json speculated existed.

Concretely: lunar.json had three aliases for MovingObjectPosition's constructor,
but the notch jar only ships one `<init>(Entity, Vec3)`, so the auto-mapper
emits `MovingObjectPosition#<init>` (no overload to disambiguate). The prior
Phase 3 migration had already rewritten the client to `<init>_Entity_Vec3`
based on the lunar signatures — this script walks those back when the
suffixed key has no counterpart in the fresh dump.

Rule per call site `mappings->getX("Class#key")`:
  - If Class#key is already present in the dump -> leave it.
  - Else strip the `_Type_Type_...` suffix. If the bare form exists in the
    dump, rewrite to it.
  - Else leave and warn — means the key is simply unmapped (legacy, or the
    auto-mapper didn't resolve it) and will be caught by the runtime
    "not mapped" warning on first use.
"""
import re
import json
import argparse
from pathlib import Path
from collections import defaultdict

CLIENT_ROOT = Path(r"C:/Users/Kot/Desktop/w/WhipClient")
CHEATBREAKER_JSON = Path(r"C:/Users/Kot/Desktop/w/WhipBin/mappings/v1_8_9/cheatbreaker.json")

RX_CALL = re.compile(r'mappings->get(Field|Method|Object)\(\s*"([^"]+)"\s*\)')
RX_STRIP_SUFFIX = re.compile(r'^(.+?)(_[A-Z][A-Za-z0-9$]*(?:_[A-Z][A-Za-z0-9$]*)*|_[IZFDJBCSV]+(?:_[IZFDJBCSV]+)*)$')


def build_keys_per_class(dump):
    """Returns {class_key: {field_keys}, ...}.

    isGlobal=1 fields are registered in BOTH `fields` and `objects`: the
    WhipClient MappingHandler now keeps the fieldID alongside the cached
    global jobject, so both `getField(...)` and `getObject(...)` resolve.
    """
    fields = defaultdict(set)
    methods = defaultdict(set)
    objects = defaultdict(set)
    for class_key, entry in dump.items():
        for fk, fv in entry.get('fields', {}).items():
            fields[class_key].add(fk)
            if fv.get('isGlobal', 0):
                objects[class_key].add(fk)
        for mk in entry.get('methods', {}):
            methods[class_key].add(mk)
    return fields, methods, objects


def strip_type_suffix(key):
    """Greedy strip of the auto-generated `_Type_Type_...` suffix. Yields a
    list of candidate unsuffixed keys from most- to least-stripped.

    Example: `<init>_Entity_Vec3` -> [`<init>_Entity_Vec3`, `<init>_Entity`, `<init>`]
    """
    out = [key]
    cur = key
    while True:
        m = re.match(r'^(.+?)_([A-Z][A-Za-z0-9$]*(?:Arr)*|[IZFDJBCSV](?:Arr)*)$', cur)
        if not m:
            break
        cur = m.group(1)
        out.append(cur)
    return out


def class_name_candidates(cls):
    """Legacy `_` inner-class separator -> bytecode `$`, both orientations."""
    out = [cls]
    if '_' in cls and '$' not in cls:
        # First `_` to `$`: `MovingObjectPosition_MovingObjectType` -> `MovingObjectPosition$MovingObjectType`
        idx = cls.find('_')
        out.append(cls[:idx] + '$' + cls[idx+1:])
    return out


def key_candidates(key):
    """Candidates for a member key.

    Beyond overload-suffix stripping, also strip a leading class-name prefix
    on enum constants (`MovingObjectType_BLOCK` -> `BLOCK`) — legacy from when
    lunar.json inlined the owner class into the key.
    """
    cands = list(strip_type_suffix(key))
    # Enum-constant prefix: `<ClassName>_<CONSTANT>` -> `<CONSTANT>`
    m = re.match(r'^([A-Z][A-Za-z0-9]*)_([A-Z0-9_]+)$', key)
    if m:
        cands.append(m.group(2))
    return cands


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dry', action='store_true')
    args = ap.parse_args()

    dump = json.load(open(CHEATBREAKER_JSON, encoding='utf-8'))
    fields_set, methods_set, objects_set = build_keys_per_class(dump)

    def have(kind, cls, key):
        bucket = {'Field': fields_set, 'Method': methods_set, 'Object': objects_set}[kind]
        return key in bucket.get(cls, set())

    total_fixed = 0
    total_unmapped = 0
    files_touched = 0
    warnings = []

    for path in list(CLIENT_ROOT.rglob('*.h')) + list(CLIENT_ROOT.rglob('*.cpp')):
        try:
            content = path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            continue
        if 'mappings->get' not in content:
            continue

        edits = [0]
        unmapped = [0]

        def repl(m):
            kind, full_key = m.group(1), m.group(2)
            if '#' not in full_key:
                return m.group(0)
            cls, key = full_key.split('#', 1)

            # Try (class_candidate, key_candidate) combinations in order of
            # "closest to what the user typed" so the first match wins. This
            # catches `_` -> `$` inner-class renames AND overload-suffix
            # stripping in a single pass.
            for new_cls in class_name_candidates(cls):
                for new_key in key_candidates(key):
                    if have(kind, new_cls, new_key):
                        if new_cls != cls or new_key != key:
                            edits[0] += 1
                            return f'mappings->get{kind}("{new_cls}#{new_key}")'
                        return m.group(0)
            unmapped[0] += 1
            warnings.append(f'{path.relative_to(CLIENT_ROOT).as_posix()}: unmapped {kind} {cls}#{key}')
            return m.group(0)

        new_content = RX_CALL.sub(repl, content)
        if edits[0] > 0:
            files_touched += 1
            total_fixed += edits[0]
            if not args.dry:
                path.write_text(new_content, encoding='utf-8', newline='')
            print(f'{"[DRY]" if args.dry else "     "} {path.relative_to(CLIENT_ROOT).as_posix()}: {edits[0]} realign(s)')
        total_unmapped += unmapped[0]

    print(f'\nFiles realigned: {files_touched}, keys realigned: {total_fixed}')
    print(f'Unmapped keys left (runtime "not mapped" warnings): {total_unmapped}')
    if warnings:
        print('\nUnmapped call sites:')
        for w in warnings[:40]:
            print(f'  {w}')
        if len(warnings) > 40:
            print(f'  ... and {len(warnings) - 40} more')


if __name__ == '__main__':
    main()
