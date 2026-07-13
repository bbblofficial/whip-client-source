#!/usr/bin/env python3
"""Strict per-version mapping verifier for WhipClient.

The existing `mapping_pipeline.py` only flags mappings that are unknown across
ALL versions, so a key that exists in lunar.json but is missing from
cheatbreaker.json slips through silently — the C++ code compiles, boots, and
then blows up at runtime with undefined behaviour because `GetObjectField`
gets a nullptr fieldID.

This tool closes that gap. For each key the C++ code references via
`mappings->get{Class,Field,Method,Object}("x")`, it confirms that the target
version's JSON contains a fully-populated mapping (non-empty name + sig where
applicable). Anything else is reported with the call-site that exercises it
so we can go fix the dump or the wrapper.

Usage:
    python tools/verify_mappings.py <version> [--client-root <path>]

Example:
    python tools/verify_mappings.py cheatbreaker
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

MAPPING_CALL_REGEX = re.compile(
    r'mappings(?:->|\.getInstance\(\)\.)\s*get(Class|Field|Method|Object)\s*\(\s*"([^"]+)"\s*\)'
)
WRAPPER_FUNC_REGEX = re.compile(r'(\w+)\s*\([^;=]*\)\s*(?:const\s*)?(?:override\s*)?\{')
CPP_KEYWORDS = frozenset((
    'if', 'for', 'while', 'switch', 'class', 'struct',
    'namespace', 'catch', 'return', 'do', 'else',
))


def load_json(path: Path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def scan_client_keys(client_root: Path):
    """Walk every .h/.cpp under the client, yield (key, kind, file, line)."""
    used = []
    exts = {'.h', '.hpp', '.cpp', '.c'}
    for p in client_root.rglob('*'):
        if p.suffix not in exts:
            continue
        try:
            text = p.read_text(encoding='utf-8', errors='ignore')
        except OSError:
            continue
        for m in MAPPING_CALL_REGEX.finditer(text):
            kind, key = m.group(1), m.group(2)
            line = text.count('\n', 0, m.start()) + 1
            used.append((key, kind, p, line))
    return used


def flatten_mapping(version_json):
    """Return sets of classes, fields, methods and full metadata dicts."""
    classes = {}
    fields = defaultdict(list)   # key -> [(class_key, entry)]
    methods = defaultdict(list)
    objects = defaultdict(list)

    for class_key, class_data in version_json.items():
        classes[class_key] = class_data
        for fkey, fv in class_data.get('fields', {}).items():
            if fv.get('isGlobal'):
                objects[fkey].append((class_key, fv))
            else:
                fields[fkey].append((class_key, fv))
        for mkey, mv in class_data.get('methods', {}).items():
            methods[mkey].append((class_key, mv))
    return classes, fields, methods, objects


def entry_looks_valid(entry):
    """Heuristic: mapping entry must have a non-empty name and sig.
    `<init>` is an accepted method name — it's the JVM marker for constructors."""
    name = entry.get('name', '')
    sig = entry.get('sig', '')
    if not name:
        return False, 'empty name'
    if not sig:
        return False, 'empty sig'
    return True, ''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('version', help='Mapping version to verify (e.g. cheatbreaker or lunar)')
    parser.add_argument('--client-root', default='C:/Users/Kot/Desktop/w/WhipClient',
                        help='Root of the WhipClient source tree')
    parser.add_argument('--mappings-root', default='C:/Users/Kot/Desktop/w/WhipBin/mappings',
                        help='Root of the WhipBin mappings tree')
    parser.add_argument('--minecraft-version', default='v1_8_9',
                        help='Minecraft version directory inside mappings root')
    parser.add_argument('--max-callsites', type=int, default=3,
                        help='Max call-sites to print per missing key')
    args = parser.parse_args()

    client_root = Path(args.client_root)
    mappings_path = Path(args.mappings_root) / args.minecraft_version / f'{args.version}.json'
    if not mappings_path.exists():
        print(f'[verify] Mapping file not found: {mappings_path}', file=sys.stderr)
        sys.exit(2)

    mapping = load_json(mappings_path)
    classes, fields, methods, objects = flatten_mapping(mapping)

    used = scan_client_keys(client_root)
    callsites = defaultdict(list)
    for key, kind, p, line in used:
        callsites[(kind, key)].append((p, line))

    print(f'[verify] Mapping: {mappings_path}')
    print(f'[verify] Scanned client root: {client_root}')
    print(f'[verify] C++ call-sites found: {len(used)} across {len(callsites)} unique keys')
    print()

    missing = []
    broken = []

    for (kind, key), sites in sorted(callsites.items()):
        if kind == 'Class':
            if key not in classes:
                missing.append((kind, key, sites))
                continue
            # Class entry must have a non-empty className
            if not classes[key].get('className'):
                broken.append((kind, key, 'empty className', sites))
        elif kind == 'Field':
            candidates = fields.get(key, [])
            if not candidates:
                missing.append((kind, key, sites))
                continue
            ok = any(entry_looks_valid(e)[0] for _, e in candidates)
            if not ok:
                reasons = '; '.join(sorted({entry_looks_valid(e)[1] for _, e in candidates}))
                broken.append((kind, key, reasons, sites))
        elif kind == 'Method':
            candidates = methods.get(key, [])
            if not candidates:
                missing.append((kind, key, sites))
                continue
            ok = any(entry_looks_valid(e)[0] for _, e in candidates)
            if not ok:
                reasons = '; '.join(sorted({entry_looks_valid(e)[1] for _, e in candidates}))
                broken.append((kind, key, reasons, sites))
        elif kind == 'Object':
            candidates = objects.get(key, [])
            if not candidates:
                # An Object-kind key may have been declared as a non-global field in the JSON;
                # still flag it because getObject(key) will return null.
                if fields.get(key):
                    broken.append((kind, key, 'declared as non-global field (isGlobal=0)', sites))
                else:
                    missing.append((kind, key, sites))
                continue
            ok = any(entry_looks_valid(e)[0] for _, e in candidates)
            if not ok:
                reasons = '; '.join(sorted({entry_looks_valid(e)[1] for _, e in candidates}))
                broken.append((kind, key, reasons, sites))

    def dump(entries, label):
        if not entries:
            print(f'[verify] {label}: none')
            return
        print(f'[verify] {label}: {len(entries)}')
        for kind, key, *rest in entries:
            if len(rest) == 1:
                sites = rest[0]
                extra = ''
            else:
                extra, sites = rest
                extra = f' ({extra})'
            print(f'  [{kind}] {key}{extra}')
            for p, line in sites[:args.max_callsites]:
                rel = p.relative_to(client_root) if client_root in p.parents or p == client_root else p
                print(f'      at {rel}:{line}')
            if len(sites) > args.max_callsites:
                print(f'      ... and {len(sites) - args.max_callsites} more call-site(s)')
        print()

    dump(missing, 'MISSING keys (no entry in the JSON)')
    dump(broken, 'BROKEN entries (present but incomplete)')

    if not missing and not broken:
        print(f'[verify] ✓ every C++ key resolves cleanly in {args.version}.json')
        sys.exit(0)
    sys.exit(1)


if __name__ == '__main__':
    main()
