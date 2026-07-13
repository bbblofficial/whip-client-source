#!/usr/bin/env python3
"""Drop lunar.json's hand-crafted nicknames and rename WhipClient wrapper calls
to address mappings by their raw MCP member name (with an auto-generated
param-type suffix when a class declares multiple methods under the same name).

After Phase 2 every client call was `mappings->getX("Class#lunarKey")` where
`lunarKey` might be a legacy alias (`posXE`, `theItem`, `MovingObjectPositionConstructor_Entity`).
Phase 3 makes the auto-mapper emit keys like `Class#mcpName` directly, so the
nicknames in lunar.json stop being load-bearing. This script rewrites both
sides in the same pass so the build stays consistent.

Transforms applied:
  1. Rename each lunar.json field/method key from its alias to the real MCP
     `name` value. When multiple methods in a class share an MCP name, the
     overloads get a `_Type1_Type2_...` suffix built from the signature.
  2. Rewrite every C++ `mappings->get{Field,Method,Object}("Class#lunarKey")`
     call site to use the new key.

Runs in one shot — re-running it after success is a no-op.
"""
import re
import json
import sys
import argparse
from pathlib import Path
from collections import defaultdict

CLIENT_ROOT = Path(r"C:/Users/Kot/Desktop/w/WhipClient")
LUNAR_JSON = Path(r"C:/Users/Kot/Desktop/w/WhipBin/mappings/v1_8_9/lunar.json")

RX_CALL = re.compile(r'mappings->get(Field|Method|Object)\(\s*"([^"]+)"\s*\)')


def short_type_token(desc: str) -> str:
    """JNI descriptor -> short token (matches JsonOutput.shortTypeToken)."""
    i = 0
    arrays = 0
    while i < len(desc) and desc[i] == '[':
        arrays += 1; i += 1
    if i >= len(desc):
        return '?'
    c = desc[i]
    if c == 'L':
        end = desc.find(';', i)
        if end < 0:
            return '?'
        internal = desc[i+1:end]
        cut = max(internal.rfind('/'), internal.rfind('$'))
        base = internal[cut+1:] if cut >= 0 else internal
    else:
        base = c
    return base + ('Arr' * arrays)


def param_tokens(desc: str):
    """`(Lnet/.../Entity;I)V` -> `['Entity', 'I']`"""
    out = []
    if not desc or len(desc) < 2 or desc[0] != '(':
        return out
    i = 1
    while i < len(desc) and desc[i] != ')':
        start = i
        while i < len(desc) and desc[i] == '[':
            i += 1
        if i >= len(desc):
            break
        c = desc[i]
        if c == 'L':
            end = desc.find(';', i)
            if end < 0:
                break
            i = end + 1
        else:
            i += 1
        out.append(short_type_token(desc[start:i]))
    return out


def overload_suffix(sig: str) -> str:
    toks = param_tokens(sig)
    return '' if not toks else '_' + '_'.join(toks)


def build_rewrite_table(lunar):
    """For each (classKey, memberKind, lunarKey) return the new key.

    Returns:
        fields: {class_key: {old_key: new_key}}
        methods: {class_key: {old_key: new_key}}
        objects: {class_key: {old_key: new_key}}
    """
    fields_out = defaultdict(dict)
    methods_out = defaultdict(dict)
    objects_out = defaultdict(dict)

    for class_key, class_data in lunar.items():
        raw_fields = class_data.get('fields', {})
        # Group fields by their mcp `name` so we catch same-name duplicates
        # (global static finals like the PlayerDigging actions share a name
        # with a plain instance field in rare cases — the suffix prevents
        # the destination dict from collapsing them).
        mcp_name_counts = defaultdict(int)
        for fk, fv in raw_fields.items():
            mcp_name_counts[fv.get('name', fk)] += 1
        for fk, fv in raw_fields.items():
            mcp_name = fv.get('name', fk)
            # Fields in Java can't overload — but the safety suffix is only
            # useful if we ever allow different-sig entries to share a name.
            # Static-global/object entries live in the `fields` bucket too,
            # so we split them into the right destination map at emit time.
            new_key = mcp_name
            is_global = bool(fv.get('isGlobal', 0))
            if is_global:
                objects_out[class_key][fk] = new_key
            else:
                fields_out[class_key][fk] = new_key

        raw_methods = class_data.get('methods', {})
        # Count overloads by mcp method name
        mcp_name_counts = defaultdict(int)
        for mk, mv in raw_methods.items():
            mcp_name_counts[mv.get('name', mk)] += 1
        for mk, mv in raw_methods.items():
            mcp_name = mv.get('name', mk)
            if mcp_name_counts[mcp_name] > 1:
                new_key = mcp_name + overload_suffix(mv.get('sig', ''))
            else:
                new_key = mcp_name
            methods_out[class_key][mk] = new_key

    return fields_out, methods_out, objects_out


def rewrite_lunar(lunar, fields_r, methods_r, objects_r):
    """Produce a new lunar.json with keys renamed to the MCP form."""
    out = {}
    for class_key, class_data in lunar.items():
        new_fields = {}
        new_methods = {}
        for fk, fv in class_data.get('fields', {}).items():
            is_global = bool(fv.get('isGlobal', 0))
            bucket = objects_r if is_global else fields_r
            new_key = bucket[class_key].get(fk, fk)
            # First-write-wins so duplicate destinations don't silently overwrite
            new_fields.setdefault(new_key, fv)
        for mk, mv in class_data.get('methods', {}).items():
            new_key = methods_r[class_key].get(mk, mk)
            new_methods.setdefault(new_key, mv)
        out[class_key] = {
            'className': class_data.get('className'),
            'fields': new_fields,
            'methods': new_methods,
        }
    return out


def rewrite_client(fields_r, methods_r, objects_r, dry):
    """Rewrite each wrapper call site in-place."""
    def lookup(kind, class_key, old_key):
        if kind == 'Field':
            return fields_r.get(class_key, {}).get(old_key)
        if kind == 'Method':
            return methods_r.get(class_key, {}).get(old_key)
        if kind == 'Object':
            return objects_r.get(class_key, {}).get(old_key)
        return None

    total = 0
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

        def repl(m):
            kind, full_key = m.group(1), m.group(2)
            if '#' not in full_key:
                return m.group(0)
            class_key, old_key = full_key.split('#', 1)
            new_key = lookup(kind, class_key, old_key)
            if new_key is None or new_key == old_key:
                return m.group(0)
            edits[0] += 1
            return f'mappings->get{kind}("{class_key}#{new_key}")'

        new_content = RX_CALL.sub(repl, content)
        if edits[0] > 0:
            files_touched += 1
            total += edits[0]
            if not dry:
                path.write_text(new_content, encoding='utf-8', newline='')
            print(f'{"[DRY]" if dry else "     "} {path.relative_to(CLIENT_ROOT).as_posix()}: {edits[0]} rename(s)')
    print(f'\nFiles touched: {files_touched}, total renames: {total}')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dry', action='store_true')
    args = ap.parse_args()

    lunar = json.load(open(LUNAR_JSON, encoding='utf-8'))
    fields_r, methods_r, objects_r = build_rewrite_table(lunar)

    new_lunar = rewrite_lunar(lunar, fields_r, methods_r, objects_r)
    if not args.dry:
        json.dump(new_lunar, open(LUNAR_JSON, 'w', encoding='utf-8'), indent=2)
        print(f'Wrote rewritten lunar.json')
    else:
        print('[DRY] Would rewrite lunar.json')

    rewrite_client(fields_r, methods_r, objects_r, args.dry)


if __name__ == '__main__':
    main()
