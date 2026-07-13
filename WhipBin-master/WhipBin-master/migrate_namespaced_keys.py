#!/usr/bin/env python3
"""One-shot migration: rewrite WhipClient mapping calls to use namespaced keys.

Transforms `mappings->getField/getMethod/getObject("X")` into `"Class#X"`, where
`Class` is the lunar-declared owner. After this, WhipClient no longer relies on
the flat-key map aliasing same-named fields across classes — which is the bug
that caused `Minecraft.theWorld` to be silently replaced by `ItemInWorldManager.theWorld`
(an int field) in CheatBreaker's mapping set.

Resolution policy for each `get*("X")` call site:
  1. If X already contains '#' -> leave unchanged.
  2. Else compute wrapper class from the file path (basename, case-insensitive
     match against lunar class keys). Non-wrapper files have no inferred class.
  3. Classes that declare X in lunar.json are the "declarers".
     - If wrapper class is a declarer -> prefix with wrapper class.
     - Else if exactly one declarer -> prefix with that.
     - Else if ambiguous or missing from lunar -> prefix with wrapper class if
       known, otherwise leave the call unchanged and record a warning.
  4. getClass(...) is left alone; class keys are globally unique.

Dry-run with --dry; run without to write changes in-place.
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


def load_declarers():
    lunar = json.load(open(LUNAR_JSON, encoding='utf-8'))
    fields = defaultdict(list)
    methods = defaultdict(list)
    objects = defaultdict(list)
    for ck, cv in lunar.items():
        for fk, fv in cv.get('fields', {}).items():
            (objects if fv.get('isGlobal', 0) else fields)[fk].append(ck)
        for mk in cv.get('methods', {}).keys():
            methods[mk].append(ck)
    cls_ci = {ck.lower(): ck for ck in lunar.keys()}
    return fields, methods, objects, cls_ci


def infer_wrapper_class(path, cls_ci):
    """Return the lunar class key this wrapper file represents, or None.

    Only applies to files under /wrapper/ directories. Non-wrapper files
    (modules, handlers, events) can't infer a class from the path.
    """
    posix = path.as_posix()
    if '/includes/wrapper/' not in posix and '/src/wrapper/' not in posix:
        return None
    stem = path.stem
    return cls_ci.get(stem.lower())


def rewrite_content(content, wrapper_cls, decls_f, decls_m, decls_o):
    warnings = []
    changed = [0]

    def repl(m):
        kind, key = m.group(1), m.group(2)
        if '#' in key:
            return m.group(0)

        table = {'Field': decls_f, 'Method': decls_m, 'Object': decls_o}[kind]
        declarers = table.get(key, [])

        chosen = None
        if wrapper_cls and wrapper_cls in declarers:
            chosen = wrapper_cls
        elif len(declarers) == 1:
            chosen = declarers[0]
        elif wrapper_cls:
            chosen = wrapper_cls
        elif len(declarers) > 1:
            # ambiguous in a non-wrapper file — can't decide
            warnings.append(f'ambiguous {kind} key {key!r}: declarers={declarers}')
            return m.group(0)

        if chosen is None:
            warnings.append(f'unresolvable {kind} key {key!r}: no declarer and no wrapper class')
            return m.group(0)

        changed[0] += 1
        return f'mappings->get{kind}("{chosen}#{key}")'

    new = RX_CALL.sub(repl, content)
    return new, changed[0], warnings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dry', action='store_true', help='Preview changes without writing')
    args = ap.parse_args()

    decls_f, decls_m, decls_o, cls_ci = load_declarers()

    total_changed = 0
    files_touched = 0
    all_warnings = []

    for path in list(CLIENT_ROOT.rglob('*.h')) + list(CLIENT_ROOT.rglob('*.cpp')):
        try:
            content = path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            continue
        if 'mappings->get' not in content:
            continue
        wrapper_cls = infer_wrapper_class(path, cls_ci)
        new_content, changed, warnings = rewrite_content(content, wrapper_cls, decls_f, decls_m, decls_o)
        if warnings:
            rel = path.relative_to(CLIENT_ROOT).as_posix()
            for w in warnings:
                all_warnings.append(f'{rel}: {w}')
        if changed > 0:
            total_changed += changed
            files_touched += 1
            if not args.dry:
                path.write_text(new_content, encoding='utf-8', newline='')
            rel = path.relative_to(CLIENT_ROOT).as_posix()
            print(f'{"[DRY]" if args.dry else "     "} {rel}: {changed} call(s)  wrapperCls={wrapper_cls}')

    print()
    print(f'Total files touched: {files_touched}')
    print(f'Total call sites rewritten: {total_changed}')
    if all_warnings:
        print(f'\nWarnings ({len(all_warnings)}):')
        for w in all_warnings[:40]:
            print(f'  {w}')
        if len(all_warnings) > 40:
            print(f'  ... and {len(all_warnings)-40} more')


if __name__ == '__main__':
    main()
