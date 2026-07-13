#!/usr/bin/env python3

import os
import re
import json
import argparse
import sys
import struct
from pathlib import Path
from collections import defaultdict

MAPPINGS_DIR = Path("mappings")
OUT_DIR = Path("out")

QUOTED_STRING_REGEX = re.compile(r'"([^"]+)"')
MAPPING_CALL_REGEX = re.compile(r'mappings->get(?:Method|Field|Class|Object)\(\s*"([^"]+)"\s*\)')
FUNC_DEF_WITH_BRACE = re.compile(r'(\w+)\s*\([^;=]*\)\s*(?:const\s*)?(?:override\s*)?\{')

WRAPPER_SUBDIRS = ("includes/wrapper/", "src/wrapper/")
CPP_KEYWORDS = frozenset(('if', 'for', 'while', 'switch', 'class', 'struct',
                           'namespace', 'catch', 'return'))


def list_versions():
    return [d.name for d in MAPPINGS_DIR.iterdir() if d.is_dir()]


def list_mapping_files(version):
    version_dir = MAPPINGS_DIR / version
    if not version_dir.exists():
        print(f"[ERROR] Missing mappings directory for version {version}")
        sys.exit(2)
    files = list(version_dir.glob("*.json"))
    if not files:
        print(f"[ERROR] No .json files found in {version_dir}")
        sys.exit(2)
    return files


def _merge_duplicate_keys(pairs):
    d = {}
    for k, v in pairs:
        if k in d and isinstance(d[k], dict) and isinstance(v, dict):
            for sub in ("methods", "fields"):
                if sub in v:
                    d[k].setdefault(sub, {}).update(v[sub])
        else:
            d[k] = v
    return d

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f, object_pairs_hook=_merge_duplicate_keys)


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def collect_all_known_ids():
    """Collect all mapping IDs across every version's JSON files.

    Fields and methods are namespaced by their declaring class key (`Class#key`),
    matching what the WBIN emits and what C++ wrappers must request. Class keys
    stay unscoped since they're globally unique.
    """
    known_classes = set()
    known_methods = set()
    known_fields = set()
    for version_dir in MAPPINGS_DIR.iterdir():
        if not version_dir.is_dir():
            continue
        for json_path in version_dir.glob("*.json"):
            data = load_json(json_path)
            known_classes.update(data.keys())
            for cls_key, cls_data in data.items():
                for mk in cls_data.get("methods", {}).keys():
                    known_methods.add(f"{cls_key}#{mk}")
                for fk in cls_data.get("fields", {}).keys():
                    known_fields.add(f"{cls_key}#{fk}")
    return known_classes, known_methods, known_fields


def _is_wrapper_path(filepath, client_root):
    """Check if a file is in a wrapper directory."""
    try:
        rel = filepath.relative_to(client_root)
        rel_str = str(rel).replace("\\", "/")
        return any(rel_str.startswith(d) for d in WRAPPER_SUBDIRS)
    except ValueError:
        return False


def _parse_wrapper_functions(content):
    """For each mappings->get*("id") call, find the enclosing function name.

    Returns {function_name: set of mapping IDs}.
    """
    lines = content.split('\n')
    func_to_ids = defaultdict(set)

    for i, line in enumerate(lines):
        for m in MAPPING_CALL_REGEX.finditer(line):
            mapping_id = m.group(1)
            for j in range(i, max(i - 50, -1), -1):
                if '{' not in lines[j]:
                    continue
                func_match = FUNC_DEF_WITH_BRACE.search(lines[j])
                if func_match:
                    func_name = func_match.group(1)
                    if func_name not in CPP_KEYWORDS:
                        func_to_ids[func_name].add(mapping_id)
                        break

    return dict(func_to_ids)


def scan_used_ids(client_root, known_classes, known_methods, known_fields):
    """Collect every quoted-string literal in the client source and keep
    only the mapping ids whose key appears among them.

    A mapping id is considered used iff its key text is written somewhere
    in the client as a `"..."` literal. This covers `mappings->getX("key")`,
    hook `getHookName()` returns, `isInstanceOf("Cls")`, logs — anything that
    spells the key out as a string. Wrapper-to-wrapper call chains no longer
    need any special tracking: the key still has to be written out as a
    string wherever it is actually requested, and that string is what we scan.
    """
    all_known = known_classes | known_methods | known_fields
    strings = set()
    for file in client_root.rglob("*"):
        if file.suffix not in (".h", ".hpp", ".cpp", ".c"):
            continue
        with open(file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        for s in QUOTED_STRING_REGEX.findall(content):
            # Mapping ids are never whitespace-containing (Class#member, with
            # underscore-joined overload suffixes). Dropping strings that
            # contain spaces drops every log/message/format literal out of
            # the candidate set up front — tightens the search and guards
            # against any future pathological hit.
            if any(ch.isspace() for ch in s):
                continue
            strings.add(s)

    used_ids = strings & all_known
    used_classes = used_ids & known_classes
    used_methods = used_ids & known_methods
    used_fields = used_ids & known_fields

    print(f"\n  Quoted strings collected: {len(strings)}")
    print(f"  Matching mapping ids:     {len(used_ids)}")
    print(f"    classes: {len(used_classes)}, methods: {len(used_methods)}, fields: {len(used_fields)}")

    return used_classes, used_methods, used_fields


def validate(name, used_classes, used_methods, used_fields, mappings, known_ids, json_path=None, fix=False, ci=False):
    missing = []
    unused = []
    known_classes, known_methods, known_fields = known_ids

    all_json_classes = set(mappings.keys())
    all_json_methods = set()
    all_json_fields = set()
    for cls_key, cls_data in mappings.items():
        for mk in cls_data.get("methods", {}).keys():
            all_json_methods.add(f"{cls_key}#{mk}")
        for fk in cls_data.get("fields", {}).keys():
            all_json_fields.add(f"{cls_key}#{fk}")

    for cls in sorted(used_classes - all_json_classes):
        if cls not in known_classes:
            missing.append(f"[CLASS] {cls}")
    for method in sorted(used_methods - all_json_methods):
        if method not in known_methods:
            missing.append(f"[METHOD] {method}")
    for field in sorted(used_fields - all_json_fields):
        if field not in known_fields:
            missing.append(f"[FIELD] {field}")

    used_method_by_cls = defaultdict(set)
    used_field_by_cls = defaultdict(set)
    for k in used_methods:
        if '#' in k:
            c, m = k.split('#', 1); used_method_by_cls[c].add(m)
    for k in used_fields:
        if '#' in k:
            c, f = k.split('#', 1); used_field_by_cls[c].add(f)

    for cls_name in sorted(all_json_classes - used_classes):
        cls_methods = set(mappings[cls_name].get("methods", {}).keys())
        cls_fields = set(mappings[cls_name].get("fields", {}).keys())
        if not (cls_methods & used_method_by_cls.get(cls_name, set())) \
                and not (cls_fields & used_field_by_cls.get(cls_name, set())):
            unused.append(f"[CLASS] {cls_name}")
    for method in sorted(all_json_methods - used_methods):
        unused.append(f"[METHOD] {method}")
    for field in sorted(all_json_fields - used_fields):
        unused.append(f"[FIELD] {field}")

    if missing:
        print(f"\n  {name} - Missing mappings:")
        for m in missing:
            print("    ", m)

    if unused:
        print(f"\n  {name} - Unused mappings:")
        for u in unused:
            print("    ", u)

    if fix and unused and json_path:
        for cls_name in list(mappings.keys()):
            used_m = used_method_by_cls.get(cls_name, set())
            used_f = used_field_by_cls.get(cls_name, set())
            cls_methods = set(mappings[cls_name].get("methods", {}).keys())
            cls_fields = set(mappings[cls_name].get("fields", {}).keys())
            if cls_name not in used_classes and not (cls_methods & used_m) and not (cls_fields & used_f):
                del mappings[cls_name]
                continue
            for method in list(mappings[cls_name].get("methods", {}).keys()):
                if method not in used_m:
                    del mappings[cls_name]["methods"][method]
            for field in list(mappings[cls_name].get("fields", {}).keys()):
                if field not in used_f:
                    del mappings[cls_name]["fields"][field]
        save_json(json_path, mappings)
        print(f"\n  {name} - Unused mappings removed.")

    if ci and missing:
        sys.exit(1)

    return missing, unused

def _write_str(f, s):
    b = s.encode("utf-8")
    f.write(struct.pack("I", len(b)))
    f.write(b)

def generate_wbin(version, name, mappings):
    out_dir = OUT_DIR / version
    out_dir.mkdir(parents=True, exist_ok=True)

    out_file = out_dir / f"{name}.wbin"

    with open(out_file, "wb") as f:
        f.write(b"WBIN")
        f.write(struct.pack("I", len(mappings)))

        for cls_key, cls_data in mappings.items():
            _write_str(f, cls_key)
            _write_str(f, cls_data["className"])

            # Emit field/method keys as `ClassKey#field` so WhipClient's flat
            # lookup map can't alias same-named keys across classes. Wrappers
            # must request the namespaced form: mappings->getField("Minecraft#theWorld").
            methods = cls_data.get("methods", {})
            f.write(struct.pack("I", len(methods)))
            for m_key, m_data in methods.items():
                _write_str(f, f"{cls_key}#{m_key}")
                _write_str(f, m_data["name"])
                _write_str(f, m_data["sig"])
                f.write(struct.pack("B", m_data.get("isStatic", 0)))

            fields = cls_data.get("fields", {})
            f.write(struct.pack("I", len(fields)))
            for f_key, f_data in fields.items():
                _write_str(f, f"{cls_key}#{f_key}")
                _write_str(f, f_data["name"])
                _write_str(f, f_data["sig"])
                f.write(struct.pack("B", f_data.get("isStatic", 0)))
                f.write(struct.pack("B", f_data.get("isGlobal", 0)))

    print(f"  {name}.wbin generated")

def filter_mappings(used_classes, used_methods, used_fields, mappings):
    filtered = {}
    for cls_name, cls_data in mappings.items():
        methods = {m: v for m, v in cls_data.get("methods", {}).items()
                   if f"{cls_name}#{m}" in used_methods}
        fields = {f: v for f, v in cls_data.get("fields", {}).items()
                  if f"{cls_name}#{f}" in used_fields}
        if cls_name not in used_classes and not methods and not fields:
            continue
        filtered[cls_name] = {
            "className": cls_data["className"],
            "methods": methods,
            "fields": fields,
        }
    return filtered


def process_version(version, used_classes, used_methods, used_fields, known_ids, fix=False, ci=False):
    print(f"\n=== Processing version {version} ===")

    mapping_files = list_mapping_files(version)

    for json_path in mapping_files:
        name = json_path.stem
        mappings = load_json(json_path)

        missing, unused = validate(name, used_classes, used_methods, used_fields, mappings, known_ids, json_path=json_path, fix=fix, ci=ci)

        filtered = filter_mappings(used_classes, used_methods, used_fields, mappings)
        generate_wbin(version, name, filtered)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", type=str, help="Process specific version")
    parser.add_argument("--all", action="store_true", help="Process all versions")
    parser.add_argument("--fix", action="store_true", help="Remove unused mappings")
    parser.add_argument("--ci", action="store_true", help="CI mode (fail on missing)")
    parser.add_argument("--client-root", type=str, required=True,
                        help="Root path of the client project")

    args = parser.parse_args()

    client_root = Path(args.client_root)
    if not client_root.exists():
        print(f"[ERROR] Client root not found: {client_root}")
        sys.exit(2)

    if not args.version and not args.all:
        print("Specify --version or --all")
        sys.exit(1)

    if args.all:
        versions = list_versions()
    else:
        versions = [args.version]

    known_ids = collect_all_known_ids()
    known_classes, known_methods, known_fields = known_ids

    used_classes, used_methods, used_fields = scan_used_ids(
        client_root, known_classes, known_methods, known_fields
    )

    for version in versions:
        process_version(version, used_classes, used_methods, used_fields, known_ids, fix=args.fix, ci=args.ci)


if __name__ == "__main__":
    main()