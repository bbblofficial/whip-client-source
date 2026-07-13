#!/usr/bin/env python3
"""Auto-generate lunar.json (MCP-named) from wrapper-referenced keys.

Eliminates hand-curation: given the auto-mapper's downloaded SRG + MCP CSVs
and the WhipClient wrapper code, produces a complete .json that maps every
`mappings->getX("Class#member")` reference to the right (name, sig) pair
for the target naming convention (mcp / srg / notch).

Usage:
    python generate_deobf_mappings.py --version 1.7.10 --namespace mcp \
        --client-root ../WhipClient \
        --auto-mapper ../seraphyn/auto-mapper \
        --out mappings/v1_7_10/lunar-auto.json

`mcp` namespace yields Lunar-style names (deobf bytecode). `srg` yields the
intermediate Searge form. `notch` yields the vanilla obfuscated form.
"""

import argparse
import json
import re
import sys
import zipfile
from collections import defaultdict
from pathlib import Path

def scan_wrapper_keys(client_root: Path):
    """Unused — kept as a no-op for backward CLI compatibility. The
    auto-generator now emits the full MCP class universe; mapping_pipeline.py
    handles the filtering downstream the same way it filters cheatbreaker.json
    (multi-MB input → small wbin output via scan_used_ids).
    """
    return None


def parse_srg(srg_path: Path):
    """Parse an MCPConfig joined.srg file into (classes, fields, methods).

    Returns a triple of dicts:
      classes: notch_path -> srg_path     (e.g. 'aam' -> 'net/minecraft/entity/Entity')
      fields:  (srg_owner, srg_name) -> (notch_owner, notch_name)
      methods: (srg_owner, srg_name, srg_desc) -> (notch_owner, notch_name, notch_desc)

    The SRG format mixes CL/FD/MD prefixes; we parse only those lines and
    skip PK (package) entries which don't carry symbol info."""
    classes = {}
    fields = {}
    methods = {}
    for raw in srg_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not raw or raw.startswith("#"):
            continue
        parts = raw.split()
        if not parts:
            continue
        kind = parts[0]
        if kind == "CL:" and len(parts) >= 3:
            classes[parts[1]] = parts[2]
        elif kind == "FD:" and len(parts) >= 3:
            notch_full, srg_full = parts[1], parts[2]
            notch_owner, _, notch_name = notch_full.rpartition("/")
            srg_owner, _, srg_name = srg_full.rpartition("/")
            fields[(srg_owner, srg_name)] = (notch_owner, notch_name)
        elif kind == "MD:" and len(parts) >= 5:
            notch_full, notch_desc, srg_full, srg_desc = parts[1], parts[2], parts[3], parts[4]
            notch_owner, _, notch_name = notch_full.rpartition("/")
            srg_owner, _, srg_name = srg_full.rpartition("/")
            methods[(srg_owner, srg_name, srg_desc)] = (notch_owner, notch_name, notch_desc)
    return classes, fields, methods


def parse_mcp_csv(csv_path: Path):
    """MCP fields/methods CSV columns: searge, name, side, desc.
    Returns srg_name -> mcp_name."""
    out = {}
    for i, line in enumerate(csv_path.read_text(encoding="utf-8", errors="ignore").splitlines()):
        if i == 0 or not line:
            continue
        parts = line.split(",")
        if len(parts) >= 2:
            out[parts[0]] = parts[1]
    return out


def index_mcp_classes(srg_classes: dict):
    """Build short-name index from full MCP paths.
    'net/minecraft/entity/Entity' -> short 'Entity', accessible as a key
    so the wrapper's class shorthand can be resolved to the full path.
    Inner classes use '$' which we keep verbatim (overload suffix stays
    on the auto-mapper output side)."""
    by_short = defaultdict(list)
    for srg_path in srg_classes.values():
        short = srg_path.rsplit("/", 1)[-1]
        by_short[short].append(srg_path)
    return by_short


def index_class_members(jar_path: Path, srg_to_mcp_field: dict, srg_to_mcp_method: dict):
    """Walk the reference jar via Python's zipfile + manual class file parser
    to extract (class, fields[], methods[]) so we can resolve member sigs
    without a separate ASM dependency.

    We don't fully decode the constant pool — just walk the class file
    header to grab `this_class` name and the field/method tables which give
    us (name_index, descriptor_index) → strings via the constant pool's
    UTF-8 entries.
    """
    import struct

    def parse_class(data: bytes):
        if len(data) < 10 or data[:4] != b"\xCA\xFE\xBA\xBE":
            return None
        pos = 8  # skip magic + minor+major version
        cp_count = struct.unpack(">H", data[pos:pos+2])[0]
        pos += 2
        cp = [None] * cp_count
        i = 1
        while i < cp_count:
            tag = data[pos]; pos += 1
            if tag == 1:  # CONSTANT_Utf8
                length = struct.unpack(">H", data[pos:pos+2])[0]; pos += 2
                cp[i] = data[pos:pos+length].decode("utf-8", errors="replace"); pos += length
            elif tag == 7:  # Class
                cp[i] = ("Class", struct.unpack(">H", data[pos:pos+2])[0]); pos += 2
            elif tag in (3, 4):  # Integer / Float
                pos += 4
            elif tag in (5, 6):  # Long / Double — take 2 slots
                pos += 8
                i += 1
            elif tag in (9, 10, 11, 12, 18):  # FieldRef / MethodRef / InterfaceMethodRef / NameAndType / InvokeDynamic
                pos += 4
            elif tag in (8, 16, 19, 20):  # String / MethodType / Module / Package
                pos += 2
            elif tag == 15:  # MethodHandle
                pos += 3
            else:
                return None
            i += 1

        # access_flags(2) + this_class(2) + super_class(2)
        this_class_idx = struct.unpack(">H", data[pos+2:pos+4])[0]
        pos += 6
        # interfaces
        ifc = struct.unpack(">H", data[pos:pos+2])[0]; pos += 2 + ifc * 2

        def utf8(idx):
            v = cp[idx]
            if isinstance(v, tuple) and v[0] == "Class":
                return cp[v[1]]
            return v

        this_class = utf8(this_class_idx)

        def parse_members():
            count = struct.unpack(">H", data[pos:pos+2])[0]
            local_pos = pos + 2
            members = []
            for _ in range(count):
                _flags = struct.unpack(">H", data[local_pos:local_pos+2])[0]
                name_idx = struct.unpack(">H", data[local_pos+2:local_pos+4])[0]
                desc_idx = struct.unpack(">H", data[local_pos+4:local_pos+6])[0]
                attr_count = struct.unpack(">H", data[local_pos+6:local_pos+8])[0]
                local_pos += 8
                for _ in range(attr_count):
                    _name = struct.unpack(">H", data[local_pos:local_pos+2])[0]
                    alen = struct.unpack(">I", data[local_pos+2:local_pos+6])[0]
                    local_pos += 6 + alen
                members.append({
                    "name": utf8(name_idx),
                    "desc": utf8(desc_idx),
                    "static": bool(_flags & 0x0008),
                })
            return members, local_pos

        fields, pos = parse_members()
        methods, pos = parse_members()
        return this_class, fields, methods

    classes = {}
    with zipfile.ZipFile(jar_path) as zf:
        for entry in zf.namelist():
            if not entry.endswith(".class"):
                continue
            try:
                parsed = parse_class(zf.read(entry))
            except Exception:
                continue
            if parsed is None:
                continue
            this_class, fields, methods = parsed
            classes[this_class] = {"fields": fields, "methods": methods}
    return classes


def emit_for_namespace(srg_classes, srg_fields, srg_methods,
                       srg_to_mcp_field, srg_to_mcp_method,
                       jar_classes, namespace: str):
    """Emit the **full** MCP class universe for the chosen namespace.

    The downstream mapping_pipeline.py scans WhipClient for every quoted
    string literal and intersects it with the .json's known ids — only
    referenced entries land in the wbin. So we don't filter here; we hand
    the pipeline a fat .json the same way the auto-mapper hands it a fat
    cheatbreaker.json (~6 MB → ~30 KB after pipeline filter).

    The cached jar (Mojang client) holds notch-named bytecode; translate
    notch → SRG via joined.srg and SRG → MCP via the CSVs as we walk.
    """
    srg_path_to_notch = {srg: notch for notch, srg in srg_classes.items()}
    notch_field_to_srg = {(no, nf): (so, sn)
                           for (so, sn), (no, nf) in srg_fields.items()}
    notch_method_to_srg = {(no, nm, nd): (so, sn, sd)
                            for (so, sn, sd), (no, nm, nd) in srg_methods.items()}

    out = {}
    for notch_class, srg_class in srg_classes.items():
        cls_short = srg_class.rsplit("/", 1)[-1]
        emit_class = notch_class if namespace == "notch" else srg_class

        jar_info = jar_classes.get(notch_class, {"fields": [], "methods": []})

        fields_out = {}
        for f in jar_info["fields"]:
            srg_pair = notch_field_to_srg.get((notch_class, f["name"]))
            if not srg_pair:
                continue
            srg_name = srg_pair[1]
            mcp_name = srg_to_mcp_field.get(srg_name, srg_name)
            key = {"mcp": mcp_name, "srg": srg_name, "notch": f["name"]}[namespace]
            sig = _translate_desc(f["desc"], srg_classes, namespace)
            is_static = bool(f["static"])
            # Static object/array fields must be pre-loaded as global refs so
            # `mappings->getObject("Class#FIELD")` can serve them — primarily
            # for enum singletons (MovingObjectType.{MISS,BLOCK,ENTITY},
            # C02PacketUseEntity$Action.{ATTACK,INTERACT}, etc.) compared via
            # IsSameObject. Emitting isGlobal=0 here used to make every such
            # comparison silently return false on Lunar/Forge/Vanilla, which
            # in turn broke break-block / autotool / anti-bot / trajectories
            # / tick-locker WL detection downstream.
            needs_global = is_static and bool(sig) and sig[0] in ("L", "[")
            fields_out[mcp_name] = {
                "name": {"mcp": mcp_name, "srg": srg_name, "notch": f["name"]}[namespace],
                "sig": sig,
                "isStatic": 1 if is_static else 0,
                "isGlobal": 1 if needs_global else 0,
            }

        # First pass: count overloads per MCP name. When a name has 2+ overloads,
        # every one needs a disambiguating suffix or all but the last silently
        # collapse onto the same dict key. Mirrors JsonOutput.computeMcpOverloadCounts.
        mcp_method_counts = {}
        for m in jar_info["methods"]:
            if m["name"] == "<init>":
                mcp_method_counts["<init>"] = mcp_method_counts.get("<init>", 0) + 1
                continue
            srg_triple = notch_method_to_srg.get((notch_class, m["name"], m["desc"]))
            if not srg_triple:
                continue
            mcp_name = srg_to_mcp_method.get(srg_triple[1], srg_triple[1])
            mcp_method_counts[mcp_name] = mcp_method_counts.get(mcp_name, 0) + 1

        methods_out = {}
        # First overload per MCP name keeps the bare key for backward compat;
        # later overloads only get the suffixed form so they don't overwrite.
        bare_emitted = set()
        for m in jar_info["methods"]:
            if m["name"] == "<init>":
                # Ctors aren't in joined.srg (JVM resolves by signature alone).
                # Emit each one under `<init>_Type1_Type2_...` with MCP class
                # short names — same form the Java auto-mapper produces.
                ctor_entry = {
                    "name": "<init>",
                    "sig": _translate_desc(m["desc"], srg_classes, namespace),
                    "isStatic": 0,
                    "isGlobal": 0,
                }
                suffix = _overload_suffix(m["desc"], srg_classes)
                if suffix:
                    methods_out["<init>" + suffix] = ctor_entry
                if "<init>" not in bare_emitted:
                    methods_out["<init>"] = ctor_entry
                    bare_emitted.add("<init>")
                continue
            srg_triple = notch_method_to_srg.get((notch_class, m["name"], m["desc"]))
            if not srg_triple:
                continue
            srg_name = srg_triple[1]
            mcp_name = srg_to_mcp_method.get(srg_name, srg_name)
            entry = {
                "name": {"mcp": mcp_name, "srg": srg_name, "notch": m["name"]}[namespace],
                "sig": _translate_desc(m["desc"], srg_classes, namespace),
                "isStatic": 1 if m["static"] else 0,
                "isGlobal": 0,
            }
            count = mcp_method_counts.get(mcp_name, 1)
            if count > 1:
                suffixed = mcp_name + _overload_suffix(m["desc"], srg_classes)
                methods_out[suffixed] = entry
                if mcp_name not in bare_emitted:
                    methods_out[mcp_name] = entry
                    bare_emitted.add(mcp_name)
            else:
                methods_out[mcp_name] = entry
                bare_emitted.add(mcp_name)

        out[cls_short] = {
            "className": emit_class,
            "fields": fields_out,
            "methods": methods_out,
        }
    return out


_DESC_REF = re.compile(r"L([^;]+);")


def _short_type_token_mcp(desc_token: str, srg_classes: dict) -> str:
    """Mirror of JsonOutput.shortTypeToken with MCP-name resolution. Returns the
    last segment of an MCP class path (`Lnet/minecraft/entity/Entity;` → `Entity`)
    or the JNI primitive letter, with `Arr` per array dimension."""
    arr_depth = 0
    i = 0
    while i < len(desc_token) and desc_token[i] == '[':
        arr_depth += 1
        i += 1
    if i >= len(desc_token):
        return "?"
    c = desc_token[i]
    if c == 'L':
        end = desc_token.find(';', i)
        if end < 0:
            return "?"
        notch_inner = desc_token[i + 1:end]
        srg_inner = srg_classes.get(notch_inner, notch_inner)
        cut = max(srg_inner.rfind('/'), srg_inner.rfind('$'))
        base = srg_inner[cut + 1:] if cut >= 0 else srg_inner
    else:
        base = c
    return base + ("Arr" * arr_depth)


def _overload_suffix(notch_desc: str, srg_classes: dict) -> str:
    """`_Type1_Type2_...` overload-disambiguation suffix using MCP class short
    names. Matches JsonOutput.overloadSuffix output."""
    if not notch_desc or notch_desc[0] != '(':
        return ""
    end = notch_desc.find(')')
    if end < 0:
        return ""
    inner = notch_desc[1:end]
    parts = []
    i = 0
    while i < len(inner):
        start = i
        while i < len(inner) and inner[i] == '[':
            i += 1
        if i >= len(inner):
            break
        c = inner[i]
        if c == 'L':
            sc = inner.find(';', i)
            if sc < 0:
                break
            i = sc + 1
        else:
            i += 1
        parts.append(_short_type_token_mcp(inner[start:i], srg_classes))
    if not parts:
        return ""
    return "_" + "_".join(parts)


def _translate_desc(desc, srg_classes, namespace):
    """Rewrite L<class>; references in a JNI descriptor for the target
    namespace.

    The jar gives us notch-named descriptors. SRG and MCP share the same
    class path, so for those namespaces we translate notch -> SRG. For
    notch namespace we leave the descriptor untouched."""
    if namespace == "notch":
        return desc
    def repl(m):
        notch_inner = m.group(1)
        srg_inner = srg_classes.get(notch_inner)
        if srg_inner is None:
            return m.group(0)
        return f"L{srg_inner};"
    return _DESC_REF.sub(repl, desc)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True, help="MC version e.g. 1.7.10 / 1.8.9")
    ap.add_argument("--namespace", choices=("mcp", "srg", "notch"), default="mcp")
    ap.add_argument("--client-root", required=False, type=Path,
                    help="Unused; kept for backward CLI compatibility")
    ap.add_argument("--auto-mapper", required=True, type=Path,
                    help="Path to seraphyn/auto-mapper (cache must contain {version}/{srg,csv,jar})")
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()

    cache = args.auto_mapper / "cache" / args.version
    srg_path = cache / f"{args.version}-joined.srg"
    fields_csv = cache / f"{args.version}-fields.csv"
    methods_csv = cache / f"{args.version}-methods.csv"
    jar_path = cache / f"{args.version}-client.jar"

    for p in (srg_path, fields_csv, methods_csv, jar_path):
        if not p.exists():
            print(f"[ERROR] Missing {p} — run the auto-mapper at least once for {args.version}", file=sys.stderr)
            sys.exit(2)

    print(f"[+] Parsing SRG {srg_path.name}", file=sys.stderr)
    srg_classes, srg_fields, srg_methods = parse_srg(srg_path)
    print(f"    {len(srg_classes)} classes, {len(srg_fields)} fields, {len(srg_methods)} methods", file=sys.stderr)

    srg_to_mcp_field = parse_mcp_csv(fields_csv)
    srg_to_mcp_method = parse_mcp_csv(methods_csv)
    print(f"[+] MCP CSVs: {len(srg_to_mcp_field)} fields, {len(srg_to_mcp_method)} methods", file=sys.stderr)

    print(f"[+] Indexing reference jar {jar_path.name}", file=sys.stderr)
    jar_classes = index_class_members(jar_path, srg_to_mcp_field, srg_to_mcp_method)
    print(f"    {len(jar_classes)} classes parsed", file=sys.stderr)

    out = emit_for_namespace(srg_classes, srg_fields, srg_methods,
                              srg_to_mcp_field, srg_to_mcp_method,
                              jar_classes, args.namespace)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"[+] Wrote {args.out} — {len(out)} classes, namespace={args.namespace}", file=sys.stderr)


if __name__ == "__main__":
    main()
