#!/usr/bin/env python3
"""Insert a null-check right after every `mappings->getField("key")` /
`mappings->getMethod("key")` lookup that feeds directly into a JNI call.

Without the guard, missing mappings cause env->GetXxxField / CallXxxMethod to
run with a null jfieldID/jmethodID — HotSpot then reads at a bogus offset,
stores the result as an oop in the calling thread's local handle block, and
the next GC crashes when it walks the corrupted root set.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Match both single-line and two-line variants of the lookup:
#    if (!xId) xId = mappings->getField("key");
#    if (!xId)
#        xId = mappings->getField("key");
LOOKUP_RE = re.compile(
    r'(?P<head>[ \t]*if\s*\(\s*!\s*(?P<var>\w+)\s*\)[^\n;]*\n?[^\n;]*?(?P=var)\s*=\s*mappings(?:->|\.getInstance\(\)\.)\s*get(?P<kind>Field|Method)\s*\(\s*"[^"]+"\s*\)\s*;)',
)
# Default literal value to substitute per method-return type cue found in the
# next few lines. We probe the following lines for a return statement and
# pick a sensible default.
BLANK_OR_BRACE = re.compile(r'^\s*[{}\s]*$')

# jobject-returning wrappers typically wrap into a local JavaObject-derived
# value before returning — we can't easily know the wrapper's type from regex.
# Instead we return the simplest default that compiles for the detected
# return statement.
RETURN_DEFAULTS = [
    (re.compile(r'\breturn\s+(?:false|true)\s*;'),      'return false;'),
    (re.compile(r'\breturn\s+[-+0-9.]+(?:f|F)?\s*;'),   'return 0;'),
    (re.compile(r'\breturn\s*;'),                       'return;'),
    (re.compile(r'\breturn\s+\{[^{}]*\};'),             None),  # braced-list init, needs context
    (re.compile(r'\breturn\s+[A-Za-z_][\w:]*\s*\('),    None),  # return SomeCtor(...);
]


# Map each JNI accessor/method variant to the safe early-return literal.
# Set*Field returns void — treat as such separately so we emit `return;`.
JNI_DEFAULTS = [
    (re.compile(r'\bGetBooleanField\b|\bCall(?:Static)?BooleanMethod(?:[AV])?\b'),   'return false;'),
    (re.compile(r'\bGetByteField\b|\bCall(?:Static)?ByteMethod(?:[AV])?\b'),         'return 0;'),
    (re.compile(r'\bGetCharField\b|\bCall(?:Static)?CharMethod(?:[AV])?\b'),         'return 0;'),
    (re.compile(r'\bGetShortField\b|\bCall(?:Static)?ShortMethod(?:[AV])?\b'),       'return 0;'),
    (re.compile(r'\bGetIntField\b|\bCall(?:Static)?IntMethod(?:[AV])?\b'),           'return 0;'),
    (re.compile(r'\bGetLongField\b|\bCall(?:Static)?LongMethod(?:[AV])?\b'),         'return 0;'),
    (re.compile(r'\bGetFloatField\b|\bCall(?:Static)?FloatMethod(?:[AV])?\b'),       'return 0.0f;'),
    (re.compile(r'\bGetDoubleField\b|\bCall(?:Static)?DoubleMethod(?:[AV])?\b'),     'return 0.0;'),
    # Void calls and setters
    (re.compile(r'\bCall(?:Static)?VoidMethod(?:[AV])?\b|\bSet\w*Field\b'),          'return;'),
    # Object-returning accessors
    (re.compile(r'\bGet(?:Static)?ObjectField\b'),                                   '__OBJECT__'),
    (re.compile(r'\bCall(?:Static)?ObjectMethod(?:[AV])?\b'),                        '__OBJECT__'),
]


def detect_return_default(lines_after):
    """Decide how to bail early by reading the JNI call that immediately
    follows the lookup. We only scan until the function's closing brace
    (inferred via a trailing blank-line-plus-brace heuristic) so we don't
    borrow the return statement of a neighbouring function."""
    joined = '\n'.join(lines_after)

    # Cut the scan at the next line that is only whitespace + } with no `{`
    # before it — that's the function's closing brace (most of the time).
    cut = len(joined)
    brace_depth = 0
    for i, line in enumerate(lines_after):
        brace_depth += line.count('{') - line.count('}')
        if brace_depth < 0:
            cut = sum(len(l) + 1 for l in lines_after[:i])
            break
    window = joined[:cut]

    # Prefer inferring from the JNI accessor used right after the lookup.
    first_jni = None
    for pattern, default in JNI_DEFAULTS:
        m = pattern.search(window)
        if m and (first_jni is None or m.start() < first_jni[0]):
            first_jni = (m.start(), default)
    if first_jni:
        _, default = first_jni
        if default != '__OBJECT__':
            return default
        # Object/Method returning an Object — look at the function's actual
        # return statement to decide (wrapper vs raw jobject).
        m = re.search(r'return\s+\{\s*(?:this->)?env\s*,\s*[A-Za-z_]\w*\s*\}\s*;', window)
        if m:
            prefix = 'this->' if 'this->env' in m.group(0) else ''
            return f'return {{ {prefix}env, nullptr }};'
        # Wrapper ctor style: `return ClassName(env, obj);` or `return ClassName(NULL, NULL);`
        m = re.search(r'return\s+([A-Za-z_]\w*)\s*\(\s*(?:this->)?(?:env|NULL|nullptr)\s*,', window)
        if m:
            cls = m.group(1)
            return f'return {cls}(NULL, NULL);'
        m = re.search(r'return\s+(?:nullptr|NULL)\s*;', window)
        if m:
            return 'return nullptr;'
        # Unknown wrapper shape — let the caller skip this site rather than
        # emit a `return {};` that may not compile for ctor-only wrappers.
        return None
    return None


def patch_file(path: Path) -> int:
    text = path.read_text(encoding='utf-8')

    # Process match by match, inserting a null-check AFTER the lookup statement.
    # We rebuild the file by walking matches and carrying the offsets forward.
    result_parts = []
    last_end = 0
    patched = 0

    for m in LOOKUP_RE.finditer(text):
        head_text = m.group('head')
        var = m.group('var')

        # Grab whatever indentation the `if` line uses.
        first_line_indent_match = re.match(r'[ \t]*', head_text)
        indent = first_line_indent_match.group(0) if first_line_indent_match else ''

        # Skip if there's already a null-check in the next ~200 chars.
        after = text[m.end():m.end() + 300]
        if re.search(rf'!\s*{re.escape(var)}\b', after[:120]) or re.search(rf'{re.escape(var)}\s*==\s*(?:nullptr|NULL|0)\b', after[:120]):
            continue

        # Decide the early-return default by peeking at the nearest `return` stmt
        # within the enclosing function body. Scan forward until the next closing
        # brace at the function's indent level (approximate: up to 800 chars).
        default = detect_return_default(after[:800].splitlines())
        if not default:
            continue

        # Append text up to (and including) the match, then the new guard line.
        result_parts.append(text[last_end:m.end()])
        result_parts.append(f'\n{indent}if (!{var}) {default}')
        last_end = m.end()
        patched += 1

    if patched:
        result_parts.append(text[last_end:])
        path.write_text(''.join(result_parts), encoding='utf-8')
    return patched


def main():
    client_root = Path(sys.argv[1] if len(sys.argv) > 1 else 'C:/Users/Kot/Desktop/w/WhipClient')
    total = 0
    touched_files = 0
    for p in (*client_root.rglob('includes/wrapper/**/*.h'),
              *client_root.rglob('src/wrapper/**/*.cpp'),
              *client_root.rglob('includes/wrapper/**/*.hpp'),
              *client_root.rglob('src/wrapper/**/*.hpp')):
        n = patch_file(p)
        if n:
            print(f'  +{n:3}  {p.relative_to(client_root)}')
            total += n
            touched_files += 1
    print(f'\n[patch] Added {total} null-check lines across {touched_files} files.')


if __name__ == '__main__':
    main()
