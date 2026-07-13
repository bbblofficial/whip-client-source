#!/usr/bin/env python3
"""Find C++ wrapper methods that grab a jfieldID/jmethodID via mappings->get*
and then immediately use it with a JNI call, without guarding against null.

These are the sites that crash when the mapping is missing — everything else
returns a safe default because the wrapper already checks the id.
"""

import argparse
import re
import sys
from pathlib import Path

# if (!someId) someId = mappings->getField/Method("key");
LOOKUP_RE = re.compile(
    r'if\s*\(\s*!\s*(\w+)\s*\)\s*\1\s*=\s*mappings(?:->|\.getInstance\(\)\.)\s*get(Field|Method)\s*\(\s*"([^"]+)"\s*\)\s*;'
)
# Any of these JNI calls after lookup on the same variable = crash risk
JNI_USE_RE_TMPL = r'(?:Get|Set|Call)\w+?Field\s*\([^;]*?\b{id}\b|Call\w+?Method\s*\([^;]*?\b{id}\b|Call\w+?MethodA\s*\([^;]*?\b{id}\b'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--client-root', default='C:/Users/Kot/Desktop/w/WhipClient')
    args = parser.parse_args()

    client_root = Path(args.client_root)
    offenders = []

    for p in client_root.rglob('*'):
        if p.suffix not in {'.h', '.hpp', '.cpp'}:
            continue
        try:
            text = p.read_text(encoding='utf-8', errors='ignore')
        except OSError:
            continue

        for m in LOOKUP_RE.finditer(text):
            var_name = m.group(1)
            kind = m.group(2)
            key = m.group(3)
            after = text[m.end():m.end() + 800]  # look ahead ~800 chars

            # Look for a null-check within the window
            null_check = re.search(
                rf'if\s*\(\s*!\s*{re.escape(var_name)}\s*\)|if\s*\(\s*{re.escape(var_name)}\s*==\s*(?:nullptr|NULL|0)\s*\)',
                after,
            )
            jni_use = re.search(JNI_USE_RE_TMPL.format(id=re.escape(var_name)), after)

            if jni_use and (not null_check or jni_use.start() < null_check.start()):
                line = text.count('\n', 0, m.start()) + 1
                offenders.append((p.relative_to(client_root), line, var_name, kind, key))

    if not offenders:
        print('[audit] No offending wrappers — every lookup has a null-check before its JNI call.')
        return 0

    print(f'[audit] {len(offenders)} wrappers use a {{field|method}}ID without a null-check:')
    current_file = None
    for path, line, var, kind, key in offenders:
        if path != current_file:
            print(f'\n  {path}')
            current_file = path
        print(f'    :{line:<4} {var} = get{kind}("{key}")')
    return 1


if __name__ == '__main__':
    sys.exit(main())
