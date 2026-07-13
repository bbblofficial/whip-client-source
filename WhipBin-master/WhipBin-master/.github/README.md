# WhipMappingsManager

Pipeline for managing JNI mapping files used by [WhipClient](https://github.com/Whip-Industries/WhipClient). Validates mapping JSONs against the client codebase, detects unused/missing entries, and generates optimized `.wbin` binary files.

## Structure

```
mappings/
  v1_8_9/
    lunar.json
    vanilla.json
  v1_7_10/
    lunar.json
out/
  v1_8_9/
    lunar.wbin
mapping_pipeline.py
```

## Usage

```bash
# Process a single version
py mapping_pipeline.py --version v1_8_9 --client-root ../WhipClient

# Process all versions
py mapping_pipeline.py --all --client-root ../WhipClient

# Auto-remove unused mappings from JSON
py mapping_pipeline.py --all --client-root ../WhipClient --fix

# CI mode (exit 1 on missing mappings)
py mapping_pipeline.py --all --client-root ../WhipClient --ci
```

## What it does

1. **Scans** wrapper files in the client (`includes/wrapper/`, `src/wrapper/`) to find which `getClass`, `getMethod`, `getField` IDs are referenced
2. **Filters** by usage — only wrapper functions actually called from non-wrapper code are considered
3. **Cross-checks** missing IDs across all versions to avoid false positives
4. **Validates** against the JSON and reports missing/unused entries
5. **Generates** `.wbin` files containing only the used mappings

## WBIN format

```
"WBIN"                          magic (4 bytes)
u32                             class count
  per class:
    str                         key
    str                         className
    u32                         method count
      per method:
        str                     key
        str                     name
        str                     sig
        u8                      isStatic
    u32                         field count
      per field:
        str                     key
        str                     name
        str                     sig
        u8                      isStatic
        u8                      isGlobal
```

Strings are encoded as `u32 length` + `utf-8 bytes`.

## CLI flags

| Flag | Description |
|------|-------------|
| `--version VERSION` | Process a specific version (e.g. `v1_8_9`) |
| `--all` | Process all versions found in `mappings/` |
| `--client-root PATH` | Path to the WhipClient project root (required) |
| `--fix` | Remove unused mappings from JSON files |
| `--ci` | Exit with code 1 if any mappings are missing |
