# file_quick_signature

A quick-change file signature key cache: keys of the form `{path}_{size}_{mtime_ns}` detect file modifications without reading file contents, and a JSON-backed store maps those keys to arbitrary payloads (content hashes, embeddings, ...) so unchanged files skip re-processing. Keys are byte-identical with the historical ones, so existing `signature.json` caches keep working.

Works on Windows and Linux alike — pure `os`/`json`/`re`, no platform-specific code. Cross-machine caches (different roots or separators) are reconciled with regex path remapping.

## Install

Editable:

```bash
pip install -e . --no-build-isolation
```

## Keys: build, reverse-parse

`file_quick_signature.path` owns the key grammar:

```python
from file_quick_signature.key import file_quick_signature, parse_key

key = file_quick_signature(r"E:\pool\a.jpg")   # "E:\\pool\\a.jpg_98304_133851860294701234"
sig = parse_key(key)                            # SignatureKey(path=..., size=98304, mtime_ns=133851860294701234)
sig.path, sig.size, sig.mtime_ns                # the constituent quantities
```

The key is `"{realpath}_{st_size}_{st_mtime_ns}"` — same bytes the historical implementation produced. `parse_key` reverses it by splitting on the last two separators, so underscores inside paths are safe. Raises `ValueError` on malformed keys.

## Store: query with compute-on-miss

`query` returns, for every input path in order, the payload the store has recorded for that path's quick-signature key:

```python
from file_quick_signature.store import SignatureStore

store = SignatureStore("E:/pool/signature.json").load()
results, not_found_idx, not_found_keys = store.query(
    img_paths, compute=my_batch_hash)   # misses -> my_batch_hash(paths), recorded + saved
```

- `results` — one entry per input path, aligned 1:1: the stored payload on a hit, the computed payload on a miss (when `compute` is given), None on a miss without `compute`.
- `compute(miss_paths) -> payloads` is called once, with all missed paths in query order (e.g. a batch hashing function); it returns one payload per missed path, in the same order. Those payloads fill the missing slots in `results` and are recorded in the store.
- `not_found_idx` / `not_found_keys` — the indices (into the input list) of the paths that missed, and the keys they were looked up under (post file-remap).
- `query` without `compute` is a pure lookup that never saves.
- `save=False` records in memory only (the historical `clean_cache` semantics).
- Missing JSON file loads as an empty store; `json_path=None` is in-memory only and `save()` raises.

## Path remapping (regex)

Both remap sides take an ordered list of `(pattern, replacement)` regex pairs applied with `re.sub` in list order (later rules see earlier output). A Windows path used as a *replacement* must double its backslashes: `path.replace("\\", "\\\\")` — a lone `\U`/`\A` in a replacement template is an escape error.

**File-side** (`file_remappers`) rewrites a live file's path before its key is built — new lookups and new records stay in the cache's path space. Rule `("xxx/yyy", "ccc")`: the file `xxx/yyy/aa/cc` is looked up (and recorded) as `ccc/aa/cc`.

**Cache-side** (`cache_remappers`) rewrites the path component of *stored keys* at `load()` — old keys migrate into the live path space (persists on next `save`; on collision the later entry wins). Rule `("ccc", "xxx/yyy")`: the stored key `ccc/aa/cc` becomes `xxx/yyy/aa/cc`.

For one relocated root configure either side, not both — the two sides translate in opposite directions, and both active for the same prefix make lookups miss.

### Windows ↔ Linux example

A cache built on Windows (`E:\pool\a.jpg` keys) used from a Linux mount, or vice versa, needs a prefix rewrite plus separator normalization. Write the pairs by hand:

```python
# On Linux, files at /mnt/e/pool/... hit the Windows-built cache:
SignatureStore("/mnt/e/pool/signature.json",
               file_remappers=[(r"^/mnt/e", "E:"), (r"/", r"\\")])

# Or migrate the cache keys into the live Linux space instead:
SignatureStore("/mnt/e/pool/signature.json",
               cache_remappers=[(r"^E:\\", "/mnt/e/"), (r"\\", "/")])
```

…or generate them from the two roots (`key.py`), which also component-bounds the prefix rule so `/mnt/e2` does not catch `/mnt/e` rules:

```python
from file_quick_signature.key import (linux_to_windows_remappers,
                                      windows_to_linux_remappers)

# On Linux, files at /mnt/e/pool/... hit the Windows-built cache:
SignatureStore("/mnt/e/pool/signature.json",
               file_remappers=linux_to_windows_remappers("/mnt/e", "E:"))

# Or migrate the cache keys into the live Linux space instead:
SignatureStore("/mnt/e/pool/signature.json",
               cache_remappers=windows_to_linux_remappers("E:", "/mnt/e"))
```

`linux_to_windows_remappers(linux_root, windows_root)` yields `[(r"^<linux_root>(?=/|$)", "<windows_root>"), (r"/", r"\\")]`; `windows_to_linux_remappers(windows_root, linux_root)` the inverse. `/` separators in the Windows root are accepted (`E:/pool` behaves as `E:\pool`); roots match exactly as given (drive-letter case included). Paths outside the root keep their prefix — only their separators are normalized. Both functions raise `ValueError` for a filesystem root (`/` or `\`).

## Development

Tests (class-based pytest, stdlib-only package):

```bash
conda run -n science python -m pytest tests/ -q
```
