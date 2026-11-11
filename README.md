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

key = file_quick_signature(r"E:\pool\a.jpg")  # "E:\\pool\\a.jpg_98304_133851860294701234"
sig = parse_key(key)  # SignatureKey(path=..., size=98304, mtime_ns=133851860294701234)
sig.path, sig.size, sig.mtime_ns  # the constituent quantities
```

The key is `"{realpath}_{st_size}_{st_mtime_ns}"` — same bytes the historical implementation produced. `parse_key` reverses it by splitting on the last two separators, so underscores inside paths are safe. Raises `ValueError` on malformed keys.

## Store: query with compute-on-miss

`query` returns, for every input path in order, the payload the store has recorded for that path's quick-signature key:

```python
from file_quick_signature.store import SignatureStore

store = SignatureStore("E:/pool/signature.json").load()
results, not_found_idx, not_found_keys = store.query(
    img_paths, compute=my_batch_hash
)  # misses -> my_batch_hash(paths), recorded + saved
```

- `results` — one entry per input path, aligned 1:1: the stored payload on a hit, the computed payload on a miss (when `compute` is given), None on a miss without `compute`.
- `compute(miss_paths) -> payloads` is called once, with all missed paths in query order (e.g. a batch hashing function); it returns one payload per missed path, in the same order. Those payloads fill the missing slots in `results` and are recorded in the store.
- `not_found_idx` / `not_found_keys` — the indices (into the input list) of the paths that missed, and the keys they were looked up under (post file-remap).
- `query` without `compute` is a pure lookup that never saves.
- `save=False` records in memory only (the historical `clean_cache` semantics).
- Missing JSON file loads as an empty store; `json_path=None` is in-memory only and `save()` raises.

## Path remapping (regex)

Both remap sides take an ordered list of `(pattern, replacement)` regex pairs applied with `re.sub` in list order (later rules see earlier output). A Windows path used as a *replacement* must double its backslashes: `path.replace("\\", "\\\\")` — a lone `\U`/`\A` in a replacement template is an escape error.

A pair may carry a third element selecting the behavior when its pattern matches nothing: `"raise"` (raise `ValueError`), `"warn"` (log a warning, leave the path unchanged), or `"ignore"` (leave it unchanged — the default, and always the behavior of bare two-element pairs). `"warn"` reports through the `file_quick_signature.key` logger; with no logging configured, Python's last-resort handler still prints it to stderr. Example: `[(r"^E:\\pool", "E:/data", "raise")]` turns any path outside `E:\pool` into an error instead of a silently mis-keyed lookup. An invalid third element raises `ValueError` — checked even when the pattern matches, so a typo cannot hide behind a hit.

**File-side** (`file_remappers`) rewrites a live file's path before its key is built — new lookups and new records stay in the cache's path space. Rule `("xxx/yyy", "ccc")`: the file `xxx/yyy/aa/cc` is looked up (and recorded) as `ccc/aa/cc`.

**Cache-side** (`cache_remappers`) rewrites the path component of *stored keys* at `load()` — old keys migrate into the live path space (persists on next `save`; on collision the later entry wins). Rule `("ccc", "xxx/yyy")`: the stored key `ccc/aa/cc` becomes `xxx/yyy/aa/cc`.

For one relocated root configure either side, not both — the two sides translate in opposite directions, and both active for the same prefix make lookups miss.

### Windows ↔ Linux example

A cache built on Windows (`E:\pool\a.jpg` keys) used from a Linux mount, or vice versa, needs a prefix rewrite plus separator normalization. Write the pairs by hand:

```python
# On Linux, files at /mnt/e/pool/... hit the Windows-built cache:
SignatureStore("/mnt/e/pool/signature.json", file_remappers=[(r"^/mnt/e", "E:"), (r"/", r"\\")])

# Or migrate the cache keys into the live Linux space instead:
SignatureStore("/mnt/e/pool/signature.json", cache_remappers=[(r"^E:\\", "/mnt/e/"), (r"\\", "/")])
```

…or generate them from the two roots (`key.py`), which also component-bounds the prefix rule so `/mnt/e2` does not catch `/mnt/e` rules:

```python
from file_quick_signature.key import linux_to_windows_remappers, windows_to_linux_remappers

# On Linux, files at /mnt/e/pool/... hit the Windows-built cache:
SignatureStore(
    "/mnt/e/pool/signature.json", file_remappers=linux_to_windows_remappers("/mnt/e", "E:")
)

# Or migrate the cache keys into the live Linux space instead:
SignatureStore(
    "/mnt/e/pool/signature.json", cache_remappers=windows_to_linux_remappers("E:", "/mnt/e")
)
```

`linux_to_windows_remappers(linux_root, windows_root)` yields `[(r"^<linux_root>(?=/|$)", "<windows_root>"), (r"/", r"\\")]`; `windows_to_linux_remappers(windows_root, linux_root)` the inverse. `/` separators in the Windows root are accepted (`E:/pool` behaves as `E:\pool`); roots match exactly as given (drive-letter case included). Paths outside the root keep their prefix — only their separators are normalized. Both functions raise `ValueError` for a filesystem root (`/` or `\`).

### Relative-path keys

`key.py` also generates base-relative pairs — a portable cache whose keys no longer depend on where the tree lives:

```python
from file_quick_signature.key import absolute_to_relative_remappers, relative_to_absolute_remappers

# Key live files relative to the pool root: E:\pool\sub\a.jpg -> "sub\a.jpg"
SignatureStore("signature.json", file_remappers=absolute_to_relative_remappers(r"E:\pool"))

# Strict: any path outside the base is an error, not a silently mis-keyed lookup
absolute_to_relative_remappers("/mnt/e/pool", on_unmatched="raise")

# Reverse: stored relative keys are read as absolute live paths at load
SignatureStore("signature.json", cache_remappers=relative_to_absolute_remappers("/mnt/e/pool"))
```

`absolute_to_relative_remappers(base, on_unmatched="ignore")` yields a prefix rule stripping `base` and its separator, plus a separator-normalization rule to the base's flavor — `E:/pool/sub/a.jpg` and `E:\pool\sub\a.jpg` land on the same key. A path not carrying the `base` prefix (outside the tree, or already relative) is governed by `on_unmatched`; under the default it keeps its form apart from separator normalization, so already-relative paths stay in the relative key space.

`relative_to_absolute_remappers(base, on_unmatched="ignore")` is the inverse: it prepends `base` + separator to paths that do not look absolute in either OS's syntax (`C:`, `\\unc`, `/rooted`, `\rooted`); already-absolute paths match nothing and pass through (per `on_unmatched`), so re-applying is a no-op.

Bases of any flavor work — Windows `E:\pool` / `E:/pool` / `C:\`, POSIX `/mnt/e` / `/`, or relative (`pool` strips that prefix from relative paths; `relative_to_absolute_remappers(os.path.relpath(A, B))` re-anchors paths relative to `A` into paths relative to `B`). Bases match textually, exactly as written (drive-letter case included).

Cross-OS sharing: relative keys carry the base flavor's separators, so to share one relative cache between Windows and POSIX, append a separator rule on the Windows side so both key with `/` — `file_remappers=absolute_to_relative_remappers(r"E:\pool") + [(r"\\", "/")]`.

## Development

Tests (class-based pytest, stdlib-only package):

```bash
python -m pytest tests/ -q
```

Lint and format check (ruff, configured in `ruff.toml`):

```bash
ruff check .
ruff format --check .
```
