# file_quick_signature

A quick-change file signature key cache: keys of the form `{path}_{size}_{mtime_ns}` detect file modifications without reading file contents, and a JSON-backed store maps those keys to arbitrary payloads (content hashes, embeddings, ...) so unchanged files skip re-processing. Keys are byte-identical with the historical ones, so existing `signature.json` caches keep working.

Works on Windows and Linux alike — pure `os`/`json`/`re`, no platform-specific code. Cross-machine caches (different roots or separators) are reconciled with path remapping.

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

## Path remapping

A remapper is any class with a `remap(path) -> str` method (`key.Remapper`) — however it works internally. The built-in classes cover the common cases; your own class plugs in the same way. Both remap sides take one remapper, or an ordered sequence of them (later remappers see earlier output).

- `RegexRemapper(*rules)` — ordered `re.sub` rules: `(pattern, replacement)` pairs, e.g. `RegexRemapper((r"^E:", "/mnt/e"), (r"\\", "/"))`. A Windows path used as a *replacement* must double its backslashes: `path.replace("\\", "\\\\")` — a lone `\U`/`\A` in a replacement template is an escape error. Rules are validated once at construction.
- `LinuxToWindowsRemapper(linux_root, windows_root, on_unmatched=...)` / `WindowsToLinuxRemapper(...)` — the cross-OS bridge (regex internally).
- `AbsoluteToRelativeRemapper(base, on_unmatched=...)` / `RelativeToAbsoluteRemapper(...)` — portable relative-path keys (`os.path.relpath` / `join` semantics internally).

A rule or remapper's `on_unmatched` selects the behavior for a path it cannot remap: `"raise"` (raise `ValueError`), `"warn"` (log a warning, leave the path unchanged), or `"ignore"` (leave it unchanged — the default, and always the behavior of bare two-element regex pairs). `"warn"` reports through the `file_quick_signature.key` logger; with no logging configured, Python's last-resort handler still prints it to stderr. Example: `RegexRemapper((r"^E:\\pool", "E:/data", "raise"))` turns any path outside `E:\pool` into an error instead of a silently mis-keyed lookup. An invalid value raises `ValueError` at construction, so a typo cannot hide behind a hit.

**File-side** (`file_remappers`) rewrites a live file's path before its key is built — new lookups and new records stay in the cache's path space. `RegexRemapper((r"xxx/yyy", "ccc"))`: the file `xxx/yyy/aa/cc` is looked up (and recorded) as `ccc/aa/cc`.

**Cache-side** (`cache_remappers`) rewrites the path component of *stored keys* at `load()` — old keys migrate into the live path space (persists on next `save`; on collision the later entry wins). `RegexRemapper((r"ccc", r"xxx/yyy"))`: the stored key `ccc/aa/cc` becomes `xxx/yyy/aa/cc`.

For one relocated root configure either side, not both — the two sides translate in opposite directions, and both active for the same prefix make lookups miss.

### Windows ↔ Linux example

A cache built on Windows (`E:\pool\a.jpg` keys) used from a Linux mount, or vice versa, needs a prefix rewrite plus separator normalization. Write the rules by hand:

```python
# On Linux, files at /mnt/e/pool/... hit the Windows-built cache:
SignatureStore(
    "/mnt/e/pool/signature.json",
    file_remappers=RegexRemapper((r"^/mnt/e", "E:"), (r"/", r"\\")),
)

# Or migrate the cache keys into the live Linux space instead:
SignatureStore(
    "/mnt/e/pool/signature.json",
    cache_remappers=RegexRemapper((r"^E:\\", "/mnt/e/"), (r"\\", "/")),
)
```

…or use the bridge classes (`key.py`), which component-bound the prefix rule so `/mnt/e2` does not catch `/mnt/e` rules:

```python
from file_quick_signature.key import LinuxToWindowsRemapper, WindowsToLinuxRemapper

# On Linux, files at /mnt/e/pool/... hit the Windows-built cache:
SignatureStore("/mnt/e/pool/signature.json", file_remappers=LinuxToWindowsRemapper("/mnt/e", "E:"))

# Or migrate the cache keys into the live Linux space instead:
SignatureStore("/mnt/e/pool/signature.json", cache_remappers=WindowsToLinuxRemapper("E:", "/mnt/e"))
```

`LinuxToWindowsRemapper("/mnt/e", "E:")` maps `/mnt/e/pool/a.jpg` to `E:\pool\a.jpg`; `WindowsToLinuxRemapper("E:", "/mnt/e")` is the inverse — the two round-trip back to the original path. `/` separators in the Windows root are accepted (`E:/pool` behaves as `E:\pool`); roots match exactly as given (drive-letter case included). Paths outside the root are governed by `on_unmatched` (default: they keep their prefix — only their separators are normalized). Both classes raise `ValueError` for a filesystem root (`/` or `\`).

### Relative-path keys

`key.py` also provides base-relative remappers — a portable cache whose keys no longer depend on where the tree lives:

```python
from file_quick_signature.key import AbsoluteToRelativeRemapper, RelativeToAbsoluteRemapper

# Key live files relative to the pool root: E:\pool\sub\a.jpg -> "sub\a.jpg"
SignatureStore("signature.json", file_remappers=AbsoluteToRelativeRemapper(r"E:\pool"))

# Strict: any path outside the base is an error, not a silently mis-keyed lookup
AbsoluteToRelativeRemapper("/mnt/e/pool", on_unmatched="raise")

# Reverse: stored relative keys are read as absolute live paths at load
SignatureStore("signature.json", cache_remappers=RelativeToAbsoluteRemapper("/mnt/e/pool"))
```

`AbsoluteToRelativeRemapper(base, on_unmatched="ignore")` applies `os.path.relpath(path, base)` semantics: redundant components normalize away (`./x/../sub/a.jpg` keys the same as `sub/a.jpg`), the Windows flavor reads both separators and matches case-insensitively, and the base itself maps to `"."`. A path the base cannot relativize is governed by `on_unmatched`: one not absolute in the base's flavor (already-relative inputs, other-OS roots), one on a different drive (Windows flavor), or one outside the base — under the default each is left unchanged, so already-relative paths stay in the relative key space and outside trees never produce `..`-escape keys.

`RelativeToAbsoluteRemapper(base, on_unmatched="ignore")` is the inverse (`os.path.join` + normalize semantics): it anchors a relative path under `base`, resolving `..` components (`../other/a.jpg` under `/mnt/e/pool` maps to `/mnt/e/other/a.jpg`); paths already absolute-looking in either OS's syntax (`C:`, `\\unc`, `/rooted`, `\rooted`) are governed by `on_unmatched` — under the default they pass through unchanged, so re-applying is a no-op. The two classes round-trip: rel then abs restores the original absolute path, abs then rel the original relative path.

Bases of any absolute flavor work — Windows `E:\pool` / `E:/pool` / `C:\` / UNC, POSIX `/mnt/e` / `/` — and the flavor is detected textually from the base, so a foreign-flavor base works on any host OS (the POSIX flavor treats `\` as a regular filename character). `RelativeToAbsoluteRemapper` also accepts a relative base: `RelativeToAbsoluteRemapper(os.path.relpath(A, B))` re-anchors paths relative to `A` into paths relative to `B`. `AbsoluteToRelativeRemapper` rejects relative bases — relativizing against them is not well defined (strip relative prefixes with `RegexRemapper` instead).

Cross-OS sharing: relative keys carry the base flavor's separators, so to share one relative cache between Windows and POSIX, append a separator rule on the Windows side so both key with `/` — `file_remappers=[AbsoluteToRelativeRemapper(r"E:\pool"), RegexRemapper((r"\\", "/"))]`.

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
