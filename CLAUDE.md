# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`file_quick_signature` is a small personal-reuse Python (>= 3.9, stdlib-only) library: quick-change file signature keys (`{path}_{size}_{mtime_ns}`) that detect file modification without reading contents, plus a JSON-backed `SignatureStore` mapping those keys to payloads (content hashes, ...) with compute-on-miss queries and regex path remapping. Full API semantics (key grammar, remap directions, Windows/Linux bridging examples) live in README.md — extend it when changing behavior.

## Commands

- Install (editable): `pip install -e . --no-build-isolation`
- All tests: `python -m pytest tests/ -q`
- One test: `python -m pytest tests/test_store.py::TestQuery::test_hit_and_miss -v`
- No linter or formatter is configured.

## Architecture

- `src` layout, no runtime dependencies. Two modules under `src/file_quick_signature/`:
  - `key.py` — pure key logic, no I/O except `stat`: `build_key` / `parse_key` (reverse-parse into `SignatureKey(path, size, mtime_ns)`), `apply_remappers` (ordered `re.sub` pairs), `remap_key`, `linux_to_windows_remappers` / `windows_to_linux_remappers` (generated windows↔linux bridge pairs), `file_quick_signature`
  - `store.py` — `SignatureStore`: JSON load/save (format identical to the historical `signature.json`), `query(paths, compute, save)` with compute-on-miss recording
- `__init__.py` is documentation only; consumers import from the concrete modules (`from file_quick_signature.store import SignatureStore`).
- Absolute imports only, never relative.
- Key-format compatibility is a hard constraint: keys produced for un-remapped paths must stay byte-identical to `f"{os.path.realpath(path)}_{st.st_size}_{st.st_mtime_ns}"` — existing historical caches (~160k entries) depend on it. `tests/test_key.py::test_parity_with_reference_formula` guards this; never change the format without a migration story.
- Remap rules are `(pattern, replacement)` regex pairs; replacements containing Windows paths must double backslashes (re.sub template semantics — `\U` etc. are escape errors).
- Tests are pytest class-based, mirror modules, always use `tmp_path`.
