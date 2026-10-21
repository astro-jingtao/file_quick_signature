from __future__ import annotations

import json
import os
from typing import Any, Callable, List, Optional, Sequence, Tuple

from file_quick_signature.key import file_quick_signature, remap_key

# A remapper is a (pattern, replacement) regex pair; lists are applied in order.
FileRemappers = Optional[Sequence[Tuple[str, str]]]


class SignatureStore:
    """
    JSON-backed cache mapping file quick-signature keys to arbitrary payloads
    (content hashes, embeddings, ...), so unchanged files skip re-processing.

    The JSON file is a plain ``{key: payload}`` dict (historically
    ``signature.json``). Keys are ``"{path}_{size}_{mtime_ns}"`` strings;
    see `file_quick_signature.key` for building and reverse-parsing them.

    Parameters
    ----------
    json_path : str, optional
        Path of the JSON cache file. ``None`` gives an in-memory-only store
        (`save` then refuses rather than silently dropping data).
    file_remappers : sequence of (pattern, replacement), optional
        File-side remap: regex pairs applied to a file's canonical path before
        its lookup key is built. Rule ``("xxx/yyy", "ccc")`` makes the file
        ``xxx/yyy/aa/cc`` be looked up (and recorded) as ``ccc/aa/cc``, so new
        keys stay in the cache's path space.
    cache_remappers : sequence of (pattern, replacement), optional
        Cache-side remap: regex pairs applied to the path component of stored
        keys at `load` time. Rule ``("ccc", "xxx/yyy")`` rewrites the stored
        key ``ccc/aa/cc`` into ``xxx/yyy/aa/cc``, so lookups from the live
        file tree hit entries recorded under a different root. The rename is
        in-memory; it persists only when the store is later saved (on
        collision the later entry wins).

    For one relocated root configure EITHER side, not both — a file rule
    writes new keys into the cache's space, a cache rule migrates old keys
    into the live space; applying both for the same prefix makes lookups
    miss (each side translates in the opposite direction).
    """

    def __init__(self,
                 json_path: Optional[str] = None,
                 file_remappers: FileRemappers = None,
                 cache_remappers: FileRemappers = None):
        self.json_path = json_path
        self.file_remappers: List[Tuple[str, str]] = list(file_remappers or [])
        self.cache_remappers: List[Tuple[str, str]] = list(cache_remappers or [])
        self.data: dict = {}

    def load(self) -> "SignatureStore":
        """Read the JSON file (a missing file yields an empty store), then apply
        `cache_remappers` to rename stored keys into the live path space."""
        if self.json_path is not None and os.path.exists(self.json_path):
            with open(self.json_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        else:
            raw = {}

        if self.cache_remappers:
            self.data = {remap_key(k, self.cache_remappers): v for k, v in raw.items()}
        else:
            self.data = raw
        return self

    def save(self) -> None:
        if self.json_path is None:
            raise ValueError("SignatureStore has no json_path; cannot save")
        with open(self.json_path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=4)

    def signature(self, path: str) -> str:
        """Quick-signature key for a live file path, under `file_remappers`."""
        return file_quick_signature(path, self.file_remappers)

    def query(self,
              paths: Sequence[str],
              compute: Optional[Callable[[Sequence[str]], Sequence[Any]]] = None,
              save: bool = True):
        """
        Look up payloads for ``paths``, computing and recording misses.

        Parameters
        ----------
        paths : list[str]
            File paths to query.
        compute : callable, optional
            ``compute(miss_paths) -> payloads`` — invoked once with the paths
            whose keys missed (e.g. a batch hash function). Its payloads fill
            the result list and are recorded in the store.
        save : bool
            Whether to persist the store after recording computed payloads.
            Ignored when ``compute`` is None (a pure query never saves).

        Returns
        -------
        tuple
            ``(payloads, not_found_idx, not_found_sign)`` — payloads aligned
            with ``paths`` (None for misses when ``compute`` is None), the
            indices of misses, and their keys (post file-remap).
        """
        payloads: list = []
        not_found_idx: List[int] = []
        not_found_sign: List[str] = []
        for i, img_path in enumerate(paths):
            this_sign = self.signature(img_path)
            this_payload = self.data.get(this_sign, None)
            if this_payload is None:
                not_found_idx.append(i)
                not_found_sign.append(this_sign)

            payloads.append(this_payload)

        if not_found_idx and compute is not None:
            new_paths = [paths[i] for i in not_found_idx]
            new_payloads = compute(new_paths)

            for i_new, i_all in enumerate(not_found_idx):
                payloads[i_all] = new_payloads[i_new]
                self.data[not_found_sign[i_new]] = new_payloads[i_new]

            if save:
                self.save()

        return payloads, not_found_idx, not_found_sign
