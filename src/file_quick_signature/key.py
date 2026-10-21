from __future__ import annotations

import os
import re
from typing import NamedTuple, Optional, Sequence, Tuple

# Key format: "{path}_{size}_{mtime_ns}", byte-identical to the historical
# reference implementation (`f"{os.path.realpath(path)}_{st.st_size}_{st.st_mtime_ns}"`).
# Reversible: `size` and `mtime_ns` are plain integers, so splitting from the
# right on the last two separators always recovers the three components —
# underscores inside the path are harmless.
KEY_SEPARATOR = "_"


class SignatureKey(NamedTuple):
    """The constituent quantities of a quick-signature key (see `parse_key`)."""

    path: str
    size: int
    mtime_ns: int


def build_key(path: str, size: int, mtime_ns: int) -> str:
    """Assemble a key from its components — the exact inverse of `parse_key`."""
    return f"{path}{KEY_SEPARATOR}{size}{KEY_SEPARATOR}{mtime_ns}"


def _parse_int_field(text: str, key: str, field: str) -> int:
    # Optional leading '-' keeps pre-1970 (negative) mtimes parsable.
    body = text[1:] if text.startswith("-") else text
    if not body.isdigit():
        raise ValueError(
            f"Malformed quick-signature key {key!r}: {field} field {text!r} is not an integer")
    return int(text)


def parse_key(key: str) -> SignatureKey:
    """
    Reverse-parse a quick-signature key into its constituent quantities.

    Parameters
    ----------
    key : str
        A key in the "{path}_{size}_{mtime_ns}" format produced by
        `file_quick_signature` / `build_key`.

    Returns
    -------
    SignatureKey
        Named tuple ``(path, size, mtime_ns)``; also unpacks as a plain tuple.

    Raises
    ------
    ValueError
        If the key does not carry two trailing integer fields.
    """
    parts = key.rsplit(KEY_SEPARATOR, 2)
    if len(parts) != 3:
        raise ValueError(
            f"Malformed quick-signature key {key!r}: expected "
            f"'{{path}}{KEY_SEPARATOR}{{size}}{KEY_SEPARATOR}{{mtime_ns}}'")
    path, size_text, mtime_text = parts
    size = _parse_int_field(size_text, key, "size")
    mtime_ns = _parse_int_field(mtime_text, key, "mtime_ns")
    return SignatureKey(path, size, mtime_ns)


def apply_remappers(path: str,
                    remappers: Optional[Sequence[Tuple[str, str]]]) -> str:
    """
    Apply an ordered list of ``(pattern, replacement)`` regex pairs to a path.

    Each pair is applied via ``re.sub(pattern, replacement, path)`` in list
    order, so later rules see the output of earlier ones. ``None`` or an empty
    list returns the path unchanged.
    """
    if not remappers:
        return path
    for pattern, replacement in remappers:
        path = re.sub(pattern, replacement, path)
    return path


def remap_key(key: str,
              remappers: Optional[Sequence[Tuple[str, str]]]) -> str:
    """Remap the path component of a key, keeping size and mtime_ns intact."""
    sig = parse_key(key)
    return build_key(apply_remappers(sig.path, remappers), sig.size, sig.mtime_ns)


def file_quick_signature(path: str,
                         remappers: Optional[Sequence[Tuple[str, str]]] = None) -> str:
    """
    Return a quick-change fingerprint for the given file.
    The key "{canonical_path}_{size}_{mtime_ns}" can be stored and later
    compared to detect any modification without reading the file.

    Parameters
    ----------
    path : str
        Absolute or relative path to the file.
    remappers : sequence of (pattern, replacement), optional
        Regex pairs applied to the canonical path before the key is built
        (file-side remap: the file at ``xxx/yyy/aa/cc`` is keyed as
        ``ccc/aa/cc`` given the rule ``("xxx/yyy", "ccc")``). The file itself
        is always stated at its real location; only the key's path component
        is rewritten.

    Returns
    -------
    str
        Key in the format ``{canonical_path}_{size_in_bytes}_{mtime_ns}``
        canonical_path : str  - absolute, symlink-free path (after remappers)
        size_in_bytes  : int  - st_size from os.stat
        mtime_ns       : int  - st_mtime_ns from os.stat (nanosecond precision)

    Raises
    ------
    FileNotFoundError
        If the path does not exist or is not a file.
    OSError
        For other system-level errors during stat.
    """
    # Resolve symlinks and make path absolute so the caller always
    # compares the same identity.
    canonical_path = os.path.realpath(path)

    # Single system call to fetch everything we need.
    st = os.stat(canonical_path, follow_symlinks=True)

    key_path = apply_remappers(canonical_path, remappers)

    return build_key(key_path, st.st_size, st.st_mtime_ns)
