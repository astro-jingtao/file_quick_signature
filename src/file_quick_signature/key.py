"""Quick-signature key grammar: build, reverse-parse, and remap path components."""

from __future__ import annotations

from collections.abc import Sequence
import logging
import os
import re
from typing import Literal, NamedTuple, Union

# Key format: "{path}_{size}_{mtime_ns}", byte-identical to the historical
# reference implementation (`f"{os.path.realpath(path)}_{st.st_size}_{st.st_mtime_ns}"`).
# Reversible: `size` and `mtime_ns` are plain integers, so splitting from the
# right on the last two separators always recovers the three components —
# underscores inside the path are harmless.
KEY_SEPARATOR = "_"

# Library logger. No NullHandler on purpose: with no logging configuration
# Python's last-resort handler still emits warnings to stderr, so "warn"
# unmatched-remapper reports are visible without any setup.
_logger = logging.getLogger(__name__)

# Accepted values for a remapper's optional on_unmatched element.
_VALID_ON_UNMATCHED = ("raise", "warn", "ignore")

# A remapper is a (pattern, replacement) regex pair, optionally extended with
# a third element naming the behavior when the pattern matches nothing:
# "raise" (ValueError), "warn" (log a warning and skip), or "ignore"
# (skip silently — the default and the historical behavior of bare pairs).
OnUnmatched = Literal["raise", "warn", "ignore"]
Remapper = Union[tuple[str, str], tuple[str, str, OnUnmatched]]


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
    body = text.removeprefix("-")
    if not body.isdigit():
        raise ValueError(
            f"Malformed quick-signature key {key!r}: {field} field {text!r} is not an integer"
        )
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
            f"'{{path}}{KEY_SEPARATOR}{{size}}{KEY_SEPARATOR}{{mtime_ns}}'"
        )
    path, size_text, mtime_text = parts
    size = _parse_int_field(size_text, key, "size")
    mtime_ns = _parse_int_field(mtime_text, key, "mtime_ns")
    return SignatureKey(path, size, mtime_ns)


def apply_remappers(path: str, remappers: Sequence[Remapper] | None) -> str:
    """
    Apply an ordered list of ``(pattern, replacement)`` regex pairs to a path.

    Each pair is applied via ``re.sub(pattern, replacement, path)`` in list
    order, so later rules see the output of earlier ones. ``None`` or an empty
    list returns the path unchanged.

    A pair may carry a third element ``on_unmatched`` selecting the behavior
    when its pattern matches nothing: ``"raise"`` raises `ValueError`,
    ``"warn"`` logs a warning and leaves the path unchanged, and ``"ignore"``
    (the default, and always the behavior of bare two-element pairs) silently
    leaves it unchanged.
    """
    if not remappers:
        return path
    for rule in remappers:
        if len(rule) == 3:
            pattern, replacement, on_unmatched = rule
        elif len(rule) == 2:
            pattern, replacement = rule
            on_unmatched = "ignore"
        else:
            raise ValueError(
                f"Malformed remapper {rule!r}: expected '(pattern, replacement)' "
                "or '(pattern, replacement, on_unmatched)'"
            )
        # Validate before substituting so a bogus value cannot hide behind a
        # pattern that happens to match.
        if on_unmatched not in _VALID_ON_UNMATCHED:
            raise ValueError(
                f"Invalid on_unmatched {on_unmatched!r} in remapper {rule!r}: "
                f"expected one of {_VALID_ON_UNMATCHED}"
            )
        new_path, n_subs = re.subn(pattern, replacement, path)
        if n_subs == 0 and on_unmatched != "ignore":
            if on_unmatched == "raise":
                raise ValueError(
                    f"Remapper pattern {pattern!r} did not match path {path!r} "
                    "(on_unmatched='raise')"
                )
            _logger.warning(
                "Remapper pattern %r did not match path %r; leaving it unchanged",
                pattern,
                path,
            )
        path = new_path
    return path


def remap_key(key: str, remappers: Sequence[Remapper] | None) -> str:
    """Remap the path component of a key, keeping size and mtime_ns intact."""
    sig = parse_key(key)
    return build_key(apply_remappers(sig.path, remappers), sig.size, sig.mtime_ns)


def _bridge_remappers(
    src_root: str, dst_root: str, src_sep: str, dst_sep: str
) -> list[tuple[str, str]]:
    # Shared builder for the two direction-named functions below: a prefix-swap
    # rule plus a separator-normalization rule, both built from the two roots.
    src = src_root.rstrip(src_sep)
    dst = dst_root.rstrip(dst_sep)
    # A root made of separators alone (either flavor) is a filesystem root.
    if not src.strip(src_sep + dst_sep) or not dst.strip(src_sep + dst_sep):
        raise ValueError(
            f"Cannot bridge {src_root!r} -> {dst_root!r}: a bridge root must "
            f"be a named directory ('/mnt/e', 'E:'), not the filesystem root "
            f"('/', '\\')"
        )
    # Replacement templates must double backslashes (re.sub template semantics).
    return [
        # Component-bounded prefix swap: the lookahead keeps sibling roots
        # sharing a textual prefix (/mnt/e vs /mnt/e2) out of the rewrite.
        ("^" + re.escape(src) + "(?=" + re.escape(src_sep) + "|$)", dst.replace("\\", "\\\\")),
        # Separator normalization for the rest of the path. The swapped-in
        # dst prefix already uses dst separators, so it is unaffected.
        (re.escape(src_sep), dst_sep.replace("\\", "\\\\")),
    ]


def linux_to_windows_remappers(linux_root: str, windows_root: str) -> list[tuple[str, str]]:
    r"""Regex pairs rewriting a Linux path under ``linux_root`` into its Windows
    form under ``windows_root`` — for `SignatureStore(file_remappers=...)`
    when a Windows-built cache is read from a Linux mount.

    ``linux_to_windows_remappers("/mnt/e", "E:")`` yields rules equivalent to
    ``[(r"^/mnt/e(?=/|$)", "E:"), (r"/", r"\\")]``: ``/mnt/e/pool/a.jpg`` is
    keyed as ``E:\pool\a.jpg``, so live Linux lookups hit the Windows-built
    cache. Sibling roots (``/mnt/e2/...``) keep their prefix; only their
    separators are normalized. ``/`` separators in ``windows_root`` are
    accepted (``E:/pool`` behaves as ``E:\pool``).

    Roots are matched exactly as given (drive-letter case included) — write
    them the way they appear in the cache keys / live paths.

    Raises
    ------
    ValueError
        If either root is the filesystem root itself (normalizes to ``/`` or
        ``\``) — bridge between named roots instead.
    """
    return _bridge_remappers(linux_root, windows_root.replace("/", "\\"), "/", "\\")


def windows_to_linux_remappers(windows_root: str, linux_root: str) -> list[tuple[str, str]]:
    r"""Regex pairs rewriting a Windows path under ``windows_root`` into its
    Linux form under ``linux_root`` — for `SignatureStore(cache_remappers=...)`
    migrating Windows-built keys into the live Linux path space (the inverse
    of `linux_to_windows_remappers`; also usable as ``file_remappers`` to key
    live Windows files into a Linux-built cache).

    ``windows_to_linux_remappers("E:", "/mnt/e")`` yields rules equivalent to
    ``[(r"^E:(?=\\|$)", "/mnt/e"), (r"\\", "/")]``: the stored key
    ``E:\pool\a.jpg`` is read as ``/mnt/e/pool/a.jpg``. ``/`` separators in
    ``windows_root`` are accepted (``E:/pool`` behaves as ``E:\pool``).

    Roots are matched exactly as given (drive-letter case included) — write
    them the way they appear in the cache keys / live paths.

    Raises
    ------
    ValueError
        If either root is the filesystem root itself (normalizes to ``/`` or
        ``\``) — bridge between named roots instead.
    """
    return _bridge_remappers(windows_root.replace("/", "\\"), linux_root, "\\", "/")


def file_quick_signature(path: str, remappers: Sequence[Remapper] | None = None) -> str:
    """
    Return a quick-change fingerprint for the given file.
    The key "{canonical_path}_{size}_{mtime_ns}" can be stored and later
    compared to detect any modification without reading the file.

    Parameters
    ----------
    path : str
        Absolute or relative path to the file.
    remappers : sequence of (pattern, replacement[, on_unmatched]), optional
        Regex pairs applied to the canonical path before the key is built
        (file-side remap: the file at ``xxx/yyy/aa/cc`` is keyed as
        ``ccc/aa/cc`` given the rule ``("xxx/yyy", "ccc")``); see
        `apply_remappers` for the optional third element. The file itself
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
        If the path does not exist.
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
