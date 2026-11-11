"""Quick-signature key grammar: build, reverse-parse, and remap path components."""

from __future__ import annotations

from collections.abc import Sequence
import logging
import ntpath
import os
import posixpath
import re
from types import ModuleType
from typing import Literal, NamedTuple, Protocol, Union, runtime_checkable

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

# Accepted values for every remapper's on_unmatched parameter.
_VALID_ON_UNMATCHED = ("raise", "warn", "ignore")

# A single regex rule for `RegexRemapper`: a (pattern, replacement) pair,
# optionally extended with a third element naming the behavior when the
# pattern matches nothing: "raise" (ValueError), "warn" (log a warning and
# skip), or "ignore" (skip silently — the default for bare pairs).
OnUnmatched = Literal["raise", "warn", "ignore"]
RegexRule = Union[tuple[str, str], tuple[str, str, OnUnmatched]]

# Textual path-shape probes, independent of the host OS and the Python
# version (unlike ntpath.isabs, whose UNC answer changed across releases):
# a path absolute in Windows syntax (drive + root, or a UNC lead)...
_WIN_ROOTED = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\)")
# ...and one absolute-looking in either OS's syntax (drive lead, UNC lead,
# or a separator root of either flavor).
_ANY_ROOTED = re.compile(r"^(?:[A-Za-z]:|\\\\|[/\\])")


@runtime_checkable
class Remapper(Protocol):
    """The library's remapping interface: anything with a ``remap`` method.

    A remapper rewrites one path string into the path space of a cache; how
    it does so — regex rules, os.path functions, anything — is the class's
    own choice. The classes in this module cover the common cases; any other
    class with this method is accepted wherever a remapper is taken.
    """

    def remap(self, path: str) -> str:
        """Rewrite ``path`` and return the result (a skipped path returns unchanged)."""
        ...


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


def _check_on_unmatched(on_unmatched: OnUnmatched) -> None:
    # Shared upfront validation for every remapper class's parameter.
    if on_unmatched not in _VALID_ON_UNMATCHED:
        raise ValueError(
            f"Invalid on_unmatched {on_unmatched!r}: expected one of {_VALID_ON_UNMATCHED}"
        )


def _report_unmatched(path: str, on_unmatched: OnUnmatched, message: str) -> str:
    # Shared non-match dispatch: raise, warn-and-keep, or silently keep. The
    # return value is the path the caller must keep.
    if on_unmatched == "raise":
        raise ValueError(f"{message} (on_unmatched='raise')")
    _logger.warning("%s; leaving it unchanged", message)
    return path


class RegexRemapper:
    """A remapper applying ordered regex rules with ``re.sub``.

    Each rule is a ``(pattern, replacement)`` pair, optionally extended with
    a third element ``on_unmatched`` selecting the behavior when the pattern
    matches nothing: ``"raise"`` raises `ValueError`, ``"warn"`` logs a
    warning and leaves the path unchanged, and ``"ignore"`` (the default, and
    always the behavior of bare two-element pairs) silently leaves it
    unchanged. Rules apply in order, later rules seeing earlier output; a
    replacement containing Windows backslashes must double them (``re.sub``
    template semantics — a lone ``\\U`` is an escape error). Rules are
    validated once at construction, so a malformed rule or a bogus
    ``on_unmatched`` value fails immediately, never on the first path.
    """

    def __init__(self, *rules: RegexRule) -> None:
        """``rules`` — one or more ``(pattern, replacement[, on_unmatched])`` tuples."""
        self._rules: list[tuple[str, str, OnUnmatched]] = []
        for rule in rules:
            if not isinstance(rule, (tuple, list)) or len(rule) not in (2, 3):
                raise ValueError(
                    f"Malformed remapper rule {rule!r}: expected '(pattern, replacement)' "
                    "or '(pattern, replacement, on_unmatched)'"
                )
            if len(rule) == 3:
                pattern, replacement, on_unmatched = rule
            else:
                pattern, replacement = rule
                on_unmatched = "ignore"
            # Validate before anything can match so a bogus value cannot hide
            # behind a pattern that happens to hit.
            _check_on_unmatched(on_unmatched)
            self._rules.append((pattern, replacement, on_unmatched))

    def remap(self, path: str) -> str:
        """Apply every rule in order; an unmatched rule acts per its on_unmatched."""
        for pattern, replacement, on_unmatched in self._rules:
            new_path, n_subs = re.subn(pattern, replacement, path)
            if n_subs == 0 and on_unmatched != "ignore":
                _report_unmatched(
                    path, on_unmatched, f"Remapper pattern {pattern!r} did not match path {path!r}"
                )
            path = new_path
        return path


def apply_remappers(path: str, remappers: Remapper | Sequence[Remapper] | None) -> str:
    """
    Apply one remapper, or an ordered sequence of them, to a path.

    A single `Remapper` is accepted directly; a sequence is applied in order,
    so later remappers see earlier output. ``None`` returns the path
    unchanged. An element that is not a remapper (e.g. a historical bare
    regex pair) raises `TypeError` — wrap pairs in `RegexRemapper`.
    """
    if remappers is None:
        return path
    items = [remappers] if isinstance(remappers, Remapper) else list(remappers)
    for item in items:
        if not isinstance(item, Remapper):
            raise TypeError(
                f"Expected a Remapper or a sequence of Remapper, got {item!r} "
                "(wrap regex pairs in RegexRemapper)"
            )
        path = item.remap(path)
    return path


def remap_key(key: str, remappers: Remapper | Sequence[Remapper] | None) -> str:
    """Remap the path component of a key, keeping size and mtime_ns intact."""
    sig = parse_key(key)
    return build_key(apply_remappers(sig.path, remappers), sig.size, sig.mtime_ns)


def _bridge_rules(
    src_root: str, dst_root: str, src_sep: str, dst_sep: str, on_unmatched: OnUnmatched
) -> list[RegexRule]:
    # Shared rule builder for the two direction-named bridge classes: a
    # prefix-swap rule plus a separator-normalization rule, both built from
    # the two roots. Only the prefix rule carries on_unmatched — the
    # separator rule matches any path containing a source separator.
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
        (
            "^" + re.escape(src) + "(?=" + re.escape(src_sep) + "|$)",
            dst.replace("\\", "\\\\"),
            on_unmatched,
        ),
        # Separator normalization for the rest of the path. The swapped-in
        # dst prefix already uses dst separators, so it is unaffected.
        (re.escape(src_sep), dst_sep.replace("\\", "\\\\")),
    ]


class LinuxToWindowsRemapper:
    r"""Remaps Linux paths under ``linux_root`` into their Windows form under
    ``windows_root`` — for `SignatureStore(file_remappers=...)` when a
    Windows-built cache is read from a Linux mount.

    ``LinuxToWindowsRemapper("/mnt/e", "E:")`` maps ``/mnt/e/pool/a.jpg`` to
    ``E:\pool\a.jpg``, so live Linux lookups hit the Windows-built cache.
    Internally a component-bounded prefix swap plus separator normalization,
    so sibling roots (``/mnt/e2/...``) keep their prefix — only their
    separators normalize. ``/`` separators in ``windows_root`` are accepted
    (``E:/pool`` behaves as ``E:\pool``).

    A path the ``linux_root`` prefix rule does not match is governed by
    ``on_unmatched`` (default ``"ignore"``: unchanged apart from separator
    normalization).

    Parameters
    ----------
    linux_root, windows_root : str
        Roots, matched exactly as given (drive-letter case included) — write
        them the way they appear in the cache keys / live paths.
    on_unmatched : "raise" | "warn" | "ignore"
        Behavior for a path outside ``linux_root``.

    Raises
    ------
    ValueError
        If either root is the filesystem root itself (normalizes to ``/`` or
        ``\``) — bridge between named roots instead.
    """

    def __init__(
        self, linux_root: str, windows_root: str, on_unmatched: OnUnmatched = "ignore"
    ) -> None:
        """Build the prefix-swap + separator rules; see the class docstring."""
        _check_on_unmatched(on_unmatched)
        self._rules = RegexRemapper(
            *_bridge_rules(linux_root, windows_root.replace("/", "\\"), "/", "\\", on_unmatched)
        )

    def remap(self, path: str) -> str:
        """Swap the ``linux_root`` prefix and normalize separators."""
        return self._rules.remap(path)


class WindowsToLinuxRemapper:
    r"""Remaps Windows paths under ``windows_root`` into their Linux form under
    ``linux_root`` — for `SignatureStore(cache_remappers=...)` migrating
    Windows-built keys into the live Linux path space (the inverse of
    `LinuxToWindowsRemapper`; also usable as ``file_remappers`` to key live
    Windows files into a Linux-built cache).

    ``WindowsToLinuxRemapper("E:", "/mnt/e")`` maps the stored key
    ``E:\pool\a.jpg`` to ``/mnt/e/pool/a.jpg``. ``/`` separators in
    ``windows_root`` are accepted (``E:/pool`` behaves as ``E:\pool``).

    A path the ``windows_root`` prefix rule does not match is governed by
    ``on_unmatched`` (default ``"ignore"``: unchanged apart from separator
    normalization).

    Parameters
    ----------
    windows_root, linux_root : str
        Roots, matched exactly as given (drive-letter case included) — write
        them the way they appear in the cache keys / live paths.
    on_unmatched : "raise" | "warn" | "ignore"
        Behavior for a path outside ``windows_root``.

    Raises
    ------
    ValueError
        If either root is the filesystem root itself (normalizes to ``/`` or
        ``\``) — bridge between named roots instead.
    """

    def __init__(
        self, windows_root: str, linux_root: str, on_unmatched: OnUnmatched = "ignore"
    ) -> None:
        """Build the prefix-swap + separator rules; see the class docstring."""
        _check_on_unmatched(on_unmatched)
        self._rules = RegexRemapper(
            *_bridge_rules(windows_root.replace("/", "\\"), linux_root, "\\", "/", on_unmatched)
        )

    def remap(self, path: str) -> str:
        """Swap the ``windows_root`` prefix and normalize separators."""
        return self._rules.remap(path)


def _flavor_module(base: str) -> ModuleType:
    # Textual flavor detection (host-OS independent): a Windows lead — drive
    # letter, UNC, or backslash root — selects ntpath semantics; a "/"-rooted
    # or relative base selects posixpath. The Windows flavor reads "/" and
    # "\" interchangeably; the POSIX flavor treats "\" as a regular character.
    if base.startswith("\\") or re.match(r"[A-Za-z]:", base):
        return ntpath
    return posixpath


class AbsoluteToRelativeRemapper:
    r"""Remaps absolute paths under ``base`` to their form relative to
    ``base`` (`os.path.relpath` semantics) — for `SignatureStore(
    file_remappers=...)` keying a live tree into a portable cache of
    relative-path keys that no longer depends on where the tree is mounted.

    ``AbsoluteToRelativeRemapper(r"E:\pool")`` maps ``E:\pool\sub\a.jpg`` to
    ``sub\a.jpg``. Redundant components normalize away (``./x/../sub/a.jpg``
    keys the same as ``sub/a.jpg``), and under the Windows flavor both
    separators read the same and matching is case-insensitive (POSIX flavor:
    case-sensitive, ``\`` a regular character). ``base`` itself maps to
    ``"."``.

    A path the base cannot relativize is governed by ``on_unmatched``
    (default ``"ignore"``: the path is left unchanged): one not absolute in
    the base's flavor (already-relative inputs, other-OS roots), one relpath
    cannot join to the base (a different drive under the Windows flavor), or
    one outside the base (its relative form would escape through ``..``) —
    under ``"raise"`` each raises `ValueError`, under ``"warn"`` each is
    logged and skipped.

    ``base`` selects the path flavor textually, exactly as written
    (drive-letter case included): Windows ``E:\pool`` / ``E:/pool`` /
    ``C:\`` / UNC use Windows semantics, POSIX ``/mnt/e`` / ``/`` use POSIX
    semantics — on any host OS. A relative base is rejected: relativizing
    against it is not well defined (strip relative prefixes with
    `RegexRemapper` instead).

    Raises
    ------
    ValueError
        If ``base`` is empty or relative, or ``on_unmatched`` is invalid.
    """

    def __init__(self, base: str, on_unmatched: OnUnmatched = "ignore") -> None:
        """Store base + flavor; see the class docstring."""
        _check_on_unmatched(on_unmatched)
        if not base:
            raise ValueError("Cannot build relative-path remappers from an empty base")
        self._pathmod = _flavor_module(base)
        absolute_base = _WIN_ROOTED.match(base) if self._pathmod is ntpath else base.startswith("/")
        if not absolute_base:
            raise ValueError(
                f"Cannot relativize against relative base {base!r}: base must be absolute"
            )
        self._base = base
        self._on_unmatched = on_unmatched

    def remap(self, path: str) -> str:
        """Relativize ``path`` against the base; see the class docstring."""
        absolute_path = _WIN_ROOTED.match(path) if self._pathmod is ntpath else path.startswith("/")
        if not absolute_path:
            return _report_unmatched(
                path,
                self._on_unmatched,
                f"Path {path!r} is not absolute; cannot relativize against base {self._base!r}",
            )
        try:
            rel = self._pathmod.relpath(path, self._base)
        except ValueError as exc:
            # relpath's own refusal — e.g. a different drive under ntpath.
            return _report_unmatched(
                path,
                self._on_unmatched,
                f"Cannot relativize {path!r} against base {self._base!r}: {exc}",
            )
        if rel == ".." or rel.startswith(".." + self._pathmod.sep):
            # The path is outside the base: its relative form escapes upward.
            return _report_unmatched(
                path, self._on_unmatched, f"Path {path!r} is not under base {self._base!r}"
            )
        return rel


class RelativeToAbsoluteRemapper:
    r"""Remaps relative paths to their form under ``base`` — the inverse of
    `AbsoluteToRelativeRemapper` (`os.path.join` + normalize semantics) — for
    `SignatureStore(cache_remappers=...)` migrating a relative-keyed cache
    into the live absolute path space, or as ``file_remappers`` to key live
    relative paths into an absolute-keyed cache.

    ``RelativeToAbsoluteRemapper("/mnt/e/pool")`` maps ``sub/a.jpg`` to
    ``/mnt/e/pool/sub/a.jpg``; ``..`` components resolve (``../other/a.jpg``
    maps to ``/mnt/e/other/a.jpg``). A path already absolute-looking in
    either OS's syntax (drive-rooted ``C:``, UNC ``\\server``, or
    separator-rooted ``/x`` / ``\x``) is governed by ``on_unmatched`` — under
    the default it passes through unchanged, so re-applying the remapper to
    its own output is a no-op.

    ``base`` may be absolute or relative: a relative base re-anchors
    relative paths into that base's space —
    ``RelativeToAbsoluteRemapper(os.path.relpath(A, B))`` moves paths
    relative to ``A`` into paths relative to ``B``. The flavor is detected
    textually as in `AbsoluteToRelativeRemapper` (Windows flavor: both
    separators read the same; POSIX flavor: ``\`` a regular character).

    Raises
    ------
    ValueError
        If ``base`` is empty, or ``on_unmatched`` is invalid.
    """

    def __init__(self, base: str, on_unmatched: OnUnmatched = "ignore") -> None:
        """Store base + flavor; see the class docstring."""
        _check_on_unmatched(on_unmatched)
        if not base:
            raise ValueError("Cannot build relative-path remappers from an empty base")
        self._base = base
        self._pathmod = _flavor_module(base)
        self._on_unmatched = on_unmatched

    def remap(self, path: str) -> str:
        """Anchor ``path`` under the base; see the class docstring."""
        if _ANY_ROOTED.match(path):
            return _report_unmatched(
                path,
                self._on_unmatched,
                f"Path {path!r} is already absolute; base {self._base!r} not prepended",
            )
        return self._pathmod.normpath(self._pathmod.join(self._base, path))


def file_quick_signature(path: str, remappers: Remapper | Sequence[Remapper] | None = None) -> str:
    """
    Return a quick-change fingerprint for the given file.
    The key "{canonical_path}_{size}_{mtime_ns}" can be stored and later
    compared to detect any modification without reading the file.

    Parameters
    ----------
    path : str
        Absolute or relative path to the file.
    remappers : Remapper or sequence of Remapper, optional
        Remappers applied to the canonical path before the key is built
        (file-side remap: `RegexRemapper((r"xxx/yyy", "ccc"))` keys the file
        at ``xxx/yyy/aa/cc`` as ``ccc/aa/cc``; `LinuxToWindowsRemapper` and
        `AbsoluteToRelativeRemapper` cover the common cross-OS and
        relative-key cases). The file itself is always stated at its real
        location; only the key's path component is rewritten.

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
