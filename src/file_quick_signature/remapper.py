"""Path remappers: the remapping interface and the built-in classes."""

from __future__ import annotations

import logging
import ntpath
import posixpath
import re
from types import ModuleType
from typing import Literal, Protocol, Union, runtime_checkable

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
