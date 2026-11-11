import logging
import os
import re

import pytest

from file_quick_signature.key import (
    AbsoluteToRelativeRemapper,
    LinuxToWindowsRemapper,
    RegexRemapper,
    RelativeToAbsoluteRemapper,
    Remapper,
    SignatureKey,
    WindowsToLinuxRemapper,
    apply_remappers,
    build_key,
    file_quick_signature,
    parse_key,
    remap_key,
)


class TestBuildAndParseRoundTrip:
    """parse_key(build_key(...)) must round-trip byte-identically, whatever the path."""

    @pytest.mark.parametrize(
        "path",
        [
            r"E:\pool\a.jpg",
            "/mnt/e/pool/a.jpg",
            r"C:\under_score_dir\file_name_1.jpg",  # underscores in the path
            r"C:\dir\trailing_digits_123_456.jpg",  # path ends like the suffix code
            r"C:\dir\a_1_2_3_4_5.jpg",  # many digit-ish segments
            "中文图片/图片_0001.jpg",  # non-ASCII
            r"\\server\share\img.jpg",  # UNC path
            "a",  # no separator at all in the path
        ],
    )
    def test_round_trip(self, path):
        key = build_key(path, 123, 456789)
        assert key == f"{path}_123_456789"
        sig = parse_key(key)
        assert sig == SignatureKey(path, 123, 456789)
        assert (sig.path, sig.size, sig.mtime_ns) == (path, 123, 456789)
        assert build_key(*sig) == key

    def test_negative_mtime_round_trip(self):
        # Pre-1970 mtimes are negative; the suffix code must still parse.
        key = build_key("/data/old.bin", 10, -987654321)
        assert parse_key(key) == SignatureKey("/data/old.bin", 10, -987654321)

    def test_zero_fields(self):
        key = build_key("/x", 0, 0)
        assert parse_key(key) == SignatureKey("/x", 0, 0)

    @pytest.mark.parametrize(
        "bad",
        [
            "no-separators-at-all",
            "only_one_123",
            "path_size_notanumber",
            "path_notanumber_123",
            "",
        ],
    )
    def test_malformed_key_raises(self, bad):
        with pytest.raises(ValueError, match="Malformed"):
            parse_key(bad)


class TestFileQuickSignature:
    def _write(self, path, size=10):
        path.write_bytes(b"x" * size)
        st = os.stat(str(path))
        return st

    def test_parity_with_reference_formula(self, tmp_path):
        """Byte-identical with the historical reference formula (no remappers)."""
        p = tmp_path / "img.jpg"
        st = self._write(p)
        reference = f"{os.path.realpath(str(p))}_{st.st_size}_{st.st_mtime_ns}"
        assert file_quick_signature(str(p)) == reference
        assert file_quick_signature(str(p), remappers=None) == reference

    def test_relative_path_same_key(self, tmp_path):
        p = tmp_path / "img.jpg"
        self._write(p)
        assert file_quick_signature(str(p)) == file_quick_signature(
            os.path.join(str(tmp_path), ".", "img.jpg")
        )

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            file_quick_signature(r"Z:\definitely\not\here.jpg")

    def test_parse_back_matches_stat(self, tmp_path):
        p = tmp_path / "img.jpg"
        self._write(p, size=42)
        sig = parse_key(file_quick_signature(str(p)))
        st = os.stat(str(p))
        assert sig.path == os.path.realpath(str(p))
        assert sig.size == st.st_size == 42
        assert sig.mtime_ns == st.st_mtime_ns

    def test_file_remapper_rewrites_key_path_only(self, tmp_path):
        """File-side remap: xxx/yyy/aa/cc is keyed as ccc/aa/cc."""
        real_dir = tmp_path / "xxx" / "yyy"
        real_dir.mkdir(parents=True)
        f = real_dir / "aa" / "cc"
        f.parent.mkdir()
        self._write(f, size=7)

        remapper = RegexRemapper((re.escape(str(tmp_path / "xxx" / "yyy")), "ccc"))
        key = file_quick_signature(str(f), remappers=remapper)

        sig = parse_key(key)
        expected_rel = os.path.join("aa", "cc")
        assert sig.path == os.path.join("ccc", expected_rel)
        assert sig.size == 7
        assert sig.mtime_ns == os.stat(str(f)).st_mtime_ns

    def test_file_remapper_prefix_regex(self, tmp_path):
        """A drive-root regex rule maps a Windows path onto a Linux-style cache space."""
        f = tmp_path / "img.jpg"
        self._write(f, size=11)
        # NTFS stores 100-ns units; use a multiple of 100 so the stat round-trips.
        os.utime(str(f), ns=(2500, 2500))

        rule = (re.escape(str(tmp_path)) + r"(\\|/)", "/mnt/e/")
        remapper = RegexRemapper(rule)
        key = file_quick_signature(str(f), remappers=remapper)

        assert key == "/mnt/e/img.jpg_11_2500"


class TestRemapperProtocol:
    """A remapper is any class with a remap method — no inheritance required."""

    class _Upper:
        def remap(self, path):
            return path.upper()

    def test_duck_typed_remapper_accepted(self):
        assert apply_remappers("/a/b", self._Upper()) == "/A/B"

    def test_builtin_classes_satisfy_protocol(self):
        for r in (
            RegexRemapper((r"^/a", "/x")),
            LinuxToWindowsRemapper("/mnt/e", "E:"),
            AbsoluteToRelativeRemapper("/mnt/e"),
        ):
            assert isinstance(r, Remapper)

    def test_none_and_empty_pass_through(self):
        assert apply_remappers("/a/b", None) == "/a/b"
        assert apply_remappers("/a/b", []) == "/a/b"

    def test_sequence_applied_in_order(self):
        # Later remappers see earlier remappers' output.
        remappers = [RegexRemapper((r"^E:", "/mnt/e")), RegexRemapper((r"\\", "/"))]
        assert apply_remappers(r"E:\pool\a.jpg", remappers) == "/mnt/e/pool/a.jpg"

    def test_rejects_bare_regex_pair(self):
        # The historical tuple syntax must fail loudly, not with AttributeError.
        with pytest.raises(TypeError, match="RegexRemapper"):
            apply_remappers("/a/b", [(r"^Z:", "/mnt/z")])
        with pytest.raises(TypeError, match="RegexRemapper"):
            apply_remappers("/a/b", ("^Z:", "/mnt/z"))


class TestRegexRemapper:
    def test_ordered_application(self):
        rules = [(r"^E:", "/mnt/e"), (r"\\", "/")]
        assert RegexRemapper(*rules).remap(r"E:\pool\a.jpg") == "/mnt/e/pool/a.jpg"

    def test_backreferences(self):
        remapper = RegexRemapper((r"^/mnt/([a-z])/(.*)$", r"/media/\1_drive/\2"))
        assert remapper.remap("/mnt/e/pool/a.jpg") == "/media/e_drive/pool/a.jpg"

    def test_no_match_unchanged(self):
        assert RegexRemapper((r"^Z:", "/mnt/z")).remap("/a/b") == "/a/b"


class TestOnUnmatched:
    """A remapper's on_unmatched selects the behavior on a path it cannot remap."""

    def test_bare_pair_stays_ignore(self):
        # Historical semantics: a bare pair passes unmatched paths through.
        assert RegexRemapper((r"^Z:", "/mnt/z", "ignore")).remap("/a/b") == "/a/b"

    def test_raise_raises(self):
        with pytest.raises(ValueError, match="did not match"):
            RegexRemapper((r"^Z:", "/mnt/z", "raise")).remap("/a/b")

    def test_raise_reports_pattern_and_path(self):
        with pytest.raises(ValueError, match=re.escape("'^Z:' did not match path '/a/b'")):
            RegexRemapper((r"^Z:", "/mnt/z", "raise")).remap("/a/b")

    def test_warn_logs_and_leaves_path(self, caplog):
        with caplog.at_level(logging.WARNING):
            out = RegexRemapper((r"^Z:", "/mnt/z", "warn")).remap("/a/b")
        assert out == "/a/b"
        assert any("did not match" in m and "/a/b" in m for m in caplog.messages)

    def test_matching_rule_unaffected_by_mode(self):
        for mode in ("raise", "warn", "ignore"):
            assert RegexRemapper((r"^/a", "/x", mode)).remap("/a/b") == "/x/b"

    def test_invalid_mode_raises_even_when_matching(self):
        # A matching pattern must not mask a bogus on_unmatched value.
        with pytest.raises(ValueError, match="Invalid on_unmatched"):
            RegexRemapper((r"^/a", "/x", "explode")).remap("/a/b")

    def test_invalid_mode_rejected_at_construction(self):
        # Fail fast: a bogus value never waits for the first path.
        with pytest.raises(ValueError, match="Invalid on_unmatched"):
            RegexRemapper((r"^/a", "/x", "explode"))

    def test_malformed_arity_raises(self):
        with pytest.raises(ValueError, match="Malformed remapper"):
            RegexRemapper((r"^Z:",))
        with pytest.raises(ValueError, match="Malformed remapper"):
            RegexRemapper(("/a", "/z", "raise", "extra"))
        with pytest.raises(ValueError, match="Malformed remapper"):
            RegexRemapper("^Z:")

    def test_mode_flows_through_remap_key(self):
        key = build_key(r"E:\pool\a.jpg", 5, 6)
        with pytest.raises(ValueError, match="did not match"):
            remap_key(key, RegexRemapper((r"^/mnt", "/media", "raise")))


class TestRemapKey:
    def test_path_component_remapped_only(self):
        key = build_key(r"E:\pool\a.jpg", 5, 6)
        remapper = RegexRemapper((re.escape(r"E:\pool"), r"/mnt/e/pool"))
        out = remap_key(key, remapper)
        assert out == build_key(r"/mnt/e/pool\a.jpg", 5, 6)
        assert parse_key(out).size == 5
        assert parse_key(out).mtime_ns == 6

    def test_idempotent_when_nothing_matches(self):
        key = build_key(r"E:\pool\a.jpg", 5, 6)
        assert remap_key(key, RegexRemapper((r"^/mnt", r"/media"))) == key


class TestLinuxToWindowsRemapper:
    """The bridge classes: prefix swap + separator rewrite, with on_unmatched."""

    def test_basic_mapping(self):
        remapper = LinuxToWindowsRemapper("/mnt/e", "E:")
        assert remapper.remap("/mnt/e/pool/a.jpg") == r"E:\pool\a.jpg"
        assert remapper.remap("/mnt/e") == "E:"

    def test_outside_path_default_ignores(self):
        # Outside the linux root: unchanged apart from separator normalization.
        assert LinuxToWindowsRemapper("/mnt/e", "E:").remap("/other/a.jpg") == r"\other\a.jpg"

    def test_outside_path_raise_raises(self):
        remapper = LinuxToWindowsRemapper("/mnt/e", "E:", on_unmatched="raise")
        with pytest.raises(ValueError, match="did not match"):
            remapper.remap("/other/a.jpg")

    def test_outside_path_warn_logs_and_keeps(self, caplog):
        remapper = LinuxToWindowsRemapper("/mnt/e", "E:", on_unmatched="warn")
        with caplog.at_level(logging.WARNING):
            out = remapper.remap("/other/a.jpg")
        assert out == r"\other\a.jpg"
        assert any("did not match" in m for m in caplog.messages)

    def test_invalid_on_unmatched_raises_at_construction(self):
        with pytest.raises(ValueError, match="Invalid on_unmatched"):
            LinuxToWindowsRemapper("/mnt/e", "E:", on_unmatched="boom")

    def test_deeper_roots(self):
        # Roots deeper than a drive/mount point work the same way.
        l2w = LinuxToWindowsRemapper("/mnt/e/data.v2", r"E:\Data (2024)")
        assert l2w.remap("/mnt/e/data.v2/img.jpg") == r"E:\Data (2024)\img.jpg"

    def test_regex_metachars_in_roots(self):
        # Parentheses/dots in a root must not be read as regex syntax.
        l2w = LinuxToWindowsRemapper("/mnt/e/my (data)/x.y", r"E:\pool")
        assert l2w.remap("/mnt/e/my (data)/x.y/a.jpg") == r"E:\pool\a.jpg"

    def test_sibling_prefix_not_rewritten(self):
        # /mnt/e2 shares the textual prefix /mnt/e — the boundary lookahead
        # must keep its prefix out of the swap (only separators normalize).
        remapper = LinuxToWindowsRemapper("/mnt/e", "E:")
        assert remapper.remap("/mnt/e2/x.jpg") == r"\mnt\e2\x.jpg"

    def test_forward_slash_windows_root_normalized(self):
        assert LinuxToWindowsRemapper("/mnt/e", "E:/pool").remap("/mnt/e/a.jpg") == (
            LinuxToWindowsRemapper("/mnt/e", r"E:\pool").remap("/mnt/e/a.jpg")
        )

    def test_filesystem_root_raises(self):
        with pytest.raises(ValueError, match="named directory"):
            LinuxToWindowsRemapper("/", "E:")

    def test_trailing_separator_roots(self):
        # A trailing separator on either root is stripped; the mapping is identical.
        assert LinuxToWindowsRemapper("/mnt/e/", "E:\\").remap("/mnt/e/a.jpg") == (
            LinuxToWindowsRemapper("/mnt/e", "E:").remap("/mnt/e/a.jpg")
        )


class TestWindowsToLinuxRemapper:
    def test_basic_mapping(self):
        remapper = WindowsToLinuxRemapper("E:", "/mnt/e")
        assert remapper.remap(r"E:\pool\a.jpg") == "/mnt/e/pool/a.jpg"
        assert remapper.remap("E:") == "/mnt/e"

    def test_outside_path_raise_raises(self):
        remapper = WindowsToLinuxRemapper("E:", "/mnt/e", on_unmatched="raise")
        with pytest.raises(ValueError, match="did not match"):
            remapper.remap(r"D:\pool\a.jpg")

    def test_forward_slash_windows_root_normalized(self):
        assert WindowsToLinuxRemapper("E:/pool", "/mnt/e").remap(r"E:\pool\a.jpg") == (
            WindowsToLinuxRemapper(r"E:\pool", "/mnt/e").remap(r"E:\pool\a.jpg")
        )

    def test_filesystem_root_raises(self):
        with pytest.raises(ValueError, match="named directory"):
            WindowsToLinuxRemapper(r"E:\pool", "\\")


class TestBridgeRoundTrip:
    """l2w then w2l (and back) restores the original path and key — the two
    directions are inverses of each other."""

    @pytest.mark.parametrize(
        ("linux_root", "windows_root"),
        [
            ("/mnt/e", "E:"),
            ("/mnt/e", r"E:\pool"),
            ("/mnt/e/data.v2", r"E:\Data (2024)"),
            ("/mnt/e/my (data)/x.y", r"E:\pool"),
        ],
    )
    @pytest.mark.parametrize(
        "path",
        [
            "/mnt/e/pool/a.jpg",
            "/mnt/e/deep/dir/img_1.png",
            "/mnt/e/data.v2/x.tar.gz",
            "/mnt/e",
        ],
    )
    def test_linux_windows_linux_is_identity(self, linux_root, windows_root, path):
        # Only paths under the linux root stay inside the bridge; others are
        # governed by on_unmatched and normalize separators only.
        if not (path == linux_root or path.startswith(linux_root + "/")):
            pytest.skip("path outside the bridged root")
        l2w = LinuxToWindowsRemapper(linux_root, windows_root)
        w2l = WindowsToLinuxRemapper(windows_root, linux_root)
        assert w2l.remap(l2w.remap(path)) == path

    def test_windows_linux_windows_is_identity(self):
        w2l = WindowsToLinuxRemapper(r"E:\pool", "/mnt/e")
        l2w = LinuxToWindowsRemapper("/mnt/e", r"E:\pool")
        for path in (r"E:\pool\a.jpg", r"E:\pool\deep\dir\img_1.png", r"E:\pool"):
            assert l2w.remap(w2l.remap(path)) == path

    def test_remap_key_round_trip(self):
        l2w = LinuxToWindowsRemapper("/mnt/e", "E:")
        w2l = WindowsToLinuxRemapper("E:", "/mnt/e")
        key = build_key("/mnt/e/pool/a.jpg", 98304, 133851860294701234)
        assert remap_key(remap_key(key, l2w), w2l) == key

    def test_remap_key_round_trip_deep_roots(self):
        l2w = LinuxToWindowsRemapper("/mnt/e/data.v2", r"E:\Data (2024)")
        w2l = WindowsToLinuxRemapper(r"E:\Data (2024)", "/mnt/e/data.v2")
        key = build_key("/mnt/e/data.v2/img.jpg", 11, 2500)
        assert remap_key(remap_key(key, l2w), w2l) == key


class TestAbsoluteToRelativeRemapper:
    """relpath-based relativization against an absolute base."""

    def test_windows_base(self):
        remapper = AbsoluteToRelativeRemapper(r"E:\pool")
        assert remapper.remap(r"E:\pool\sub\a.jpg") == r"sub\a.jpg"
        assert remapper.remap(r"E:\pool\a.jpg") == "a.jpg"

    def test_posix_base(self):
        remapper = AbsoluteToRelativeRemapper("/mnt/e/pool")
        assert remapper.remap("/mnt/e/pool/sub/a.jpg") == "sub/a.jpg"
        assert remapper.remap("/mnt/e/pool/a.jpg") == "a.jpg"

    def test_mixed_separator_input_same_key(self):
        # The Windows flavor reads both separators: E:/pool/... and E:\pool\...
        # land on the same relative key.
        assert AbsoluteToRelativeRemapper(r"E:\pool").remap("E:/pool/sub/a.jpg") == r"sub\a.jpg"

    def test_windows_flavor_case_insensitive(self):
        # Drive and component case do not matter under the Windows flavor.
        assert AbsoluteToRelativeRemapper(r"E:\pool").remap(r"e:\POOL\sub\a.jpg") == r"sub\a.jpg"

    def test_redundant_components_normalize(self):
        # relpath semantics: ./ and ../ segments collapse, so keys are stable.
        remapper = AbsoluteToRelativeRemapper("/mnt/e/pool")
        assert remapper.remap("/mnt/e/pool/./sub/../sub/a.jpg") == "sub/a.jpg"

    def test_base_itself_maps_to_dot(self):
        assert AbsoluteToRelativeRemapper("/mnt/e/pool").remap("/mnt/e/pool") == "."

    def test_outside_path_per_on_unmatched(self):
        strict = AbsoluteToRelativeRemapper("/mnt/e", on_unmatched="raise")
        with pytest.raises(ValueError, match="is not under base"):
            strict.remap("/other/x.jpg")
        # Default: the path is left unchanged, no ..-escape key is produced.
        lax = AbsoluteToRelativeRemapper("/mnt/e")
        assert lax.remap("/other/x.jpg") == "/other/x.jpg"

    def test_outside_path_warn_logs_and_keeps(self, caplog):
        remapper = AbsoluteToRelativeRemapper("/mnt/e", on_unmatched="warn")
        with caplog.at_level(logging.WARNING):
            out = remapper.remap("/other/x.jpg")
        assert out == "/other/x.jpg"
        assert any("is not under base" in m for m in caplog.messages)

    def test_sibling_prefix_is_outside(self):
        # /mnt/e shares a textual prefix with /mnt/e2 — relpath escapes, so
        # the sibling is treated as outside, not stripped.
        assert AbsoluteToRelativeRemapper("/mnt/e").remap("/mnt/e2/x.jpg") == "/mnt/e2/x.jpg"

    def test_not_absolute_input_per_on_unmatched(self):
        strict = AbsoluteToRelativeRemapper(r"E:\pool", on_unmatched="raise")
        with pytest.raises(ValueError, match="is not absolute"):
            strict.remap(r"sub\a.jpg")
        # Default: already-relative input keeps its form (relative key space).
        assert AbsoluteToRelativeRemapper(r"E:\pool").remap(r"sub\a.jpg") == r"sub\a.jpg"

    def test_foreign_flavor_input_is_not_absolute(self):
        # A Windows-flavor path is not absolute in a POSIX-flavor base — it
        # is governed by on_unmatched, never garbage-relativized.
        assert AbsoluteToRelativeRemapper("/mnt/e").remap(r"E:\pool\a.jpg") == r"E:\pool\a.jpg"

    def test_cross_drive_per_on_unmatched(self):
        # relpath refuses across drives; on_unmatched governs the refusal.
        strict = AbsoluteToRelativeRemapper(r"E:\pool", on_unmatched="raise")
        with pytest.raises(ValueError, match="Cannot relativize"):
            strict.remap(r"D:\x\a.jpg")
        lax = AbsoluteToRelativeRemapper(r"E:\pool")
        assert lax.remap(r"D:\x\a.jpg") == r"D:\x\a.jpg"

    def test_relative_base_rejected(self):
        with pytest.raises(ValueError, match="base must be absolute"):
            AbsoluteToRelativeRemapper("pool")

    def test_empty_base_raises(self):
        with pytest.raises(ValueError, match="empty base"):
            AbsoluteToRelativeRemapper("")

    def test_invalid_on_unmatched_raises_at_construction(self):
        with pytest.raises(ValueError, match="Invalid on_unmatched"):
            AbsoluteToRelativeRemapper("/mnt/e", on_unmatched="boom")


class TestRelativeToAbsoluteRemapper:
    """join+normalize-based re-anchoring of relative paths under a base."""

    def test_prepends_base(self):
        assert RelativeToAbsoluteRemapper(r"E:\pool").remap(r"sub\a.jpg") == r"E:\pool\sub\a.jpg"
        assert RelativeToAbsoluteRemapper("/mnt/e/pool").remap("sub/a.jpg") == (
            "/mnt/e/pool/sub/a.jpg"
        )

    def test_mixed_separator_relative_normalized(self):
        # The Windows flavor normalizes the joined path's separators.
        assert RelativeToAbsoluteRemapper(r"E:\pool").remap("sub/a.jpg") == r"E:\pool\sub\a.jpg"

    def test_dotdot_components_resolve(self):
        remapper = RelativeToAbsoluteRemapper("/mnt/e/pool")
        assert remapper.remap("../other/a.jpg") == "/mnt/e/other/a.jpg"

    def test_absolute_paths_not_prefixed(self):
        # Already absolute-looking in either OS's syntax: pass through.
        win = RelativeToAbsoluteRemapper(r"E:\pool")
        assert win.remap(r"C:\other\a.jpg") == r"C:\other\a.jpg"
        assert win.remap("/other/a.jpg") == "/other/a.jpg"
        assert win.remap(r"\\server\share\a.jpg") == r"\\server\share\a.jpg"
        posix = RelativeToAbsoluteRemapper("/mnt/e/pool")
        assert posix.remap("/other/a.jpg") == "/other/a.jpg"

    def test_absolute_paths_per_on_unmatched(self):
        strict = RelativeToAbsoluteRemapper("/mnt/e", on_unmatched="raise")
        with pytest.raises(ValueError, match="is already absolute"):
            strict.remap("/abs/a.jpg")

    def test_reapplication_is_noop(self):
        # Idempotence: the output is already absolute, so a second pass keeps it.
        remapper = RelativeToAbsoluteRemapper("/mnt/e/pool")
        once = remapper.remap("sub/a.jpg")
        assert remapper.remap(once) == once

    def test_relative_base_reanchors(self):
        # Paths relative to A become paths relative to B by anchoring on
        # relpath(A, B).
        remapper = RelativeToAbsoluteRemapper("../b")
        assert remapper.remap("x/y.jpg") == "../b/x/y.jpg"

    def test_posix_flavor_backslash_is_literal(self):
        # posixpath treats "\" as a regular filename character — a
        # POSIX-flavor base does not normalize backslash separators.
        remapper = RelativeToAbsoluteRemapper("/mnt/e/pool")
        assert remapper.remap("sub\\a.jpg") == "/mnt/e/pool/sub\\a.jpg"

    def test_empty_base_raises(self):
        with pytest.raises(ValueError, match="empty base"):
            RelativeToAbsoluteRemapper("")

    def test_invalid_on_unmatched_raises_at_construction(self):
        with pytest.raises(ValueError, match="Invalid on_unmatched"):
            RelativeToAbsoluteRemapper("/mnt/e", on_unmatched="boom")


class TestRelativeRoundTrip:
    """to_rel then to_abs (and back) restores the original path — the two
    remappers are inverses of each other."""

    @pytest.mark.parametrize(
        ("base", "abs_path", "rel"),
        [
            (r"E:\pool", r"E:\pool\sub\a.jpg", r"sub\a.jpg"),
            (r"E:\pool", r"E:\pool\a.jpg", "a.jpg"),
            (r"E:\pool", r"E:\pool", "."),
            (r"E:\pool", r"E:\pool\deep\dir\img_1.png", r"deep\dir\img_1.png"),
            ("/mnt/e/pool", "/mnt/e/pool/deep/img.png", "deep/img.png"),
            ("/mnt/e/pool", "/mnt/e/pool/a.jpg", "a.jpg"),
            ("/mnt/e/pool", "/mnt/e/pool", "."),
        ],
    )
    def test_abs_rel_abs_is_identity(self, base, abs_path, rel):
        to_rel = AbsoluteToRelativeRemapper(base)
        to_abs = RelativeToAbsoluteRemapper(base)
        assert to_rel.remap(abs_path) == rel
        assert to_abs.remap(rel) == abs_path
        assert to_abs.remap(to_rel.remap(abs_path)) == abs_path

    @pytest.mark.parametrize(
        ("base", "abs_path", "rel"),
        [
            (r"E:\pool", r"E:\pool\sub\a.jpg", r"sub\a.jpg"),
            ("/mnt/e/pool", "/mnt/e/pool/deep/img.png", "deep/img.png"),
        ],
    )
    def test_rel_abs_rel_is_identity(self, base, abs_path, rel):
        to_rel = AbsoluteToRelativeRemapper(base)
        to_abs = RelativeToAbsoluteRemapper(base)
        assert to_rel.remap(to_abs.remap(rel)) == rel

    def test_redundant_input_normalizes_once_and_round_trips(self):
        to_rel = AbsoluteToRelativeRemapper("/mnt/e/pool")
        to_abs = RelativeToAbsoluteRemapper("/mnt/e/pool")
        messy = "/mnt/e/pool/./sub/../sub/a.jpg"
        normalized = to_abs.remap(to_rel.remap(messy))
        assert normalized == "/mnt/e/pool/sub/a.jpg"
        assert to_rel.remap(normalized) == "sub/a.jpg"
        # The composed remap is idempotent: a second pass changes nothing.
        assert to_abs.remap(to_rel.remap(normalized)) == normalized

    def test_remap_key_round_trip(self):
        to_rel = AbsoluteToRelativeRemapper("/mnt/e/pool")
        to_abs = RelativeToAbsoluteRemapper("/mnt/e/pool")
        key = build_key("/mnt/e/pool/a.jpg", 98304, 133851860294701234)
        assert remap_key(remap_key(key, to_rel), to_abs) == key
