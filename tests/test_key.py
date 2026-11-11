import logging
import os
import re

import pytest

from file_quick_signature.key import (
    SignatureKey,
    absolute_to_relative_remappers,
    apply_remappers,
    build_key,
    file_quick_signature,
    linux_to_windows_remappers,
    parse_key,
    relative_to_absolute_remappers,
    remap_key,
    windows_to_linux_remappers,
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

        rule = (re.escape(str(tmp_path / "xxx" / "yyy")), "ccc")
        key = file_quick_signature(str(f), remappers=[rule])

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
        key = file_quick_signature(str(f), remappers=[rule])

        assert key == "/mnt/e/img.jpg_11_2500"


class TestApplyRemappers:
    def test_none_and_empty_pass_through(self):
        assert apply_remappers("/a/b", None) == "/a/b"
        assert apply_remappers("/a/b", []) == "/a/b"

    def test_ordered_application(self):
        # Later rules see earlier rules' output.
        rules = [(r"^E:", "/mnt/e"), (r"\\", "/")]
        assert apply_remappers(r"E:\pool\a.jpg", rules) == "/mnt/e/pool/a.jpg"

    def test_backreferences(self):
        rules = [(r"^/mnt/([a-z])/(.*)$", r"/media/\1_drive/\2")]
        assert apply_remappers("/mnt/e/pool/a.jpg", rules) == "/media/e_drive/pool/a.jpg"

    def test_no_match_unchanged(self):
        assert apply_remappers("/a/b", [(r"^Z:", "/mnt/z")]) == "/a/b"


class TestOnUnmatched:
    """A remapper's optional third element selects the non-match behavior."""

    def test_bare_pair_stays_ignore(self):
        # Historical semantics: a bare pair passes unmatched paths through.
        assert apply_remappers("/a/b", [(r"^Z:", "/mnt/z", "ignore")]) == "/a/b"

    def test_raise_raises(self):
        with pytest.raises(ValueError, match="did not match"):
            apply_remappers("/a/b", [(r"^Z:", "/mnt/z", "raise")])

    def test_raise_reports_pattern_and_path(self):
        with pytest.raises(ValueError, match=r"'\^Z:' did not match path '/a/b'"):
            apply_remappers("/a/b", [(r"^Z:", "/mnt/z", "raise")])

    def test_warn_logs_and_leaves_path(self, caplog):
        with caplog.at_level(logging.WARNING):
            out = apply_remappers("/a/b", [(r"^Z:", "/mnt/z", "warn")])
        assert out == "/a/b"
        assert any("did not match" in m and "/a/b" in m for m in caplog.messages)

    def test_matching_rule_unaffected_by_mode(self):
        for mode in ("raise", "warn", "ignore"):
            assert apply_remappers("/a/b", [(r"^/a", "/x", mode)]) == "/x/b"

    def test_invalid_mode_raises_even_when_matching(self):
        # A matching pattern must not mask a bogus on_unmatched value.
        with pytest.raises(ValueError, match="Invalid on_unmatched"):
            apply_remappers("/a/b", [(r"^/a", "/x", "explode")])

    def test_malformed_arity_raises(self):
        with pytest.raises(ValueError, match="Malformed remapper"):
            apply_remappers("/a/b", [(r"^Z:",)])
        with pytest.raises(ValueError, match="Malformed remapper"):
            apply_remappers("/a/b", [("/a", "/z", "raise", "extra")])

    def test_mode_flows_through_remap_key(self):
        key = build_key(r"E:\pool\a.jpg", 5, 6)
        with pytest.raises(ValueError, match="did not match"):
            remap_key(key, [(r"^/mnt", "/media", "raise")])


class TestRemapKey:
    def test_path_component_remapped_only(self):
        key = build_key(r"E:\pool\a.jpg", 5, 6)
        out = remap_key(key, [(re.escape(r"E:\pool"), r"/mnt/e/pool")])
        assert out == build_key(r"/mnt/e/pool\a.jpg", 5, 6)
        assert parse_key(out).size == 5
        assert parse_key(out).mtime_ns == 6

    def test_idempotent_when_no_rule_matches(self):
        key = build_key(r"E:\pool\a.jpg", 5, 6)
        assert remap_key(key, [(r"^/mnt", r"/media")]) == key


class TestPlatformBridgeRemappers:
    """Generated windows<->linux bridge pairs: prefix swap + separator rewrite."""

    def test_linux_to_windows(self):
        pairs = linux_to_windows_remappers("/mnt/e", "E:")
        assert apply_remappers("/mnt/e/pool/a.jpg", pairs) == r"E:\pool\a.jpg"
        assert apply_remappers("/mnt/e", pairs) == "E:"

    def test_windows_to_linux(self):
        pairs = windows_to_linux_remappers("E:", "/mnt/e")
        assert apply_remappers(r"E:\pool\a.jpg", pairs) == "/mnt/e/pool/a.jpg"
        assert apply_remappers("E:", pairs) == "/mnt/e"

    def test_round_trip_through_both_directions(self):
        l2w = linux_to_windows_remappers("/mnt/e", r"E:\pool")
        w2l = windows_to_linux_remappers(r"E:\pool", "/mnt/e")
        for path in ("/mnt/e/a.jpg", "/mnt/e/deep/dir/img_1.png"):
            assert apply_remappers(apply_remappers(path, l2w), w2l) == path

    def test_remap_key_round_trip(self):
        l2w = linux_to_windows_remappers("/mnt/e", "E:")
        w2l = windows_to_linux_remappers("E:", "/mnt/e")
        key = build_key("/mnt/e/pool/a.jpg", 98304, 133851860294701234)
        assert remap_key(remap_key(key, l2w), w2l) == key

    def test_deeper_roots(self):
        # Roots deeper than a drive/mount point work the same way.
        l2w = linux_to_windows_remappers("/mnt/e/data.v2", r"E:\Data (2024)")
        assert apply_remappers("/mnt/e/data.v2/img.jpg", l2w) == r"E:\Data (2024)\img.jpg"
        w2l = windows_to_linux_remappers(r"E:\Data (2024)", "/mnt/e/data.v2")
        assert apply_remappers(r"E:\Data (2024)\img.jpg", w2l) == "/mnt/e/data.v2/img.jpg"

    def test_regex_metachars_in_roots(self):
        # Parentheses/dots in a root must not be read as regex syntax.
        l2w = linux_to_windows_remappers("/mnt/e/my (data)/x.y", r"E:\pool")
        assert apply_remappers("/mnt/e/my (data)/x.y/a.jpg", l2w) == r"E:\pool\a.jpg"

    def test_sibling_prefix_not_rewritten(self):
        # /mnt/e2 shares the textual prefix /mnt/e — the boundary lookahead
        # must keep its prefix out of the swap (only separators normalize).
        pairs = linux_to_windows_remappers("/mnt/e", "E:")
        prefix_rule = pairs[0]
        assert re.sub(prefix_rule[0], prefix_rule[1], "/mnt/e2/x.jpg") == "/mnt/e2/x.jpg"
        assert apply_remappers("/mnt/e2/x.jpg", pairs) == r"\mnt\e2\x.jpg"

    def test_forward_slash_windows_root_normalized(self):
        assert linux_to_windows_remappers("/mnt/e", "E:/pool") == linux_to_windows_remappers(
            "/mnt/e", r"E:\pool"
        )
        assert windows_to_linux_remappers("E:/pool", "/mnt/e") == windows_to_linux_remappers(
            r"E:\pool", "/mnt/e"
        )

    def test_filesystem_root_raises(self):
        with pytest.raises(ValueError, match="named directory"):
            linux_to_windows_remappers("/", "E:")
        with pytest.raises(ValueError, match="named directory"):
            windows_to_linux_remappers(r"E:\pool", "\\")

    def test_trailing_separator_roots(self):
        # A trailing separator on either root is stripped; the rules are identical.
        assert linux_to_windows_remappers("/mnt/e/", "E:\\") == linux_to_windows_remappers(
            "/mnt/e", "E:"
        )
        assert windows_to_linux_remappers("E:\\", "/mnt/e/") == windows_to_linux_remappers(
            "E:", "/mnt/e"
        )


class TestRelativeToRemappers:
    """Generated base-relative pairs: prefix strip + separator normalize."""

    def test_windows_base_strips_prefix(self):
        pairs = absolute_to_relative_remappers(r"E:\pool")
        assert apply_remappers(r"E:\pool\sub\a.jpg", pairs) == r"sub\a.jpg"
        assert apply_remappers(r"E:\pool\a.jpg", pairs) == r"a.jpg"

    def test_posix_base_strips_prefix(self):
        pairs = absolute_to_relative_remappers("/mnt/e/pool")
        assert apply_remappers("/mnt/e/pool/sub/a.jpg", pairs) == "sub/a.jpg"
        assert apply_remappers("/mnt/e/pool/a.jpg", pairs) == "a.jpg"

    def test_base_matched_with_either_separator(self):
        # The base's own separators are matched tolerantly, so a mixed-flavor
        # input lands on the same key.
        pairs = absolute_to_relative_remappers(r"E:\pool")
        assert apply_remappers("E:/pool/sub/a.jpg", pairs) == r"sub\a.jpg"

    def test_remainder_separators_normalized(self):
        win = absolute_to_relative_remappers(r"E:\pool")
        assert apply_remappers(r"E:\pool\sub/a.jpg", win) == r"sub\a.jpg"
        posix = absolute_to_relative_remappers("/mnt/e/pool")
        assert apply_remappers("/mnt/e/pool/sub\\a.jpg", posix) == "sub/a.jpg"

    def test_filesystem_root_bases(self):
        assert apply_remappers("/a/b.jpg", absolute_to_relative_remappers("/")) == "a/b.jpg"
        assert apply_remappers(r"C:\a\b.jpg", absolute_to_relative_remappers("C:\\")) == r"a\b.jpg"
        assert apply_remappers("C:/a/b.jpg", absolute_to_relative_remappers("C:\\")) == r"a\b.jpg"

    def test_base_itself_maps_to_empty(self):
        assert apply_remappers("/mnt/e", absolute_to_relative_remappers("/mnt/e")) == ""

    def test_relative_base_strips_relative_prefix(self):
        pairs = absolute_to_relative_remappers("pool")
        assert apply_remappers("pool/sub/a.jpg", pairs) == "sub/a.jpg"

    def test_sibling_prefix_not_stripped(self):
        # /mnt/e shares a textual prefix with /mnt/e2 — boundary must hold.
        pairs = absolute_to_relative_remappers("/mnt/e")
        assert apply_remappers("/mnt/e2/x.jpg", pairs) == "/mnt/e2/x.jpg"

    def test_outside_path_flow_per_on_unmatched(self):
        strict = absolute_to_relative_remappers("/mnt/e", on_unmatched="raise")
        with pytest.raises(ValueError, match="did not match"):
            apply_remappers("/other/x.jpg", strict)
        # Default: unchanged (the POSIX normalize rule is a no-op here).
        lax = absolute_to_relative_remappers("/mnt/e")
        assert apply_remappers("/other/x.jpg", lax) == "/other/x.jpg"

    def test_already_relative_stays_relative(self):
        # No base prefix -> governed by on_unmatched; under the default only
        # separators normalize, so relative paths stay in the relative space.
        pairs = absolute_to_relative_remappers(r"E:\pool")
        assert apply_remappers(r"sub\a.jpg", pairs) == r"sub\a.jpg"
        assert apply_remappers("sub/a.jpg", pairs) == r"sub\a.jpg"

    def test_on_unmatched_stamped_on_prefix_rule_only(self):
        pairs = absolute_to_relative_remappers("/mnt/e", on_unmatched="warn")
        assert pairs[0][2] == "warn"
        assert len(pairs[1]) == 2

    def test_invalid_on_unmatched_raises_at_generation(self):
        with pytest.raises(ValueError, match="on_unmatched"):
            absolute_to_relative_remappers("/mnt/e", on_unmatched="boom")
        with pytest.raises(ValueError, match="on_unmatched"):
            relative_to_absolute_remappers("/mnt/e", on_unmatched="boom")

    def test_empty_base_raises(self):
        with pytest.raises(ValueError, match="empty base"):
            absolute_to_relative_remappers("")
        with pytest.raises(ValueError, match="empty base"):
            relative_to_absolute_remappers("")

    def test_round_trip_both_directions(self):
        for base, abs_path, rel in [
            (r"E:\pool", r"E:\pool\sub\a.jpg", r"sub\a.jpg"),
            ("/mnt/e/pool", "/mnt/e/pool/deep/img.png", "deep/img.png"),
        ]:
            to_rel = absolute_to_relative_remappers(base)
            to_abs = relative_to_absolute_remappers(base)
            assert apply_remappers(abs_path, to_rel) == rel
            assert apply_remappers(rel, to_abs) == abs_path
            assert apply_remappers(apply_remappers(rel, to_abs), to_rel) == rel

    def test_remap_key_round_trip(self):
        to_rel = absolute_to_relative_remappers("/mnt/e/pool")
        to_abs = relative_to_absolute_remappers("/mnt/e/pool")
        key = build_key("/mnt/e/pool/a.jpg", 98304, 133851860294701234)
        assert remap_key(remap_key(key, to_rel), to_abs) == key


class TestRelativeFromRemappers:
    """Generated prepend pairs: base prefix + separator normalize."""

    def test_prepends_base(self):
        win = relative_to_absolute_remappers(r"E:\pool")
        assert apply_remappers(r"sub\a.jpg", win) == r"E:\pool\sub\a.jpg"
        posix = relative_to_absolute_remappers("/mnt/e/pool")
        assert apply_remappers("sub/a.jpg", posix) == "/mnt/e/pool/sub/a.jpg"

    def test_mixed_separator_relative_normalized(self):
        win = relative_to_absolute_remappers(r"E:\pool")
        assert apply_remappers("sub/a.jpg", win) == r"E:\pool\sub\a.jpg"

    def test_absolute_paths_not_prefixed(self):
        win = relative_to_absolute_remappers(r"E:\pool")
        assert apply_remappers(r"C:\other\a.jpg", win) == r"C:\other\a.jpg"
        posix = relative_to_absolute_remappers("/mnt/e/pool")
        assert apply_remappers("/other/a.jpg", posix) == "/other/a.jpg"
        assert apply_remappers(r"\\server\share\a.jpg", posix) == "//server/share/a.jpg"
        # On pass-through only separators normalize:
        assert apply_remappers("/other/a.jpg", win) == r"\other\a.jpg"

    def test_drive_like_relative_skipped_textually(self):
        # Textual drive detection cannot distinguish a POSIX "a:b" filename
        # from a drive root; it is skipped (documented caveat).
        posix = relative_to_absolute_remappers("/mnt/e")
        assert apply_remappers("a:b", posix) == "a:b"

    def test_on_unmatched_governs_absolute_paths(self):
        strict = relative_to_absolute_remappers("/mnt/e", on_unmatched="raise")
        with pytest.raises(ValueError, match="did not match"):
            apply_remappers("/abs/a.jpg", strict)

    def test_root_base_no_doubled_separator(self):
        pairs = relative_to_absolute_remappers("/")
        assert apply_remappers("a/b.jpg", pairs) == "/a/b.jpg"
        assert apply_remappers(r"a\b.jpg", pairs) == "/a/b.jpg"

    def test_relative_base_reanchors(self):
        # Paths relative to A become paths relative to B by prepending
        # relpath(A, B).
        pairs = relative_to_absolute_remappers("../b")
        assert apply_remappers("x/y.jpg", pairs) == "../b/x/y.jpg"
