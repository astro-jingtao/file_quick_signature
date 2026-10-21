import os
import re

import pytest

from file_quick_signature.key import (SignatureKey, apply_remappers, build_key,
                                      file_quick_signature, parse_key, remap_key)


class TestBuildAndParseRoundTrip:
    """parse_key(build_key(...)) must round-trip byte-identically, whatever the path."""

    @pytest.mark.parametrize("path", [
        r"E:\pool\a.jpg",
        "/mnt/e/pool/a.jpg",
        r"C:\under_score_dir\file_name_1.jpg",       # underscores in the path
        r"C:\dir\trailing_digits_123_456.jpg",       # path ends like the suffix code
        r"C:\dir\a_1_2_3_4_5.jpg",                   # many digit-ish segments
        "中文图片/图片_0001.jpg",                      # non-ASCII
        r"\\server\share\img.jpg",                   # UNC path
        "a",                                          # no separator at all in the path
    ])
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

    @pytest.mark.parametrize("bad", [
        "no-separators-at-all",
        "only_one_123",
        "path_size_notanumber",
        "path_notanumber_123",
        "",
    ])
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
            os.path.join(str(tmp_path), ".", "img.jpg"))

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
