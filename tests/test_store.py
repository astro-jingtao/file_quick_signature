import json
import os
import re

import pytest

from file_quick_signature.key import (apply_remappers, build_key,
                                      linux_to_windows_remappers, parse_key,
                                      windows_to_linux_remappers)
from file_quick_signature.store import SignatureStore


def _make_file(path, size=10, mtime_ns=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)
    if mtime_ns is not None:
        # NTFS stores 100-ns units; callers pass multiples of 100 to round-trip.
        os.utime(str(path), ns=(mtime_ns, mtime_ns))
    return path


def _sha(payload: bytes) -> str:
    import hashlib
    return hashlib.sha256(payload).hexdigest()


def _repl_literal(text: str) -> str:
    """Embed a literal string in a re.sub replacement template (double backslashes)."""
    return text.replace("\\", "\\\\")


class TestLoadSave:

    def test_load_missing_file_empty(self, tmp_path):
        store = SignatureStore(str(tmp_path / "signature.json")).load()
        assert store.data == {}

    def test_load_none_path_empty(self):
        assert SignatureStore(None).load().data == {}

    def test_save_load_round_trip(self, tmp_path):
        json_path = str(tmp_path / "signature.json")
        store = SignatureStore(json_path)
        store.data = {"k1": "v1", "k2": "v2"}
        store.save()

        with open(json_path, "r", encoding="utf-8") as f:
            assert json.load(f) == {"k1": "v1", "k2": "v2"}

        reloaded = SignatureStore(json_path).load()
        assert reloaded.data == {"k1": "v1", "k2": "v2"}

    def test_save_without_json_path_raises(self):
        store = SignatureStore(None)
        store.data = {"k": "v"}
        with pytest.raises(ValueError, match="json_path"):
            store.save()

    def test_load_corrupt_json_raises(self, tmp_path):
        # A damaged cache file must fail loudly, not load as empty.
        json_path = tmp_path / "signature.json"
        json_path.write_text("{not json", encoding="utf-8")
        with pytest.raises(json.JSONDecodeError):
            SignatureStore(str(json_path)).load()

    def test_save_format_matches_historical(self, tmp_path):
        """indent=4, ensure_ascii=False — same formatting as the old signature.json."""
        json_path = str(tmp_path / "signature.json")
        store = SignatureStore(json_path)
        store.data = {build_key(r"E:\平\a.jpg", 1, 2): "h" * 64}
        store.save()
        with open(json_path, "r", encoding="utf-8") as f:
            text = f.read()
        assert text.startswith('{\n    "E:\\\\平\\\\a.jpg_1_2"')
        assert '平' in text  # not \u-escaped

        # Non-ASCII keys survive a full disk round-trip, not just the text form.
        reloaded = SignatureStore(json_path).load()
        assert reloaded.data == store.data


class TestQuery:

    def _prepare(self, tmp_path):
        f1 = _make_file(tmp_path / "a.jpg", size=3)
        f2 = _make_file(tmp_path / "b.jpg", size=4)
        store = SignatureStore(None)
        return store, [str(f1), str(f2)]

    def test_hit_and_miss(self, tmp_path):
        store, paths = self._prepare(tmp_path)
        h1 = _sha(b"xxx")
        store.data[store.signature(paths[0])] = h1

        results, not_found_idx, not_found_keys = store.query(paths)

        assert results[0] == h1
        assert results[1] is None
        assert not_found_idx == [1]
        assert not_found_keys == [store.signature(paths[1])]

    def test_compute_records_and_saves(self, tmp_path):
        json_path = str(tmp_path / "signature.json")
        store, paths = self._prepare(tmp_path)
        h1 = _sha(b"xxx")
        store.data[store.signature(paths[0])] = h1
        store.json_path = json_path
        h2 = _sha(b"yyy")

        def compute(miss_paths):
            assert miss_paths == [paths[1]]
            return [h2]

        results, not_found_idx, _ = store.query(paths, compute=compute)

        assert results == [h1, h2]
        assert not_found_idx == [1]
        assert store.data[store.signature(paths[1])] == h2
        # persisted
        with open(json_path, "r", encoding="utf-8") as f:
            assert json.load(f) == store.data

    def test_compute_none_leaves_store_untouched(self, tmp_path):
        store, paths = self._prepare(tmp_path)
        before = dict(store.data)
        results, not_found_idx, _ = store.query(paths)
        assert not_found_idx == [0, 1]
        assert store.data == before

    def test_compute_with_save_false_in_memory_only(self, tmp_path):
        json_path = str(tmp_path / "signature.json")
        store, paths = self._prepare(tmp_path)
        store.json_path = json_path

        results, _, _ = store.query(paths, compute=lambda ps: ["h"] * len(ps), save=False)

        assert results == ["h", "h"]
        assert not os.path.exists(json_path)

    def test_full_hit_no_compute_call(self, tmp_path):
        store, paths = self._prepare(tmp_path)
        store.data = {store.signature(p): "h" for p in paths}

        def compute(ps):
            raise AssertionError("must not be called when everything hits")

        results, not_found_idx, _ = store.query(paths, compute=compute)
        assert results == ["h", "h"]
        assert not_found_idx == []

    def test_empty_paths(self, tmp_path):
        store, _ = self._prepare(tmp_path)

        def compute(ps):
            raise AssertionError("must not be called for an empty query")

        assert store.query([], compute=compute) == ([], [], [])


class TestFileRemappers:
    """File-side remap: file xxx/yyy/aa/cc is looked up as ccc/aa/cc."""

    def test_lookup_hits_cache_from_other_root(self, tmp_path):
        cache_root = tmp_path / "ccc"
        live_root = tmp_path / "xxx" / "yyy"
        live_root.mkdir(parents=True)
        f = _make_file(live_root / "aa" / "cc", size=9)

        # A cache recorded under the ccc root
        cache_key = build_key(
            os.path.join(str(cache_root), os.path.join("aa", "cc")), 9,
            os.stat(str(f)).st_mtime_ns)

        store = SignatureStore(None,
                               file_remappers=[(re.escape(str(live_root)),
                                                _repl_literal(str(cache_root)))])
        store.data = {cache_key: "payload"}

        results, not_found_idx, _ = store.query([str(f)])
        assert results == ["payload"]
        assert not_found_idx == []

    def test_miss_records_under_remapped_key(self, tmp_path):
        cache_root = tmp_path / "ccc"
        live_root = tmp_path / "xxx" / "yyy"
        live_root.mkdir(parents=True)
        f = _make_file(live_root / "aa" / "cc", size=9)

        store = SignatureStore(None,
                               file_remappers=[(re.escape(str(live_root)),
                                                _repl_literal(str(cache_root)))])
        store.query([str(f)], compute=lambda ps: ["new_payload"], save=False)

        expected_key = build_key(
            os.path.join(str(cache_root), os.path.join("aa", "cc")), 9,
            os.stat(str(f)).st_mtime_ns)
        assert store.data == {expected_key: "new_payload"}


class TestCacheRemappers:
    """Cache-side remap: stored key ccc/aa/cc is read as xxx/yyy/aa/cc."""

    def _scenario(self, tmp_path):
        cache_root = tmp_path / "ccc"
        live_root = tmp_path / "xxx" / "yyy"
        live_root.mkdir(parents=True)
        f = _make_file(live_root / "aa" / "cc", size=9)
        stored_key = build_key(
            os.path.join(str(cache_root), os.path.join("aa", "cc")), 9,
            os.stat(str(f)).st_mtime_ns)
        return cache_root, live_root, f, stored_key

    def test_load_renames_keys_into_live_space(self, tmp_path):
        cache_root, live_root, f, stored_key = self._scenario(tmp_path)
        json_path = tmp_path / "signature.json"
        json_path.write_text(json.dumps({stored_key: "payload"}), encoding="utf-8")

        store = SignatureStore(str(json_path),
                               cache_remappers=[(re.escape(str(cache_root)),
                                                 _repl_literal(str(live_root)))]).load()

        expected_key = build_key(
            os.path.join(str(live_root), os.path.join("aa", "cc")), 9,
            os.stat(str(f)).st_mtime_ns)
        assert store.data == {expected_key: "payload"}

        results, not_found_idx, _ = store.query([str(f)])
        assert results == ["payload"]
        assert not_found_idx == []

    def test_rename_persists_on_save(self, tmp_path):
        cache_root, live_root, f, stored_key = self._scenario(tmp_path)
        json_path = tmp_path / "signature.json"
        json_path.write_text(json.dumps({stored_key: "payload"}), encoding="utf-8")

        store = SignatureStore(str(json_path),
                               cache_remappers=[(re.escape(str(cache_root)),
                                                 _repl_literal(str(live_root)))]).load()
        store.save()

        with open(json_path, "r", encoding="utf-8") as f_json:
            persisted = json.load(f_json)
        assert list(persisted) == list(store.data)
        assert stored_key not in persisted

    def test_no_cache_remappers_keeps_keys_verbatim(self, tmp_path):
        cache_root, live_root, f, stored_key = self._scenario(tmp_path)
        json_path = tmp_path / "signature.json"
        json_path.write_text(json.dumps({stored_key: "payload"}), encoding="utf-8")

        store = SignatureStore(str(json_path)).load()
        assert store.data == {stored_key: "payload"}

    def test_both_sides_same_prefix_misses(self, tmp_path):
        """Docstring/README claim: file and cache remappers for one prefix
        translate in opposite directions and make lookups miss."""
        cache_root, live_root, f, stored_key = self._scenario(tmp_path)
        json_path = tmp_path / "signature.json"
        json_path.write_text(json.dumps({stored_key: "payload"}), encoding="utf-8")

        store = SignatureStore(str(json_path),
                               file_remappers=[(re.escape(str(live_root)),
                                                _repl_literal(str(cache_root)))],
                               cache_remappers=[(re.escape(str(cache_root)),
                                                 _repl_literal(str(live_root)))]).load()
        # load() migrated the stored key into the live space; the file rule
        # maps the live path back into the cache space — the two cancel to a miss.
        results, not_found_idx, _ = store.query([str(f)])
        assert results == [None]
        assert not_found_idx == [0]

    def test_remap_collision_later_entry_wins(self, tmp_path):
        cache_root, live_root, f, stored_key = self._scenario(tmp_path)
        mtime = os.stat(str(f)).st_mtime_ns
        # A second stored key that remaps onto the same live key; the later
        # JSON entry wins the collision.
        colliding = build_key(os.path.join(str(tmp_path), "other", "aa", "cc"), 9, mtime)
        json_path = tmp_path / "signature.json"
        json_path.write_text(json.dumps({stored_key: "first", colliding: "second"}),
                             encoding="utf-8")

        store = SignatureStore(str(json_path),
                               cache_remappers=[(re.escape(str(cache_root)),
                                                 _repl_literal(str(live_root))),
                                                (re.escape(str(tmp_path / "other")),
                                                 _repl_literal(str(live_root)))]).load()
        expected_key = build_key(os.path.join(str(live_root), "aa", "cc"), 9, mtime)
        assert store.data == {expected_key: "second"}


class TestCrossPlatformBridging:
    """A cache built on one OS is usable from the other via remappers."""

    def test_windows_file_hits_linux_built_cache(self, tmp_path):
        # Cache keys recorded on a Linux machine under /mnt/e
        f = _make_file(tmp_path / "img.jpg", size=11, mtime_ns=2500)
        linux_key = build_key("/mnt/e/pool/img.jpg", 11, 2500)

        # On Windows (or any OS) the file lives under tmp_path; map it onto the
        # Linux root, normalizing separators at the same time.
        rules = [
            (re.escape(str(tmp_path)) + r"(\\|/)", "/mnt/e/pool/"),
        ]
        store = SignatureStore(None, file_remappers=rules)
        store.data = {linux_key: "payload"}

        results, not_found_idx, _ = store.query([str(f)])
        assert results == ["payload"]
        assert not_found_idx == []

    def test_linux_built_cache_remapped_to_live_paths(self, tmp_path):
        # Same reconciliation, cache-side: stored /mnt/e keys become live paths.
        f = _make_file(tmp_path / "img.jpg", size=11, mtime_ns=2500)
        linux_key = build_key("/mnt/e/pool/img.jpg", 11, 2500)
        json_path = tmp_path / "signature.json"
        json_path.write_text(json.dumps({linux_key: "payload"}), encoding="utf-8")

        live_root = str(f.parent)
        # Prefix rewrite, then separator normalization — the same rules a real
        # Linux-built cache needs to land on Windows-native live keys.
        rules = [(r"^/mnt/e/pool", _repl_literal(live_root)), (r"/", "\\\\")]
        store = SignatureStore(str(json_path), cache_remappers=rules).load()

        expected_key = build_key(os.path.join(live_root, "img.jpg"), 11, 2500)
        assert store.data == {expected_key: "payload"}

        results, not_found_idx, _ = store.query([str(f)])
        assert results == ["payload"]
        assert not_found_idx == []

    def test_generated_remappers_bridge_foreign_cache(self, tmp_path):
        """The generator functions bridge a cache keyed in the other OS's path
        space: on Windows the live path is mapped into a Linux-built key space,
        on Linux into a Windows-built one."""
        f = _make_file(tmp_path / "pool" / "img.jpg", size=11, mtime_ns=2500)
        real = os.path.realpath(str(f))
        if os.name == "nt":
            drive = os.path.splitdrive(real)[0]              # e.g. "C:"
            linux_root = "/mnt/" + drive[0].lower()
            pairs = windows_to_linux_remappers(drive, linux_root)
        else:
            linux_root = os.path.dirname(real)               # the pool directory
            pairs = linux_to_windows_remappers(linux_root, "E:")
        foreign_key = build_key(apply_remappers(real, pairs), 11, 2500)

        store = SignatureStore(None, file_remappers=pairs)
        store.data = {foreign_key: "payload"}

        results, not_found_idx, _ = store.query([str(f)])
        assert results == ["payload"]
        assert not_found_idx == []
