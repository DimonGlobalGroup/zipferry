import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "zipferry.py")


def run(*argv):
    return subprocess.run([sys.executable, TOOL, *argv], capture_output=True, text=True)


def make_zip(path, entries):
    """entries: list of (name, bytes) or (ZipInfo, bytes)."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            if isinstance(name, zipfile.ZipInfo):
                zf.writestr(name, data)
            else:
                zf.writestr(name, data)


class ZipFerryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def zp(self, name="a.zip"):
        return os.path.join(self.dir, name)

    def test_clean_archive_exit0(self):
        p = self.zp(); make_zip(p, [("hello.txt", b"hi"), ("docs/readme.md", b"# x")])
        r = run("audit", p); self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("2 entries, 2 files", r.stdout)

    def test_version(self):
        r = run("--version"); self.assertEqual(r.returncode, 0); self.assertIn("1.0.0", r.stdout)

    def test_no_command_exit2(self):
        self.assertEqual(run().returncode, 2)

    def test_missing_file_exit2(self):
        self.assertEqual(run("audit", self.zp("nope.zip")).returncode, 2)

    def test_not_a_zip_exit2_no_traceback(self):
        p = self.zp(); open(p, "wb").write(b"not a zip at all")
        r = run("audit", p); self.assertEqual(r.returncode, 2); self.assertNotIn("Traceback", r.stderr)

    def test_unsafe_dotdot(self):
        p = self.zp(); make_zip(p, [("../evil.txt", b"x")])
        r = run("audit", p); self.assertEqual(r.returncode, 1); self.assertIn("unsafe-path", r.stdout)

    def test_unsafe_absolute_and_drive_and_backslash(self):
        for name in ("/abs.txt", "C:/win.txt", "a\\b.txt"):
            p = self.zp(name.replace("/", "_").replace(":", "").replace("\\", "_") + ".zip")
            make_zip(p, [(name, b"x")])
            r = run("audit", p); self.assertIn("unsafe-path", r.stdout, name)

    def test_duplicate_entry(self):
        p = self.zp()
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("same.txt", b"one"); zf.writestr("same.txt", b"two")
        r = run("audit", p); self.assertEqual(r.returncode, 1); self.assertIn("duplicate-entry", r.stdout)

    def test_case_collision(self):
        p = self.zp(); make_zip(p, [("Photo.jpg", b"a"), ("photo.jpg", b"b")])
        r = run("audit", p); self.assertEqual(r.returncode, 1); self.assertIn("case-collision", r.stdout)

    def test_empty_file_warning_exit0(self):
        p = self.zp(); make_zip(p, [("empty.txt", b"")])
        r = run("audit", p); self.assertEqual(r.returncode, 0); self.assertIn("empty-file", r.stdout)

    def test_executable_and_nested_warnings(self):
        p = self.zp(); make_zip(p, [("run.exe", b"MZ"), ("inner.zip", b"PK")])
        r = run("audit", p); self.assertEqual(r.returncode, 0)
        self.assertIn("executable-entry", r.stdout); self.assertIn("nested-archive", r.stdout)

    def test_high_ratio(self):
        p = self.zp(); make_zip(p, [("big.txt", b"A" * 200000)])
        r = run("audit", p); self.assertEqual(r.returncode, 1); self.assertIn("high-ratio", r.stdout)
        r2 = run("audit", "--max-ratio", "100000", p); self.assertEqual(r2.returncode, 0)

    def test_total_size_limit(self):
        p = self.zp(); make_zip(p, [("a.txt", b"x" * 5000)])
        # stored data compresses; use stored entries for declared size control
        p2 = self.zp("b.zip")
        with zipfile.ZipFile(p2, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("a.txt", b"x" * 5000)
        r = run("audit", "--max-total", "100", p2); self.assertEqual(r.returncode, 1); self.assertIn("total-size", r.stdout)

    def test_too_many_entries(self):
        p = self.zp(); make_zip(p, [(f"f{i}.txt", b"x") for i in range(5)])
        r = run("audit", "--max-entries", "2", p); self.assertEqual(r.returncode, 1); self.assertIn("too-many-entries", r.stdout)

    def test_symlink_entry(self):
        info = zipfile.ZipInfo("link.txt")
        info.external_attr = (0o120777 << 16)
        p = self.zp(); make_zip(p, [(info, b"/target")])
        r = run("audit", p); self.assertIn("symlink", r.stdout)

    def test_encrypted_flag(self):
        # zipfile cannot write encrypted entries; craft via flag on a stored entry is
        # not writable post-hoc in the central directory through the public API, so
        # verify the flag logic directly against a patched central directory.
        p = self.zp(); make_zip(p, [("secret.txt", b"data")])
        raw = bytearray(open(p, "rb").read())
        idx = raw.find(b"PK\x01\x02")
        self.assertGreater(idx, 0)
        raw[idx + 8] |= 0x01  # general purpose bit flag, central header
        open(p, "wb").write(bytes(raw))
        r = run("audit", p); self.assertIn("encrypted-entry", r.stdout)

    def test_fingerprint_only_hides_canary(self):
        canary = "CANARY-SECRET-NAME.txt"
        p = self.zp(); make_zip(p, [(canary, b""), ("run.exe", b"MZ")])
        for extra in ([], ["--json"]):
            r = run("audit", "--fingerprint-only", *extra, p)
            self.assertNotIn("CANARY", r.stdout); self.assertNotIn(canary, r.stdout)
            self.assertIn("crc", r.stdout)

    def test_json_shape_and_determinism(self):
        p = self.zp(); make_zip(p, [("a.txt", b"hello"), ("b.exe", b"MZ")])
        r1 = run("audit", "--json", p); r2 = run("audit", "--json", p)
        self.assertEqual(r1.stdout, r2.stdout)
        doc = json.loads(r1.stdout)
        self.assertEqual(doc["summary"]["files"], 2)
        self.assertEqual(doc["summary"]["warnings"], 1)

    def test_max_examples_cap_counts_suppressed(self):
        p = self.zp(); make_zip(p, [(f"e{i}.txt", b"") for i in range(5)])
        r = run("audit", "--max-examples", "2", p)
        self.assertIn("empty-file", r.stdout)
        self.assertIn("3 more empty-file", r.stdout)

    def test_multiple_archives(self):
        p1 = self.zp("1.zip"); p2 = self.zp("2.zip")
        make_zip(p1, [("a.txt", b"x")]); make_zip(p2, [("b.txt", b"y")])
        r = run("audit", p1, p2); self.assertEqual(r.returncode, 0); self.assertIn("2 archives", r.stdout)

    def test_directory_entries_not_files(self):
        p = self.zp(); make_zip(p, [("docs/", b""), ("docs/a.txt", b"x")])
        r = run("audit", "--json", p); doc = json.loads(r.stdout)
        self.assertEqual(doc["summary"]["entries"], 2); self.assertEqual(doc["summary"]["files"], 1)
        self.assertNotIn("empty-file", r.stdout)

    def test_readonly_no_extraction(self):
        p = self.zp(); make_zip(p, [("evil.txt", b"x")])
        before = set(os.listdir(self.dir))
        run("audit", p)
        self.assertEqual(set(os.listdir(self.dir)), before)


if __name__ == "__main__":
    unittest.main()
