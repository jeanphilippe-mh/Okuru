import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/okuru-journal-mirror.py"
spec = importlib.util.spec_from_file_location("mirror", SCRIPT)
mirror = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mirror)


def entry(cursor, message):
    return json.dumps({"__CURSOR": cursor, "MESSAGE": message}).encode()


class MirrorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.output = self.root / "okuru.log"
        self.output.touch(mode=0o600)

    def make(self):
        result = mirror.Mirror(self.output, self.state)
        self.addCleanup(result.close)
        return result

    def test_complete_messages_and_resume(self):
        m = self.make()
        raw_json = '{"time":"first","time":"second","path":"/hello"}'
        m.append_entry(entry("a", raw_json))
        m.append_entry(entry("b", "plain\nmultiline"))
        m.append_entry(entry("c", [255, 0, 65]))
        self.assertEqual(self.output.read_bytes(), raw_json.encode() + b"\nplain\nmultiline\n\xff\x00A\n")
        m.close()
        again = self.make()
        self.assertEqual(again.cursor, "c")

    def test_rotation_preserves_both_files(self):
        m = self.make()
        m.append_entry(entry("a", "before"))
        old = self.root / "okuru.log.1"
        self.output.rename(old)
        fd = os.open(self.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        m.append_entry(entry("b", "after"))
        self.assertEqual(old.read_bytes(), b"before\n")
        self.assertEqual(self.output.read_bytes(), b"after\n")
        self.assertEqual((self.state / "cursor").read_text(), "b\n")

    def test_rotation_accepts_configured_owner_and_mode_without_changing_them(self):
        self.output.chmod(0o640)
        m = mirror.Mirror(self.output, self.state, (os.getuid(), os.getgid()))
        self.addCleanup(m.close)
        m.append_entry(entry("a", "before"))
        old = self.root / "okuru.log.1"
        self.output.rename(old)
        self.output.touch(mode=0o640)
        self.output.chmod(0o640)
        m.append_entry(entry("b", "after"))
        self.assertEqual(old.read_bytes(), b"before\n")
        self.assertEqual(self.output.read_bytes(), b"after\n")
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o640)

    def test_missing_file_is_not_created(self):
        self.output.unlink()
        with self.assertRaises(FileNotFoundError):
            self.make()
        self.assertFalse(self.output.exists())

    def test_existing_content_requires_explicit_reconciliation(self):
        self.output.write_text("historical log\n")
        with self.assertRaisesRegex(mirror.MirrorError, "reconcile manually"):
            self.make()
        self.assertEqual(self.output.read_text(), "historical log\n")
        self.assertFalse((self.state / "cursor").exists())

    def test_hardlink_and_wrong_rotate_identity_are_refused(self):
        self.output.chmod(0o640)
        with self.assertRaises(mirror.MirrorError):
            mirror.Mirror(self.output, self.state, (os.getuid() + 1, os.getgid()))
        self.output.chmod(0o600)
        second = self.root / "hardlink"
        os.link(self.output, second)
        with self.assertRaises(mirror.MirrorError):
            self.make()

    def test_failure_does_not_advance_cursor(self):
        m = self.make()
        m.append_entry(entry("a", "first"))
        with patch.object(mirror.os, "fsync", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                m.append_entry(entry("b", "second"))
        self.assertEqual((self.state / "cursor").read_text(), "a\n")
        with self.assertRaises(mirror.MirrorError):
            m.append_entry(b'not-json')
        self.assertEqual((self.state / "cursor").read_text(), "a\n")

    def test_unsafe_output_and_lock_refused(self):
        self.output.unlink()
        self.output.symlink_to(self.root / "other")
        with self.assertRaises(OSError):
            self.make()
        self.output.unlink()
        self.output.write_text("old\n")
        self.output.chmod(0o600)
        with self.assertRaises(mirror.MirrorError):
            self.make()
        self.output.unlink()
        self.output.touch(mode=0o600)
        m = self.make()
        with self.assertRaises(mirror.MirrorError):
            self.make()
        m.close()
        self.output.chmod(0o644)
        with self.assertRaises(mirror.MirrorError):
            self.make()

    def test_invalid_cursor_is_not_silently_ignored(self):
        cursor = self.state / "cursor"
        cursor.write_text("")
        cursor.chmod(0o600)
        with self.assertRaises(mirror.MirrorError):
            self.make()

    def test_command_uses_literal_unit_and_resumes(self):
        import subprocess
        fake = self.root / "journalctl"
        args_file = self.root / "arguments"
        fake.write_text("#!/usr/bin/env python3\nimport json,sys\nopen(" + repr(str(args_file)) + ", 'w').write('\\n'.join(sys.argv[1:]))\nprint(json.dumps({'__CURSOR':'s=1','MESSAGE':'full message'}))\n")
        fake.chmod(0o700)
        cmd = ["python3", str(SCRIPT), "--output", str(self.output), "--state-dir", str(self.state), "--journalctl", str(fake), "--once"]
        subprocess.run(cmd, check=True)
        args = args_file.read_text().splitlines()
        self.assertIn("_SYSTEMD_UNIT=okuru.service", args)
        self.assertNotIn("--unit=okuru.service", args)
        self.assertIn("--lines=all", args)
        subprocess.run(cmd, check=True)
        self.assertIn("--after-cursor=s=1", args_file.read_text().splitlines())
        result = subprocess.run(cmd[:-1], capture_output=True)
        self.assertNotEqual(result.returncode, 0)  # fake follow command exits immediately
        args = args_file.read_text().splitlines()
        self.assertLess(args.index("--follow"), args.index("--boot=all"))
        self.assertEqual(args[-1], "_SYSTEMD_UNIT=okuru.service")

    def test_restart_and_rotation_do_not_reimport_checkpointed_entries(self):
        import subprocess
        fake = self.root / "journalctl"
        source = self.root / "entries.json"
        source.write_text(json.dumps([["a", "one"], ["b", "two"]]))
        fake.write_text(
            "#!/usr/bin/env python3\nimport json,sys\n"
            "records=json.load(open(" + repr(str(source)) + "))\n"
            "cursor=next((v.split('=',1)[1] for v in sys.argv if v.startswith('--after-cursor=')),None)\n"
            "start=next((i+1 for i,(c,_) in enumerate(records) if c==cursor),0) if cursor else 0\n"
            "for c,msg in records[start:]: print(json.dumps({'__CURSOR':c,'MESSAGE':msg}))\n"
        )
        fake.chmod(0o700)
        cmd = ["python3", str(SCRIPT), "--output", str(self.output), "--state-dir", str(self.state), "--journalctl", str(fake), "--once"]
        subprocess.run(cmd, check=True)
        subprocess.run(cmd, check=True)
        self.assertEqual(self.output.read_text(), "one\ntwo\n")
        self.output.rename(self.root / "okuru.log.1")
        self.output.touch(mode=0o600)
        source.write_text(json.dumps([["a", "one"], ["b", "two"], ["c", "three"]]))
        subprocess.run(cmd, check=True)
        subprocess.run(cmd, check=True)
        self.assertEqual((self.root / "okuru.log.1").read_text(), "one\ntwo\n")
        self.assertEqual(self.output.read_text(), "three\n")


if __name__ == "__main__":
    unittest.main()
