#!/usr/bin/env python3
"""Mirror complete Okuru journal MESSAGE fields into an append-only file."""

import argparse
import fcntl
import grp
import json
import os
from pathlib import Path
import pwd
import secrets
import stat
import subprocess
import sys
import time


class MirrorError(Exception):
    pass


def check_private_file(fd, path):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise MirrorError(f"unsafe file permissions, ownership or type: {path}")
    return info


def check_output_file(fd, path, rotated_owner):
    """Accept private root files or files created by the configured logrotate rule."""
    info = os.fstat(fd)
    mode = stat.S_IMODE(info.st_mode)
    private = info.st_uid == os.geteuid() and mode == 0o600
    rotated = (rotated_owner is not None
               and (info.st_uid, info.st_gid) == rotated_owner and mode == 0o640)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not (private or rotated):
        raise MirrorError(f"unsafe file permissions, ownership or type: {path}")
    return info


def open_directory(path, private):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    info = os.fstat(fd)
    forbidden = 0o077 if private else 0o022
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & forbidden:
        os.close(fd)
        raise MirrorError(f"unsafe directory permissions or ownership: {path}")
    return fd


def private_open(name, flags, directory):
    return os.open(name, flags | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=directory)


def write_all(fd, data):
    view = memoryview(data)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise MirrorError("short write to mirror")
        view = view[count:]


def message_bytes(entry, raw):
    if "MESSAGE" not in entry:
        # Rare journal entries without MESSAGE still remain visible.
        return raw.rstrip(b"\n") + b"\n"
    value = entry["MESSAGE"]
    if isinstance(value, str):
        return value.encode("utf-8") + b"\n"
    if isinstance(value, list) and all(type(x) is int and 0 <= x <= 255 for x in value):
        return bytes(value) + b"\n"
    if isinstance(value, list) and all(isinstance(x, str) for x in value):
        return b"".join(x.encode("utf-8") + b"\n" for x in value)
    raise MirrorError("unsupported or incomplete MESSAGE in journal JSON")


class Mirror:
    def __init__(self, output, state_dir, rotated_owner=None):
        self.path = Path(output)
        self.rotated_owner = rotated_owner
        if not self.path.name or self.path.name in (".", ".."):
            raise MirrorError("invalid output path")
        self.out_dir = open_directory(self.path.parent, private=False)
        self.state_dir = None
        self.lock_fd = None
        self.out_fd = None
        try:
            self.state_dir = open_directory(state_dir, private=True)
            self.lock_fd = private_open("lock", os.O_RDWR | os.O_CREAT, self.state_dir)
            check_private_file(self.lock_fd, "lock")
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise MirrorError("another mirror is already running") from exc
            self.cursor = self.read_cursor()
            # Never create the path: it may temporarily be absent while
            # logrotate is renaming and creating the replacement.
            self.out_fd = self.open_output()
            if self.cursor is None and os.fstat(self.out_fd).st_size:
                raise MirrorError("output is not empty and no cursor exists; reconcile manually before backfill")
        except BaseException:
            self.close()
            raise

    def close(self):
        for name in ("out_fd", "lock_fd", "state_dir", "out_dir"):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)

    def read_cursor(self):
        try:
            fd = private_open("cursor", os.O_RDONLY, self.state_dir)
        except FileNotFoundError:
            return None
        try:
            check_private_file(fd, "cursor")
            cursor = os.read(fd, 8193).decode("utf-8").rstrip("\n")
        finally:
            os.close(fd)
        if not cursor or len(cursor.encode("utf-8")) > 8192 or "\n" in cursor or "\x00" in cursor:
            raise MirrorError("invalid saved journal cursor")
        return cursor

    def open_output(self):
        flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_NONBLOCK", 0)
        fd = private_open(self.path.name, flags, self.out_dir)
        try:
            check_output_file(fd, str(self.path), self.rotated_owner)
            # The file can have just been created by logrotate. Persist its
            # directory entry before any cursor can advance past its data.
            os.fsync(self.out_dir)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def ensure_current_output(self):
        # Rotation renames the old file then creates a new one. Do not create
        # the replacement ourselves while logrotate is between those steps.
        deadline = time.monotonic() + 5
        while True:
            try:
                current = os.stat(self.path.name, dir_fd=self.out_dir, follow_symlinks=False)
                break
            except FileNotFoundError:
                if time.monotonic() >= deadline:
                    raise MirrorError("output file was not recreated after rotation")
                time.sleep(0.05)
        opened = os.fstat(self.out_fd)
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            replacement = self.open_output()
            new = os.fstat(replacement)
            if (current.st_dev, current.st_ino) != (new.st_dev, new.st_ino):
                os.close(replacement)
                raise MirrorError("output changed while reopening after rotation")
            os.close(self.out_fd)
            self.out_fd = replacement
        check_output_file(self.out_fd, str(self.path), self.rotated_owner)

    def save_cursor(self, cursor):
        name = ".cursor-" + secrets.token_hex(12)
        fd = private_open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, self.state_dir)
        try:
            try:
                write_all(fd, cursor.encode("utf-8") + b"\n")
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(name, "cursor", src_dir_fd=self.state_dir, dst_dir_fd=self.state_dir)
            os.fsync(self.state_dir)
        finally:
            try:
                os.unlink(name, dir_fd=self.state_dir)
            except FileNotFoundError:
                pass
        self.cursor = cursor

    def append_entry(self, raw):
        try:
            entry = json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise MirrorError("journalctl returned invalid JSON; cursor not advanced") from exc
        if not isinstance(entry, dict):
            raise MirrorError("journalctl returned a non-object entry; cursor not advanced")
        cursor = entry.get("__CURSOR")
        if not isinstance(cursor, str) or not cursor or len(cursor.encode("utf-8")) > 8192 or "\n" in cursor or "\x00" in cursor:
            raise MirrorError("journal entry has no usable cursor; cursor not advanced")
        data = message_bytes(entry, raw)
        self.ensure_current_output()
        write_all(self.out_fd, data)
        os.fsync(self.out_fd)
        self.save_cursor(cursor)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="existing mirror file")
    parser.add_argument("--state-dir", required=True, help="private directory for lock and cursor")
    parser.add_argument("--log-owner", help="expected owner of files created by logrotate")
    parser.add_argument("--log-group", help="expected group of files created by logrotate")
    parser.add_argument("--journalctl", default="/usr/bin/journalctl", help=argparse.SUPPRESS)
    parser.add_argument("--once", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        if bool(args.log_owner) != bool(args.log_group):
            raise MirrorError("--log-owner and --log-group must be provided together")
        rotated_owner = None
        if args.log_owner:
            try:
                rotated_owner = (pwd.getpwnam(args.log_owner).pw_uid,
                                 grp.getgrnam(args.log_group).gr_gid)
            except KeyError as exc:
                raise MirrorError("configured logrotate owner or group does not exist") from exc
        mirror = Mirror(args.output, args.state_dir, rotated_owner)
        try:
            command = [args.journalctl, "--namespace=okuru", "--output=json", "--all", "--no-pager", "--lines=all"]
            if mirror.cursor:
                command.append("--after-cursor=" + mirror.cursor)
            if not args.once:
                # On some systemd versions --follow selects the current boot;
                # clear that implicit restriction after enabling follow.
                command.extend(["--follow", "--boot=all"])
            command.append("_SYSTEMD_UNIT=okuru.service")
            process = subprocess.Popen(command, stdout=subprocess.PIPE)
            try:
                for raw in process.stdout:
                    mirror.append_entry(raw)
            except BaseException:
                if process.poll() is None:
                    process.terminate()
                raise
            finally:
                process.stdout.close()
                result = process.wait()
            if result != 0:
                raise MirrorError(f"journalctl failed with exit code {result}")
            if not args.once:
                raise MirrorError("journalctl stopped unexpectedly")
        finally:
            mirror.close()
    except (OSError, UnicodeError, MirrorError) as exc:
        print(f"okuru-journal-mirror: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
