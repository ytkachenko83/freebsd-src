#!/usr/bin/env python3
"""Exercise JID lookup/lifecycle semantics on a FreeBSD test kernel as root."""
# SPDX-License-Identifier: BSD-2-Clause

import array
import ctypes
import errno
import os
import platform
import secrets
import socket
import subprocess
import time


class Iovec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]


libc = ctypes.CDLL(None, use_errno=True)


def get(key, value, flags=0):
    """Use raw jail_get, bypassing libjail's parameter processing."""
    keybuf = ctypes.create_string_buffer(key.encode())
    valuebuf = (ctypes.c_int(value) if isinstance(value, int)
                else ctypes.create_string_buffer(value.encode()))
    if key == "name":
        # Do not add a duplicate name option: VFS keeps only the last one.
        outputkey = ctypes.create_string_buffer(b"jid")
        output = ctypes.c_int()
        name = valuebuf
    else:
        outputkey = ctypes.create_string_buffer(b"name")
        output = name = ctypes.create_string_buffer(256)
    buffers = [keybuf, valuebuf, outputkey, output]
    iov = (Iovec * len(buffers))(
        *(Iovec(ctypes.addressof(b), ctypes.sizeof(b)) for b in buffers))
    jid = libc.jail_get(iov, len(iov), flags)
    if jid < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return jid, name.value.decode()


def absent(key, value, flags=0):
    try:
        get(key, value, flags)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return True
        raise
    return False


def walk(start=0, flags=0):
    ids = []
    while True:
        try:
            jid, _ = get("lastjid", start, flags)
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                return ids
            raise
        assert jid > start, (jid, start)
        ids.append(jid)
        start = jid


def wait_absent(jid):
    deadline = time.monotonic() + 10
    while not absent("jid", jid, 8):
        if time.monotonic() >= deadline:
            raise AssertionError(f"JID {jid} still present after release")
        time.sleep(0.02)


def fork_check(jid, callback):
    pid = os.fork()
    if pid == 0:
        try:
            if libc.jail_attach(jid) != 0:
                raise OSError(ctypes.get_errno(), "jail_attach")
            callback()
        except BaseException:
            import traceback
            traceback.print_exc()
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0, "jailed check failed"


def held_socket(jid):
    """Retain a jailed socket credential on the host to keep a dying prison."""
    rx, tx = socket.socketpair()
    pid = os.fork()
    if pid == 0:
        rx.close()
        try:
            if libc.jail_attach(jid) != 0:
                os._exit(1)
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
                tx.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                    array.array("i", [sock.fileno()]))])
        finally:
            os._exit(0)
    tx.close()
    fd = None
    try:
        _, anc, _, _ = rx.recvmsg(1, socket.CMSG_SPACE(array.array("i").itemsize))
        for level, kind, data in anc:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                fds = array.array("i")
                fds.frombytes(data[:len(data) - len(data) % fds.itemsize])
                assert len(fds) == 1
                fd = fds[0]
    finally:
        rx.close()
        _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0 and fd is not None, "socket transfer failed"
    return fd


def main():
    if platform.system() != "FreeBSD" or os.geteuid() != 0:
        raise SystemExit("run as root on a FreeBSD test host")
    if subprocess.check_output(["sysctl", "-n", "security.jail.jailed"], text=True).strip() != "0":
        raise SystemExit("run outside a jail")
    libc.jail_get.argtypes = [ctypes.POINTER(Iovec), ctypes.c_uint, ctypes.c_int]
    libc.jail_get.restype = ctypes.c_int
    libc.jail_attach.argtypes = [ctypes.c_int]
    libc.jail_remove.argtypes = [ctypes.c_int]
    prefix = "jididx_" + secrets.token_hex(6)
    names = []
    journal = os.environ.get("JID_INDEX_TEST_JOURNAL")
    held = None

    def create(name, jid=None, extra=(), fail=False, childmax=0):
        names.append(name)
        if journal:
            with open(journal, "a") as stream:
                stream.write(name + "\n")
        cmd = ["jail", "-i", "-c", "name=" + name, "persist", "path=/",
               "host=inherit", "ip4=disable", "ip6=disable", f"children.max={childmax}"]
        if jid is not None:
            cmd.append(f"jid={jid}")
        result = subprocess.run(cmd + list(extra), capture_output=True, text=True)
        if fail:
            assert result.returncode != 0, "expected rejected creation"
            return None
        assert result.returncode == 0, result.stderr
        return int(result.stdout.strip())

    def remove(jid):
        if libc.jail_remove(jid) != 0:
            raise OSError(ctypes.get_errno(), "jail_remove")

    try:
        # Find a sparse, unused explicit-ID range, without touching others.
        for _ in range(100):
            base = 500000 + secrets.randbelow(400000)
            if all(absent("jid", base + i, 8) for i in range(8)):
                break
        else:
            raise AssertionError("no unused test range found")
        parent = create(prefix, base, childmax=4)
        a = create(prefix + ".a", base + 2)
        b = create(prefix + ".b", base + 4)
        outside = create(prefix + "_outside", base + 6)
        assert get("jid", parent)[1] == prefix
        assert get("jid", a)[1] == prefix + ".a"
        assert absent("jid", base + 1)
        assert get("lastjid", base + 1)[0] == a
        assert get("lastjid", a)[0] == b
        assert absent("lastjid", 2147483647)
        assert parent in walk(-1)
        print("PASS exact lookup, sparse IDs, missing cursor, INT_MAX", flush=True)

        def visibility():
            assert get("jid", a)[0] == a
            assert absent("jid", parent), "self must not count as a descendant"
            assert absent("jid", outside), "outside prison visible"
            assert walk() == [a, b]
        fork_check(parent, visibility)
        print("PASS nested visibility and filtered enumeration", flush=True)

        create(prefix + "_failed", base + 1,
               extra=("jid_index_test_unknown_parameter=1",), fail=True)
        wait_absent(base + 1)
        remove(a)
        wait_absent(a)
        assert get("lastjid", a)[0] == b
        assert get("lastjid", base + 1)[0] == b
        print("PASS failed creation and removed enumeration cursor", flush=True)

        oldname = prefix + "_old"
        old = create(oldname, base + 1)
        held = held_socket(old)
        remove(old)
        assert get("jid", old, 8)[1] == oldname
        assert absent("jid", old)
        replacement = create(prefix + "_replacement", old)
        renamed, _ = get("name", oldname, 8)
        assert renamed != old
        assert get("jid", replacement)[1] == prefix + "_replacement"
        assert get("jid", renamed, 8)[1] == oldname
        assert absent("jid", renamed)
        assert renamed in walk(flags=8)
        os.close(held)
        held = None
        wait_absent(renamed)
        print("PASS dying-JID renumbering, reuse and final release", flush=True)

        remove(parent)
        wait_absent(parent)
        wait_absent(b)
        assert get("jid", outside)[1] == prefix + "_outside"
        print("PASS subtree removal without removing unrelated jail", flush=True)
    finally:
        if held is not None:
            os.close(held)
        # Remove only this test's uniquely named jails, including failed creates.
        for name in reversed(names):
            subprocess.run(["jail", "-r", name], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=30)


if __name__ == "__main__":
    main()
