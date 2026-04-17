#!/usr/bin/env python3
"""SSH runner for GhostRing test VM.  Usage: py vm_run.py 'command'"""
import sys
import paramiko

HOST = "localhost"
PORT = 2222
USER = "root"
PASS = "123"

def run(cmd, quiet=False):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, PORT, USER, PASS, timeout=10, banner_timeout=10)
    stdin, stdout, stderr = c.exec_command(cmd, timeout=300)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    rc = stdout.channel.recv_exit_status()
    c.close()
    if not quiet:
        if out: print(out, end="")
        if err: print(err, end="", file=sys.stderr)
    return rc, out, err

if __name__ == "__main__":
    cmd = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "uname -a"
    rc, _, _ = run(cmd)
    sys.exit(rc)
