#!/usr/bin/env python3
"""SSH runner with sudo password auto-entry."""
import sys
import paramiko
import time

HOST = "localhost"
PORT = 2222
USER = "ghostring"
PASS = "ghost"

def run_sudo(cmd):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, PORT, USER, PASS, timeout=10, banner_timeout=10)
    # -S reads password from stdin
    full = f"echo '{PASS}' | sudo -S {cmd}"
    stdin, stdout, stderr = c.exec_command(full, timeout=600)
    # Stream output
    while True:
        line = stdout.readline()
        if not line:
            break
        print(line, end="")
    for line in stderr.readlines():
        print(line, end="", file=sys.stderr)
    rc = stdout.channel.recv_exit_status()
    c.close()
    return rc

if __name__ == "__main__":
    cmd = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "whoami"
    sys.exit(run_sudo(cmd))
