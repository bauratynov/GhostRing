#!/usr/bin/env python3
"""Simpler: use sshpass-like pattern — pipe root password to su via expect."""
import sys
import paramiko

HOST = "localhost"
PORT = 2222
USER = "ghostring"
PASS = "ghost"
ROOT_PASS = "123"

def run(cmd, timeout=600):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, PORT, USER, PASS, timeout=10, banner_timeout=10)

    # Use `su` with -c and pipe password via stdin (after newline for Password: prompt)
    # Trick: echo "password\ncommand" | su root — but su doesn't support stdin for command
    # Better: use `su -c 'cmd' root` and feed password via stdin
    su_cmd = f"su -c '{cmd.replace(chr(39), chr(39)+chr(92)+chr(39)+chr(39))}' root"
    stdin, stdout, stderr = c.exec_command(su_cmd, timeout=timeout, get_pty=True)
    stdin.write(ROOT_PASS + "\n")
    stdin.flush()

    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    rc = stdout.channel.recv_exit_status()

    # Strip the Password: prompt and echoed password line
    lines = out.split("\n")
    # Remove first 1-2 lines if they contain "Password:"
    while lines and ("Password" in lines[0] or not lines[0].strip()):
        lines.pop(0)
    out = "\n".join(lines)

    if out: print(out, end="")
    if err: print(err, end="", file=sys.stderr)

    c.close()
    return rc

if __name__ == "__main__":
    cmd = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "whoami"
    sys.exit(run(cmd))
