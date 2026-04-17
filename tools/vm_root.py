#!/usr/bin/env python3
"""SSH runner that uses `su -` with root password."""
import sys
import paramiko
import time

HOST = "172.19.208.100"
PORT = 22
USER = "ghostring"
PASS = "ghost"
ROOT_PASS = "123"

def run_as_root(cmd, timeout=600):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, PORT, USER, PASS, timeout=10, banner_timeout=10)

    # Open interactive shell
    chan = c.invoke_shell()
    chan.settimeout(timeout)

    def wait_for(prompt, t=5.0):
        buf = ""
        start = time.time()
        while time.time() - start < t:
            if chan.recv_ready():
                buf += chan.recv(4096).decode(errors="replace")
                if prompt in buf:
                    return buf
            time.sleep(0.1)
        return buf

    # Wait for initial prompt
    wait_for("$", 3)

    # su - root
    chan.send("su -\n")
    wait_for("Password:", 3)
    chan.send(f"{ROOT_PASS}\n")
    wait_for("#", 5)

    # Execute the command and mark end
    chan.send(f"{cmd}; echo __GR_END__=$?\n")

    out = ""
    while True:
        if chan.recv_ready():
            chunk = chan.recv(4096).decode(errors="replace")
            out += chunk
            if "__GR_END__=" in out:
                break
        else:
            time.sleep(0.1)

    # Extract rc
    idx = out.rfind("__GR_END__=")
    rc_str = out[idx + len("__GR_END__="):].split()[0]
    try:
        rc = int(rc_str)
    except ValueError:
        rc = -1

    # Clean output: strip the command echo and end marker
    out = out[:idx]
    # Remove shell echo of our command (starts right after the # prompt)
    lines = out.split("\n")
    # Filter out the command itself and empty prompt lines
    cleaned = []
    skip_first = True
    for line in lines:
        if skip_first and cmd[:20] in line:
            skip_first = False
            continue
        cleaned.append(line)
    print("\n".join(cleaned))

    c.close()
    return rc

if __name__ == "__main__":
    cmd = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "whoami"
    sys.exit(run_as_root(cmd))
