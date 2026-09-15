#!/usr/bin/env python3
"""Drive a live tsh session for the demo recorder."""

from __future__ import annotations

import os
import sys
import time

os.environ["PATH"] = "/tmp/tp/teleport:/usr/bin:/bin"
os.environ["HOME"] = "/tmp/c2cp-demo-home"
os.environ["TELEPORT_HOME"] = "/tmp/c2cp-demo-home/.tsh"
os.environ["TERM"] = "xterm-256color"
os.makedirs("/tmp/c2cp-demo-home/.tsh", exist_ok=True)
os.chdir("/tmp")


def type_line(s: str) -> None:
    sys.stdout.write("\033[32m$\033[0m ")
    sys.stdout.flush()
    time.sleep(0.08)
    for ch in s:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(0.014)
    sys.stdout.write("\n")
    sys.stdout.flush()


def run(cmd: str) -> None:
    type_line(cmd)
    os.system(cmd)
    sys.stdout.write("\n")
    sys.stdout.flush()
    time.sleep(0.25)


sys.stdout.write("\033[2J\033[H")
sys.stdout.flush()
time.sleep(0.08)
run("tsh login --proxy=127.0.0.1:4080 --user=admin --auth=local --insecure")
run("tsh ls --insecure")
run("tsh ssh --insecure packer@agent-node -- echo hello-from-agent")
time.sleep(0.8)
