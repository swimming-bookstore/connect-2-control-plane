#!/usr/bin/env python3
"""Record docs/demo.mp4 from a real bash PTY running tsh."""

from __future__ import annotations

import fcntl
import os
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "demo.mp4"

# Glyph cells must fill the frame without wrapping the PTY.
SCALE = 2
CW, CH = 6 * SCALE, 10 * SCALE
PAD_X, PAD_Y = 32, 20
W, H, FPS = 1280, 720, 12
COLS = (W - 2 * PAD_X) // CW
ROWS = (H - 2 * PAD_Y) // CH
BG = (11, 18, 32)
PAL = [
    (11, 18, 32), (239, 68, 68), (52, 211, 153), (251, 191, 36),
    (56, 189, 248), (196, 181, 253), (34, 211, 238), (230, 237, 243),
    (100, 116, 139), (248, 113, 113), (110, 231, 183), (253, 224, 71),
    (125, 211, 252), (216, 180, 254), (103, 232, 249), (255, 255, 255),
]

COMMANDS = [
    "tsh login --proxy=127.0.0.1:4080 --user=admin --insecure",
    "tsh ls --insecure",
    "tsh ssh --insecure packer@agent-node echo hello-from-agent",
]

FONT: dict[str, list[int]] = {}
for _ch, _bits in {
    "A": [14, 17, 17, 31, 17, 17, 17], "B": [30, 17, 17, 30, 17, 17, 30],
    "C": [14, 17, 16, 16, 16, 17, 14], "D": [30, 17, 17, 17, 17, 17, 30],
    "E": [31, 16, 16, 30, 16, 16, 31], "F": [31, 16, 16, 30, 16, 16, 16],
    "G": [14, 17, 16, 23, 17, 17, 14], "H": [17, 17, 17, 31, 17, 17, 17],
    "I": [14, 4, 4, 4, 4, 4, 14], "J": [7, 2, 2, 2, 2, 18, 12],
    "K": [17, 18, 20, 24, 20, 18, 17], "L": [16, 16, 16, 16, 16, 16, 31],
    "M": [17, 27, 21, 21, 17, 17, 17], "N": [17, 25, 21, 19, 17, 17, 17],
    "O": [14, 17, 17, 17, 17, 17, 14], "P": [30, 17, 17, 30, 16, 16, 16],
    "Q": [14, 17, 17, 17, 21, 18, 13], "R": [30, 17, 17, 30, 20, 18, 17],
    "S": [15, 16, 16, 14, 1, 1, 30], "T": [31, 4, 4, 4, 4, 4, 4],
    "U": [17, 17, 17, 17, 17, 17, 14], "V": [17, 17, 17, 17, 17, 10, 4],
    "W": [17, 17, 17, 21, 21, 27, 17], "X": [17, 17, 10, 4, 10, 17, 17],
    "Y": [17, 17, 10, 4, 4, 4, 4], "Z": [31, 1, 2, 4, 8, 16, 31],
    "a": [0, 0, 14, 1, 15, 17, 15], "b": [16, 16, 30, 17, 17, 17, 30],
    "c": [0, 0, 14, 16, 16, 17, 14], "d": [1, 1, 15, 17, 17, 17, 15],
    "e": [0, 0, 14, 17, 31, 16, 14], "f": [6, 9, 8, 28, 8, 8, 8],
    "g": [0, 0, 15, 17, 15, 1, 14], "h": [16, 16, 30, 17, 17, 17, 17],
    "i": [4, 0, 12, 4, 4, 4, 14], "j": [2, 0, 6, 2, 2, 18, 12],
    "k": [16, 16, 18, 20, 24, 20, 18], "l": [12, 4, 4, 4, 4, 4, 14],
    "m": [0, 0, 26, 21, 21, 21, 21], "n": [0, 0, 30, 17, 17, 17, 17],
    "o": [0, 0, 14, 17, 17, 17, 14], "p": [0, 0, 30, 17, 30, 16, 16],
    "q": [0, 0, 15, 17, 15, 1, 1], "r": [0, 0, 22, 25, 16, 16, 16],
    "s": [0, 0, 15, 16, 14, 1, 30], "t": [8, 8, 28, 8, 8, 9, 6],
    "u": [0, 0, 17, 17, 17, 19, 13], "v": [0, 0, 17, 17, 17, 10, 4],
    "w": [0, 0, 17, 21, 21, 21, 10], "x": [0, 0, 17, 10, 4, 10, 17],
    "y": [0, 0, 17, 17, 15, 1, 14], "z": [0, 0, 31, 2, 4, 8, 31],
    "0": [14, 17, 19, 21, 25, 17, 14], "1": [4, 12, 4, 4, 4, 4, 14],
    "2": [14, 17, 1, 2, 4, 8, 31], "3": [31, 2, 4, 2, 1, 17, 14],
    "4": [2, 6, 10, 18, 31, 2, 2], "5": [31, 16, 30, 1, 1, 17, 14],
    "6": [6, 8, 16, 30, 17, 17, 14], "7": [31, 1, 2, 4, 8, 8, 8],
    "8": [14, 17, 17, 14, 17, 17, 14], "9": [14, 17, 17, 15, 1, 2, 12],
    " ": [0, 0, 0, 0, 0, 0, 0], ".": [0, 0, 0, 0, 0, 4, 4],
    ",": [0, 0, 0, 0, 4, 4, 8], ":": [0, 4, 4, 0, 4, 4, 0],
    "-": [0, 0, 0, 31, 0, 0, 0], "_": [0, 0, 0, 0, 0, 0, 31],
    "/": [1, 2, 2, 4, 8, 8, 16], "\\": [16, 8, 8, 4, 2, 2, 1],
    "|": [4, 4, 4, 4, 4, 4, 4], ">": [8, 4, 2, 1, 2, 4, 8],
    "<": [2, 4, 8, 16, 8, 4, 2], "+": [0, 4, 4, 31, 4, 4, 0],
    "=": [0, 0, 31, 0, 31, 0, 0], "!": [4, 4, 4, 4, 4, 0, 4],
    "?": [14, 17, 1, 2, 4, 0, 4], "*": [0, 21, 14, 31, 14, 21, 0],
    "@": [14, 17, 23, 21, 23, 16, 14], "%": [25, 26, 2, 4, 8, 11, 19],
    "(": [2, 4, 8, 8, 8, 4, 2], ")": [8, 4, 2, 2, 2, 4, 8],
    "[": [14, 8, 8, 8, 8, 8, 14], "]": [14, 2, 2, 2, 2, 2, 14],
    '"': [10, 10, 10, 0, 0, 0, 0], "'": [4, 4, 4, 0, 0, 0, 0],
    "`": [8, 4, 0, 0, 0, 0, 0], "#": [10, 31, 10, 10, 31, 10, 0],
    "&": [12, 18, 20, 8, 21, 18, 13], "$": [4, 15, 20, 14, 5, 30, 4],
    "^": [4, 10, 17, 0, 0, 0, 0], "~": [0, 0, 9, 22, 0, 0, 0],
    "{": [6, 4, 4, 8, 4, 4, 6], "}": [12, 4, 4, 2, 4, 4, 12],
}.items():
    FONT[_ch] = _bits


class Screen:
    def __init__(self) -> None:
        self.reset()
        self.esc: bytes | None = None

    def reset(self) -> None:
        self.ch = [[" "] * COLS for _ in range(ROWS)]
        self.fg = [[7] * COLS for _ in range(ROWS)]
        self.r = self.c = 0
        self.color = 7
        self.bold = 0

    def scroll(self) -> None:
        self.ch.pop(0)
        self.fg.pop(0)
        self.ch.append([" "] * COLS)
        self.fg.append([7] * COLS)

    def put(self, ch: str) -> None:
        if ch == "\r":
            self.c = 0
            return
        if ch == "\n":
            self.c = 0
            self.r += 1
            if self.r >= ROWS:
                self.r = ROWS - 1
                self.scroll()
            return
        if ch == "\b":
            self.c = max(0, self.c - 1)
            return
        if ch == "\t":
            self.c = min(COLS - 1, (self.c + 8) & ~7)
            return
        if ord(ch) < 32:
            return
        if self.c >= COLS:
            self.c = 0
            self.r += 1
            if self.r >= ROWS:
                self.r = ROWS - 1
                self.scroll()
        self.ch[self.r][self.c] = ch
        self.fg[self.r][self.c] = (8 if self.bold else 0) | (self.color & 7)
        self.c += 1

    def csi(self, body: str, cmd: str) -> None:
        parts = [p for p in body.replace("?", "").split(";") if p != ""]
        args = [int(p) for p in parts] if parts else []
        if cmd == "m":
            for v in args or [0]:
                if v == 0:
                    self.color, self.bold = 7, 0
                elif v == 1:
                    self.bold = 1
                elif v == 22:
                    self.bold = 0
                elif 30 <= v <= 37:
                    self.color = v - 30
                elif 90 <= v <= 97:
                    self.color, self.bold = v - 90, 1
                elif v == 39:
                    self.color = 7
        elif cmd in ("H", "f"):
            self.r = max(0, min(ROWS - 1, (args[0] - 1) if args else 0))
            self.c = max(0, min(COLS - 1, (args[1] - 1) if len(args) > 1 else 0))
        elif cmd == "J" and (not args or args[0] in (2, 3)):
            self.reset()
        elif cmd == "K":
            for c in range(self.c, COLS):
                self.ch[self.r][c] = " "
                self.fg[self.r][c] = 7
        elif cmd == "C":
            self.c = min(COLS - 1, self.c + (args[0] if args else 1))
        elif cmd == "D":
            self.c = max(0, self.c - (args[0] if args else 1))
        elif cmd == "A":
            self.r = max(0, self.r - (args[0] if args else 1))
        elif cmd == "B":
            self.r = min(ROWS - 1, self.r + (args[0] if args else 1))

    def feed(self, data: bytes) -> None:
        buf = (self.esc or b"") + data
        self.esc = None
        i, n = 0, len(buf)
        while i < n:
            b = buf[i]
            if b != 0x1B:
                self.put(chr(b) if b < 128 else "?")
                i += 1
                continue
            if i + 1 >= n:
                self.esc = buf[i:]
                return
            nxt = buf[i + 1]
            if nxt == ord("["):
                j = i + 2
                while j < n and not (0x40 <= buf[j] < 0x7F):
                    j += 1
                if j >= n:
                    self.esc = buf[i:]
                    return
                self.csi(buf[i + 2:j].decode("latin1", "ignore"), chr(buf[j]))
                i = j + 1
                continue
            if nxt == ord("]"):
                j = i + 2
                while j < n:
                    if buf[j] == 7:
                        j += 1
                        break
                    if buf[j] == 0x1B:
                        if j + 1 >= n:
                            self.esc = buf[i:]
                            return
                        if buf[j + 1] == ord("\\"):
                            j += 2
                            break
                    j += 1
                else:
                    self.esc = buf[i:]
                    return
                i = j
                continue
            if nxt == ord("\\"):
                i += 2
                continue
            i += 2

    def lines(self) -> list[str]:
        return ["".join(row).rstrip() for row in self.ch]

    def at_prompt(self) -> bool:
        line = "".join(self.ch[self.r]).rstrip()
        return line in ("$", "$ ")


def fill_bg(frame: bytearray) -> None:
    r, g, b = BG
    frame[:] = bytes((r, g, b)) * W * H


def draw(screen: Screen, frame: bytearray) -> None:
    fill_bg(frame)
    for r in range(ROWS):
        for c in range(COLS):
            ch = screen.ch[r][c]
            if ch == " ":
                continue
            bits = FONT.get(ch) or FONT.get(ch.upper(), [0] * 7)
            rgb = PAL[screen.fg[r][c] & 15]
            x0 = PAD_X + c * CW
            y0 = PAD_Y + r * CH
            for rr, rowbits in enumerate(bits):
                for cc in range(5):
                    if rowbits & (1 << (4 - cc)):
                        for dy in range(SCALE):
                            py = y0 + rr * SCALE + dy
                            if py < 0 or py >= H:
                                continue
                            base = py * W
                            for dx in range(SCALE):
                                px = x0 + cc * SCALE + dx
                                if 0 <= px < W:
                                    i = (base + px) * 3
                                    frame[i], frame[i + 1], frame[i + 2] = rgb


def spawn_bash() -> tuple[int, int]:
    pid, fd = pty.fork()
    if pid == 0:
        fcntl.ioctl(1, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
        os.environ.clear()
        os.environ.update({
            "PATH": "/tmp/tp/teleport:/usr/bin:/bin",
            "HOME": "/tmp/c2cp-demo-home",
            "TELEPORT_HOME": "/tmp/c2cp-demo-home/.tsh",
            "TERM": "xterm-256color",
            "PS1": "$ ",
            "PROMPT_COMMAND": "",
            "HISTFILE": "/dev/null",
            "LANG": "C.UTF-8",
            "COLUMNS": str(COLS),
            "LINES": str(ROWS),
        })
        os.makedirs("/tmp/c2cp-demo-home/.tsh", exist_ok=True)
        os.chdir("/tmp")
        os.execv("/bin/bash", ["bash", "--norc", "--noprofile"])
    fcntl.fcntl(fd, fcntl.F_SETFL, os.O_NONBLOCK)
    return pid, fd


def maybe_password(fd: int, chunk: bytes, sent: list[bool]) -> None:
    if b"]11;" in chunk:
        os.write(fd, b"\033]11;rgb:0b0b/1212/2020\007")
    if b"6n" in chunk:
        os.write(fd, b"\033[1;1R")
    if not sent[0] and b"password" in chunk.lower():
        time.sleep(0.15)
        os.write(fd, b"adminadmin\n")
        sent[0] = True


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    os.makedirs("/tmp/c2cp-demo-home/.tsh", exist_ok=True)
    screen = Screen()
    frame = bytearray(W * H * 3)
    pid, fd = spawn_bash()
    sent = [False]
    ff = subprocess.Popen(
        [
            "ffmpeg", "-y", "-loglevel", "error",
            "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{W}x{H}", "-r", str(FPS),
            "-i", "-", "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "20",
            "-movflags", "+faststart", str(OUT),
        ],
        stdin=subprocess.PIPE,
    )
    assert ff.stdin is not None

    cmd_i = 0
    typed = 0
    typing = False
    finishing = False
    last_out = time.time()
    next_type = 0.0
    next_frame = time.time()
    deadline = time.time() + 24.0
    child_done = False
    started = False

    try:
        while time.time() < deadline:
            timeout = max(0.0, next_frame - time.time())
            ready, _, _ = select.select([fd], [], [], min(0.02, timeout))
            if ready:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    chunk = b""
                if not chunk:
                    child_done = True
                else:
                    screen.feed(chunk)
                    maybe_password(fd, chunk, sent)
                    last_out = time.time()
                    started = True
            if not child_done:
                wpid, _ = os.waitpid(pid, os.WNOHANG)
                if wpid == pid:
                    child_done = True

            now = time.time()
            idle = started and (now - last_out) > 0.35 and screen.at_prompt()
            if not typing and not finishing and idle:
                if cmd_i < len(COMMANDS):
                    typing = True
                    typed = 0
                    next_type = now + 0.12
                else:
                    finishing = True
                    next_type = now + 0.7

            if typing and now >= next_type:
                cmd = COMMANDS[cmd_i]
                if typed < len(cmd):
                    os.write(fd, cmd[typed].encode())
                    typed += 1
                    next_type = now + 0.018
                else:
                    os.write(fd, b"\n")
                    typing = False
                    cmd_i += 1
                    last_out = now

            if finishing and now >= next_type:
                os.write(fd, b"exit\n")
                finishing = False

            if now >= next_frame:
                draw(screen, frame)
                ff.stdin.write(frame)
                next_frame += 1.0 / FPS
                if now > next_frame + 0.2:
                    next_frame = now
            if child_done and now > next_frame + 0.3:
                break
    finally:
        Path("/tmp/pty_screen.txt").write_text("\n".join(screen.lines()) + "\n")
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
        ff.stdin.close()
        ff.wait()
    print(OUT, OUT.stat().st_size)
    return 0


if __name__ == "__main__":
    sys.exit(main())
