#!/usr/bin/env bash
set -euo pipefail
ROOT=/home/packer/connect-2-control-plane
gcc -O2 -I/usr/include/freetype2 -o /tmp/pty_record "$ROOT/scripts/pty_record.c" -lfreetype -lutil
mkdir -p "$ROOT/docs"
/tmp/pty_record "$ROOT/scripts/demo.sh" | ffmpeg -y -loglevel error \
  -f rawvideo -pix_fmt rgb24 -s 1280x720 -r 12 -i - \
  -c:v libx264 -pix_fmt yuv420p -crf 20 -movflags +faststart \
  "$ROOT/docs/demo.mp4"
ls -l "$ROOT/docs/demo.mp4"
