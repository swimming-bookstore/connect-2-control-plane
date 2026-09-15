#!/usr/bin/env bash
# Live tsh walkthrough in a real shell (typed, executed).
set -u
export PATH="/tmp/tp/teleport:/usr/bin:/bin"
export HOME=/tmp/c2cp-demo-home
export TELEPORT_HOME=/tmp/c2cp-demo-home/.tsh
export TERM=xterm-256color
mkdir -p "$TELEPORT_HOME"
cd /tmp
unset PROMPT_COMMAND
PS1=''

slow_type() {
  local s="$1"
  local i
  printf '\033[32m$\033[0m '
  sleep 0.08
  for ((i = 0; i < ${#s}; i++)); do
    printf '%s' "${s:i:1}"
    sleep 0.014
  done
  echo
  sleep 0.04
}

printf '\033[2J\033[H'
sleep 0.08

slow_type "tsh login --proxy=127.0.0.1:4080 --user=admin --auth=local --insecure"
tsh login --proxy=127.0.0.1:4080 --user=admin --auth=local --insecure
echo
sleep 0.25

slow_type "tsh ls --insecure"
tsh ls --insecure
echo
sleep 0.25

slow_type "tsh ssh --insecure packer@agent-node -- echo hello-from-agent"
tsh ssh --insecure packer@agent-node -- echo hello-from-agent
echo
sleep 0.8
