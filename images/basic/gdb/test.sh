#!/bin/sh

set -eu
cd /test
mkfifo /tmp/ready
./tracee > /tmp/ready &
tracee_pid=$!
trap 'kill "$tracee_pid" 2>/dev/null || true' EXIT
read -r ready < /tmp/ready
rm /tmp/ready
test "$ready" = ready
gdb --nx --batch ./tracee -ex "attach $tracee_pid" -x test.gdb
wait "$tracee_pid"
trap - EXIT
