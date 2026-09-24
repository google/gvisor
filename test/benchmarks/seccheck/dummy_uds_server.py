#!/usr/bin/env python3
# Copyright 2026 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Dummy Unix Domain Socket server for benchmarking gVisor seccheck IPC overhead.

This script provides a SOCK_SEQPACKET UDS listener that performs the required
gVisor seccheck handshake and then immediately discards all incoming bytes.
It is an intentionally dumb endpoint designed exclusively to isolate
cross-boundary IPC transfer latency from agent-side parsing latency.
"""

import os
import socket

SOCK_PATH = "/tmp/seccheck.sock"
# Max bytes to pull per socket read. 65536 == 64 KB.
# A large chunk size minimizes Python loop/syscall overhead over UDS.
CHUNK_SIZE = 65536
if os.path.exists(SOCK_PATH):
  os.remove(SOCK_PATH)

s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
s.bind(SOCK_PATH)
s.listen(1)

print(f"Dummy UDS listener running on {SOCK_PATH} - ready for handshake...")

while True:
  try:
    conn, _ = s.accept()
    # gVisor sends a Handshake protobuf first. Read it.
    conn.recv(CHUNK_SIZE)
    # Reply with Handshake{Version: 1} so Sentry can boot
    # 0x08 is varint field 1 (version), 0x01 is value 1.
    conn.send(b"\x08\x01")
    print("Handshake acknowledged. Emptying socket...")
    while True:
      if not conn.recv(CHUNK_SIZE):
        break
  except KeyboardInterrupt:
    break
  except OSError:
    pass
