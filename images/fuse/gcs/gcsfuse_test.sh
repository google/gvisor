#!/bin/bash
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

set -e

# Configurable bucket name via environment variable or argument
BUCKET=${GCS_BUCKET:-gvisor-fuse-test-bucket}
MOUNT_DIR="/mnt/gcs"

mkdir -p "$MOUNT_DIR"

echo "--- GCSFUSE COMPATIBILITY TEST ---"
echo "Bucket: gs://$BUCKET"
echo "Mount point: $MOUNT_DIR"

# gcsfuse flags for testing
# --implicit-dirs is needed for flat buckets to show simulated folders
echo "Mounting..."

gcsfuse -implicit-dirs --log-severity TRACE --foreground "$BUCKET" "$MOUNT_DIR" &
GCSFUSE_PID=$!

# Wait for mount to appear
echo "Waiting for mount..."
SUCCESS=0
for i in {1..20}; do
  if mountpoint -q "$MOUNT_DIR"; then
    echo "Mounted successfully!"
    SUCCESS=1
    break
  fi
  if ! kill -0 "$GCSFUSE_PID" 2>/dev/null; then
    echo "gcsfuse process died early."
    break
  fi
  sleep 1
done

if [[ "$SUCCESS" -ne 1 ]]; then
  echo "[FAIL] gcsfuse failed to mount the bucket."
  exit 1
fi

echo "Running supported file operations..."

TEST_FILE="$MOUNT_DIR/gvisor_test_$(date +%s)"
TEST_DIR="$MOUNT_DIR/testdir_$(date +%s)"

# 1. Directory Operations: mkdir / rmdir / readdir
echo "Testing mkdir..."
if mkdir "$TEST_DIR"; then
  echo "[OK]   Mkdir"
else
  echo "[FAIL] Mkdir"
fi

echo "Testing readdir (ls)..."
if ls "$MOUNT_DIR" | grep -q "testdir_"; then
  echo "[OK]   Readdir"
else
  echo "[FAIL] Readdir"
fi

# 2. File Creation and Basic I/O: creat / open / write / read
echo "Testing write..."
CONTENT="gvisor compatibility test $(date)"
if echo -n "$CONTENT" > "$TEST_FILE"; then
  echo "[OK]   Write"
else
  echo "[FAIL] Write"
fi

echo "Testing read..."
READBACK=$(cat "$TEST_FILE")
if [[ "$READBACK" == "$CONTENT" ]]; then
  echo "[OK]   Read"
else
  echo "[FAIL] Read (Mismatch: got '$READBACK', expected '$CONTENT')"
fi

# 3. File Attributes: stat / utimens / chmod / chown
echo "Testing stat (size)..."
FILE_SIZE=$(stat -c %s "$TEST_FILE")
EXPECTED_SIZE=${#CONTENT}
if [[ "$FILE_SIZE" -eq "$EXPECTED_SIZE" ]]; then
  echo "[OK]   Stat (Size)"
else
  echo "[FAIL] Stat (Size mismatch: expected $EXPECTED_SIZE, got $FILE_SIZE)"
fi

echo "Testing utimens (touch)..."
if touch "$TEST_FILE"; then
  echo "[OK]   Utimens (touch)"
else
  echo "[FAIL] Utimens (touch)"
fi

echo "Testing chmod (ignored but should not error)..."
if chmod 644 "$TEST_FILE"; then
  echo "[OK]   Chmod"
else
  echo "[FAIL] Chmod"
fi

echo "Testing chown (ignored but should not error)..."
if chown "$(id -u):$(id -g)" "$TEST_FILE"; then
  echo "[OK]   Chown"
else
  echo "[FAIL] Chown"
fi

# 4. File Modification: truncate / append
echo "Testing truncate..."
if truncate -s 10 "$TEST_FILE"; then
  TRUNCATED_SIZE=$(stat -c %s "$TEST_FILE")
  if [[ "$TRUNCATED_SIZE" -eq 10 ]]; then
    echo "[OK]   Truncate"
  else
    echo "[FAIL] Truncate (Size mismatch: expected 10, got $TRUNCATED_SIZE)"
  fi
else
  echo "[FAIL] Truncate"
fi

echo "Testing append..."
echo "append_content" >> "$TEST_FILE"
FINAL_SIZE=$(stat -c %s "$TEST_FILE")
if [[ "$FINAL_SIZE" -gt 10 ]]; then
  echo "[OK]   Append"
else
  echo "[FAIL] Append"
fi

# 5. Symbolic Links: symlink / readlink
echo "Testing symlink..."
LINK_FILE="$MOUNT_DIR/test_link_$(date +%s)"
if ln -s "$TEST_FILE" "$LINK_FILE"; then
  if [[ -L "$LINK_FILE" ]] && [[ "$(readlink "$LINK_FILE")" == "$TEST_FILE" ]]; then
    echo "[OK]   Symlink"
  else
    echo "[FAIL] Symlink (Creation succeeded but check failed)"
  fi
  rm "$LINK_FILE"
else
  echo "[FAIL] Symlink"
fi

# 6. Renaming: rename
echo "Testing rename (file)..."
RENAMED_FILE="$MOUNT_DIR/renamed_test_$(date +%s)"
if mv "$TEST_FILE" "$RENAMED_FILE"; then
  if [[ -f "$RENAMED_FILE" ]] && [[ ! -f "$TEST_FILE" ]]; then
    echo "[OK]   Rename (File)"
  else
    echo "[FAIL] Rename (MV succeeded but file state incorrect)"
  fi
  TEST_FILE=$RENAMED_FILE
else
  echo "[FAIL] Rename (File)"
fi

echo "Testing rename (directory)..."
RENAMED_DIR="$MOUNT_DIR/renamed_dir_$(date +%s)"
if mv "$TEST_DIR" "$RENAMED_DIR"; then
  if [[ -d "$RENAMED_DIR" ]] && [[ ! -d "$TEST_DIR" ]]; then
    echo "[OK]   Rename (Directory)"
  else
    echo "[FAIL] Rename (MV succeeded but dir state incorrect)"
  fi
  TEST_DIR=$RENAMED_DIR
else
  echo "[FAIL] Rename (Directory)"
fi

# 7. File System Info: statfs
echo "Testing statfs (df)..."
if df "$MOUNT_DIR" > /dev/null; then
  echo "[OK]   Statfs"
else
  echo "[FAIL] Statfs"
fi

# 8. Cleanup: unlink / rmdir
echo "Testing unlink (rm)..."
if rm "$TEST_FILE"; then
  echo "[OK]   Unlink"
else
  echo "[FAIL] Unlink"
fi

echo "Testing rmdir..."
if rmdir "$TEST_DIR"; then
  echo "[OK]   Rmdir"
else
  echo "[FAIL] Rmdir"
fi

echo "--- TEST COMPLETE ---"

cleanup() {
  echo "Cleaning up..."
  umount "$MOUNT_DIR" || true
  kill "$GCSFUSE_PID" 2>/dev/null || true
}
trap cleanup EXIT
sleep 2
