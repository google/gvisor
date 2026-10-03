// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sandboxsetup

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func openPath(t *testing.T, path string) int {
	t.Helper()
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open(%q, O_PATH): %v", path, err)
	}
	return fd
}

func isOpen(fd int) bool {
	_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	return err == nil
}

func TestCloseBootBinaryFDOwnExecutable(t *testing.T) {
	fd := openPath(t, "/proc/self/exe")
	if err := CloseBootBinaryFD(fd); err != nil {
		unix.Close(fd)
		t.Fatalf("CloseBootBinaryFD(own executable) = %v, want nil", err)
	}
	if isOpen(fd) {
		t.Errorf("FD %d is still open", fd)
	}
}

func TestCloseBootBinaryFDRejectsOtherFile(t *testing.T) {
	fd := openPath(t, os.DevNull)
	defer unix.Close(fd)
	if err := CloseBootBinaryFD(fd); err == nil {
		t.Fatalf("CloseBootBinaryFD(%s) = nil, want error", os.DevNull)
	}
	if !isOpen(fd) {
		t.Errorf("FD %d was closed despite not being this process's executable", fd)
	}
}

func TestCloseBootBinaryFDRejectsBadFD(t *testing.T) {
	if err := CloseBootBinaryFD(-1); err == nil {
		t.Fatalf("CloseBootBinaryFD(-1) = nil, want error")
	}
}
