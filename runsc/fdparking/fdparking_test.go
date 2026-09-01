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

package fdparking_test

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/test/testutil"
)

// childEnv is used to signal that this test binary is running as a child that
// does nothing. Used in the tests below.
const childEnv = "FDPARKING_TEST_CHILD"

func TestMain(m *testing.M) {
	if os.Getenv(childEnv) != "" {
		// Block until the parent closes our stdin, or kills.
		io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func parkingPath(t *testing.T) string {
	t.Helper()
	path, err := testutil.FindFile("runsc/fdparking/runsc-fd-parking")
	if err != nil {
		t.Fatalf("cannot find runsc-fd-parking binary: %v", err)
	}
	return path
}

// parking is a running sidecar under test.
type parking struct {
	cmd     *exec.Cmd // The sidecar itself.
	sandbox *exec.Cmd // The stand-in watched "sandbox" process.
	ringR   *os.File  // Ring stand-in read end; sees EOF once the sidecar exits.
}

// startParking starts the sidecar watching a stand-in sandbox process
// and blocks until the sidecar's deferred work is finished, using the closing
// of a stray inherited FD as the signal (as `close_range` runs last).
func startParking(t *testing.T) *parking {
	t.Helper()
	sbx := exec.Command(os.Args[0])
	sbx.Env = append(os.Environ(), childEnv+"=1")
	stdin, err := sbx.StdinPipe()
	if err != nil {
		t.Fatalf("cannot create sandbox stand-in stdin pipe: %v", err)
	}
	if err := sbx.Start(); err != nil {
		t.Fatalf("cannot start sandbox stand-in: %v", err)
	}
	t.Cleanup(func() {
		sbx.Process.Kill()
		sbx.Wait()
		stdin.Close()
	})

	pidfd, err := unix.PidfdOpen(sbx.Process.Pid, 0)
	if err != nil {
		t.Fatalf("pidfd_open(%d): %v", sbx.Process.Pid, err)
	}
	pidfdFile := os.NewFile(uintptr(pidfd), "sandbox pidfd")
	defer pidfdFile.Close()

	// A pipe write end stands in for the pin ring: its read end sees EOF
	// exactly when the last write-end reference is dropped.
	ringR, ringW, err := os.Pipe()
	if err != nil {
		t.Fatalf("cannot create ring stand-in pipe: %v", err)
	}
	t.Cleanup(func() { ringR.Close() })
	// A second pipe stands in for a stray FD leaked into the sidecar; it must
	// be closed at sidecar startup, not held until the watched process exits.
	strayR, strayW, err := os.Pipe()
	if err != nil {
		t.Fatalf("cannot create stray pipe: %v", err)
	}
	t.Cleanup(func() { strayR.Close() })

	cmd := exec.Command(parkingPath(t))
	// ExtraFiles land at FD 3 (pidfd) and FD 4 (ring), per the contract; the
	// stray lands at FD 5.
	cmd.ExtraFiles = []*os.File{pidfdFile, ringW, strayW}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("cannot start sidecar: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	ringW.Close()
	strayW.Close()

	strayR.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := strayR.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("sidecar did not finish startup (stray FD still open): read error is %v, expected EOF", err)
	}
	return &parking{cmd: cmd, sandbox: sbx, ringR: ringR}
}

// TestParking checks the fdparking sidecar's whole behavior: it
// keeps its inherited FDs open while the watched process runs, and exits
// (releasing them) once that process is gone.
func TestParking(t *testing.T) {
	p := startParking(t)
	pid := p.cmd.Process.Pid

	// Deferred startup is done (startParking waited for it), so the sidecar
	// must have unmapped its original stack and the vdso by now. Only applies
	// on 4KiB page kernels; the sidecar skips the unmapping elsewhere.
	if os.Getpagesize() == 4096 {
		maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
		if err != nil {
			t.Fatalf("cannot read sidecar maps: %v", err)
		}
		for _, mapping := range []string{"[stack]", "[vdso]", "[vvar]"} {
			if strings.Contains(string(maps), mapping) {
				t.Errorf("sidecar did not unmap %s:\n%s", mapping, maps)
			}
		}
	}

	// The sidecar must run as SCHED_IDLE, so that it never competes with
	// sandbox startup for CPU.
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		t.Fatalf("cannot read sidecar stat: %v", err)
	}
	// Fields after the parenthesized comm; fields[0] is stat field 3.
	fields := strings.Fields(string(stat[strings.LastIndexByte(string(stat), ')')+1:]))
	const policyField = 41
	if got, want := fields[policyField-3], "5"; /* SCHED_IDLE */ got != want {
		t.Errorf("sidecar scheduling policy is %s, expected %s (SCHED_IDLE)", got, want)
	}

	// While the watched process is alive, the sidecar must keep the ring open:
	// no EOF on the read end.
	p.ringR.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := p.ringR.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ring was released while the watched process was still alive: read error is %v, expected deadline exceeded", err)
	}

	if err := p.sandbox.Process.Kill(); err != nil {
		t.Fatalf("cannot kill sandbox stand-in: %v", err)
	}
	p.sandbox.Wait()

	// The sidecar must now exit, dropping the last ring reference.
	p.ringR.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := p.ringR.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("ring was not released after the watched process exited: read error is %v, expected EOF", err)
	}
	if err := p.cmd.Wait(); err != nil {
		t.Errorf("sidecar did not exit cleanly: %v", err)
	}
}

// procStatus returns the integer fields of /proc/<pid>/status (kB for Vm*).
func procStatus(t *testing.T, pid int) map[string]int {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatalf("cannot read sidecar status: %v", err)
	}
	fields := make(map[string]int)
	for _, line := range strings.Split(string(data), "\n") {
		key, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		val := strings.Fields(rest)
		if len(val) == 0 {
			continue
		}
		if n, err := strconv.Atoi(val[0]); err == nil {
			fields[key] = n
		}
	}
	return fields
}

// TestParkingMemoryFootprint verifies the sidecar's exact post-startup
// memory numbers. Every chunk of process memory is precisely accounted for,
// thank you very much.
func TestParkingMemoryFootprint(t *testing.T) {
	if os.Getpagesize() != 4096 {
		t.Skipf("the sidecar only self-minimizes on 4KiB-page kernels but current page size is %d", os.Getpagesize())
	}
	pid := startParking(t).cmd.Process.Pid

	status := procStatus(t, pid)
	for _, want := range []struct {
		field string
		kb    []int // Acceptable values in KiB
	}{
		{"VmSize", []int{8}},  // Two pages: Text page, and .bss stack page.
		{"VmRSS", []int{8}},   // Both pages necessarily resident.
		{"RssFile", []int{4}}, // Text page.
		{"RssAnon", []int{4}}, // .bss stack page.
		{"RssShmem", []int{0}},
		{"VmExe", []int{4}},
		{"VmData", []int{4}},
		{"VmStk", []int{0}}, // Original stack is unmapped.
		{"VmLib", []int{0}},
		{"Threads", []int{1}}, // Single-threaded of course.
	} {
		got, ok := status[want.field]
		if !ok {
			t.Errorf("%s missing from /proc/%d/status", want.field, pid)
			continue
		}
		if !slices.Contains(want.kb, got) {
			t.Errorf("%s is %d, expected one of %v", want.field, got, want.kb)
		}
	}

	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		t.Fatalf("cannot read sidecar maps: %v", err)
	}
	if got := strings.Count(string(maps), "\n"); got != 2 {
		t.Errorf("sidecar has %d mappings, expected exactly 2 (text and stack):\n%s", got, maps)
	}
}
