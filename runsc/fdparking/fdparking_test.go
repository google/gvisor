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
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/abi/linux"
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
// of a stray inherited FD as the signal (as closing stray FDs runs last).
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
	if state := procStat(t, cmd.Process.Pid)[0]; state == "Z" {
		t.Fatalf("sidecar died during startup: %v", cmd.Wait())
	}
	return &parking{cmd: cmd, sandbox: sbx, ringR: ringR}
}

// procStat returns the fields of /proc/<pid>/stat that follow the
// parenthesized comm, i.e. the process state byte and beyond.
func procStat(t *testing.T, pid int) []string {
	t.Helper()
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		t.Fatalf("cannot read sidecar stat: %v", err)
	}
	return strings.Fields(string(stat[strings.LastIndexByte(string(stat), ')')+1:]))
}

// canSetMM reports whether the given process is allowed to call
// prctl(PR_SET_MM), which the kernel gates on CAP_SYS_RESOURCE.
func canSetMM(t *testing.T, pid int) bool {
	t.Helper()
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatalf("cannot read sidecar status: %v", err)
	}
	var eff uint64
	found := false
	for _, line := range strings.Split(string(status), "\n") {
		rest, ok := strings.CutPrefix(line, "CapEff:")
		if !ok {
			continue
		}
		if eff, err = strconv.ParseUint(strings.TrimSpace(rest), 16, 64); err != nil {
			t.Fatalf("cannot parse %q from sidecar status: %v", line, err)
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("no CapEff line in sidecar status:\n%s", status)
	}
	const capSysResource = 24
	if eff&(1<<capSysResource) == 0 {
		// A cleared effective bit settles it on its own.
		return false
	}
	// Check if we actually can call prctl(PR_SET_MM) in practice.
	switch err := unix.Prctl(unix.PR_SET_MM, unix.PR_SET_MM_ARG_START, ^uintptr(0), 0, 0); {
	case errors.Is(err, unix.EPERM):
		return false
	case errors.Is(err, unix.EINVAL):
		return true
	default:
		t.Fatalf("prctl(PR_SET_MM, PR_SET_MM_ARG_START, -1) returned %v, expected EPERM or EINVAL", err)
		return false
	}
}

// TestParking checks the fdparking sidecar's whole behavior: it
// keeps its inherited FDs open while the watched process runs, and exits
// (releasing them) once that process is gone.
func TestParking(t *testing.T) {
	p := startParking(t)
	pid := p.cmd.Process.Pid

	t.Run("unmaps as much memory as possible", func(t *testing.T) {
		maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
		if err != nil {
			t.Fatalf("cannot read sidecar maps: %v", err)
		}
		for _, mapping := range []string{"[stack]", "[vdso]", "[vvar]", "[vvar_vclock]"} {
			if strings.Contains(string(maps), mapping) {
				t.Errorf("sidecar did not unmap %s:\n%s", mapping, maps)
			}
		}
	})

	t.Run("still has readable cmdline", func(t *testing.T) {
		const wantCmdline = "runsc-fd-parking\x00"
		cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		switch {
		case err != nil:
			t.Errorf("cannot read sidecar cmdline: %v", err)
		case len(cmdline) == 0:
			if canSetMM(t, pid) {
				t.Fatalf("sidecar has no cmdline set despite having the ability to set it")
			}
			t.Logf("sidecar has no cmdline, as expected (`prctl(PR_SET_MM)` denied)")
		case string(cmdline) != wantCmdline:
			t.Errorf("sidecar cmdline is %q, expected %q", cmdline, wantCmdline)
		}
	})

	t.Run("scheduling policy", func(t *testing.T) {
		fields := procStat(t, pid)
		const policyField = 41
		if got, want := fields[policyField-3], fmt.Sprintf("%d", linux.SCHED_IDLE); got != want {
			t.Errorf("sidecar scheduling policy is %s, expected %s (SCHED_IDLE)", got, want)
		}
	})

	t.Run("ring is held open", func(t *testing.T) {
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
	})
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

// TestParkingBinaryLayout checks the layout of the sidecar binary for minimal
// number of loadable segments.
func TestParkingBinaryLayout(t *testing.T) {
	binary, err := elf.Open(parkingPath(t))
	if err != nil {
		t.Fatalf("cannot parse sidecar binary: %v", err)
	}
	defer binary.Close()

	var loads []*elf.Prog
	for _, prog := range binary.Progs {
		if prog.Type == elf.PT_LOAD {
			loads = append(loads, prog)
		}
	}
	want := []elf.ProgFlag{elf.PF_R | elf.PF_X, elf.PF_R | elf.PF_W}
	if len(loads) != len(want) {
		t.Fatalf("sidecar has %d loadable segments, expected %d (text and stack)", len(loads), len(want))
	}
	for i, load := range loads {
		if load.Flags != want[i] {
			t.Errorf("loadable segment %d at %#x is %v, expected %v", i, load.Vaddr, load.Flags, want[i])
		}
	}
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
		kb    int
	}{
		{"VmSize", 8}, // Two pages: text page, and .bss stack page.
		{"VmExe", 4},  // Text page.
		{"VmData", 4}, // .bss stack page.
		{"VmStk", 0},  // Original stack is unmapped.
		{"VmLib", 0},
		{"Threads", 1}, // Single-threaded of course.
	} {
		got, ok := status[want.field]
		if !ok {
			t.Errorf("%s missing from /proc/%d/status", want.field, pid)
			continue
		}
		if got != want.kb {
			t.Errorf("%s is %d, expected %d", want.field, got, want.kb)
		}
	}

	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		t.Fatalf("cannot read sidecar maps: %v", err)
	}
	// Ignore the [vsyscall] page.
	var mappings []string
	for _, mapping := range strings.Split(strings.TrimSpace(string(maps)), "\n") {
		if !strings.HasSuffix(mapping, "[vsyscall]") {
			mappings = append(mappings, mapping)
		}
	}
	if len(mappings) != 2 {
		t.Errorf("sidecar has %d mappings, expected exactly 2 (text and stack):\n%s", len(mappings), maps)
	}
}
