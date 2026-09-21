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

package fsgofer_test

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/runsc/fsgofer"
)

// These tests cover the late-bind scenario of gvisor.dev/issue/14854: the host
// places a mount on the path of a mount that the gofer already serves, for
// example an emptyDir configured with
// dev.gvisor.empty-dir.<vol>.force-shared in a pod that mounts it with
// mountPropagation: HostToContainer. The mount event is propagated into the
// gofer's mount namespace (runsc/cmd/sandboxsetup makes it a slave of the
// host's) and is placed on top of the mount that the gofer serves, so the mount
// point path of the serving connection resolves to a different mount than the
// one that was opened when the connection was mounted. The gofer must serve the
// mount that its path resolves to now; otherwise every operation on the mount
// point observes a tree that the sandbox can no longer reach.
//
// The test runs the real fsgofer lisafs implementation in a mount namespace of
// its own (spawned with CLONE_NEWNS, as runsc does for the gofer process),
// while the test process plays the host: it owns the shared mount tree that
// holds the mount source, and places mounts on the source path after the gofer
// started serving it.
//
// All checks are made through the lisafs protocol against the gofer, and the
// expectations are inode numbers, file contents, sizes and modes taken from the
// host, so that a check can only pass if the gofer observed the mount that the
// host placed. The tests also validate the scenario they depend on (the mount
// point path resolves to a different mount, otherwise the checks would prove
// nothing).
//
// Coverage notes: SetStat, the xattr family, StatFS on the mount point and the
// writable-FD path are covered by TestMountPointFollowsLateMountFile, whose
// mount point is a regular file (mounting a file over a directory mount point,
// or the reverse, is rejected by the kernel with ENOTDIR). Readlink on a mount
// point is not covered: a mount point that is a symlink cannot be produced by a
// bind mount (mount(2) follows the symlink). BindAt and Connect on a mount
// point are not covered: they need a host UDS policy that the other checks do
// not require. The fallback that serves the FD that the mount was served with
// when the mount point path cannot be resolved is not covered either: the only
// way to make the path unresolvable is to move or remove the mount point, and
// Linux rejects renaming a mount point (EBUSY) and removing one.

const (
	// goferEnv marks the child process that runs the gofer side of the test.
	goferEnv = "FSGOFER_LATE_BIND_GOFER"
	// modeEnv selects what the gofer side does: "checks" or "stress".
	modeEnv = "FSGOFER_LATE_BIND_MODE"

	baseEnv         = "FSGOFER_LATE_BIND_BASE"
	oldDirInoEnv    = "FSGOFER_LATE_BIND_OLD_DIR_INO"
	newDirInoEnv    = "FSGOFER_LATE_BIND_NEW_DIR_INO"
	markerInoEnv    = "FSGOFER_LATE_BIND_MARKER_INO"
	auxEnv          = "FSGOFER_LATE_BIND_AUX_FILE"
	fileInoEnv      = "FSGOFER_LATE_BIND_FILE_INO"
	fileTypeEnv     = "FSGOFER_LATE_BIND_FILE_TYPE"
	stressMillisEnv = "FSGOFER_LATE_BIND_STRESS_MS"

	markerName = "marker.txt"
	// fileContent is written to the file that the host mounts over the mount
	// source in the last phase.
	fileContent = "aux"
)

// capSysAdmin is CAP_SYS_ADMIN, as defined in include/uapi/linux/capability.h.
const capSysAdmin = 21

func TestMain(m *testing.M) {
	if os.Getenv(goferEnv) == "1" {
		// This process is the gofer: it runs in its own mount namespace and
		// serves the mount that the parent, playing the host, will overmount.
		os.Exit(runGoferSide())
	}
	// Mounting a filesystem and creating mount namespaces require CAP_SYS_ADMIN.
	if err := ensureMountCapabilities(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running as root: %v\n", err)
		os.Exit(123)
	}
	os.Exit(m.Run())
}

// ensureMountCapabilities re-executes this test binary as root in a new user
// and mount namespace when this process does not have CAP_SYS_ADMIN, so that
// the tests can create mount namespaces and mount filesystems. It does not
// return when it re-executes.
//
// This is the re-execution that runsc/specutils.MaybeRunAsRoot() performs for
// tests that need a sandbox. It is kept local so that these tests do not depend
// on the sentry's generated protobuf packages, and can be built and run without
// a bazel build.
func ensureMountCapabilities() error {
	if hasCapSysAdmin() {
		return nil
	}
	cmd := exec.Command("/proc/self/exe", os.Args[1:]...)
	cmd.SysProcAttr = &unix.SysProcAttr{
		Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		Credential:                 &syscall.Credential{Uid: 0, Gid: 0},
		GidMappingsEnableSetgroups: false,
		Pdeathsig:                  unix.SIGKILL,
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		os.Exit(ee.ExitCode())
	}
	if err != nil {
		return err
	}
	os.Exit(0)
	return nil
}

// hasCapSysAdmin reports whether this process has CAP_SYS_ADMIN in its
// effective capability set.
func hasCapSysAdmin() bool {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		rest, ok := strings.CutPrefix(line, "CapEff:")
		if !ok {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(rest), 16, 64)
		if err != nil {
			return false
		}
		return v&(1<<capSysAdmin) != 0
	}
	return false
}

// sharedTree is the host-side mount tree: a tmpfs that holds the mount source,
// the directory that is mounted over it once the gofer is serving, and the
// directory that the gofer serves, plus a file on the host's root filesystem
// that is mounted over the mount source in the last phase (its filesystem
// differs from the tmpfs, so StatFS on the mount point becomes discriminating).
type sharedTree struct {
	base string
	src  string
	sub  string
	dst  string
	aux  string
}

func setupSharedTree(t *testing.T) *sharedTree {
	t.Helper()
	baseDir, err := os.MkdirTemp(os.Getenv("TEST_TMPDIR"), "latebind")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	tree := &sharedTree{
		base: filepath.Join(baseDir, "mnt"),
		aux:  filepath.Join(baseDir, "aux-file"),
	}
	tree.src = filepath.Join(tree.base, "src")
	tree.sub = filepath.Join(tree.base, "sub")
	tree.dst = filepath.Join(tree.base, "dst")

	if err := os.MkdirAll(tree.base, 0777); err != nil {
		t.Fatalf("MkdirAll(%q): %v", tree.base, err)
	}
	if err := unix.Mount("tmpfs", tree.base, "tmpfs", 0, ""); err != nil {
		if err == unix.EPERM || err == unix.EACCES {
			// This environment does not permit mounting (the test re-executes
			// itself in a user namespace for that reason, which can also be
			// disabled).
			t.Skipf("mounting is not permitted in this environment: %v", err)
		}
		t.Fatalf("mount tmpfs at %q: %v", tree.base, err)
	}
	for _, d := range []string{tree.src, tree.sub, tree.dst} {
		if err := os.MkdirAll(d, 0777); err != nil {
			t.Fatalf("MkdirAll(%q): %v", d, err)
		}
	}
	if err := os.WriteFile(filepath.Join(tree.sub, markerName), []byte("hello"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(tree.aux, []byte(fileContent), 0644); err != nil {
		t.Fatalf("WriteFile(%q): %v", tree.aux, err)
	}
	// The mount source must be on a shared mount, so that mount events under it
	// are propagated to the mounts that are slaves of it: the mount in the
	// gofer's namespace.
	if err := unix.Mount("", tree.base, "", unix.MS_SHARED|unix.MS_REC, ""); err != nil {
		t.Fatalf("make %q shared: %v", tree.base, err)
	}
	t.Cleanup(func() {
		// The test may have left mounts on the source path; unmount them before
		// the tmpfs that contains it.
		drainMounts(t, tree.src)
		if err := unix.Unmount(tree.base, 0); err != nil {
			t.Errorf("unmount %q: %v", tree.base, err)
		}
		if err := os.RemoveAll(baseDir); err != nil {
			t.Errorf("RemoveAll(%q): %v", baseDir, err)
		}
	})
	return tree
}

// bindOverSource places what is at from over the mount source. Inside the
// gofer's mount namespace this is placed on top of the mount that the gofer
// serves.
func bindOverSource(t *testing.T, from, src string) {
	t.Helper()
	if err := unix.Mount(from, src, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("mount %q over %q: %v", from, src, err)
	}
}

// drainMounts unmounts everything that is mounted at path. Mounts can stack
// (a mount can be placed over a mount), so more than one unmount may be needed.
func drainMounts(t *testing.T, path string) {
	t.Helper()
	for range 50 {
		switch err := unix.Unmount(path, 0); err {
		case nil:
			// Keep going: another mount may be underneath.
		case unix.EINVAL, unix.ENOENT:
			return
		default:
			// The mount may be busy until the process serving it is done.
			time.Sleep(10 * time.Millisecond)
		}
	}
	t.Errorf("could not unmount the mounts at %q", path)
}

func inoOf(t *testing.T, path string) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatalf("stat(%q): %v", path, err)
	}
	return st.Ino
}

func modeOf(t *testing.T, path string) uint32 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatalf("stat(%q): %v", path, err)
	}
	return uint32(st.Mode)
}

func sizeOf(t *testing.T, path string) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatalf("stat(%q): %v", path, err)
	}
	return uint64(st.Size)
}

func fileTypeOf(t *testing.T, path string) uint32 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatalf("stat(%q): %v", path, err)
	}
	return uint32(st.Mode) & unix.S_IFMT
}

// startGofer starts the gofer side of the test in a mount namespace of its own.
// This is how runsc starts the gofer process:
// runsc/container.createGoferProcess sets CLONE_NEWNS.
func startGofer(t *testing.T, tree *sharedTree, mode string, stressMillis int) (childOut *bufio.Reader, stdin *bufio.Writer, child *exec.Cmd) {
	t.Helper()
	cmd := exec.Command("/proc/self/exe")
	cmd.Env = append(os.Environ(),
		goferEnv+"=1",
		modeEnv+"="+mode,
		baseEnv+"="+tree.base,
		oldDirInoEnv+"="+strconv.FormatUint(inoOf(t, tree.src), 10),
		newDirInoEnv+"="+strconv.FormatUint(inoOf(t, tree.sub), 10),
		markerInoEnv+"="+strconv.FormatUint(inoOf(t, filepath.Join(tree.sub, markerName)), 10),
		auxEnv+"="+tree.aux,
		fileInoEnv+"="+strconv.FormatUint(inoOf(t, tree.aux), 10),
		fileTypeEnv+"="+strconv.FormatUint(uint64(fileTypeOf(t, tree.aux)), 10),
		stressMillisEnv+"="+strconv.Itoa(stressMillis),
	)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the gofer process with CLONE_NEWNS: %v", err)
	}
	// The gofer must be gone before the mount tree is torn down, or its host FDs
	// keep the mounts busy. This cleanup runs before setupSharedTree's cleanup
	// (cleanups run in reverse order).
	t.Cleanup(func() {
		_ = in.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})
	childOut = bufio.NewReader(out)
	stdin = bufio.NewWriter(in)
	// The gofer reports the state of the mount tree that it serves, and the
	// mount events that it received, until it is ready for the late mount.
	waitForGoferLine(t, childOut, "ready")
	return childOut, stdin, cmd
}

// signal sends a command to the gofer side.
func signal(t *testing.T, stdin *bufio.Writer, msg string) {
	t.Helper()
	if _, err := stdin.WriteString(msg + "\n"); err != nil {
		t.Fatalf("signaling the gofer: %v", err)
	}
	if err := stdin.Flush(); err != nil {
		t.Fatalf("flushing to the gofer: %v", err)
	}
}

// waitForGoferLine reads the gofer's output until it prints the given line.
func waitForGoferLine(t *testing.T, childOut *bufio.Reader, want string) {
	t.Helper()
	for {
		line, err := childOut.ReadString('\n')
		if err != nil {
			t.Fatalf("waiting for %q from the gofer: %v", want, err)
		}
		line = strings.TrimSpace(line)
		if line == want {
			return
		}
		t.Logf("gofer: %s", line)
	}
}

// collectGoferOutput reads the gofer's report and fails the test for every
// failed check and for a non-zero failure count.
func collectGoferOutput(t *testing.T, childOut *bufio.Reader) {
	t.Helper()
	sawDone := false
	for {
		line, err := childOut.ReadString('\n')
		line = strings.TrimSpace(line)
		if line != "" {
			switch {
			case strings.HasPrefix(line, "FAIL:"):
				t.Errorf("gofer: %s", line)
			case strings.HasPrefix(line, "PASS:"):
				t.Logf("gofer: %s", line)
			case strings.HasPrefix(line, "DONE "):
				sawDone = true
				if n, _ := strconv.Atoi(strings.TrimPrefix(line, "DONE ")); n != 0 {
					t.Errorf("gofer reported %d failed checks", n)
				}
			default:
				t.Logf("gofer: %s", line)
			}
		}
		if err != nil {
			break
		}
	}
	if !sawDone {
		t.Errorf("gofer did not report its results")
	}
}

// TestMountPointFollowsLateMount verifies that once the host replaces the mount
// at the path of a mount that the gofer serves, the gofer serves the mount that
// the path resolves to now, for every operation that resolves names relative to
// the mount point. It then verifies that removing that mount makes the gofer
// follow the path back, that the gofer does not keep the replaced mount busy
// while it is idle, that a mount that is a file is followed too (including the
// writable-FD path), and finally that an unresolvable mount point path falls
// back to serving the FD that the mount was served with.
func TestMountPointFollowsLateMount(t *testing.T) {
	tree := setupSharedTree(t)
	childOut, stdin, child := startGofer(t, tree, "checks", 0)

	// Phase 1: a directory is mounted over the mount source.
	bindOverSource(t, tree.sub, tree.src)
	signal(t, stdin, "mounted")
	waitForGoferLine(t, childOut, "checks-done")

	// The gofer is idle now, and must not have a host FD open on the mount that
	// the path resolved to while it was serving it: a mount that the gofer
	// keeps open can no longer be unmounted from the host (it fails with EBUSY
	// while the sandbox is running), so a gofer that resolves the mount point
	// per operation must only hold the mount it was mounted with.
	var unmountErr error
	for range 100 {
		if unmountErr = unix.Unmount(tree.src, 0); unmountErr == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if unmountErr != nil {
		t.Errorf("unmounting the late mount at %q while the gofer is running: %v", tree.src, unmountErr)
	}
	signal(t, stdin, "unmounted")
	waitForGoferLine(t, childOut, "unmount-checks-done")

	collectGoferOutput(t, childOut)
	if err := child.Wait(); err != nil {
		t.Errorf("gofer process: %v", err)
	}
}

// TestMountPointLateMountConcurrent verifies that concurrent operations on the
// mount point stay consistent while the host repeatedly replaces the mount at
// the mount point underneath them, and that resolving the mount point for every
// operation does not leak host FDs.
//
// Run with -race to verify that resolving the mount point for each operation is
// safe under the read concurrency that lisafs gives to operations on the same
// FD.
func TestMountPointLateMountConcurrent(t *testing.T) {
	const stressMillis = 750
	tree := setupSharedTree(t)
	childOut, stdin, child := startGofer(t, tree, "stress", stressMillis)

	bindOverSource(t, tree.sub, tree.src)
	signal(t, stdin, "mounted")

	// The gofer warms up before it starts to read the mount point concurrently,
	// so that the mount is not being replaced while the warm-up runs.
	waitForGoferLine(t, childOut, "stress-ready")

	deadline := time.Now().Add(time.Duration(stressMillis) * time.Millisecond)
	for time.Now().Before(deadline) {
		if err := unix.Unmount(tree.src, 0); err != nil {
			// The gofer may be reading through the mount that was just placed,
			// which keeps it busy until that operation is done. Retry.
			time.Sleep(5 * time.Millisecond)
			continue
		}
		bindOverSource(t, tree.sub, tree.src)
		time.Sleep(5 * time.Millisecond)
	}
	// End with a single late mount in place, and let the gofer check that it
	// serves what the path resolves to now.
	drainMounts(t, tree.src)
	bindOverSource(t, tree.sub, tree.src)
	signal(t, stdin, "mounted")

	collectGoferOutput(t, childOut)
	if err := child.Wait(); err != nil {
		t.Errorf("gofer process: %v", err)
	}
}

// TestMountPointFollowsLateMountFile is the same scenario for a mount point that
// is a regular file rather than a directory: the host mounts a file from another
// filesystem over the mount source, and the gofer must serve it, including the
// writable-FD path that SetStat takes (which fails on the replaced mount, a
// file from the tmpfs that is only readable through the old FD).
func TestMountPointFollowsLateMountFile(t *testing.T) {
	tree := setupSharedFileTree(t)
	childOut, stdin, child := startGoferFile(t, tree)

	bindOverSource(t, tree.aux, tree.src)
	signal(t, stdin, "mounted")
	waitForGoferLine(t, childOut, "file-checks-done")

	collectGoferOutput(t, childOut)
	if err := child.Wait(); err != nil {
		t.Errorf("gofer process: %v", err)
	}
}

// sharedFileTree is the host-side tree for a mount point that is a regular file.
type sharedFileTree struct {
	base string
	src  string
	dst  string
	aux  string
}

func setupSharedFileTree(t *testing.T) *sharedFileTree {
	t.Helper()
	baseDir, err := os.MkdirTemp(os.Getenv("TEST_TMPDIR"), "latebindfile")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	tree := &sharedFileTree{
		base: filepath.Join(baseDir, "mnt"),
		aux:  filepath.Join(baseDir, "aux-file"),
	}
	tree.src = filepath.Join(tree.base, "src-file")
	tree.dst = filepath.Join(tree.base, "dst-file")
	if err := os.MkdirAll(tree.base, 0777); err != nil {
		t.Fatalf("MkdirAll(%q): %v", tree.base, err)
	}
	if err := unix.Mount("tmpfs", tree.base, "tmpfs", 0, ""); err != nil {
		if err == unix.EPERM || err == unix.EACCES {
			t.Skipf("mounting is not permitted in this environment: %v", err)
		}
		t.Fatalf("mount tmpfs at %q: %v", tree.base, err)
	}
	if err := os.WriteFile(tree.src, []byte("old"), 0644); err != nil {
		t.Fatalf("WriteFile(%q): %v", tree.src, err)
	}
	if err := os.WriteFile(tree.dst, []byte("old"), 0644); err != nil {
		t.Fatalf("WriteFile(%q): %v", tree.dst, err)
	}
	// A file on the host's root filesystem: a different filesystem than the
	// tmpfs, so that StatFS on the mount point is discriminating.
	if err := os.WriteFile(tree.aux, []byte(fileContent), 0644); err != nil {
		t.Fatalf("WriteFile(%q): %v", tree.aux, err)
	}
	if err := unix.Mount("", tree.base, "", unix.MS_SHARED|unix.MS_REC, ""); err != nil {
		t.Fatalf("make %q shared: %v", tree.base, err)
	}
	t.Cleanup(func() {
		drainMounts(t, tree.src)
		if err := unix.Unmount(tree.base, 0); err != nil {
			t.Errorf("unmount %q: %v", tree.base, err)
		}
		if err := os.RemoveAll(baseDir); err != nil {
			t.Errorf("RemoveAll(%q): %v", baseDir, err)
		}
	})
	return tree
}

// startGoferFile starts the gofer side of the file test in a mount namespace of
// its own, serving a mount whose root is a regular file.
func startGoferFile(t *testing.T, tree *sharedFileTree) (childOut *bufio.Reader, stdin *bufio.Writer, child *exec.Cmd) {
	t.Helper()
	cmd := exec.Command("/proc/self/exe")
	cmd.Env = append(os.Environ(),
		goferEnv+"=1",
		modeEnv+"=file",
		baseEnv+"="+tree.base,
		oldDirInoEnv+"="+strconv.FormatUint(inoOf(t, tree.src), 10),
		// Not used by the file mode: the mount point is not a directory and
		// there is no stress run.
		newDirInoEnv+"=0",
		markerInoEnv+"=0",
		stressMillisEnv+"=0",
		auxEnv+"="+tree.aux,
		fileInoEnv+"="+strconv.FormatUint(inoOf(t, tree.aux), 10),
		fileTypeEnv+"="+strconv.FormatUint(uint64(fileTypeOf(t, tree.aux)), 10),
	)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the gofer process with CLONE_NEWNS: %v", err)
	}
	t.Cleanup(func() {
		_ = in.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})
	childOut = bufio.NewReader(out)
	stdin = bufio.NewWriter(in)
	waitForGoferLine(t, childOut, "ready")
	return childOut, stdin, cmd
}

// runGoferSide runs the gofer side of the test in this process, which is in its
// own mount namespace, and returns the process exit code.
func runGoferSide() int {
	base := os.Getenv(baseEnv)
	srcName, dstName := "src", "dst"
	if os.Getenv(modeEnv) == "file" {
		// The served mount is a regular file in this mode.
		srcName, dstName = "src-file", "dst-file"
	}
	src := filepath.Join(base, srcName)
	dst := filepath.Join(base, dstName)
	oldDirIno := mustParseUint(os.Getenv(oldDirInoEnv))
	newDirIno := mustParseUint(os.Getenv(newDirInoEnv))
	markerIno := mustParseUint(os.Getenv(markerInoEnv))
	fileIno := mustParseUint(os.Getenv(fileInoEnv))
	fileType := uint32(mustParseUint(os.Getenv(fileTypeEnv)))
	stressMillis := mustParseUint(os.Getenv(stressMillisEnv))
	in := bufio.NewReader(os.Stdin)

	failures := 0
	report := func(ok bool, format string, args ...any) {
		status := "PASS"
		if !ok {
			status = "FAIL"
			failures++
		}
		fmt.Printf("%s: %s\n", status, fmt.Sprintf(format, args...))
	}

	// Receive mount events from the host: the gofer's mount namespace is a
	// slave of the host's (runsc/cmd/sandboxsetup.SetupRootFS).
	if err := unix.Mount("", base, "", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
		fmt.Printf("FAIL: making %q a slave of the host's mounts: %v\n", base, err)
		return 1
	}
	// What runsc/cmd/sandboxsetup.SetupMounts does for a mount whose options
	// request propagation: bind the source into the gofer's tree and make the
	// result a slave, so that mounts placed on the source path are propagated
	// onto it. Both are regular files when the served mount is a file.
	if err := unix.Mount(src, dst, "", unix.MS_BIND, ""); err != nil {
		fmt.Printf("FAIL: bind %q -> %q: %v\n", src, dst, err)
		return 1
	}
	if err := unix.Mount("", dst, "", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
		fmt.Printf("FAIL: making %q a slave: %v\n", dst, err)
		return 1
	}

	if err := fsgofer.OpenProcSelfFD("/proc/self/fd"); err != nil {
		fmt.Printf("FAIL: OpenProcSelfFD: %v\n", err)
		return 1
	}
	serverSock, clientSock, err := unet.SocketPair(false)
	if err != nil {
		fmt.Printf("FAIL: SocketPair: %v\n", err)
		return 1
	}
	server := lisafs.NewServer()
	conn, err := server.CreateConnection(serverSock, dst, fsgofer.ConnectionOpts(false /* readonly */), fsgofer.NewConnectionImpl(&fsgofer.Config{}))
	if err != nil {
		fmt.Printf("FAIL: CreateConnection: %v\n", err)
		return 1
	}
	server.StartConnection(conn)
	client, rootInode, _, err := lisafs.NewClient(clientSock)
	if err != nil {
		fmt.Printf("FAIL: NewClient: %v\n", err)
		return 1
	}
	if err := client.StartChannels(); err != nil {
		fmt.Printf("FAIL: StartChannels: %v\n", err)
		return 1
	}
	ctx := context.Background()
	root := client.NewFD(rootInode.ControlFD)

	// The mount point must still refer to the mount that was bound at startup:
	// if the host had already placed a mount on the source path, the test would
	// not exercise anything.
	var preStat lisafs.Statx
	if err := root.StatTo(ctx, &preStat); err != nil {
		fmt.Printf("FAIL: StatTo(root): %v\n", err)
		return 1
	}
	if preStat.Ino != oldDirIno {
		fmt.Printf("FAIL: the mount point serves ino %d, want the mount source's ino %d\n", preStat.Ino, oldDirIno)
		return 1
	}
	if os.Getenv(modeEnv) == "file" && uint32(preStat.Mode)&unix.S_IFMT != unix.S_IFREG {
		fmt.Printf("FAIL: the mount point is not a regular file: mode=%#o\n", preStat.Mode)
		return 1
	}
	if os.Getenv(modeEnv) != "file" {
		if ino, err := root.Walk(ctx, markerName); err == nil {
			closeFD(ctx, client.NewFD(ino.ControlFD))
			fmt.Printf("FAIL: before the late mount, Walk(%q) already succeeded\n", markerName)
			return 1
		}
	}
	preMntID := mountIDOf(dst)
	if preMntID == unixMntIDUnknown {
		// Every comparison below would degenerate; skip loudly instead of
		// reporting a propagation failure.
		fmt.Printf("SKIP: STATX_MNT_ID is not supported by this kernel\n")
		fmt.Println("DONE 0")
		return 0
	}
	fmt.Printf("INFO: before the late mount: mount point ino=%d mnt_id=%d\n", preStat.Ino, preMntID)

	fmt.Println("ready")
	if msg, ok := waitForHost(in, "mounted"); !ok {
		fmt.Printf("FAIL: unexpected host message %q\n", msg)
		return 1
	}

	switch os.Getenv(modeEnv) {
	case "file":
		// The mount that this connection serves is a regular file, bound from
		// the mount source file; the pre-state check above verified that the
		// mount point still serves it.
		if got := mountIDOf(dst); got == preMntID {
			fmt.Printf("FAIL: the mount point path still resolves to mount %d, the host's mount did not propagate\n", preMntID)
			return 1
		}
		runFileMountChecks(ctx, root, report, fileIno, fileType)
		fmt.Println("file-checks-done")

	case "checks":
		// The mount point path must now resolve to a different mount. If it does
		// not, the propagation that this test depends on did not happen and the
		// checks below would not prove anything.
		if postMntID := mountIDOf(dst); postMntID == preMntID {
			fmt.Printf("FAIL: the mount point path still resolves to mount %d, the host's mount did not propagate\n", preMntID)
			return 1
		}
		runLateMountChecks(ctx, root, report, preStat, oldDirIno, newDirIno, markerIno)
		fmt.Println("checks-done")

		if msg, ok := waitForHost(in, "unmounted"); !ok {
			fmt.Printf("FAIL: unexpected host message %q\n", msg)
			return 1
		}
		runAfterUnmountChecks(ctx, root, report, preStat, preMntID, oldDirIno, markerIno)
		fmt.Println("unmount-checks-done")

	case "stress":
		runStress(ctx, root, report, preStat, preMntID, oldDirIno, newDirIno, markerIno, int(stressMillis))
		if msg, ok := waitForHost(in, "mounted"); !ok {
			fmt.Printf("FAIL: unexpected host message %q\n", msg)
			return 1
		}
		// The host ends the stress run with the late mount in place: the gofer
		// must serve it, which also proves that the mount events in this test
		// reached the gofer at all.
		runLateMountChecks(ctx, root, report, preStat, oldDirIno, newDirIno, markerIno)

	default:
		fmt.Printf("FAIL: unknown mode %q\n", os.Getenv(modeEnv))
		return 1
	}

	fmt.Printf("DONE %d\n", failures)

	// Shut down the connection and the server. The client must be closed before
	// waiting for the server's connections to finish.
	closeFD(ctx, root)
	server.Destroy()
	client.Close()
	server.Wait()

	if failures != 0 {
		return 1
	}
	return 0
}

// waitForHost waits for a command from the test process.
func waitForHost(in *bufio.Reader, want string) (string, bool) {
	line, err := in.ReadString('\n')
	if err != nil {
		return "", false
	}
	line = strings.TrimSpace(line)
	return line, line == want
}

// runLateMountChecks verifies that the operations that resolve names relative to
// the mount point observe the mount that is at the mount point now.
func runLateMountChecks(ctx context.Context, root lisafs.ClientFD, report func(bool, string, ...any), preStat lisafs.Statx, oldDirIno, newDirIno, markerIno uint64) {
	client := root.Client()
	base := os.Getenv(baseEnv)
	sub := filepath.Join(base, "sub")

	// Walk (lookup) of a name that exists in the late-mounted directory: the
	// path taken by open(2) and stat(2) in the sandbox.
	childIno, err := root.Walk(ctx, markerName)
	report(err == nil && childIno.Stat.Ino == markerIno, "Walk(%q) sees the late-mounted file (err=%v, ino=%d want %d)", markerName, err, childIno.Stat.Ino, markerIno)
	if err == nil {
		closeFD(ctx, client.NewFD(childIno.ControlFD))
	}

	// Stat of the mount point itself.
	var stat lisafs.Statx
	if err := root.StatTo(ctx, &stat); err != nil {
		report(false, "StatTo(root): %v", err)
	} else {
		report(stat.Ino == newDirIno, "Stat(root) reports the late-mounted directory (ino=%d want %d, was %d)", stat.Ino, newDirIno, oldDirIno)
	}

	// WalkStat, the RPC that the sentry uses for revalidation, starting at the
	// mount point.
	stats, err := root.WalkStat(ctx, []string{""})
	report(err == nil && len(stats) == 1 && stats[0].Ino == newDirIno, "WalkStat([%q]) reports the late-mounted directory (err=%v, ino=%v want %d)", "", err, inosOf(stats), newDirIno)

	// Open + Getdents64 of the mount point: readdir(2) in the sandbox.
	openFDID, _, err := root.OpenAt(ctx, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		report(false, "OpenAt(root): %v", err)
	} else {
		openFD := client.NewFD(openFDID)
		dirents, err := openFD.Getdents64(ctx, -64*1024)
		report(err == nil && containsName(direntNames(dirents), markerName), "Getdents64(root) lists the late-mounted directory (err=%v, entries=[%s] want %s)", err, direntNames(dirents), markerName)
		closeFD(ctx, openFD)
	}

	// Creating, removing, and renaming entries below the mount point must affect
	// the mount that the path resolves to now, not the mount that was replaced.
	created := false
	childIno, openFDID, donatedFD, err := root.OpenCreateAt(ctx, "created.txt", unix.O_RDWR, 0777, lisafs.UID(unix.Getuid()), lisafs.GID(unix.Getgid()))
	if err != nil {
		report(false, "OpenCreateAt(created.txt): %v", err)
	} else {
		closeFD(ctx, client.NewFD(childIno.ControlFD))
		closeFD(ctx, client.NewFD(openFDID))
		if donatedFD >= 0 {
			// The gofer donates a host FD for the created file. It refers to
			// the mount that the file is in, and must be closed by us: it would
			// keep that mount busy.
			if err := unix.Close(donatedFD); err != nil {
				report(false, "closing the donated FD: %v", err)
			}
		}
		created = fileExists(filepath.Join(sub, "created.txt"))
		report(created, "OpenCreateAt(created.txt) created the file in the late-mounted directory")
	}

	mkdirCreated := false
	dirIno, err := root.MkdirAt(ctx, "created-dir", 0777, lisafs.UID(unix.Getuid()), lisafs.GID(unix.Getgid()))
	if err != nil {
		report(false, "MkdirAt(created-dir): %v", err)
	} else {
		// MkdirAt returns a control FD for the new directory; close it, it would
		// otherwise keep the mount that the directory is in busy.
		closeFD(ctx, client.NewFD(dirIno.ControlFD))
		mkdirCreated = fileExists(filepath.Join(sub, "created-dir"))
		report(mkdirCreated, "MkdirAt(created-dir) created the directory in the late-mounted directory")
	}

	// Mknod, Symlink and Link below the mount point.
	if nodeIno, err := root.MknodAt(ctx, "node", unix.S_IFREG|0644, lisafs.UID(unix.Getuid()), lisafs.GID(unix.Getgid()), 0, 0); err != nil {
		report(false, "MknodAt(node): %v", err)
	} else {
		closeFD(ctx, client.NewFD(nodeIno.ControlFD))
		report(fileExists(filepath.Join(sub, "node")), "MknodAt(node) created the file in the late-mounted directory")
	}

	if linkIno, err := root.SymlinkAt(ctx, "link", "target", lisafs.UID(unix.Getuid()), lisafs.GID(unix.Getgid())); err != nil {
		report(false, "SymlinkAt(link): %v", err)
	} else {
		closeFD(ctx, client.NewFD(linkIno.ControlFD))
		target, err := os.Readlink(filepath.Join(sub, "link"))
		report(err == nil && target == "target", "SymlinkAt(link) created the symlink in the late-mounted directory (target=%q err=%v)", target, err)
	}

	if nodeIno, err := root.Walk(ctx, "node"); err != nil {
		report(false, "Walk(node): %v", err)
	} else {
		nodeFD := client.NewFD(nodeIno.ControlFD)
		if linkIno, err := root.LinkAt(ctx, nodeFD.ID(), "nodelink"); err != nil {
			report(false, "LinkAt(nodelink): %v", err)
		} else {
			closeFD(ctx, client.NewFD(linkIno.ControlFD))
			nlink := uint64(0)
			if st, err := os.Stat(filepath.Join(sub, "nodelink")); err == nil {
				if sys, ok := st.Sys().(*syscall.Stat_t); ok {
					nlink = uint64(sys.Nlink)
				}
			}
			report(nlink == 2, "LinkAt(nodelink) created the hard link in the late-mounted directory (nlink=%d want 2)", nlink)
		}
		closeFD(ctx, nodeFD)
	}

	// Renaming below the mount point.
	if err := root.RenameAt(ctx, "node", root.ID(), "node-renamed", 0); err != nil {
		report(false, "RenameAt(node -> node-renamed): %v", err)
	} else {
		report(fileExists(filepath.Join(sub, "node-renamed")) && !fileExists(filepath.Join(sub, "node")), "RenameAt(node -> node-renamed) moved the file in the late-mounted directory")
	}

	// Unlink below the mount point, and of the created file.
	if created {
		if err := root.UnlinkAt(ctx, "created.txt", 0); err != nil {
			report(false, "UnlinkAt(created.txt): %v", err)
		} else {
			report(!fileExists(filepath.Join(sub, "created.txt")), "UnlinkAt(created.txt) removed the file from the late-mounted directory")
		}
	}
	if err := root.UnlinkAt(ctx, "node-renamed", 0); err != nil {
		report(false, "UnlinkAt(node-renamed): %v", err)
	} else {
		report(!fileExists(filepath.Join(sub, "node-renamed")), "UnlinkAt(node-renamed) removed the file from the late-mounted directory")
	}

	// A control FD that identifies a specific file must keep identifying it:
	// resolving the mount point again must not leak into other FDs. The
	// expectation is the inode of the directory as the host sees it, taken
	// before the directory is renamed behind the gofer's back.
	if mkdirCreated {
		wantIno, err := inoAt(filepath.Join(sub, "created-dir"))
		if err != nil {
			report(false, "statting the created directory as the host: %v", err)
		}
		walkedIno, err := root.Walk(ctx, "created-dir")
		if err != nil {
			report(false, "Walk(created-dir): %v", err)
		} else {
			dirFD := client.NewFD(walkedIno.ControlFD)
			// Renaming the directory through the host does not change what the
			// control FD refers to.
			if err := os.Rename(filepath.Join(sub, "created-dir"), filepath.Join(sub, "renamed-dir")); err != nil {
				report(false, "renaming the child: %v", err)
			} else {
				var childStat lisafs.Statx
				report(dirFD.StatTo(ctx, &childStat) == nil, "a control FD obtained by Walk identifies its file after the path was renamed")
				report(childStat.Ino == wantIno, "the control FD still reports the directory it was walked to (ino=%d want %d from the host)", childStat.Ino, wantIno)
			}
			closeFD(ctx, dirFD)
			_ = os.RemoveAll(filepath.Join(sub, "renamed-dir"))
		}
	}
	_ = os.RemoveAll(filepath.Join(sub, "created-dir"))

	// SetStat on the mount point: the mode change must be applied to the mount
	// that the path resolves to now.
	modeBefore, err := modeAt(sub)
	if err != nil {
		report(false, "statting the late-mounted directory as the host: %v", err)
		return
	}
	setStatReq := linux.Statx{Mask: unix.STATX_MODE, Mode: uint16(modeBefore&^0777 | 0700)}
	if mask, failureErr, err := root.SetStat(ctx, &setStatReq); err != nil || failureErr != nil || mask != 0 {
		report(false, "SetStat(root, MODE): mask=%#x failureErr=%v err=%v", mask, failureErr, err)
	} else if mode, err := modeAt(sub); err != nil {
		report(false, "statting the late-mounted directory after SetStat: %v", err)
	} else {
		report(mode&0777 == 0700, "SetStat(root, MODE) changed the mode of the late-mounted directory (mode=%#o want 0700)", mode&0777)
	}

	// The xattr family on the mount point.
	const xattrName = "user.fsgofer_test"
	if err := root.SetXattr(ctx, xattrName, "value", 0); err != nil {
		report(false, "SetXattr(root): %v", err)
	} else {
		hostValue, hostErr := xattrAt(sub, xattrName)
		report(hostErr == nil && hostValue == "value", "SetXattr(root) set the xattr on the late-mounted directory (host value=%q err=%v)", hostValue, hostErr)
	}
	if value, err := root.GetXattr(ctx, xattrName, 0); err != nil {
		report(false, "GetXattr(root): %v", err)
	} else {
		report(value == "value", "GetXattr(root) reads the xattr of the late-mounted directory (value=%q want %q)", value, "value")
	}
	if names, err := root.ListXattr(ctx, 0); err != nil {
		report(false, "ListXattr(root): %v", err)
	} else {
		report(containsString(names, xattrName), "ListXattr(root) lists the xattr of the late-mounted directory (names=%v want %q)", names, xattrName)
	}
	if err := root.RemoveXattr(ctx, xattrName); err != nil {
		report(false, "RemoveXattr(root): %v", err)
	} else {
		_, hostErr := xattrAt(sub, xattrName)
		report(hostErr != nil, "RemoveXattr(root) removed the xattr from the late-mounted directory (host err=%v)", hostErr)
	}

	// StatFS on the mount point: both mounts are on the same tmpfs here, so this
	// only smokes the code path; the file phase checks a mount on a different
	// filesystem.
	var statFS lisafs.StatFS
	report(root.StatFSTo(ctx, &statFS) == nil, "StatFSTo(root) succeeded")
}

// runAfterUnmountChecks verifies that the mount point follows the path back to
// the mount that was there before the host's mount was removed.
func runAfterUnmountChecks(ctx context.Context, root lisafs.ClientFD, report func(bool, string, ...any), preStat lisafs.Statx, preMntID, oldDirIno, markerIno uint64) {
	if got := mountIDOf(filepath.Join(os.Getenv(baseEnv), "dst")); got != preMntID {
		report(false, "the mount point path resolves to mount %d after the host's mount was removed, want %d", got, preMntID)
	}

	var stat lisafs.Statx
	if err := root.StatTo(ctx, &stat); err != nil {
		report(false, "StatTo(root) after unmount: %v", err)
	} else {
		report(stat.Ino == oldDirIno, "Stat(root) reports the mount that was at the path before (ino=%d want %d, was %d)", stat.Ino, oldDirIno, preStat.Ino)
	}

	if ino, err := root.Walk(ctx, markerName); err == nil {
		closeFD(ctx, root.Client().NewFD(ino.ControlFD))
		report(false, "Walk(%q) still sees the removed mount's file (ino=%d, the removed mount's file was %d)", markerName, ino.Stat.Ino, markerIno)
	} else {
		report(isNotExist(err), "Walk(%q) does not see the removed mount's file (err=%v)", markerName, err)
	}

	stats, err := root.WalkStat(ctx, []string{""})
	report(err == nil && len(stats) == 1 && stats[0].Ino == oldDirIno, "WalkStat([%q]) reports the mount that was at the path before (err=%v, ino=%v want %d)", "", err, inosOf(stats), oldDirIno)
}

// runFileMountChecks verifies that a mount that is a regular file, on a
// different filesystem than the mount it replaced, is followed, including the
// writable-FD path used by SetStat.
func runFileMountChecks(ctx context.Context, root lisafs.ClientFD, report func(bool, string, ...any), fileIno uint64, fileType uint32) {
	var stat lisafs.Statx
	if err := root.StatTo(ctx, &stat); err != nil {
		report(false, "StatTo(root) after the file was mounted: %v", err)
	} else {
		report(stat.Ino == fileIno && uint32(stat.Mode)&unix.S_IFMT == fileType, "Stat(root) reports the mounted file (ino=%d want %d, type=%#o want %#o)", stat.Ino, fileIno, uint32(stat.Mode)&unix.S_IFMT, fileType)
	}

	// Read the file through the mount point.
	openFDID, _, err := root.OpenAt(ctx, unix.O_RDONLY)
	if err != nil {
		report(false, "OpenAt(root) of the mounted file: %v", err)
	} else {
		openFD := root.Client().NewFD(openFDID)
		buf := make([]byte, len(fileContent))
		n, err := openFD.Read(ctx, buf, 0)
		report(err == nil && string(buf[:n]) == fileContent, "Read(root) reads the mounted file (n=%d value=%q want %q)", n, string(buf[:n]), fileContent)
		closeFD(ctx, openFD)
	}

	// SetStat(SIZE) on the mount point takes the writable-FD path: the FD must
	// be a writable FD on the mount that the path resolves to now. On the mount
	// that was replaced this fails (it is a directory), so this check
	// discriminates the two.
	const newSize = 8
	aux := os.Getenv(auxEnv)
	setStatReq := linux.Statx{Mask: unix.STATX_SIZE, Size: newSize}
	if mask, failureErr, err := root.SetStat(ctx, &setStatReq); err != nil || failureErr != nil || mask != 0 {
		report(false, "SetStat(root, SIZE): mask=%#x failureErr=%v err=%v", mask, failureErr, err)
	} else if size, err := sizeAt(aux); err != nil {
		report(false, "statting the mounted file as the host: %v", err)
	} else {
		report(size == newSize, "SetStat(root, SIZE) truncated the mounted file (size=%d want %d)", size, newSize)
	}

	// StatFS on the mount point must report the filesystem that is mounted at
	// the path now, which is not the tmpfs that held the replaced directory.
	var statFS lisafs.StatFS
	if err := root.StatFSTo(ctx, &statFS); err != nil {
		report(false, "StatFSTo(root) of the mounted file: %v", err)
	} else {
		wantType, err := fsTypeAt(os.Getenv(auxEnv))
		if err != nil {
			report(false, "statfs of the mounted file as the host: %v", err)
		} else {
			report(uint64(statFS.Type) == wantType, "StatFSTo(root) reports the filesystem of the mounted file (type=%#x want %#x)", uint64(statFS.Type), wantType)
		}
	}
}

// runStress verifies that operations on the mount point stay consistent while
// the host replaces the mount at the mount point underneath them, and that
// resolving the mount point for every operation does not leak host FDs.
func runStress(ctx context.Context, root lisafs.ClientFD, report func(bool, string, ...any), preStat lisafs.Statx, preMntID, oldDirIno, newDirIno, markerIno uint64, stressMillis int) {
	const warmup = 50
	client := root.Client()

	oneIteration := func() error {
		var stat lisafs.Statx
		if err := root.StatTo(ctx, &stat); err != nil {
			return fmt.Errorf("StatTo: %w", err)
		}
		if stat.Ino != oldDirIno && stat.Ino != newDirIno {
			return fmt.Errorf("Stat(root) reported ino %d, which is neither the replaced mount's directory (%d) nor the late-mounted one (%d)", stat.Ino, oldDirIno, newDirIno)
		}
		if ino, err := root.Walk(ctx, markerName); err == nil {
			closeFD(ctx, client.NewFD(ino.ControlFD))
			if ino.Stat.Ino != markerIno {
				return fmt.Errorf("Walk(%q) reported ino %d, want %d", markerName, ino.Stat.Ino, markerIno)
			}
		} else if !isNotExist(err) {
			return fmt.Errorf("Walk(%q): %v", markerName, err)
		}
		if stats, err := root.WalkStat(ctx, []string{""}); err != nil {
			return fmt.Errorf("WalkStat: %w", err)
		} else if len(stats) != 1 || (stats[0].Ino != oldDirIno && stats[0].Ino != newDirIno) {
			return fmt.Errorf("WalkStat reported %v, want one of [%d %d]", inosOf(stats), oldDirIno, newDirIno)
		}
		openFDID, _, err := root.OpenAt(ctx, unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			return fmt.Errorf("OpenAt: %w", err)
		}
		openFD := client.NewFD(openFDID)
		dirents, err := openFD.Getdents64(ctx, -64*1024)
		closeFD(ctx, openFD)
		if err != nil {
			return fmt.Errorf("Getdents64: %w", err)
		}
		for _, d := range dirents {
			if name := string(d.Name); name != "." && name != ".." && name != markerName {
				return fmt.Errorf("Getdents64 listed unexpected entry %q", name)
			}
		}
		return nil
	}

	// The mount point must resolve to the mount that the host placed before the
	// stress run starts.
	if got := mountIDOf(os.Getenv(baseEnv) + "/dst"); got == preMntID {
		report(false, "the mount point path still resolves to mount %d, the host's mount did not propagate", preMntID)
		return
	}
	// Warm up so that FDs that are allocated once, e.g. by the runtime, are
	// already allocated when the FD count below is measured.
	for range warmup {
		if err := oneIteration(); err != nil {
			report(false, "warmup: %v", err)
			return
		}
	}
	// The host may now replace the mount at any time.
	fmt.Println("stress-ready")
	fdsBefore, err := fdsOnTree(os.Getenv(baseEnv))
	if err != nil {
		report(false, "counting the gofer's FDs on the mount tree: %v", err)
		return
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		failures []error
		iters    int
	)
	// Operations on the same control FD may run concurrently: lisafs guarantees
	// read concurrency for them, and they are dispatched on several channels.
	deadline := time.Now().Add(time.Duration(stressMillis) * time.Millisecond)
	workers := 8
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20000 {
				if time.Now().After(deadline) {
					return
				}
				err := oneIteration()
				mu.Lock()
				iters++
				if err != nil && len(failures) < 10 {
					failures = append(failures, err)
				}
				mu.Unlock()
				if err != nil {
					return
				}
			}
		}()
	}
	wg.Wait()
	// The stress run must have done work: with no iterations the checks below
	// would pass without exercising anything.
	report(iters > 0, "the concurrent workers ran (iterations=%d)", iters)
	report(len(failures) == 0, "concurrent operations on the mount point stayed consistent (%d iterations, %d failures)", iters, len(failures))
	for _, err := range failures {
		report(false, "concurrent operation: %v", err)
	}
	fdsAfter, err := fdsOnTree(os.Getenv(baseEnv))
	if err != nil {
		report(false, "counting the gofer's FDs on the mount tree after the stress run: %v", err)
	} else {
		report(fdsAfter <= fdsBefore, "resolving the mount point per operation does not leak host FDs on the mount tree (%d FDs after %d iterations, %d before)", fdsAfter, iters, fdsBefore)
	}

	var lastStat lisafs.Statx
	if err := root.StatTo(ctx, &lastStat); err != nil {
		report(false, "StatTo(root) after the stress run: %v", err)
	} else if lastStat.Ino != preStat.Ino && lastStat.Ino != oldDirIno && lastStat.Ino != newDirIno {
		report(false, "Stat(root) after the stress run reported ino %d, want one of the mount point's known directories", lastStat.Ino)
	}
}

// Host-side observations used by the gofer side of the tests. The gofer is a
// plain process in its own mount namespace, so it observes the effects of its
// own operations directly.

func inoAt(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

func modeAt(path string) (uint32, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	return uint32(st.Mode), nil
}

func sizeAt(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Size), nil
}

func fsTypeAt(path string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Type), nil
}

func xattrAt(path, name string) (string, error) {
	buf := make([]byte, 256)
	n, err := unix.Getxattr(path, name, buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// unixMntIDUnknown is returned by mountIDOf when the mount ID is unavailable.
const unixMntIDUnknown = ^uint64(0)

func mountIDOf(path string) uint64 {
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_STATX_SYNC_AS_STAT, unix.STATX_MNT_ID, &st); err != nil {
		return unixMntIDUnknown
	}
	if st.Mask&unix.STATX_MNT_ID == 0 {
		return unixMntIDUnknown
	}
	return st.Mnt_id
}

// fdsOnTree counts the host FDs of this process that refer to a file or
// directory in the mount tree rooted at base, i.e. the FDs that the gofer opens
// to serve it. Runtime FDs (pipes, sockets, event pollers, memfds) are not
// counted: the Go runtime allocates some of them lazily.
func fdsOnTree(base string) (int, error) {
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range ents {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err != nil {
			continue
		}
		if strings.HasPrefix(target, base) {
			count++
		}
	}
	return count, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func isNotExist(err error) bool {
	return err == unix.ENOENT || strings.Contains(err.Error(), "no such file or directory")
}

// closeFD closes a lisafs FD. The FD has pointer methods and therefore cannot be
// closed on the value returned by Client.NewFD, and closes are batched on the
// client, so flush the close: the tests below check what the gofer has open, and
// a batched close would leave the server-side host FD (and the mount it refers
// to) in place.
func closeFD(ctx context.Context, fd lisafs.ClientFD) {
	fd.Close(ctx, true /* flush */)
}

func inosOf(stats []lisafs.Statx) []uint64 {
	inos := make([]uint64, 0, len(stats))
	for _, s := range stats {
		inos = append(inos, s.Ino)
	}
	return inos
}

func direntNames(dirents []lisafs.Dirent64) string {
	names := make([]string, 0, len(dirents))
	for _, d := range dirents {
		names = append(names, string(d.Name))
	}
	return strings.Join(names, " ")
}

func containsName(names, name string) bool {
	for _, n := range strings.Fields(names) {
		if n == name {
			return true
		}
	}
	return false
}

func containsString(names []string, name string) bool {
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

func mustParseUint(s string) uint64 {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		fmt.Printf("FAIL: parsing %q: %v\n", s, err)
		os.Exit(1)
	}
	return v
}
