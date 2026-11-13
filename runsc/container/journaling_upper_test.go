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

package container

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs/journal"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/sandbox"
	"gvisor.dev/gvisor/runsc/specutils"
)

// makeWritableRootfs creates a writable container rootfs directory containing
// lower-file and read-only bind mount points for host system binary/library
// directories so --overlay2=root:self can create .gvisor.filestore.<sandbox-id>
// directly inside Spec.Root.Path without root privileges.
func makeWritableRootfs(t *testing.T) (string, []specs.Mount) {
	t.Helper()
	rootPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootPath, "lower-file"), []byte("lower"), 0644); err != nil {
		t.Fatalf("WriteFile(lower-file): %v", err)
	}
	var mounts []specs.Mount
	for _, sysDir := range []string{"/bin", "/usr", "/lib", "/lib64"} {
		fi, err := os.Stat(sysDir)
		if err != nil || !fi.IsDir() {
			continue
		}
		dstDir := filepath.Join(rootPath, strings.TrimPrefix(sysDir, "/"))
		if err := os.MkdirAll(dstDir, 0755); err != nil {
			t.Fatalf("MkdirAll(%q): %v", dstDir, err)
		}
		mounts = append(mounts, specs.Mount{
			Type:        "bind",
			Destination: sysDir,
			Source:      sysDir,
			Options:     []string{"rbind", "ro"},
		})
	}
	return rootPath, mounts
}

// journalingUpperTest runs containers with self-backed rootfs overlays and
// tracks their combined journal+filestore files.
type journalingUpperTest struct {
	t      *testing.T
	bigSum string
}

func newJournalingUpperTest(t *testing.T) *journalingUpperTest {
	t.Helper()
	return &journalingUpperTest{t: t}
}

func (p *journalingUpperTest) plainConf() *config.Config {
	conf := testutil.TestConfig(p.t)
	if err := conf.Overlay2.Set("root:self"); err != nil {
		p.t.Fatalf("Overlay2.Set: %v", err)
	}
	return conf
}

func (p *journalingUpperTest) conf(imageID string, importPath string) *config.Config {
	conf := p.plainConf()
	conf.JournalingRootfsUpper = config.JournalingRootfsUpperOn
	conf.JournalingRootfsUpperImport = importPath
	conf.JournalingRootfsUpperImageID = imageID
	return conf
}

func (p *journalingUpperTest) importOnlyConf(imageID, importPath string) *config.Config {
	conf := p.plainConf()
	conf.JournalingRootfsUpper = config.JournalingRootfsUpperOff
	conf.JournalingRootfsUpperImport = importPath
	conf.JournalingRootfsUpperImageID = imageID
	return conf
}

func applyWritableRootfs(spec *specs.Spec, rootPath string, sysMounts []specs.Mount) {
	spec.Root = &specs.Root{Path: rootPath, Readonly: false}
	spec.Mounts = append(append([]specs.Mount(nil), sysMounts...), spec.Mounts...)
}

func (p *journalingUpperTest) createOnRoot(conf *config.Config, rootPath string, sysMounts []specs.Mount, mutateSpec func(*specs.Spec), mutateArgs func(*Args), args ...string) (*Container, func(), error) {
	spec := testutil.NewSpecWithArgs(args...)
	applyWritableRootfs(spec, rootPath, sysMounts)
	if mutateSpec != nil {
		mutateSpec(spec)
	}
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		p.t.Fatalf("SetupContainer: %v", err)
	}
	cargs := Args{ID: testutil.RandomContainerID(), Spec: spec, BundleDir: bundleDir}
	if mutateArgs != nil {
		mutateArgs(&cargs)
	}
	c, err := New(conf, cargs)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	filestorePath := selfFilestoreOf(c)
	return c, func() {
		if err := c.Destroy(); err != nil {
			p.t.Errorf("Destroy: %v", err)
		}
		cleanup()
		waitUnlockedPath(p.t, filestorePath)
	}, nil
}

func (p *journalingUpperTest) create(conf *config.Config, args ...string) (*Container, string, func(), error) {
	rootPath, sysMounts := makeWritableRootfs(p.t)
	c, cleanup, err := p.createOnRoot(conf, rootPath, sysMounts, nil, nil, args...)
	return c, rootPath, cleanup, err
}

func (p *journalingUpperTest) start(conf *config.Config) (*Container, string, func()) {
	p.t.Helper()
	c, _, cleanup, err := p.create(conf, "sleep", "1000")
	if err != nil {
		p.t.Fatalf("creating container: %v", err)
	}
	if err := c.Start(conf); err != nil {
		cleanup()
		p.t.Fatalf("starting container: %v", err)
	}
	return c, selfFilestoreOf(c), cleanup
}

func selfFilestoreOf(c *Container) string {
	return sentryapi.SelfFilestorePath(c.Spec.Root.Path, c.Saver.ID.SandboxID)
}

func (p *journalingUpperTest) sh(conf *config.Config, c *Container, script string) string {
	p.t.Helper()
	out, err := executeCombinedOutput(conf, c, nil, "/bin/sh", "-c", script)
	if err != nil {
		p.t.Fatalf("script %q failed: %v, output: %s", script, err, out)
	}
	return string(out)
}

func (p *journalingUpperTest) check(conf *config.Config, c *Container) {
	p.t.Helper()
	got := p.sh(conf, c, `
cat /journaled/d/f
cat /journaled/d/link
md5sum /journaled/big | cut -d' ' -f1
stat -c '%a %s' /journaled/d/f
stat -c '%Y' /
if test -e /lower-file; then echo lower present; else echo lower deleted; fi
ls -A / | grep '^\.gvisor\.filestore' || true
ls /journaled/d
`)
	want := "hello\nhello\n" + p.bigSum + "\n600 6\n1234567890\nlower deleted\nf\nlink\n"
	if got != want {
		p.t.Errorf("files after import:\n%s\nwant:\n%s", got, want)
	}
	if _, err := os.Stat(filepath.Join(c.Spec.Root.Path, "lower-file")); err != nil {
		p.t.Errorf("lower-file was modified on the host: %v", err)
	}
}

func waitUnlockedPath(t *testing.T, path string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		t.Fatalf("opening %q: %v", path, err)
	}
	defer f.Close()
	start := time.Now()
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
			return
		}
		if time.Since(start) > pollTimeout {
			t.Fatalf("%q is still locked %v after container destroy: %v", path, pollTimeout, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (p *journalingUpperTest) kill(c *Container, cleanup func()) {
	p.t.Helper()
	if err := unix.Kill(c.SandboxPid(), unix.SIGKILL); err != nil {
		p.t.Fatalf("killing sandbox: %v", err)
	}
	_, _ = c.Wait()
	cleanup()
}

func (p *journalingUpperTest) files(conf *config.Config, c *Container, names ...string) string {
	p.t.Helper()
	script := ""
	for _, name := range names {
		script += fmt.Sprintf("cat /journaled/%s 2>/dev/null || echo -; ", name)
	}
	return p.sh(conf, c, script)
}

func TestJournalingRootfsUpper(t *testing.T) {
	p := newJournalingUpperTest(t)
	conf1 := p.conf("image-1", "" /* importPath */)

	// First sandbox: write files, delete /lower-file, verify .gvisor.filestore
	// is hidden from inside the container, and verify another sandbox cannot
	// import the live filestore while c1 is running.
	c1, fs1, cleanup1 := p.start(conf1)
	p.bigSum = strings.TrimSpace(p.sh(conf1, c1, `
mkdir -p /journaled/d
echo hello > /journaled/d/f
chmod 600 /journaled/d/f
ln -s f /journaled/d/link
dd if=/dev/urandom of=/journaled/big bs=4096 count=300 2>/dev/null
rm /lower-file
touch -d @1234567890 /
md5sum /journaled/big | cut -d' ' -f1
`))
	if hidden := p.sh(conf1, c1, "ls -A / | grep '^\\.gvisor\\.filestore' || true"); hidden != "" {
		t.Fatalf("self filestore visible inside container: %q", hidden)
	}

	// Importing fs1 while c1 is still running must fail immediately via flock.
	if _, _, cleanupBusy, err := p.create(p.conf("image-1", fs1), "sleep", "1000"); err == nil {
		cleanupBusy()
		t.Errorf("importing an active container's filestore succeeded")
	} else if !strings.Contains(err.Error(), "in use by another sandbox") {
		t.Errorf("importing active filestore: got %v, want \"in use by another sandbox\"", err)
	}

	p.kill(c1, cleanup1)

	// Destroy must preserve .gvisor.filestore.<sandbox-id> in Spec.Root.Path.
	if _, err := os.Stat(fs1); err != nil {
		t.Fatalf("self filestore deleted on Destroy: %v", err)
	}

	// Second sandbox: import fs1 WITH runtime journaling enabled, mutate, and
	// stop cleanly. Its own .gvisor.filestore.<id2> is hardlinked and preserved!
	conf2 := p.conf("image-1", fs1)
	c2, fs2, cleanup2 := p.start(conf2)
	p.check(conf2, c2)
	// Two sandboxes cannot import the same underlying file concurrently either.
	if _, _, cleanupDup, err := p.create(p.importOnlyConf("image-1", fs1), "sleep", "1000"); err == nil {
		cleanupDup()
		t.Errorf("second concurrent import of same file succeeded")
	} else if !strings.Contains(err.Error(), "in use by another sandbox") {
		t.Errorf("second concurrent import: got %v, want \"in use by another sandbox\"", err)
	}
	p.sh(conf2, c2, "echo clean > /journaled/clean")
	cleanup2()
	if _, err := os.Stat(fs2); err != nil {
		t.Fatalf("second self filestore deleted on Destroy: %v", err)
	}

	// Third sandbox: import fs2 via /proc/self/fd/N with runtime journaling
	// enabled, let init exit on its own, and verify changes persist in fs3.
	importFDFile, err := os.OpenFile(fs2, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("OpenFile(%q): %v", fs2, err)
	}
	defer importFDFile.Close()
	procFDPath := fmt.Sprintf("/proc/self/fd/%d", importFDFile.Fd())
	conf3 := p.conf("image-1", procFDPath)
	c3, _, cleanup3, err := p.create(conf3, "/bin/sh", "-c", "echo exited > /journaled/exited")
	if err != nil {
		t.Fatalf("creating c3 via proc fd: %v", err)
	}
	importFDFile.Close()
	fs3 := selfFilestoreOf(c3)
	if err := c3.Start(conf3); err != nil {
		cleanup3()
		t.Fatalf("starting c3: %v", err)
	}
	if ws, err := c3.Wait(); err != nil || ws.ExitStatus() != 0 {
		t.Fatalf("c3 exited with %v, %v", ws, err)
	}
	cleanup3()

	// Wrong image ID is refused without damaging fs3.
	badConf := p.conf("image-2", fs3)
	cBad, _, cleanupBad, err := p.create(badConf, "sleep", "1000")
	if err == nil {
		err = cBad.Start(badConf)
		cleanupBad()
	}
	if err == nil {
		t.Errorf("importing with mismatched image ID succeeded")
	} else if !strings.Contains(err.Error(), `journal was created for image "image-1"`) {
		t.Errorf("mismatched image ID: got %v, want image mismatch", err)
	}

	// Fourth sandbox: import a copy of fs3 WITHOUT runtime journaling enabled
	// (--journaling-rootfs-upper=off) and WITHOUT setting an image ID, verifying
	// startup replay is decoupled from runtime journaling and image ID checking
	// is optional by default.
	unjournaledCopy := filepath.Join(t.TempDir(), "imported.filestore")
	copySparseFile(t, fs3, unjournaledCopy)
	conf4 := p.importOnlyConf("" /* imageID */, unjournaledCopy)
	c4, _, cleanup4, err := p.create(conf4, "sleep", "1000")
	if err != nil {
		t.Fatalf("creating unjournaled import container: %v", err)
	}
	if err := c4.Start(conf4); err != nil {
		cleanup4()
		t.Fatalf("starting unjournaled import container: %v", err)
	}
	p.check(conf4, c4)
	if got, want := p.sh(conf4, c4, "cat /journaled/clean /journaled/exited"), "clean\nexited\n"; got != want {
		t.Errorf("files after unjournaled import: got %q, want %q", got, want)
	}
	p.sh(conf4, c4, "echo transient > /journaled/transient")
	cleanup4()
	// Because runtime journaling was off, no .gvisor.filestore.<id4> was created
	// in c4's Spec.Root.Path.
	if _, err := os.Stat(selfFilestoreOf(c4)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("unjournaled container left self filestore behind: err=%v", err)
	}
}

func copySparseFile(t *testing.T, srcPath, dstPath string) {
	t.Helper()
	src, err := os.Open(srcPath)
	if err != nil {
		t.Fatalf("Open(%q): %v", srcPath, err)
	}
	defer src.Close()
	end, ok, err := journal.FilestoreEnd(src)
	if err != nil || !ok {
		fi, statErr := src.Stat()
		if statErr != nil {
			t.Fatalf("Stat(%q): %v", srcPath, statErr)
		}
		end = uint64(fi.Size())
	}
	size := (end + 4095) &^ 4095
	buf := make([]byte, size)
	n, err := unix.Pread(int(src.Fd()), buf, 0)
	if err != nil {
		t.Fatalf("Pread(%q): %v", srcPath, err)
	}
	if err := os.WriteFile(dstPath, buf[:n], 0600); err != nil {
		t.Fatalf("WriteFile(%q): %v", dstPath, err)
	}
}

func TestJournalingRootfsUpperShrink(t *testing.T) {
	p := newJournalingUpperTest(t)
	const bigSize = 64 << 20

	c1, fs1, cleanup1 := p.start(p.conf("image-1", ""))
	p.sh(p.conf("image-1", ""), c1, fmt.Sprintf(`
mkdir -p /journaled
echo small > /journaled/small
echo after > /journaled/after
dd if=/dev/urandom of=/journaled/big bs=1M count=%d 2>/dev/null
rm /journaled/big
`, bigSize>>20))
	p.kill(c1, cleanup1)

	f1, err := os.Open(fs1)
	if err != nil {
		t.Fatalf("Open(%q): %v", fs1, err)
	}
	endBeforeCompact, ok, err := journal.FilestoreEnd(f1)
	f1.Close()
	if err != nil || !ok {
		t.Fatalf("FilestoreEnd(%q): %#x, %t, %v", fs1, endBeforeCompact, ok, err)
	}
	if endBeforeCompact < 2*journal.DefaultRegionSize+bigSize {
		t.Fatalf("filestore end before compaction is %d bytes, want >= %d", endBeforeCompact, uint64(2*journal.DefaultRegionSize+bigSize))
	}

	// Importing into c2 compacts the journal after replay so the deleted 64 MiB
	// file is no longer referenced by the active region.
	conf2 := p.conf("image-1", fs1)
	c2, fs2, cleanup2 := p.start(conf2)
	if got, want := p.files(conf2, c2, "small", "big", "after"), "small\n-\nafter\n"; got != want {
		t.Errorf("files after first import: got %q, want %q", got, want)
	}
	p.kill(c2, cleanup2)

	fiBefore, err := os.Stat(fs2)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	f, err := os.OpenFile(fs2, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if err := shrinkJournalingRootfsUpperFilestore(fs2, f); err != nil {
		f.Close()
		t.Fatalf("shrinkJournalingRootfsUpperFilestore: %v", err)
	}
	f.Close()
	fiAfter, err := os.Stat(fs2)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	t.Logf("filestore shrank from %d to %d bytes (pre-compaction mark %d)", fiBefore.Size(), fiAfter.Size(), endBeforeCompact)
	wantMax := int64(endBeforeCompact) - bigSize
	if fiAfter.Size() > wantMax || fiAfter.Size()%int64(os.Getpagesize()) != 0 {
		t.Errorf("filestore size after shrinking is %d bytes (was %d, pre-compaction mark %d), want page-aligned <= %d", fiAfter.Size(), fiBefore.Size(), endBeforeCompact, wantMax)
	}

	conf3 := p.importOnlyConf("image-1", fs2)
	c3, _, cleanup3, err := p.create(conf3, "sleep", "1000")
	if err != nil {
		t.Fatalf("create c3: %v", err)
	}
	if err := c3.Start(conf3); err != nil {
		cleanup3()
		t.Fatalf("start c3: %v", err)
	}
	if got, want := p.files(conf3, c3, "small", "big", "after"), "small\n-\nafter\n"; got != want {
		t.Errorf("files after shrinking and importing: got %q, want %q", got, want)
	}
	cleanup3()
}

type fileState struct {
	size int64
	data []byte
}

func snapshotFileState(t *testing.T, path string) fileState {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %q: %v", path, err)
	}
	end, ok, err := func() (uint64, bool, error) {
		f, err := os.Open(path)
		if err != nil {
			return 0, false, err
		}
		defer f.Close()
		return journal.FilestoreEnd(f)
	}()
	if err != nil || !ok {
		end = uint64(fi.Size())
	}
	buf := make([]byte, end)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %q: %v", path, err)
	}
	defer f.Close()
	n, err := unix.Pread(int(f.Fd()), buf, 0)
	if err != nil {
		t.Fatalf("pread %q: %v", path, err)
	}
	return fileState{size: fi.Size(), data: buf[:n]}
}

// TestJournalingRootfsUpperCheckpointPlainRestore checks both directions of
// checkpoint compatibility:
//  1. Checkpointing a journaled sandbox and restoring WITHOUT journaling.
//  2. Checkpointing a NON-journaled sandbox (where regular-file data occupies
//     page 0 of the filestore!) and restoring WITH journaling enabled, then
//     crashing and importing the newly journaled filestore!
func TestJournalingRootfsUpperCheckpointPlainRestore(t *testing.T) {
	p := newJournalingUpperTest(t)
	conf := p.conf("image-1", "")
	ckptDir := t.TempDir()
	fsDir := t.TempDir()

	c1, fs1, cleanup1 := p.start(conf)
	p.sh(conf, c1, "mkdir -p /journaled && echo A > /journaled/a && rm /lower-file")
	if err := c1.FSSave(conf, fsDir, sandbox.FSSaveOpts{Paths: []string{"/"}}); err != nil {
		t.Fatalf("FSSave: %v", err)
	}
	p.sh(conf, c1, "echo B > /journaled/b")
	if err := c1.Checkpoint(conf, ckptDir, sandbox.CheckpointOpts{}); err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	_, _ = c1.Wait()
	cleanup1()
	before := snapshotFileState(t, fs1)

	script := "cat /journaled/a /journaled/b 2>/dev/null; test -e /lower-file && echo lower present; echo C > /journaled/c"

	// 1a. Restore checkpoint WITHOUT journaling.
	plain := p.plainConf()
	root2, sysMounts2 := makeWritableRootfs(t)
	c2, cleanup2, err := p.createOnRoot(plain, root2, sysMounts2, nil, func(args *Args) { args.CheckpointDirPath = ckptDir }, "sleep", "1000")
	if err != nil {
		t.Fatalf("creating c2: %v", err)
	}
	if err := c2.Restore(plain, ckptDir, sandbox.DirectIOOff, false, nil); err != nil {
		cleanup2()
		t.Fatalf("Restore c2: %v", err)
	}
	if got, want := p.sh(plain, c2, script), "A\nB\n"; got != want {
		t.Errorf("after unjournaled restore: got %q, want %q", got, want)
	}
	// Now checkpoint the UNJOURNALED container c2 (whose first page 0 holds
	// regular-file data!) and restore into a JOURNALED container c2j!
	plainCkptDir := t.TempDir()
	if err := c2.Checkpoint(plain, plainCkptDir, sandbox.CheckpointOpts{}); err != nil {
		t.Fatalf("Checkpoint unjournaled c2: %v", err)
	}
	_, _ = c2.Wait()
	cleanup2()

	// Verify fs1 was never touched by c2.
	if got := snapshotFileState(t, fs1); got.size != before.size || !bytes.Equal(got.data, before.data) {
		t.Errorf("fs1 modified by plain restore")
	}

	// 1b. Start from filesystem checkpoint WITHOUT journaling.
	root3, sysMounts3 := makeWritableRootfs(t)
	c3, cleanup3, err := p.createOnRoot(plain, root3, sysMounts3, nil, func(args *Args) { args.FSRestoreImagePaths = []string{fsDir} }, "sleep", "1000")
	if err != nil {
		t.Fatalf("creating c3: %v", err)
	}
	if err := c3.Start(plain); err != nil {
		cleanup3()
		t.Fatalf("Start c3: %v", err)
	}
	if err := c3.WaitFSRestore(); err != nil {
		t.Fatalf("WaitFSRestore: %v", err)
	}
	if got, want := p.sh(plain, c3, script), "A\n"; got != want {
		t.Errorf("after plain fs-restore: got %q, want %q", got, want)
	}
	cleanup3()

	// 2. Restore the checkpoint taken from UNJOURNALED c2 WITH journaling
	// enabled, mutate, SIGKILL, and import!
	rootJ, sysMountsJ := makeWritableRootfs(t)
	cJ, cleanupJ, err := p.createOnRoot(conf, rootJ, sysMountsJ, nil, func(args *Args) { args.CheckpointDirPath = plainCkptDir }, "sleep", "1000")
	if err != nil {
		t.Fatalf("creating journaled restore container: %v", err)
	}
	fsJ := selfFilestoreOf(cJ)
	if err := cJ.Restore(conf, plainCkptDir, sandbox.DirectIOOff, false, nil); err != nil {
		cleanupJ()
		t.Fatalf("Restore into journaled container: %v", err)
	}
	waitActivePath(t, fsJ)
	if got, want := p.files(conf, cJ, "a", "b", "c"), "A\nB\nC\n"; got != want {
		t.Errorf("after journaled restore of unjournaled checkpoint: got %q, want %q", got, want)
	}
	p.sh(conf, cJ, "echo D > /journaled/d")
	p.kill(cJ, cleanupJ)

	confImp := p.importOnlyConf("image-1", fsJ)
	cImp, _, cleanupImp := p.start(confImp)
	if got, want := p.files(confImp, cImp, "a", "b", "c", "d"), "A\nB\nC\nD\n"; got != want {
		t.Errorf("after crash and import of journaled restore: got %q, want %q", got, want)
	}
	cleanupImp()
}

type journalingUpperImages struct {
	checkpoint   string
	fsCheckpoint string
	tar          string
}

func (p *journalingUpperTest) makeImages() journalingUpperImages {
	p.t.Helper()
	conf := p.conf("image-1", "")
	imgs := journalingUpperImages{
		checkpoint:   p.t.TempDir(),
		fsCheckpoint: p.t.TempDir(),
		tar:          filepath.Join(p.t.TempDir(), "upper.tar"),
	}
	c, _, cleanup := p.start(conf)
	p.sh(conf, c, "mkdir -p /journaled && echo A > /journaled/a")
	if err := c.FSSave(conf, imgs.fsCheckpoint, sandbox.FSSaveOpts{Paths: []string{"/"}}); err != nil {
		p.t.Fatalf("FSSave: %v", err)
	}
	tarFile, err := os.Create(imgs.tar)
	if err != nil {
		p.t.Fatalf("Create: %v", err)
	}
	if err := c.TarRootfsUpperLayer(tarFile); err != nil {
		p.t.Fatalf("TarRootfsUpperLayer: %v", err)
	}
	tarFile.Close()
	if err := c.Checkpoint(conf, imgs.checkpoint, sandbox.CheckpointOpts{}); err != nil {
		p.t.Fatalf("Checkpoint: %v", err)
	}
	_, _ = c.Wait()
	cleanup()
	return imgs
}

var populateMethods = []string{"restore", "fs-restore", "tar"}

func (p *journalingUpperTest) populate(conf *config.Config, method string, imgs journalingUpperImages) (*Container, string, func(), error) {
	p.t.Helper()
	conf.AllowRootfsTarAnnotation = true
	var (
		mutateSpec func(*specs.Spec)
		mutateArgs func(*Args)
	)
	switch method {
	case "restore":
		mutateArgs = func(args *Args) { args.CheckpointDirPath = imgs.checkpoint }
	case "fs-restore":
		mutateArgs = func(args *Args) { args.FSRestoreImagePaths = []string{imgs.fsCheckpoint} }
	case "tar":
		mutateSpec = func(spec *specs.Spec) {
			if spec.Annotations == nil {
				spec.Annotations = make(map[string]string)
			}
			spec.Annotations[specutils.AnnotationRootfsUpperTar] = imgs.tar
		}
	default:
		p.t.Fatalf("unknown method %q", method)
	}
	rootPath, sysMounts := makeWritableRootfs(p.t)
	c, cleanup, err := p.createOnRoot(conf, rootPath, sysMounts, mutateSpec, mutateArgs, "sleep", "1000")
	if err != nil {
		return nil, "", nil, err
	}
	fsPath := selfFilestoreOf(c)
	if method == "restore" {
		err = c.Restore(conf, imgs.checkpoint, sandbox.DirectIOOff, false, nil)
	} else {
		err = c.Start(conf)
	}
	if err != nil {
		cleanup()
		return nil, fsPath, nil, err
	}
	return c, fsPath, cleanup, nil
}

func waitActivePath(t *testing.T, path string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening %q: %v", path, err)
	}
	defer f.Close()
	deadline := time.Now().Add(pollTimeout)
	for {
		_, ok, err := journal.FilestoreEnd(f)
		if err != nil {
			t.Fatalf("journal.FilestoreEnd: %v", err)
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("journal in %q is still incomplete after %v", path, pollTimeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestJournalingRootfsUpperPopulateAndImportRefusal(t *testing.T) {
	src := newJournalingUpperTest(t)
	imgs := src.makeImages()

	// Create a valid exported filestore to verify that --journaling-rootfs-upper-import
	// is rejected when combined with restore, fs-restore, or tar.
	_, baseFS, cleanupBase := src.start(src.conf("image-1", ""))
	cleanupBase()

	for _, method := range populateMethods {
		t.Run(method, func(t *testing.T) {
			p := newJournalingUpperTest(t)
			// Combining import with populate is rejected.
			if _, _, cleanupBad, err := p.populate(p.conf("image-1", baseFS), method, imgs); err == nil {
				cleanupBad()
				t.Fatalf("%s combined with --journaling-rootfs-upper-import succeeded", method)
			}

			// Populating a new journaled container works, and after SIGKILL its
			// self filestore can be imported!
			conf := p.conf("image-1", "")
			c1, fs1, cleanup1, err := p.populate(conf, method, imgs)
			if err != nil {
				t.Fatalf("%s: %v", method, err)
			}
			waitActivePath(t, fs1)
			if hidden := p.sh(conf, c1, "ls -A / | grep '^\\.gvisor\\.filestore' || true"); hidden != "" {
				t.Errorf("after %s: self filestore visible inside container: %q", method, hidden)
			}
			if got, want := p.files(conf, c1, "a"), "A\n"; got != want {
				t.Errorf("after %s: got %q, want %q", method, got, want)
			}
			p.sh(conf, c1, "echo B > /journaled/b")
			p.kill(c1, cleanup1)

			impConf := p.importOnlyConf("image-1", fs1)
			c2, _, cleanup2 := p.start(impConf)
			if got, want := p.files(impConf, c2, "a", "b"), "A\nB\n"; got != want {
				t.Errorf("after crash and import: got %q, want %q", got, want)
			}
			cleanup2()
		})
	}
}

func (p *journalingUpperTest) expectKilled(c *Container) {
	p.t.Helper()
	ws, err := c.Wait()
	if err != nil {
		p.t.Fatalf("Wait: %v", err)
	}
	if !ws.Signaled() && ws.ExitStatus() == 0 {
		p.t.Fatalf("sandbox exited with status %v, want a failure", ws)
	}
}

func TestJournalingRootfsUpperActivationFailure(t *testing.T) {
	src := newJournalingUpperTest(t)
	imgs := src.makeImages()

	for _, method := range populateMethods {
		t.Run(method, func(t *testing.T) {
			p := newJournalingUpperTest(t)
			failConf := p.conf("image-1", "")
			failConf.TestOnlyJournalingRootfsUpperFault = "activation"
			c, fsPath, cleanup, err := p.populate(failConf, method, imgs)
			if method == "tar" {
				if err == nil || !strings.Contains(err.Error(), "journaling rootfs upper") {
					if err == nil {
						cleanup()
					}
					t.Fatalf("tar import with failing activation: got %v, want journaling rootfs upper error", err)
				}
			} else {
				if err != nil {
					t.Fatalf("%s: %v", method, err)
				}
				p.expectKilled(c)
				cleanup()
			}

			// The preserved filestore must be marked incomplete, and importing it
			// must fail with ErrIncomplete!
			f, openErr := os.Open(fsPath)
			if openErr != nil {
				t.Fatalf("Open(%q): %v", fsPath, openErr)
			}
			incomplete, incErr := journal.Incomplete(f)
			f.Close()
			if incErr != nil || !incomplete {
				t.Fatalf("journal.Incomplete(%q) = %t, %v; want true, nil", fsPath, incomplete, incErr)
			}

			impConf := p.importOnlyConf("image-1", fsPath)
			cImp, _, cleanupImp, impErr := p.create(impConf, "sleep", "1000")
			if impErr == nil {
				impErr = cImp.Start(impConf)
				cleanupImp()
			}
			if impErr == nil || !strings.Contains(impErr.Error(), "is incomplete") {
				t.Fatalf("importing incomplete filestore: got %v, want incomplete error", impErr)
			}
		})
	}
}

func TestJournalingRootfsUpperSaveResume(t *testing.T) {
	p := newJournalingUpperTest(t)
	conf := p.conf("image-1", "")
	ckptDir := t.TempDir()

	c1, fs1, cleanup1 := p.start(conf)
	p.sh(conf, c1, "mkdir -p /journaled && echo A > /journaled/a && echo B > /journaled/b")
	if err := c1.Checkpoint(conf, ckptDir, sandbox.CheckpointOpts{Resume: true}); err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	p.sh(conf, c1, "echo C > /journaled/c && rm /journaled/b")
	p.kill(c1, cleanup1)

	impConf := p.importOnlyConf("image-1", fs1)
	c2, _, cleanup2 := p.start(impConf)
	if got, want := p.files(impConf, c2, "a", "b", "c"), "A\n-\nC\n"; got != want {
		t.Errorf("after save-resume, crash, and import: got %q, want %q", got, want)
	}
	cleanup2()
}

func TestJournalingRootfsUpperLargeSnapshot(t *testing.T) {
	p := newJournalingUpperTest(t)
	conf1 := p.conf("image-1", "")
	conf1.TestOnlyJournalingRootfsUpperRegionSize = 16 << 10
	const n = 500

	c1, fs1, cleanup1 := p.start(conf1)
	p.sh(conf1, c1, fmt.Sprintf(`
mkdir -p /journaled/many
i=0
while [ $i -lt %d ]; do echo $i > /journaled/many/file-with-a-long-name-$i; i=$((i+1)); done
`, n))
	p.kill(c1, cleanup1)

	check := func(what string, conf *config.Config, c *Container) {
		t.Helper()
		got := p.sh(conf, c, "ls /journaled/many | wc -l; cat /journaled/many/file-with-a-long-name-123")
		if want := fmt.Sprintf("%d\n123\n", n); strings.TrimLeft(got, " ") != want {
			t.Errorf("%s: got %q, want %q", what, got, want)
		}
	}

	conf2 := p.conf("image-1", fs1)
	conf2.TestOnlyJournalingRootfsUpperRegionSize = 16 << 10
	c2, fs2, cleanup2 := p.start(conf2)
	check("after first crash and import", conf2, c2)
	p.sh(conf2, c2, "echo new > /journaled/new")
	p.kill(c2, cleanup2)

	conf3 := p.importOnlyConf("image-1", fs2)
	c3, _, cleanup3 := p.start(conf3)
	check("after second crash and import", conf3, c3)
	if got, want := p.files(conf3, c3, "new"), "new\n"; got != want {
		t.Errorf("after second crash and import: got %q, want %q", got, want)
	}
	cleanup3()
}

type multiUpperTest struct {
	t           *testing.T
	conf        *config.Config
	enabled     [2]bool
	imports     [2]string
	imageIDs    [2]string
	rootViaFlag bool
}

var multiUpperNames = [2]string{"root", "sub"}

func newMultiUpperTest(t *testing.T) *multiUpperTest {
	t.Helper()
	conf := testutil.TestConfig(t)
	if err := conf.Overlay2.Set("root:self"); err != nil {
		t.Fatalf("Overlay2.Set: %v", err)
	}
	rootDir, cleanup, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("SetupRootDir: %v", err)
	}
	t.Cleanup(cleanup)
	conf.RootDir = rootDir
	conf.JournalingRootfsUpperAnnotations = config.JournalingRootfsUpperAnnotationsOn
	return &multiUpperTest{
		t:        t,
		conf:     conf,
		enabled:  [2]bool{true, true},
		imageIDs: [2]string{"image-1", "image-1"},
	}
}

func (m *multiUpperTest) specs() ([]*specs.Spec, []string, *config.Config) {
	conf := *m.conf
	sps, ids := createSpecs(sleepCmd, sleepCmd)
	for i, spec := range sps {
		rootPath, sysMounts := makeWritableRootfs(m.t)
		applyWritableRootfs(spec, rootPath, sysMounts)
		name := multiUpperNames[i]
		spec.Annotations[specutils.ContainerdContainerNameAnnotation] = name
		if !m.enabled[i] && m.imports[i] == "" {
			continue
		}
		if i == 0 && m.rootViaFlag {
			if m.enabled[i] {
				conf.JournalingRootfsUpper = config.JournalingRootfsUpperOn
			} else {
				conf.JournalingRootfsUpper = config.JournalingRootfsUpperOff
			}
			conf.JournalingRootfsUpperImport = m.imports[i]
			conf.JournalingRootfsUpperImageID = m.imageIDs[i]
			continue
		}
		if m.enabled[i] {
			spec.Annotations[specutils.AnnotationRootfsUpperJournal+"."+name] = "true"
		}
		if m.imports[i] != "" {
			spec.Annotations[specutils.AnnotationRootfsUpperJournalImport+"."+name] = m.imports[i]
		}
		if m.imageIDs[i] != "" {
			spec.Annotations[specutils.AnnotationRootfsUpperJournalImageID+"."+name] = m.imageIDs[i]
		}
	}
	return sps, ids, &conf
}

func (m *multiUpperTest) start() ([]*Container, [2]string, func(), *config.Config) {
	m.t.Helper()
	specs, ids, conf := m.specs()
	cs, cleanup, err := startContainers(conf, specs, ids)
	if err != nil {
		m.t.Fatalf("starting containers: %v", err)
	}
	fsPaths := [2]string{selfFilestoreOf(cs[0]), selfFilestoreOf(cs[1])}
	return cs, fsPaths, func() {
		cleanup()
		for _, p := range fsPaths {
			waitUnlockedPath(m.t, p)
		}
	}, conf
}

func (m *multiUpperTest) kill(cs []*Container, cleanup func()) {
	m.t.Helper()
	if err := unix.Kill(cs[0].SandboxPid(), unix.SIGKILL); err != nil {
		m.t.Fatalf("killing sandbox: %v", err)
	}
	_, _ = cs[0].Wait()
	cleanup()
}

func (m *multiUpperTest) sh(conf *config.Config, c *Container, script string) string {
	m.t.Helper()
	out, err := executeCombinedOutput(conf, c, nil, "/bin/sh", "-c", script)
	if err != nil {
		m.t.Fatalf("script %q failed: %v, output: %s", script, err, out)
	}
	return string(out)
}

func (m *multiUpperTest) files(conf *config.Config, c *Container, names ...string) string {
	m.t.Helper()
	script := ""
	for _, name := range names {
		script += fmt.Sprintf("cat /journaled/%s 2>/dev/null || echo -; ", name)
	}
	return m.sh(conf, c, script)
}

func TestJournalingRootfsUpperMultiContainer(t *testing.T) {
	for _, rootViaFlag := range []bool{false, true} {
		t.Run(fmt.Sprintf("rootViaFlag=%t", rootViaFlag), func(t *testing.T) {
			m := newMultiUpperTest(t)
			m.rootViaFlag = rootViaFlag

			cs, fsPaths1, cleanup, conf := m.start()
			m.sh(conf, cs[0], "mkdir -p /journaled && echo R > /journaled/root")
			m.sh(conf, cs[1], "mkdir -p /journaled && echo S > /journaled/sub")
			m.kill(cs, cleanup)

			check := func(what string, conf *config.Config, cs []*Container, want0, want1 string) {
				t.Helper()
				if got := m.files(conf, cs[0], "root", "sub", "more"); got != want0 {
					t.Errorf("%s: root container files: got %q, want %q", what, got, want0)
				}
				if got := m.files(conf, cs[1], "root", "sub", "more"); got != want1 {
					t.Errorf("%s: subcontainer files: got %q, want %q", what, got, want1)
				}
			}

			m.imports = fsPaths1
			cs, fsPaths2, cleanup, conf := m.start()
			check("after crash and import", conf, cs, "R\n-\n-\n", "-\nS\n-\n")
			m.sh(conf, cs[1], "echo M > /journaled/more")
			cleanup()

			m.enabled = [2]bool{false, false}
			m.imports = fsPaths2
			cs, _, cleanup, conf = m.start()
			check("after clean unjournaled import", conf, cs, "R\n-\n-\n", "-\nS\nM\n")
			cleanup()
		})
	}
}

func TestJournalingRootfsUpperSubcontainerNotJournaled(t *testing.T) {
	m := newMultiUpperTest(t)
	m.enabled[1] = false
	cs, fsPaths, cleanup, conf := m.start()
	m.sh(conf, cs[0], "mkdir -p /journaled && echo R > /journaled/root")
	m.sh(conf, cs[1], "mkdir -p /journaled && echo S > /journaled/sub")
	cleanup()

	if _, err := os.Stat(fsPaths[0]); err != nil {
		t.Fatalf("journaled root filestore deleted on Destroy: %v", err)
	}
	if _, err := os.Stat(fsPaths[1]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unjournaled subcontainer filestore was not deleted on Destroy: err=%v", err)
	}
}

func TestJournalingRootfsUpperSubcontainerImageMismatch(t *testing.T) {
	m := newMultiUpperTest(t)
	cs, fsPaths, cleanup, conf := m.start()
	m.sh(conf, cs[1], "mkdir -p /journaled && echo S > /journaled/sub")
	cleanup()

	m.imports = fsPaths
	m.imageIDs[1] = "image-2"
	specs, ids, conf := m.specs()
	if _, cleanupBad, err := startContainers(conf, specs, ids); err == nil {
		cleanupBad()
		t.Fatalf("starting subcontainer with mismatched image ID succeeded")
	} else if !strings.Contains(err.Error(), `journal was created for image "image-1"`) {
		t.Errorf("subcontainer mismatched image ID: got %v, want image mismatch", err)
	}
	waitUnlockedPath(t, fsPaths[0])
	waitUnlockedPath(t, fsPaths[1])

	m.imageIDs[1] = "image-1"
	m.enabled = [2]bool{false, false}
	cs, _, cleanup, conf = m.start()
	if got, want := m.files(conf, cs[1], "sub"), "S\n"; got != want {
		t.Errorf("subcontainer files after failed mismatch attempt: got %q, want %q", got, want)
	}
	cleanup()
}

func TestJournalingRootfsUpperMultiContainerCheckpoint(t *testing.T) {
	src := newMultiUpperTest(t)
	ckptDir := t.TempDir()
	cs, _, cleanup, conf := src.start()
	src.sh(conf, cs[0], "mkdir -p /journaled && echo R > /journaled/root")
	src.sh(conf, cs[1], "mkdir -p /journaled && echo S > /journaled/sub")
	if err := cs[0].Checkpoint(conf, ckptDir, sandbox.CheckpointOpts{}); err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	_, _ = cs[0].Wait()
	cleanup()

	// Restore with runtime journaling enabled on both containers.
	m := newMultiUpperTest(t)
	specs, ids, conf := m.specs()
	cs, cleanupRestore, err := restoreContainers(conf, specs, ids, ckptDir)
	if err != nil {
		t.Fatalf("restoring containers: %v", err)
	}
	fsPaths := [2]string{selfFilestoreOf(cs[0]), selfFilestoreOf(cs[1])}
	cleanup = func() {
		cleanupRestore()
		waitUnlockedPath(t, fsPaths[0])
		waitUnlockedPath(t, fsPaths[1])
	}
	for i := range cs {
		waitActivePath(t, fsPaths[i])
		if got, want := m.files(conf, cs[i], "root", "sub"), [2]string{"R\n-\n", "-\nS\n"}[i]; got != want {
			t.Errorf("container %d files after restore: got %q, want %q", i, got, want)
		}
	}
	m.sh(conf, cs[0], "echo R2 > /journaled/root2")
	m.sh(conf, cs[1], "echo S2 > /journaled/sub2")
	m.kill(cs, cleanup)

	mImp := newMultiUpperTest(t)
	mImp.enabled = [2]bool{false, false}
	mImp.imports = fsPaths
	cs, _, cleanup, conf = mImp.start()
	if got, want := mImp.files(conf, cs[0], "root", "root2", "sub", "sub2"), "R\nR2\n-\n-\n"; got != want {
		t.Errorf("root container files after crash and import: got %q, want %q", got, want)
	}
	if got, want := mImp.files(conf, cs[1], "root", "root2", "sub", "sub2"), "-\n-\nS\nS2\n"; got != want {
		t.Errorf("subcontainer files after crash and import: got %q, want %q", got, want)
	}
	cleanup()
}

func TestJournalingRootfsUpperOverlayValidation(t *testing.T) {
	p := newJournalingUpperTest(t)

	// Runtime journaling requires a file-backed rootfs overlay (rejects none and memory).
	for _, medium := range []string{"none", "root:memory"} {
		t.Run("journal-"+medium, func(t *testing.T) {
			conf := p.conf("image-1", "")
			if err := conf.Overlay2.Set(medium); err != nil {
				t.Fatalf("Overlay2.Set(%q): %v", medium, err)
			}
			c, _, cleanup, err := p.create(conf, "sleep", "1000")
			if err == nil {
				err = c.Start(conf)
				cleanup()
			}
			if err == nil || !strings.Contains(err.Error(), "requires a file-backed rootfs overlay") {
				t.Fatalf("starting with %q: got %v, want file-backed rootfs overlay error", medium, err)
			}
		})
	}

	// Import without runtime journaling works even when --overlay2=root:memory
	// is configured, and rejects --overlay2=none!
	cSrc, fsSrc, cleanupSrc := p.start(p.conf("image-1", ""))
	p.sh(p.conf("image-1", ""), cSrc, "mkdir -p /journaled && echo MEM > /journaled/m")
	cleanupSrc()

	memConf := p.importOnlyConf("image-1", fsSrc)
	if err := memConf.Overlay2.Set("root:memory"); err != nil {
		t.Fatalf("Overlay2.Set: %v", err)
	}
	cMem, _, cleanupMem := p.start(memConf)
	if got, want := p.files(memConf, cMem, "m"), "MEM\n"; got != want {
		t.Errorf("import with root:memory: got %q, want %q", got, want)
	}
	cleanupMem()

	noneConf := p.importOnlyConf("image-1", fsSrc)
	if err := noneConf.Overlay2.Set("none"); err != nil {
		t.Fatalf("Overlay2.Set: %v", err)
	}
	if _, _, cleanupNone, err := p.create(noneConf, "sleep", "1000"); err == nil {
		cleanupNone()
		t.Fatalf("import with overlay2=none succeeded")
	}
}

func TestJournalingRootfsUpperAnnotationGateAndFastExit(t *testing.T) {
	p := newJournalingUpperTest(t)

	// Annotations are rejected unless JournalingRootfsUpperAnnotations is on, and
	// /proc/self/fd/* is rejected in annotations even when enabled.
	rootPath, sysMounts := makeWritableRootfs(t)
	plain := p.plainConf()
	if _, cleanup, err := p.createOnRoot(plain, rootPath, sysMounts, func(spec *specs.Spec) {
		spec.Annotations = map[string]string{specutils.AnnotationRootfsUpperJournal: "true"}
	}, nil, "sleep", "1000"); err == nil {
		cleanup()
		t.Fatalf("annotation succeeded without --journaling-rootfs-upper-annotations=on")
	}
	allowConf := p.plainConf()
	allowConf.JournalingRootfsUpperAnnotations = config.JournalingRootfsUpperAnnotationsOn
	if _, cleanup, err := p.createOnRoot(allowConf, rootPath, sysMounts, func(spec *specs.Spec) {
		spec.Annotations = map[string]string{specutils.AnnotationRootfsUpperJournalImport: "/proc/self/fd/3"}
	}, nil, "sleep", "1000"); err == nil {
		cleanup()
		t.Fatalf("procfs import annotation succeeded")
	}

	// A short-lived container started from fs-restore that exits 0 immediately
	// must wait for background journal activation before tearing down so its
	// preserved filestore is complete and importable.
	imgs := p.makeImages()
	conf := p.conf("image-1", "")
	rootFast, sysMountsFast := makeWritableRootfs(t)
	cFast, cleanupFast, err := p.createOnRoot(conf, rootFast, sysMountsFast, nil, func(args *Args) {
		args.FSRestoreImagePaths = []string{imgs.fsCheckpoint}
	}, "/bin/sh", "-c", "echo fast > /journaled/fast")
	if err != nil {
		t.Fatalf("createOnRoot: %v", err)
	}
	fsFast := selfFilestoreOf(cFast)
	if err := cFast.Start(conf); err != nil {
		cleanupFast()
		t.Fatalf("Start: %v", err)
	}
	if ws, err := cFast.Wait(); err != nil || ws.ExitStatus() != 0 {
		cleanupFast()
		t.Fatalf("Wait: %v, %v", ws, err)
	}
	cleanupFast()

	impConf := p.importOnlyConf("image-1", fsFast)
	cImp, _, cleanupImp := p.start(impConf)
	if got, want := p.files(impConf, cImp, "a", "fast"), "A\nfast\n"; got != want {
		t.Errorf("after fast-exit fs-restore and import: got %q, want %q", got, want)
	}
	cleanupImp()
}
