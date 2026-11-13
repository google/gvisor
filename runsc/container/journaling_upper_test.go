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

}
