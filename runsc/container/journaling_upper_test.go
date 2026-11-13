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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
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

func selfFilestoreOf(c *Container) string {
	return sentryapi.SelfFilestorePath(c.Spec.Root.Path, c.Saver.ID.SandboxID)
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
