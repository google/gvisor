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
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/state/statefile"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/sandbox"
	"gvisor.dev/gvisor/runsc/specutils"
)

// requireFilestoreReflink probes the test filesystem before starting a sandbox.
// Set TEST_TMPDIR to an XFS (reflink=1) or btrfs directory to run these tests.
func requireFilestoreReflink(t *testing.T, dir string) {
	t.Helper()
	src, err := os.CreateTemp(dir, "reflink-source")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	defer os.Remove(src.Name())
	dst, err := os.CreateTemp(dir, "reflink-destination")
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	defer os.Remove(dst.Name())
	if _, err := src.Write([]byte("reflink test")); err != nil {
		t.Fatal(err)
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, dst.Fd(), unix.FICLONE, src.Fd()); errno != 0 {
		if errno == unix.EOPNOTSUPP || errno == unix.ENOTTY || errno == unix.EINVAL {
			t.Skipf("test filesystem does not support reflink: %v", errno)
		}
		t.Fatal(errno)
	}
}

func TestExternalFilestoreCheckpointRestore(t *testing.T) {
	if !testutil.IsCheckpointSupported() {
		t.Skip("checkpoint unsupported")
	}
	dir, err := os.MkdirTemp(testutil.TmpDir(), "external-filestore-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	requireFilestoreReflink(t, dir)
	for platform, platformConf := range configs(t, true /* noOverlay */) {
		for _, tc := range []struct {
			name                                                        string
			resume, persistenceFailure, readOnlyRoot, reorder, relocate bool
			compression                                                 statefile.CompressionLevel
		}{
			{name: "stop", compression: statefile.CompressionLevelNone},
			{name: "resume", resume: true, compression: statefile.CompressionLevelNone},
			{name: "persistence-failure", persistenceFailure: true, compression: statefile.CompressionLevelNone},
			{name: "compressed", resume: true, compression: statefile.CompressionLevelFlateBestSpeed},
			{name: "read-only-root", resume: true, readOnlyRoot: true, compression: statefile.CompressionLevelNone},
			{name: "reordered-stop", reorder: true, compression: statefile.CompressionLevelNone},
			{name: "reordered-resume", reorder: true, resume: true, compression: statefile.CompressionLevelNone},
			{name: "reordered-read-only-root", reorder: true, resume: true, readOnlyRoot: true, compression: statefile.CompressionLevelNone},
			{name: "reordered-relocated-sources", reorder: true, relocate: true, resume: true, compression: statefile.CompressionLevelNone},
		} {
			resume := tc.resume
			t.Run(platform+"/"+tc.name, func(t *testing.T) {
				confCopy := *platformConf
				conf := &confCopy
				if err := conf.Overlay2.Set("all:dir=" + dir); err != nil {
					t.Fatal(err)
				}
				conf.FilestoreReflink = config.FilestoreReflinkEnabled
				// The rootfs uses the host's /var/run -> /run symlink. This mount's
				// canonical path differs from its OCI destination.
				target, err := filepath.EvalSymlinks("/var/run")
				if err != nil || target != "/run" {
					t.Skip("requires /var/run -> /run")
				}
				lower, err := os.MkdirTemp(dir, "lower-")
				if err != nil {
					t.Fatal(err)
				}
				spec := testutil.NewSpecWithArgs("sleep", "100000")
				spec.Root.Readonly = tc.readOnlyRoot
				mount := "/var/run/gvisor-filestore-test"
				spec.Mounts = append(spec.Mounts,
					specs.Mount{Source: lower, Destination: mount, Type: "bind", Options: []string{"bind"}},
					specs.Mount{Destination: "/filestore-tmpfs", Type: "tmpfs"},
					specs.Mount{Source: lower, Destination: "/reorder-second", Type: "bind", Options: []string{"bind"}})
				_, bundle, cleanup, err := testutil.SetupContainer(spec, conf)
				if err != nil {
					t.Fatal(err)
				}
				defer cleanup()
				args := Args{ID: testutil.RandomContainerID(), Spec: spec, BundleDir: bundle}
				cont, err := New(conf, args)
				if err != nil {
					t.Fatal(err)
				}
				defer cont.Destroy()
				if err := cont.Start(conf); err != nil {
					t.Fatal(err)
				}
				paths := []string{mount + "/data", "/filestore-tmpfs/data", "/reorder-second/data"}
				if !tc.readOnlyRoot {
					paths = append(paths, "/filestore-root-data")
				}
				write := func(c *Container, cfg *config.Config, value string) {
					t.Helper()
					for i, name := range paths {
						if ws, err := execute(cfg, c, "/bin/sh", "-c", fmt.Sprintf("printf '%s-%d' > %s", value, i, name)); err != nil || ws.ExitStatus() != 0 {
							t.Fatalf("write %s: status=%v err=%v", name, ws, err)
						}
					}
				}
				check := func(c *Container, cfg *config.Config, value string) {
					t.Helper()
					for i, name := range paths {
						out, err := executeCombinedOutput(cfg, c, nil, "/bin/cat", name)
						want := fmt.Sprintf("%s-%d", value, i)
						if err != nil || string(out) != want {
							t.Fatalf("read %s: %q, %v; want %q", name, out, err, want)
						}
					}
				}
				write(cont, conf, "checkpoint")
				invalidDir := filepath.Join(dir, "unsupported-split")
				if err := cont.Checkpoint(conf, dir, sandbox.CheckpointOpts{FilestoreSnapshotDir: invalidDir, SplitFSCheckpointPaths: []string{"all-tmpfs"}}); err == nil {
					t.Fatal("accepted external split filesystem checkpoint")
				}
				check(cont, conf, "checkpoint")

				image, err := os.MkdirTemp(dir, "image-")
				if err != nil {
					t.Fatal(err)
				}
				snapshots := image + "-filestores"
				opts := sandbox.CheckpointOpts{Resume: resume, Compression: tc.compression, FilestoreSnapshotDir: snapshots}
				if tc.persistenceFailure {
					// Capture into the real destination FDs, then force a real
					// directory fsync failure after the stopping RPC returns.
					// No source sandbox remains to rescue a deleted snapshot.
					err := cont.checkpoint(conf, image, opts, func(conf *config.Config, cid, image string, opts sandbox.CheckpointOpts) error {
						opts.FilestoreSnapshotDir = "/proc"
						return cont.Sandbox.Checkpoint(conf, cid, image, opts)
					})
					if !errors.Is(err, unix.EINVAL) {
						t.Fatalf("post-capture directory sync: %v; want EINVAL", err)
					}
				} else if err := cont.Checkpoint(conf, image, opts); err != nil {
					t.Fatal(err)
				}
				if resume {
					write(cont, conf, "source-changed")
					check(cont, conf, "source-changed")
				} else {
					// Exercise real tmpfs destruction before using the snapshots.
					if err := cont.Destroy(); err != nil {
						t.Fatal(err)
					}
				}
				if tc.reorder {
					// Restore permits a different OCI mount order. Each mount
					// must retain its own contents even when backing files have
					// the same chunk-sized length.
					restoreSpec := *spec
					restoreSpec.Mounts = append([]specs.Mount(nil), spec.Mounts...)
					first, second := len(restoreSpec.Mounts)-3, len(restoreSpec.Mounts)-1
					restoreSpec.Mounts[first], restoreSpec.Mounts[second] = restoreSpec.Mounts[second], restoreSpec.Mounts[first]
					if tc.relocate {
						newLower, err := os.MkdirTemp(dir, "relocated-lower-")
						if err != nil {
							t.Fatal(err)
						}
						restoreSpec.Mounts[first].Source, restoreSpec.Mounts[second].Source = newLower, newLower
					}
					restoreBundle, restoreCleanup, err := testutil.SetupBundleDir(&restoreSpec)
					if err != nil {
						t.Fatal(err)
					}
					defer restoreCleanup()
					args.Spec, args.BundleDir = &restoreSpec, restoreBundle
				}
				restoredConf := *conf
				restoredConf.FilestoreAdoptDir = snapshots
				for i := 0; i < 2; i++ {
					args.ID = testutil.RandomContainerID()
					args.CheckpointDirPath = image
					restored, err := New(&restoredConf, args)
					if err != nil {
						t.Fatal(err)
					}
					defer restored.Destroy()
					if err := restored.Restore(&restoredConf, image, sandbox.DirectIOOff, false, nil); err != nil {
						t.Fatal(err)
					}
					check(restored, &restoredConf, "checkpoint")
					write(restored, &restoredConf, fmt.Sprintf("clone-%d", i))
					if tc.reorder && i == 0 {
						// Save from the reordered layout and restore with the
						// original order, exercising a second checkpoint cycle.
						secondImage, err := os.MkdirTemp(dir, "second-image-")
						if err != nil {
							t.Fatal(err)
						}
						secondSnapshots := secondImage + "-filestores"
						if err := restored.Checkpoint(&restoredConf, secondImage, sandbox.CheckpointOpts{Resume: true, FilestoreSnapshotDir: secondSnapshots}); err != nil {
							t.Fatal(err)
						}
						secondConf := *conf
						secondConf.FilestoreAdoptDir = secondSnapshots
						second, err := New(&secondConf, Args{ID: testutil.RandomContainerID(), Spec: spec, BundleDir: bundle, CheckpointDirPath: secondImage})
						if err != nil {
							t.Fatal(err)
						}
						defer second.Destroy()
						if err := second.Restore(&secondConf, secondImage, sandbox.DirectIOOff, false, nil); err != nil {
							t.Fatal(err)
						}
						check(second, &secondConf, "clone-0")
					}
				}
				if resume {
					check(cont, conf, "source-changed")
				}
			})
		}
	}
}

// TestExternalFilestoreFailureCleanup models both a lost save response and
// post-capture persistence errors. Both can follow termination of the source.
func TestExternalFilestoreFailureCleanup(t *testing.T) {
	for _, tc := range []struct {
		name      string
		attempted bool
		failure   error
	}{
		{"before-rpc", false, unix.EIO},
		{"lost-response", true, unix.ECONNRESET},
		{"disk-full", true, unix.ENOSPC},
		{"sync-io-error", true, unix.EIO},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := os.MkdirTemp(testutil.TmpDir(), "filestore-cleanup-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			requireFilestoreReflink(t, dir)
			c := &Container{Spec: &specs.Spec{}, Status: Running, Sandbox: &sandbox.Sandbox{FilestoreReflink: true}, GoferMountConfs: []specutils.GoferMountConf{{Upper: specutils.AnonOverlay}}}
			opts := sandbox.CheckpointOpts{FilestoreSnapshotDir: filepath.Join(dir, "snapshots")}
			var files []*os.File
			err = c.checkpoint(&config.Config{}, dir, opts, func(_ *config.Config, _, _ string, opts sandbox.CheckpointOpts) error {
				files = opts.FilestoreSnapshotFiles
				if tc.attempted {
					opts.SaveStarted()
				}
				for _, f := range files {
					if _, err := f.Write([]byte("only surviving copy")); err != nil {
						t.Fatal(err)
					}
				}
				return tc.failure
			})
			if !errors.Is(err, tc.failure) {
				t.Fatalf("checkpoint: %v; want %v", err, tc.failure)
			}
			for _, f := range files {
				if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Errorf("FD not closed: %v", err)
				}
				data, err := os.ReadFile(f.Name())
				if tc.attempted {
					if err != nil || string(data) != "only surviving copy" {
						t.Errorf("lost recovery artifact: %q, %v", data, err)
					}
				} else if !os.IsNotExist(err) {
					t.Errorf("pre-RPC artifact not removed: %v", err)
				}
			}
		})
	}
}
