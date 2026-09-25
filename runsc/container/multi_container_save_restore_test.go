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

// This file holds the save/restore (checkpoint/restore) tests that involve more
// than one container.

package container

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/fscheckpoint"
	fspb "gvisor.dev/gvisor/pkg/sentry/fscheckpoint/fscheckpoint_proto_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/state/checkpointfiles"
	"gvisor.dev/gvisor/pkg/state/statefile"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/sandbox"
	"gvisor.dev/gvisor/runsc/specutils"
)

func restoreContainers(conf *config.Config, specs []*specs.Spec, ids []string, imagePath string) ([]*Container, func(), error) {
	if len(conf.RootDir) == 0 {
		panic("conf.RootDir not set. Call testutil.SetupRootDir() to set.")
	}

	cu := cleanup.Cleanup{}
	defer cu.Clean()

	var containers []*Container
	for i, spec := range specs {
		bundleDir, cleanup, err := testutil.SetupBundleDir(spec)
		if err != nil {
			return nil, nil, fmt.Errorf("error setting up container: %v", err)
		}
		cu.Add(cleanup)

		args := Args{
			ID:                ids[i],
			Spec:              spec,
			BundleDir:         bundleDir,
			CheckpointDirPath: imagePath,
		}
		cont, err := New(conf, args)
		if err != nil {
			return nil, nil, fmt.Errorf("error creating container: %v", err)
		}
		cu.Add(func() { cont.Destroy() })
		containers = append(containers, cont)

		if err := cont.Restore(conf, imagePath, false /* direct */, false /* background */, nil /* networkArgs */); err != nil {
			return nil, nil, fmt.Errorf("error restoring container: %v", err)
		}

		time.Sleep(100 * time.Millisecond)
	}

	restoreWaiter := make(chan error, 1)
	go func() {
		restoreWaiter <- containers[0].WaitRestore()
	}()

	// WaitRestore() should return after restore is complete.
	select {
	case waitErr := <-restoreWaiter:
		if waitErr != nil {
			return nil, nil, waitErr
		}
	case <-time.After(10 * time.Second):
		return nil, nil, fmt.Errorf("error waiting for restore to complete")
	}

	return containers, cu.Release(), nil
}

// TestCheckpointRestore tests that checkpoint/restore works
// with multi-containers.
func TestMultiContainerCheckpointRestore(t *testing.T) {
	// Skip overlay because test requires writing to host file.
	for name, conf := range configs(t, true /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
			compressionLevels := []statefile.CompressionLevel{
				statefile.CompressionLevelNone,
				statefile.CompressionLevelFlateBestSpeed,
			}
			for _, compression := range compressionLevels {
				t.Run(string(compression), func(t *testing.T) {
					testMultiContainerCheckpointRestore(t, conf, compression)
				})
			}
		})
	}
}

func testMultiContainerCheckpointRestore(t *testing.T, conf *config.Config, compression statefile.CompressionLevel) {
	rootDir, cleanup, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("error creating root dir: %v", err)
	}
	defer cleanup()
	conf.RootDir = rootDir

	dir, err := os.MkdirTemp(testutil.TmpDir(), "checkpoint-test")
	if err != nil {
		t.Fatalf("os.MkdirTemp() failed: %v", err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatalf("error chmoding file: %q, %v", dir, err)
	}

	outputPath := filepath.Join(dir, "output")
	outputFile, err := createWriteableOutputFile(outputPath)
	if err != nil {
		t.Fatalf("error creating output file: %v", err)
	}
	defer outputFile.Close()

	// Create 3 containers. First requires a restore call, second requires a restoreSubcontainer
	// that needs to wait, third issues a restoreSubcontainer call that actually restores the
	// entire sandbox.
	script := fmt.Sprintf("for ((i=0; ;i++)); do echo $i >> %q; sleep 1; done", outputPath)
	testSpecs, ids := createSpecs(
		sleepCmd,
		[]string{"bash", "-c", script},
		sleepCmd,
	)

	conts, cleanup, err := startContainers(conf, testSpecs, ids)
	if err != nil {
		t.Fatalf("error starting containers: %v", err)
	}
	defer cleanup()

	// Wait until application has ran.
	if err := waitForFileNotEmpty(outputFile); err != nil {
		t.Fatalf("Failed to wait for output file: %v", err)
	}

	checkpointWaiter := make(chan error, 1)
	go func() {
		// WaitCheckpoint on the second container.
		checkpointWaiter <- conts[1].WaitCheckpoint()
	}()

	// Checkpoint root container; save state into new file.
	if err := conts[0].Checkpoint(conf, dir, sandbox.CheckpointOpts{Compression: compression}); err != nil {
		t.Fatalf("error checkpointing container to empty file: %v", err)
	}

	// Wait for the checkpoint to complete. The initial sandbox not destroyed yet
	// to check that no conflict with it occurs during restore.
	select {
	case waitErr := <-checkpointWaiter:
		if waitErr != nil {
			t.Errorf("error waiting for checkpoint to complete: %v", waitErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for checkpoint to complete")
	}

	lastNum, err := readOutputNum(outputPath, -1)
	if err != nil {
		t.Fatalf("error with outputFile: %v", err)
	}

	// Restore into new containers with different IDs.
	newIds := make([]string, 0, len(ids))
	for range ids {
		newIds = append(newIds, testutil.RandomContainerID())
	}
	for _, specs := range testSpecs[1:] {
		specs.Annotations[specutils.ContainerdSandboxIDAnnotation] = newIds[0]
	}

	for range 2 {
		// Delete and recreate file before restoring.
		if err := os.Remove(outputPath); err != nil {
			t.Fatalf("error removing file")
		}
		outputFile2, err := createWriteableOutputFile(outputPath)
		if err != nil {
			t.Fatalf("error creating output file: %v", err)
		}
		defer outputFile2.Close()

		conts2, cleanup2, err := restoreContainers(conf, testSpecs, newIds, dir)
		if err != nil {
			t.Fatalf("error restoring containers: %v", err)
		}
		defer cleanup2()

		// Wait until application has ran.
		if err := waitForFileNotEmpty(outputFile2); err != nil {
			t.Fatalf("Failed to wait for output file: %v", err)
		}

		firstNum, err := readOutputNum(outputPath, 0)
		if err != nil {
			t.Fatalf("error with outputFile: %v", err)
		}

		// Check that lastNum is one less than firstNum and that the container
		// picks up from where it left off.
		if lastNum+1 != firstNum {
			t.Errorf("error numbers not in order, previous: %d, next: %d", lastNum, firstNum)
		}

		for _, cont := range conts2 {
			state := cont.State()
			if state.Status != Running {
				t.Fatalf("container %v is not running: %v", cont.ID, state.Status)
			}
		}

		// Future restores will reuse newIds. It requires the other containers
		// using those IDs to cease to exist because they share the same identity.
		cleanup2()
	}
}

// TestFSCheckpointCommand tests filesystem checkpoint and restore functionality
// triggered from outside the sandbox (equivalent to 'runsc fscheckpoint' CLI command).
//
// It verifies that:
// - The directory specified by 'path' is checkpointed and its changes are restored.
// - The directory specified by 'lostPath' is not checkpointed and its changes are NOT preserved.
// - When 'all' is true, all tmpfs filesystems are checkpointed and restored.
func TestFSCheckpointCommand(t *testing.T) {
	for _, tc := range []struct {
		name           string
		savePath       string
		lostPath       string
		all            bool
		multipaths     bool
		modifyManifest func(t *testing.T, imagePath string)
	}{
		{name: "root", savePath: "/", lostPath: "/homedir"},
		{name: "all", savePath: "/", lostPath: "/homedir", all: true},
		{name: "homedir", savePath: "/homedir", lostPath: "/lost-dir"},
		{name: "multipath", multipaths: true},
		{
			name:     "phony_runsc_version",
			savePath: "/",
			lostPath: "/homedir",
			modifyManifest: func(t *testing.T, imagePath string) {
				manifestPath := filepath.Join(imagePath, checkpointfiles.FSCheckpointManifestFileName)
				data, err := os.ReadFile(manifestPath)
				if err != nil {
					t.Fatalf("Failed to read manifest: %v", err)
				}
				var pb fspb.Manifest
				if err := proto.Unmarshal(data, &pb); err != nil {
					t.Fatalf("Failed to unmarshal manifest: %v", err)
				}
				// Ascertain that a different runsc version doesn't mean we fail
				pb.RunscVersion = "prehistoric"
				newData, err := proto.Marshal(&pb)
				if err != nil {
					t.Fatalf("Failed to marshal manifest: %v", err)
				}
				if err := os.WriteFile(manifestPath, newData, 0644); err != nil {
					t.Fatalf("Failed to write manifest: %v", err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := testutil.TestConfig(t)

			rootDir, cleanupRoot, err := testutil.SetupRootDir()
			if err != nil {
				t.Fatalf("Error creating root dir: %v", err)
			}
			defer cleanupRoot()
			conf.RootDir = rootDir

			// Configure overlay.
			conf.Overlay2.Set("root:self")

			// Containers are matched between save and restore by their names. If no
			// name is specified, runsc auto-assigns container names based on ordering,
			// but if a container dies and is externally restarted, runsc doesn't know
			// that the old and new containers are related and will assign the new
			// container a new name. So for restoring to work after container restart,
			// we need to assign a name explicitly.
			const (
				rootName = "root-container"
				subName  = "sub-container"
				initName = "init-container"
			)

			// Each container must use a distinct writable temporary directory as its
			// filesystem root, to hold the filestore file used by disk-backed overlay.
			appSrc, err := testutil.FindFile("test/cmd/test_app/test_app")
			if err != nil {
				t.Fatal("Error finding test_app:", err)
			}
			setupSpecRoots := func(containerSpecs []*specs.Spec, ids []string) (func(), error) {
				var cleanupSpecRoots cleanup.Cleanup
				defer cleanupSpecRoots.Clean()
				for i, spec := range containerSpecs {
					contRootPath, err := os.MkdirTemp(testutil.TmpDir(), fmt.Sprintf("%s-root", ids[i]))
					if err != nil {
						return nil, fmt.Errorf("error creating root directory for container %d: %v", i, err)
					}
					cleanupSpecRoots.Add(func() { os.RemoveAll(contRootPath) })
					spec.Root.Path = contRootPath
					spec.Root.Readonly = false
					// Copy test_app to "/app" inside the container.
					appDst := filepath.Join(contRootPath, "app")
					if err := copyFile(appSrc, appDst); err != nil {
						return nil, fmt.Errorf("error copying app binary from %q to %q: %v", appSrc, appDst, err)
					}
				}
				return cleanupSpecRoots.Release(), nil
			}

			// Start two containers which sleep.
			testAppSleepArgv := []string{"/app", "reaper"}
			saveSpecs, ids := createSpecs(testAppSleepArgv, testAppSleepArgv)

			// Container names are used to match between save and restore.
			saveSpecs[0].Annotations[specutils.ContainerdContainerNameAnnotation] = rootName
			saveSpecs[1].Annotations[specutils.ContainerdContainerNameAnnotation] = subName

			// Helper to add mount hints.
			addMountHint := func(spec *specs.Spec, name, source string, share string) {
				// Adding a "bind" mount type annotation with share=container will cause
				// the bind mount to be overlaid with medium=self.
				spec.Annotations["dev.gvisor.spec.mount."+name+".source"] = source
				spec.Annotations["dev.gvisor.spec.mount."+name+".share"] = share
				spec.Annotations["dev.gvisor.spec.mount."+name+".type"] = "bind"
			}

			// Add bind mounts and hints.
			var savedirSources []string
			var lostdirSources []string
			for i, spec := range saveSpecs {
				savePath := tc.savePath
				lostPath := tc.lostPath
				share := "container"
				if tc.multipaths {
					savePath = fmt.Sprintf("/data%d", i+1)
					lostPath = fmt.Sprintf("/lost-dir%d", i+1)
					share = "pod"
				}
				if savePath != "/" {
					saveSource, err := os.MkdirTemp(testutil.TmpDir(), fmt.Sprintf("savedir-%d", i))
					if err != nil {
						t.Fatalf("Error creating savedir source: %v", err)
					}
					defer os.RemoveAll(saveSource)
					savedirSources = append(savedirSources, saveSource)

					spec.Mounts = append(spec.Mounts, specs.Mount{
						Source:      saveSource,
						Destination: savePath,
						Type:        "bind",
					})
					// Enable overlay for savePath mount.
					addMountHint(saveSpecs[0], fmt.Sprintf("savedir-%d", i), saveSource, share)
				}

				lostdirSource, err := os.MkdirTemp(testutil.TmpDir(), fmt.Sprintf("lostdir-%d", i))
				if err != nil {
					t.Fatalf("Error creating lostdir source: %v", err)
				}
				defer os.RemoveAll(lostdirSource)
				lostdirSources = append(lostdirSources, lostdirSource)

				spec.Mounts = append(spec.Mounts, specs.Mount{
					Source:      lostdirSource,
					Destination: lostPath,
					Type:        "bind",
				})
				// Enable overlay for lostPath mount.
				addMountHint(saveSpecs[0], fmt.Sprintf("lostdir-%d", i), lostdirSource, share)
			}

			cleanupRootsOld, err := setupSpecRoots(saveSpecs, ids)
			if err != nil {
				t.Fatalf("Error setting up container roots: %v", err)
			}
			defer cleanupRootsOld()

			conts, cleanupContsOld, err := startContainers(conf, saveSpecs, ids)
			if err != nil {
				t.Fatalf("Error starting containers: %v", err)
			}
			defer cleanupContsOld()

			// Populate container filesystems.
			savePathFsTreeArgs := make([][]string, len(conts))
			lostPathFsTreeArgs := make([][]string, len(conts))
			for i := range conts {
				savePath := tc.savePath
				lostPath := tc.lostPath
				if tc.multipaths {
					savePath = fmt.Sprintf("/data%d", i+1)
					lostPath = fmt.Sprintf("/lost-dir%d", i+1)
				}
				// Populate the path to be checkpointed.
				args := []string{"--depth=10", "--file-per-level=10", "--file-size=65537", "--create-symlink", "--add-empty-files", "--target-dir=" + savePath, fmt.Sprintf("--seed=%d", rand.Uint64())}
				savePathFsTreeArgs[i] = args
				if ws, err := execute(conf, conts[i], "/app", append([]string{"fsTreeCreate"}, args...)...); err != nil || ws != 0 {
					t.Fatalf("Error populating checkpoint filesystem for container %d, ws: %v, err: %v", i, ws, err)
				}

				// Populate the path to be lost with a single file.
				args = []string{"--depth=1", "--file-per-level=1", "--file-size=0", "--target-dir=" + lostPath, fmt.Sprintf("--seed=%d", rand.Uint64())}
				lostPathFsTreeArgs[i] = args
				if ws, err := execute(conf, conts[i], "/app", append([]string{"fsTreeCreate"}, args...)...); err != nil || ws != 0 {
					t.Fatalf("Error creating lost file for container %d: ws: %v, err: %v", i, ws, err)
				}
			}

			// Save a filesystem checkpoint and kill the sandbox.
			waitFSCheckpointErrC := make(chan error, 1)
			go func() {
				waitFSCheckpointErrC <- conts[0].WaitFSCheckpoint()
			}()
			imagePath, err := os.MkdirTemp(testutil.TmpDir(), "fscheckpoint-image")
			if err != nil {
				t.Fatalf("Error creating temp dir: %v", err)
			}
			defer os.RemoveAll(imagePath)

			fsSavePathArg := tc.savePath
			if tc.all {
				fsSavePathArg = fscheckpoint.AllTmpfsPath
			}
			var paths []checkpoint.ResourceID
			if tc.multipaths {
				paths = []checkpoint.ResourceID{
					{ContainerName: rootName, Path: "/data1"},
					{ContainerName: subName, Path: "/data2"},
				}
			} else {
				paths = []checkpoint.ResourceID{{Path: fsSavePathArg}}
			}
			if err := conts[0].FSSave(conf, imagePath, sandbox.FSSaveOpts{
				ExitAfterSaving: true,
				Paths:           paths,
			}); err != nil {
				t.Fatalf("Error saving filesystem checkpoint: %v", err)
			}
			select {
			case err := <-waitFSCheckpointErrC:
				if err != nil {
					// Container.WaitFSCheckpoint, like Container.WaitCheckpoint, is
					// inherently racy. Both wait for the "next" checkpoint to be
					// saved. If FSSave completes before WaitFSCheckpoint starts
					// waiting, then WaitFSCheckpoint will miss the FSSave and return
					// an error when the sandbox exits. There is no way to know when
					// WaitFSCheckpoint has started waiting, so there is no way to be
					// completely safe from this race. To avoid causing test flakes,
					// log the error but don't fail the test.
					t.Logf("Error waiting for FS checkpoint: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("Timed out waiting for WaitFSCheckpoint")
			}

			if tc.modifyManifest != nil {
				tc.modifyManifest(t, imagePath)
			}

			// Start three containers which sleep, two of which restore from the
			// filesystem checkpoint.
			restoreSpecs, restoreIDs := createSpecs(testAppSleepArgv, testAppSleepArgv, testAppSleepArgv)
			restoreSpecs[0].Annotations[specutils.ContainerdContainerNameAnnotation] = rootName
			restoreSpecs[1].Annotations[specutils.ContainerdContainerNameAnnotation] = subName
			restoreSpecs[2].Annotations[specutils.ContainerdContainerNameAnnotation] = initName

			// Create one more source for the 3rd container (initName)
			lostdirSource2, err := os.MkdirTemp(testutil.TmpDir(), "lostdir-2")
			if err != nil {
				t.Fatalf("Error creating lostdir source: %v", err)
			}
			defer os.RemoveAll(lostdirSource2)
			lostdirSources = append(lostdirSources, lostdirSource2)
			if tc.savePath != "/" {
				saveSource2, err := os.MkdirTemp(testutil.TmpDir(), "savedir-2")
				if err != nil {
					t.Fatalf("Error creating savedir source: %v", err)
				}
				defer os.RemoveAll(saveSource2)
				savedirSources = append(savedirSources, saveSource2)
			}

			for i, spec := range restoreSpecs {
				savePath := tc.savePath
				lostPath := tc.lostPath
				share := "container"
				if tc.multipaths {
					savePath = fmt.Sprintf("/data%d", i+1)
					lostPath = fmt.Sprintf("/lost-dir%d", i+1)
					share = "pod"
				}
				if savePath != "/" {
					spec.Mounts = append(spec.Mounts, specs.Mount{
						Source:      savedirSources[i],
						Destination: savePath,
						Type:        "bind",
					})
					// Enable overlay for savePath mount.
					addMountHint(restoreSpecs[0], fmt.Sprintf("savedir-%d", i), savedirSources[i], share)
				}

				spec.Mounts = append(spec.Mounts, specs.Mount{
					Source:      lostdirSources[i],
					Destination: lostPath,
					Type:        "bind",
				})
				// Enable overlay for lostPath mount.
				addMountHint(restoreSpecs[0], fmt.Sprintf("lostdir-%d", i), lostdirSources[i], share)
			}

			cleanupRootsNew, err := setupSpecRoots(restoreSpecs, restoreIDs)
			if err != nil {
				t.Fatalf("Error setting up container roots: %v", err)
			}
			defer cleanupRootsNew()
			restoreConts, cleanupContsNew, err := startContainersWithArgs(conf, restoreSpecs, restoreIDs, func(i int, contArgs *Args) {
				if i == 0 {
					contArgs.FSRestoreImagePath = imagePath
				}
			})
			if err != nil {
				t.Fatalf("Error starting containers: %v", err)
			}
			defer cleanupContsNew()

			// Verify container filesystems restored from checkpoint.
			for i := range restoreConts[:2] {
				lostPath := tc.lostPath
				if tc.multipaths {
					lostPath = fmt.Sprintf("/lost-dir%d", i+1)
				}
				// Checkpointed path must be verified successfully.
				if ws, err := execute(conf, restoreConts[i], "/app", append([]string{"fsTreeVerify"}, savePathFsTreeArgs[i]...)...); err != nil || ws != 0 {
					t.Fatalf("Error verifying checkpointed filesystem for container %d, ws: %v, err: %v", i, ws, err)
				}

				if tc.all {
					// If all tmpfs mounts are checkpointed then the lost path should
					// also be restored.
					if ws, err := execute(conf, restoreConts[i], "/app", append([]string{"fsTreeVerify"}, lostPathFsTreeArgs[i]...)...); err != nil || ws != 0 {
						t.Fatalf("Error verifying lost path is also restored for container %d when using --path=all-tmpfs, ws: %v, err: %v", i, ws, err)
					}
				} else {
					// Verify that the lost path is cleared.
					out, status, err := executeCombinedOutputWithStatus(conf, restoreConts[i], nil, "/app", "assertIsEmpty", lostPath)
					if err != nil || status != 0 {
						t.Fatalf("Lost path %q was not cleared for container %d, status: %v, err: %v, output: %s", lostPath, i, status, err, string(out))
					}
				}
			}
			for i, cont := range restoreConts[:2] {
				if err := cont.WaitFSRestore(); err != nil {
					t.Errorf("Error waiting for FS restore for container %d: %v", i, err)
				}
			}

			// Restart the second container and verify that its filesystem is restored
			// again.
			restoreConts[1].Destroy()
			restartID := testutil.RandomContainerID()
			contsRestart, cleanupContsRestart, err := startContainers(conf, restoreSpecs[1:2], []string{restartID})
			if err != nil {
				t.Fatalf("Error starting container: %v", err)
			}
			defer cleanupContsRestart()
			if ws, err := execute(conf, contsRestart[0], "/app", append([]string{"fsTreeVerify"}, savePathFsTreeArgs[1]...)...); err != nil || ws != 0 {
				t.Fatalf("Error verifying filesystem for restarted container, ws: %v, err: %v", ws, err)
			}
			if tc.all {
				if ws, err := execute(conf, contsRestart[0], "/app", append([]string{"fsTreeVerify"}, lostPathFsTreeArgs[1]...)...); err != nil || ws != 0 {
					t.Fatalf("Error verifying lost path is also restored for restarted container when using --path=all-tmpfs, ws: %v, err: %v", ws, err)
				}
			} else {
				lostPath := tc.lostPath
				if tc.multipaths {
					lostPath = "/lost-dir2"
				}
				out, status, err := executeCombinedOutputWithStatus(conf, contsRestart[0], nil, "/app", "assertIsEmpty", lostPath)
				if err != nil || status != 0 {
					t.Fatalf("Lost path %q was not cleared for restarted container, status: %v, err: %v, output: %s", lostPath, status, err, string(out))
				}
			}
			if err := contsRestart[0].WaitFSRestore(); err != nil {
				t.Errorf("Error waiting for FS restore: %v", err)
			}
		})
	}
}

// TestCheckpointRestoreAnnotation adds checkpoint annotations to the spec and makes the workload
// trigger a checkpoint. The workload resumes after checkpoint is triggered. Also checks that the
// procfs checkpoint file blocks reads until checkpoint/restore completes.
func TestCheckpointRestoreAnnotation(t *testing.T) {
	conf := testutil.TestConfig(t)

	rootDir, cleanup, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("error creating root dir: %v", err)
	}
	defer cleanup()
	conf.RootDir = rootDir

	// Directory used for  workload->test communication.
	outDir, err := os.MkdirTemp(testutil.TmpDir(), "container")
	if err != nil {
		t.Fatal("os.MkdirTemp failed:", err)
	}
	defer os.RemoveAll(outDir)
	out := path.Join(outDir, "output")

	// Trigger a checkpoint and read the file to wait for the checkpoint to complete.
	cmd := fmt.Sprintf(`exec 3<>/proc/gvisor/checkpoint; echo 1 >&3; cat <&3 >> %q; sleep inf`, out)
	checkpointCmd := []string{"/bin/bash", "-c", cmd}

	testSpecs, ids := createSpecs(sleepCmd, checkpointCmd)

	dir, err := os.MkdirTemp(testutil.TmpDir(), "checkpoint-test")
	if err != nil {
		t.Fatalf("os.MkdirTemp() failed: %v", err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatalf("error chmoding file: %q, %v", dir, err)
	}

	// Setup the first container to enable checkpointing from inside the sandbox,
	// but don't expose procfs files.
	testSpecs[0].Annotations["dev.gvisor.internal.checkpoint.path"] = dir
	testSpecs[0].Annotations["dev.gvisor.internal.checkpoint.resume"] = "true"
	// Use compression=none to force the creation of multiple files.
	testSpecs[0].Annotations["dev.gvisor.internal.checkpoint.compression"] = "none"

	// Expose procfs files in the second container.
	testSpecs[1].Annotations["dev.gvisor.internal.checkpoint.enable"] = "true"

	testSpecs[0].Mounts = append(testSpecs[0].Mounts, specs.Mount{
		Source:      outDir,
		Destination: outDir,
		Type:        "bind",
	})

	conts, cleanup, err := startContainers(conf, testSpecs, ids)
	if err != nil {
		t.Fatalf("error starting containers: %v", err)
	}
	defer cleanup()

	if err := conts[0].WaitCheckpoint(); err != nil {
		t.Fatalf("error waiting for checkpoint: %v", err)
	}

	// Wait until the checkpoint read unblocks and writes to `out`.
	if err := waitForContent(out, "resume\n"); err != nil {
		t.Fatal(err)
	}

	// Check that procfs files are exposed in the first container as well.
	// * checkpoint file should exist and be readable
	if ws, err := execute(conf, conts[0], "/usr/bin/test", "-r", "/proc/gvisor/checkpoint"); err != nil {
		t.Fatal(err)
	} else if ws != 0 {
		t.Fatalf("/proc/gvisor/checkpoint does not exist or is not readable in the first container: %v", ws)
	}
	// * checkpoint file should not be writable
	if ws, err := execute(conf, conts[0], "/usr/bin/test", "!", "-w", "/proc/gvisor/checkpoint"); err != nil {
		t.Fatal(err)
	} else if ws != 0 {
		t.Fatalf("/proc/gvisor/checkpoint is writable in the first container: %v", ws)
	}
	// * spec_environ file should exist and be readable
	if ws, err := execute(conf, conts[0], "/usr/bin/test", "-r", "/proc/gvisor/spec_environ"); err != nil {
		t.Fatal(err)
	} else if ws != 0 {
		t.Fatalf("/proc/gvisor/spec_environ does not exist or is not readable in the first container: %v", ws)
	}

	// Restore into a new container with same IDs (e.g. clone). It requires the
	// original container to cease to exist because they share the same ID.
	cleanup()
	conts = nil

	dir2, err := os.MkdirTemp(testutil.TmpDir(), "checkpoint-test")
	if err != nil {
		t.Fatalf("os.MkdirTemp() failed: %v", err)
	}
	defer os.RemoveAll(dir2)

	// Append a new env var in the second container. If the same env var is
	// defined multiple times, the last one is used.
	const newEnvVar = "GVISOR_RESTORE_TEST_ENV_VAR=newvar"
	testSpecs[1].Process.Env = append(testSpecs[1].Process.Env, newEnvVar)

	// Remove the checkpoint annotation from the first container.
	for name := range testSpecs[0].Annotations {
		if strings.HasPrefix(name, "dev.gvisor.internal.checkpoint") {
			delete(testSpecs[0].Annotations, name)
		}
	}

	conts, cleanup, err = restoreContainers(conf, testSpecs, ids, dir)
	if err != nil {
		t.Fatalf("error creating containers: %v", err)
	}
	defer cleanup()

	// Wait until the checkpoint read unblocks and writes to `out`.
	if err := waitForContent(out, "resume\nrestore\n"); err != nil {
		t.Fatal(err)
	}

	// Check that the new env var is present in /proc/gvisor/spec_environ.
	if out, err := executeCombinedOutput(conf, conts[1], nil, "/usr/bin/strings", "/proc/gvisor/spec_environ"); err != nil {
		t.Fatalf("out=%q, err=%v", string(out), err)
	} else if !strings.Contains(string(out), newEnvVar) {
		t.Fatalf("env var %q not found in /proc/gvisor/spec_environ: %q", newEnvVar, string(out))
	}
}

func TestFSCheckpointAnnotation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		path       string
		lostPath   string
		multipaths bool
	}{
		{name: "root", path: "/", lostPath: "/homedir"},
		{name: "homedir", path: "/homedir", lostPath: "/lost-dir"},
		{name: "multipaths", path: "/homedir", lostPath: "/lost-dir", multipaths: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := testutil.TestConfig(t)

			rootDir, cleanupRoot, err := testutil.SetupRootDir()
			if err != nil {
				t.Fatalf("Error creating root dir: %v", err)
			}
			defer cleanupRoot()
			conf.RootDir = rootDir

			// Configure overlay.
			conf.Overlay2.Set("root:self")

			// Each container must use a distinct writable temporary directory as its
			// filesystem root, to hold the filestore file used by disk-backed overlay.
			appSrc, err := testutil.FindFile("test/cmd/test_app/test_app")
			if err != nil {
				t.Fatal("Error finding test_app:", err)
			}
			setupSpecRoots := func(containerSpecs []*specs.Spec, ids []string) (func(), error) {
				var cleanupSpecRoots cleanup.Cleanup
				defer cleanupSpecRoots.Clean()
				for i, spec := range containerSpecs {
					contRootPath, err := os.MkdirTemp(testutil.TmpDir(), fmt.Sprintf("%s-root", ids[i]))
					if err != nil {
						return nil, fmt.Errorf("error creating root directory for container %d: %v", i, err)
					}
					cleanupSpecRoots.Add(func() { os.RemoveAll(contRootPath) })
					spec.Root.Path = contRootPath
					spec.Root.Readonly = false
					// Copy test_app to "/app" inside the container.
					appDst := filepath.Join(contRootPath, "app")
					if err := copyFile(appSrc, appDst); err != nil {
						return nil, fmt.Errorf("error copying app binary from %q to %q: %v", appSrc, appDst, err)
					}
				}
				return cleanupSpecRoots.Release(), nil
			}

			// Create a directory for the filesystem checkpoint.
			imagePath, err := os.MkdirTemp(testutil.TmpDir(), "fscheckpoint-image")
			if err != nil {
				t.Fatalf("Error creating temp dir: %v", err)
			}
			defer os.RemoveAll(imagePath)

			// Start containers which sleep.
			testAppSleepArgv := []string{"/app", "reaper"}
			saveSpecs, ids := createSpecs(testAppSleepArgv, testAppSleepArgv)

			// Helper to add mount hints.
			addMountHint := func(spec *specs.Spec, name, source string) {
				spec.Annotations["dev.gvisor.spec.mount."+name+".source"] = source
				if tc.multipaths {
					spec.Annotations["dev.gvisor.spec.mount."+name+".share"] = "pod"
				} else {
					spec.Annotations["dev.gvisor.spec.mount."+name+".share"] = "container"
				}
				spec.Annotations["dev.gvisor.spec.mount."+name+".type"] = "bind"
			}

			const (
				rootName = "root-container"
				subName  = "sub-container"
			)
			if tc.multipaths {
				saveSpecs[0].Annotations[specutils.ContainerdContainerNameAnnotation] = rootName
				saveSpecs[1].Annotations[specutils.ContainerdContainerNameAnnotation] = subName
			}

			// Add bind mount to /homedir for both containers, using different host directories to avoid filestore conflict.
			var homedirSources []string
			var lostdirSources []string
			for i, spec := range saveSpecs {
				homedirSource, err := os.MkdirTemp(testutil.TmpDir(), fmt.Sprintf("homedir-source-%d", i))
				if err != nil {
					t.Fatalf("Error creating homedir source: %v", err)
				}
				defer os.RemoveAll(homedirSource)
				homedirSources = append(homedirSources, homedirSource)

				spec.Mounts = append(spec.Mounts, specs.Mount{
					Source:      homedirSource,
					Destination: "/homedir",
					Type:        "bind",
				})
				addMountHint(saveSpecs[0], fmt.Sprintf("homedir-%d", i), homedirSource)

				if tc.name == "homedir" || tc.multipaths {
					lostdirSource, err := os.MkdirTemp(testutil.TmpDir(), fmt.Sprintf("lostdir-source-%d", i))
					if err != nil {
						t.Fatalf("Error creating lostdir source: %v", err)
					}
					defer os.RemoveAll(lostdirSource)
					lostdirSources = append(lostdirSources, lostdirSource)

					spec.Mounts = append(spec.Mounts, specs.Mount{
						Source:      lostdirSource,
						Destination: "/lost-dir",
						Type:        "bind",
					})
					addMountHint(saveSpecs[0], fmt.Sprintf("lostdir-%d", i), lostdirSource)
				}

				if i > 0 {
					// Remove conflicting mounts from sub-containers.
					var cleanMounts []specs.Mount
					for _, m := range spec.Mounts {
						if m.Destination != testutil.TmpDir() {
							cleanMounts = append(cleanMounts, m)
						}
					}
					spec.Mounts = cleanMounts
				}
			}

			cleanupRootsOld, err := setupSpecRoots(saveSpecs, ids)
			if err != nil {
				t.Fatalf("Error setting up container roots: %v", err)
			}
			defer cleanupRootsOld()

			// The root container must specify the filesystem checkpoint path and
			// options, but files in /proc/gvisor are enabled on a per-container basis.
			saveSpecs[0].Annotations["dev.gvisor.internal.fscheckpoint.path"] = imagePath
			saveSpecs[0].Annotations["dev.gvisor.internal.fscheckpoint.resume"] = "true"
			if tc.multipaths {
				saveSpecs[0].Annotations["dev.gvisor.internal.fscheckpoint.paths"] = fmt.Sprintf("%s:%s,%s:%s", rootName, tc.path, subName, tc.path)
			} else if tc.path != "/" {
				saveSpecs[0].Annotations["dev.gvisor.internal.fscheckpoint.paths"] = tc.path
			}
			saveSpecs[1].Annotations["dev.gvisor.internal.fscheckpoint.enable"] = "true"
			conts, cleanupContsOld, err := startContainers(conf, saveSpecs, ids)
			if err != nil {
				t.Fatalf("Error starting containers: %v", err)
			}
			defer cleanupContsOld()

			// Populate container filesystems.
			fsTreeCommonArgs := []string{"--depth=10", "--file-per-level=10", "--file-size=65537", "--create-symlink", "--add-empty-files"}
			checkpointFsTreeArgs := make([][]string, len(conts))
			for i := range conts {
				// Populate the path to be checkpointed.
				args := append(fsTreeCommonArgs, "--target-dir="+tc.path, fmt.Sprintf("seed=%d", rand.Uint64()))
				checkpointFsTreeArgs[i] = args
				if ws, err := execute(conf, conts[i], "/app", append([]string{"fsTreeCreate"}, args...)...); err != nil || ws != 0 {
					t.Fatalf("Error populating checkpoint filesystem for container %d, ws: %v, err: %v", i, ws, err)
				}

				// Populate the path to be lost with a single file.
				if ws, err := execute(conf, conts[i], "/app", "fsTreeCreate", "--depth=1", "--file-per-level=1", "--file-size=0", "--target-dir="+tc.lostPath); err != nil || ws != 0 {
					t.Fatalf("Error creating lost file for container %d: ws: %v, err: %v", i, ws, err)
				}
			}

			// Saving a filesystem checkpoint from the first container should fail,
			// since the /proc/gvisor files are not enabled for that container.
			if ws, err := execute(conf, conts[0], "/app", "fsCheckpoint"); err != nil {
				t.Fatalf("Error invoking fsCheckpoint in container 0: %v", err)
			} else if !ws.Exited() || ws.ExitStatus() == 0 {
				t.Fatalf("fsCheckpoint in container 0 returned unexpected wait status %v", ws)
			}

			// Saving a filesystem checkpoint from the second container should succeed.
			if ws, err := execute(conf, conts[1], "/app", "fsCheckpoint"); err != nil || ws != 0 {
				t.Fatalf("Error saving filesystem checkpoint from container 1, ws: %v, err: %v", ws, err)
			}

			// Kill containers.
			for i, c := range conts {
				if err := c.SignalContainer(unix.SIGKILL, false); err != nil {
					t.Fatalf("Error killing container %d: %v", i, err)
				}
			}

			// Start containers which sleep, restoring from the filesystem checkpoint.
			restoreSpecs, ids := createSpecs(testAppSleepArgv, testAppSleepArgv)
			if tc.multipaths {
				restoreSpecs[0].Annotations[specutils.ContainerdContainerNameAnnotation] = rootName
				restoreSpecs[1].Annotations[specutils.ContainerdContainerNameAnnotation] = subName
			}
			for i, spec := range restoreSpecs {
				spec.Mounts = append(spec.Mounts, specs.Mount{
					Source:      homedirSources[i],
					Destination: "/homedir",
					Type:        "bind",
				})
				addMountHint(restoreSpecs[0], fmt.Sprintf("homedir-%d", i), homedirSources[i])

				if tc.name == "homedir" || tc.multipaths {
					spec.Mounts = append(spec.Mounts, specs.Mount{
						Source:      lostdirSources[i],
						Destination: "/lost-dir",
						Type:        "bind",
					})
					addMountHint(restoreSpecs[0], fmt.Sprintf("lostdir-%d", i), lostdirSources[i])
				}

				if i > 0 {
					// Remove conflicting mounts from sub-containers.
					var cleanMounts []specs.Mount
					for _, m := range spec.Mounts {
						if m.Destination != testutil.TmpDir() {
							cleanMounts = append(cleanMounts, m)
						}
					}
					spec.Mounts = cleanMounts
				}
			}

			cleanupRootsNew, err := setupSpecRoots(restoreSpecs, ids)
			if err != nil {
				t.Fatalf("Error setting up container roots: %v", err)
			}
			defer cleanupRootsNew()
			conts, cleanupContsNew, err := startContainersWithArgs(conf, restoreSpecs, ids, func(i int, contArgs *Args) {
				if i == 0 {
					contArgs.FSRestoreImagePath = imagePath
				}
			})
			if err != nil {
				t.Fatalf("Error starting containers: %v", err)
			}
			defer cleanupContsNew()

			// Verify container filesystems restored from checkpoint.
			for i := range conts {
				// Checkpointed path must be verified successfully.
				if ws, err := execute(conf, conts[i], "/app", append([]string{"fsTreeVerify"}, checkpointFsTreeArgs[i]...)...); err != nil || ws != 0 {
					t.Fatalf("Error verifying checkpointed filesystem for container %d, ws: %v, err: %v", i, ws, err)
				}

				// Verify that the lost path is cleared.
				out, status, err := executeCombinedOutputWithStatus(conf, conts[i], nil, "/app", "assertIsEmpty", tc.lostPath)
				if err != nil || status != 0 {
					t.Fatalf("Lost path %q was not cleared for container %d, status: %v, err: %v, output: %s", tc.lostPath, i, status, err, string(out))
				}
			}
		})
	}
}

func waitForContent(path, want string) error {
	readFileFn := func() error {

		if got, err := os.ReadFile(path); err != nil {
			return fmt.Errorf("Reading from test output file %q failed: %v", path, err)
		} else if !strings.Contains(string(got), want) {
			return fmt.Errorf("Output file doesn't match, want: %q, got: %q", want, string(got))
		}
		return nil
	}
	return testutil.Poll(readFileFn, 10*time.Second)
}

func TestFSCheckpointSharedVolume(t *testing.T) {
	conf := testutil.TestConfig(t)

	rootDir, cleanupRoot, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("Error creating root dir: %v", err)
	}
	defer cleanupRoot()
	conf.RootDir = rootDir

	// Configure overlay.
	conf.Overlay2.Set("root:self")

	const (
		rootName = "root-container"
		subName  = "sub-container"
	)

	appSrc, err := testutil.FindFile("test/cmd/test_app/test_app")
	if err != nil {
		t.Fatal("Error finding test_app:", err)
	}
	setupSpecRoots := func(containerSpecs []*specs.Spec, ids []string) (func(), error) {
		var cleanupSpecRoots cleanup.Cleanup
		defer cleanupSpecRoots.Clean()
		for i, spec := range containerSpecs {
			contRootPath, err := os.MkdirTemp(testutil.TmpDir(), fmt.Sprintf("%s-root", ids[i]))
			if err != nil {
				return nil, fmt.Errorf("error creating root directory for container %d: %v", i, err)
			}
			cleanupSpecRoots.Add(func() { os.RemoveAll(contRootPath) })
			spec.Root.Path = contRootPath
			spec.Root.Readonly = false
			appDst := filepath.Join(contRootPath, "app")
			if err := copyFile(appSrc, appDst); err != nil {
				return nil, fmt.Errorf("error copying app binary from %q to %q: %v", appSrc, appDst, err)
			}
		}
		return cleanupSpecRoots.Release(), nil
	}

	sharedSource, err := os.MkdirTemp(testutil.TmpDir(), "shared-source")
	if err != nil {
		t.Fatalf("Error creating shared source: %v", err)
	}
	defer os.RemoveAll(sharedSource)

	testAppSleepArgv := []string{"/app", "reaper"}
	saveSpecs, ids := createSpecs(testAppSleepArgv, testAppSleepArgv)

	saveSpecs[0].Annotations[specutils.ContainerdContainerNameAnnotation] = rootName
	saveSpecs[1].Annotations[specutils.ContainerdContainerNameAnnotation] = subName

	// Add mount hint for shared volume.
	saveSpecs[0].Annotations["dev.gvisor.spec.mount.shared-vol.source"] = sharedSource
	saveSpecs[0].Annotations["dev.gvisor.spec.mount.shared-vol.share"] = "pod"
	saveSpecs[0].Annotations["dev.gvisor.spec.mount.shared-vol.type"] = "tmpfs"

	// Both containers mount the same source to /shared.
	saveSpecs[0].Mounts = append(saveSpecs[0].Mounts, specs.Mount{
		Source:      sharedSource,
		Destination: "/shared",
		Type:        "bind",
	})
	saveSpecs[1].Mounts = append(saveSpecs[1].Mounts, specs.Mount{
		Source:      sharedSource,
		Destination: "/shared",
		Type:        "bind",
	})

	imagePath, err := os.MkdirTemp(testutil.TmpDir(), "fscheckpoint-image")
	if err != nil {
		t.Fatalf("Error creating temp dir: %v", err)
	}
	defer os.RemoveAll(imagePath)

	cleanupRootsOld, err := setupSpecRoots(saveSpecs, ids)
	if err != nil {
		t.Fatalf("Error setting up container roots: %v", err)
	}
	defer cleanupRootsOld()

	conts, cleanupContsOld, err := startContainers(conf, saveSpecs, ids)
	if err != nil {
		t.Fatalf("Error starting containers: %v", err)
	}
	defer cleanupContsOld()

	// Write file from root-container.
	if ws, err := execute(conf, conts[0], "/app", "fsTreeCreate", "--depth=1", "--file-per-level=1", "--file-size=10", "--target-dir=/shared", "--seed=123"); err != nil || ws != 0 {
		t.Fatalf("Error writing to shared volume from root container, ws: %v, err: %v", ws, err)
	}

	// Verify file is visible in sub-container.
	if ws, err := execute(conf, conts[1], "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--target-dir=/shared", "--seed=123"); err != nil || ws != 0 {
		t.Fatalf("Error verifying shared volume from sub-container before checkpoint, ws: %v, err: %v", ws, err)
	}

	// Checkpoint specifying BOTH paths.
	// Since share=pod is used, the filesystem is created by the first container (root-container).
	// Specifying both ensures it matches container0's mount and gets saved.
	if err := conts[0].FSSave(conf, imagePath, sandbox.FSSaveOpts{
		ExitAfterSaving: true,
		Paths: []checkpoint.ResourceID{
			{ContainerName: rootName, Path: "/shared"},
			{ContainerName: subName, Path: "/shared"},
		},
	}); err != nil {
		t.Fatalf("Error saving filesystem checkpoint: %v", err)
	}

	for i, c := range conts {
		if err := c.SignalContainer(unix.SIGKILL, false); err != nil && !strings.Contains(err.Error(), "no such process") {
			t.Fatalf("Error killing container %d: %v", i, err)
		}
	}

	restoreSpecs, restoreIDs := createSpecs(testAppSleepArgv, testAppSleepArgv)
	restoreSpecs[0].Annotations[specutils.ContainerdContainerNameAnnotation] = rootName
	restoreSpecs[1].Annotations[specutils.ContainerdContainerNameAnnotation] = subName

	restoreSpecs[0].Annotations["dev.gvisor.spec.mount.shared-vol.source"] = sharedSource
	restoreSpecs[0].Annotations["dev.gvisor.spec.mount.shared-vol.share"] = "pod"
	restoreSpecs[0].Annotations["dev.gvisor.spec.mount.shared-vol.type"] = "tmpfs"

	restoreSpecs[0].Mounts = append(restoreSpecs[0].Mounts, specs.Mount{
		Source:      sharedSource,
		Destination: "/shared",
		Type:        "bind",
	})
	restoreSpecs[1].Mounts = append(restoreSpecs[1].Mounts, specs.Mount{
		Source:      sharedSource,
		Destination: "/shared",
		Type:        "bind",
	})

	cleanupRootsNew, err := setupSpecRoots(restoreSpecs, restoreIDs)
	if err != nil {
		t.Fatalf("Error setting up container roots: %v", err)
	}
	defer cleanupRootsNew()

	restoreConts, cleanupContsNew, err := startContainersWithArgs(conf, restoreSpecs, restoreIDs, func(i int, contArgs *Args) {
		if i == 0 {
			contArgs.FSRestoreImagePath = imagePath
		}
	})
	if err != nil {
		t.Fatalf("Error starting containers: %v", err)
	}
	defer cleanupContsNew()

	// Verify data is restored in both containers.
	if ws, err := execute(conf, restoreConts[0], "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--target-dir=/shared", "--seed=123"); err != nil || ws != 0 {
		t.Fatalf("Error verifying shared volume from root container after restore, ws: %v, err: %v", ws, err)
	}
	if ws, err := execute(conf, restoreConts[1], "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--target-dir=/shared", "--seed=123"); err != nil || ws != 0 {
		t.Fatalf("Error verifying shared volume from sub-container after restore, ws: %v, err: %v", ws, err)
	}
}

// TestMultiContainerSharedVolumeCheckpointRestore tests that checkpoint/restore works
// with multi-containers sharing an overlay filestore volume.
func TestMultiContainerSharedVolumeCheckpointRestore(t *testing.T) {
	compression := statefile.CompressionLevelNone

	conf := testutil.TestConfig(t)
	// Enable host-backed overlay.
	tempDir, err := os.MkdirTemp(testutil.TmpDir(), "overlay-filestore")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tempDir)
	if err := conf.Overlay2.Set("all:dir=" + tempDir); err != nil {
		t.Fatalf("error setting overlay2: %v", err)
	}

	rootDir, cleanupRoot, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("error creating root dir: %v", err)
	}
	defer cleanupRoot()
	conf.RootDir = rootDir

	dir, err := os.MkdirTemp(testutil.TmpDir(), "checkpoint-test-shared")
	if err != nil {
		t.Fatalf("os.MkdirTemp() failed: %v", err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatalf("error chmoding file: %q, %v", dir, err)
	}

	sharedDir, err := os.MkdirTemp(testutil.TmpDir(), "shared-vol")
	if err != nil {
		t.Fatalf("os.MkdirTemp() failed: %v", err)
	}
	defer os.RemoveAll(sharedDir)
	if err := os.Chmod(sharedDir, 0777); err != nil {
		t.Fatalf("error chmoding file: %q, %v", sharedDir, err)
	}

	singleSharedDir, err := os.MkdirTemp(testutil.TmpDir(), "single-shared-vol")
	if err != nil {
		t.Fatalf("os.MkdirTemp() failed: %v", err)
	}
	defer os.RemoveAll(singleSharedDir)
	if err := os.Chmod(singleSharedDir, 0777); err != nil {
		t.Fatalf("error chmoding file: %q, %v", singleSharedDir, err)
	}

	appSrc, err := testutil.FindFile("test/cmd/test_app/test_app")
	if err != nil {
		t.Fatal("Error finding test_app:", err)
	}

	setupSpecRoots := func(containerSpecs []*specs.Spec, ids []string) (func(), error) {
		var cleanupSpecRoots cleanup.Cleanup
		defer cleanupSpecRoots.Clean()
		for i, spec := range containerSpecs {
			contRootPath, err := os.MkdirTemp(testutil.TmpDir(), fmt.Sprintf("%s-root", ids[i]))
			if err != nil {
				return nil, fmt.Errorf("error creating root directory for container %d: %v", i, err)
			}
			cleanupSpecRoots.Add(func() { os.RemoveAll(contRootPath) })
			spec.Root.Path = contRootPath
			spec.Root.Readonly = false
			appDst := filepath.Join(contRootPath, "app")
			if err := copyFile(appSrc, appDst); err != nil {
				return nil, fmt.Errorf("error copying app binary from %q to %q: %v", appSrc, appDst, err)
			}
		}
		return cleanupSpecRoots.Release(), nil
	}

	testAppSleepArgv := []string{"/app", "reaper"}
	testSpecs, ids := createSpecs(
		testAppSleepArgv,
		testAppSleepArgv,
		testAppSleepArgv,
	)

	testSpecs[0].Annotations["dev.gvisor.spec.mount.shared-vol.share"] = "pod"
	testSpecs[0].Annotations["dev.gvisor.spec.mount.shared-vol.type"] = "tmpfs"
	testSpecs[0].Annotations["dev.gvisor.spec.mount.shared-vol.source"] = sharedDir

	sharedMount := specs.Mount{
		Destination: "/shared",
		Source:      sharedDir,
		Type:        "bind",
	}
	testSpecs[0].Mounts = append(testSpecs[0].Mounts, sharedMount)
	testSpecs[1].Mounts = append(testSpecs[1].Mounts, sharedMount)
	testSpecs[2].Mounts = append(testSpecs[2].Mounts, sharedMount)

	testSpecs[0].Annotations["dev.gvisor.spec.mount.single-shared-vol.share"] = "pod"
	testSpecs[0].Annotations["dev.gvisor.spec.mount.single-shared-vol.type"] = "tmpfs"
	testSpecs[0].Annotations["dev.gvisor.spec.mount.single-shared-vol.source"] = singleSharedDir

	singleSharedMount := specs.Mount{
		Destination: "/single_shared",
		Source:      singleSharedDir,
		Type:        "bind",
	}
	testSpecs[0].Mounts = append(testSpecs[0].Mounts, singleSharedMount)

	cleanupRoots, err := setupSpecRoots(testSpecs, ids)
	if err != nil {
		t.Fatalf("error setting up container roots: %v", err)
	}
	defer cleanupRoots()

	conts, cleanupConts, err := startContainers(conf, testSpecs, ids)
	if err != nil {
		t.Fatalf("error starting containers: %v", err)
	}
	defer cleanupConts()

	// Write file from root-container.
	if ws, err := execute(conf, conts[0], "/app", "fsTreeCreate", "--depth=1", "--file-per-level=1", "--file-size=10", "--target-dir=/shared", "--seed=123"); err != nil || ws != 0 {
		t.Fatalf("Error writing to shared volume from root container, ws: %v, err: %v", ws, err)
	}

	// Write file to single-shared volume from root-container.
	if ws, err := execute(conf, conts[0], "/app", "fsTreeCreate", "--depth=1", "--file-per-level=1", "--file-size=10", "--target-dir=/single_shared", "--seed=789"); err != nil || ws != 0 {
		t.Fatalf("Error writing to single shared volume from root container, ws: %v, err: %v", ws, err)
	}

	// Verify file is visible in sub-container.
	if ws, err := execute(conf, conts[1], "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--target-dir=/shared", "--seed=123"); err != nil || ws != 0 {
		t.Fatalf("Error verifying shared volume from sub-container before checkpoint, ws: %v, err: %v", ws, err)
	}
	if ws, err := execute(conf, conts[2], "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--target-dir=/shared", "--seed=123"); err != nil || ws != 0 {
		t.Fatalf("Error verifying shared volume from sub-container 2 before checkpoint, ws: %v, err: %v", ws, err)
	}

	// Write file from sub-container.
	if ws, err := execute(conf, conts[1], "/app", "fsTreeCreate", "--depth=1", "--file-per-level=1", "--file-size=10", "--target-dir=/shared/sub", "--seed=456"); err != nil || ws != 0 {
		t.Fatalf("Error writing to shared volume from sub container, ws: %v, err: %v", ws, err)
	}

	// Verify file is visible in root-container.
	if ws, err := execute(conf, conts[0], "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--target-dir=/shared/sub", "--seed=456"); err != nil || ws != 0 {
		t.Fatalf("Error verifying shared volume from root container before checkpoint, ws: %v, err: %v", ws, err)
	}
	if ws, err := execute(conf, conts[2], "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--target-dir=/shared/sub", "--seed=456"); err != nil || ws != 0 {
		t.Fatalf("Error verifying shared volume from sub-container 2 before checkpoint, ws: %v, err: %v", ws, err)
	}

	if err := conts[0].Checkpoint(conf, dir, sandbox.CheckpointOpts{Compression: compression}); err != nil {
		t.Fatalf("error checkpointing container: %v", err)
	}

	newIds := make([]string, 0, len(ids))
	for range ids {
		newIds = append(newIds, testutil.RandomContainerID())
	}
	for _, spec := range testSpecs[1:] {
		spec.Annotations[specutils.ContainerdSandboxIDAnnotation] = newIds[0]
	}

	cleanupRootsNew, err := setupSpecRoots(testSpecs, newIds)
	if err != nil {
		t.Fatalf("error setting up container roots: %v", err)
	}
	defer cleanupRootsNew()

	newConts, newCleanup, err := restoreContainers(conf, testSpecs, newIds, dir)
	if err != nil {
		t.Fatalf("error restoring containers: %v", err)
	}
	defer newCleanup()

	// Verify data is restored in all containers.
	if ws, err := execute(conf, newConts[0], "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--target-dir=/shared", "--seed=123"); err != nil || ws != 0 {
		t.Fatalf("Error verifying shared volume from root container after restore, ws: %v, err: %v", ws, err)
	}
	if ws, err := execute(conf, newConts[1], "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--target-dir=/shared", "--seed=123"); err != nil || ws != 0 {
		t.Fatalf("Error verifying shared volume from sub-container after restore, ws: %v, err: %v", ws, err)
	}
	if ws, err := execute(conf, newConts[2], "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--target-dir=/shared", "--seed=123"); err != nil || ws != 0 {
		t.Fatalf("Error verifying shared volume from sub-container 2 after restore, ws: %v, err: %v", ws, err)
	}
	if ws, err := execute(conf, newConts[0], "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--target-dir=/single_shared", "--seed=789"); err != nil || ws != 0 {
		t.Fatalf("Error verifying single shared volume from root container after restore, ws: %v, err: %v", ws, err)
	}

	// Verify data from sub-container write.
	if ws, err := execute(conf, newConts[0], "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--target-dir=/shared/sub", "--seed=456"); err != nil || ws != 0 {
		t.Fatalf("Error verifying shared volume sub-dir from root container after restore, ws: %v, err: %v", ws, err)
	}
	if ws, err := execute(conf, newConts[1], "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--target-dir=/shared/sub", "--seed=456"); err != nil || ws != 0 {
		t.Fatalf("Error verifying shared volume sub-dir from sub-container after restore, ws: %v, err: %v", ws, err)
	}
	if ws, err := execute(conf, newConts[2], "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--target-dir=/shared/sub", "--seed=456"); err != nil || ws != 0 {
		t.Fatalf("Error verifying shared volume sub-dir from sub-container 2 after restore, ws: %v, err: %v", ws, err)
	}

	for _, c := range newConts {
		c.SignalContainer(unix.SIGKILL, false)
		c.Wait()
	}
}

// TestMultiContainerChainedCheckpointRestore tests that a multi-container
// sandbox that was restored from a split filesystem checkpoint can be
// checkpointed again, by chaining split checkpoint/restore 3 times.
//
// The sandbox runs two sub-containers, each storing its incrementing counter in
// a container-private tmpfs mount (saved via SplitFSCheckpointPaths) and
// writing the current value to an output file on the host once per second.
// Every iteration:
//  1. Checkpoints the sandbox with SplitFSCheckpointPaths targeting both
//     sub-containers' tmpfs mounts, verifies that the split filesystem image
//     files were created, and records the last counter each container wrote.
//  2. Destroys the containers, so that the restored ones don't conflict with
//     them, and recreates the host output files.
//  3. Restores the sandbox into containers with new IDs and checks that both
//     applications resumed counting from the counter preserved in the split
//     filesystem checkpoint, and that all containers are running.
func TestMultiContainerChainedCheckpointRestore(t *testing.T) {
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint not supported")
	}

	// Skip overlay on default mounts because the test communicates progress
	// via output files on the host; each sub-container's counter file lives on
	// a dedicated tmpfs mount backed by a filestore via mount hints.
	for name, conf := range configs(t, true /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
			testMultiContainerChainedCheckpointRestore(t, conf)
		})
	}
}

func testMultiContainerChainedCheckpointRestore(t *testing.T, conf *config.Config) {
	rootDir, cleanup, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("error creating root dir: %v", err)
	}
	defer cleanup()
	conf.RootDir = rootDir

	testDir := makeTempDir(t, "chained-checkpoint-test")
	outputPath1 := filepath.Join(testDir, "output1")
	outputFile1 := resetOutputFile(t, outputPath1)
	outputPath2 := filepath.Join(testDir, "output2")
	outputFile2 := resetOutputFile(t, outputPath2)

	const (
		container1Name = "sub-container-1"
		container2Name = "sub-container-2"
		tmpfsMount1    = "/tmpfs1"
		tmpfsMount2    = "/tmpfs2"
	)

	counterFile1 := filepath.Join(tmpfsMount1, "counter")
	counterFile2 := filepath.Join(tmpfsMount2, "counter")
	script1 := fmt.Sprintf("echo 0 > %q; while true; do i=$(cat %q); echo $i >> %q; echo $((i+1)) > %q; sleep 1; done", counterFile1, counterFile1, outputPath1, counterFile1)
	script2 := fmt.Sprintf("echo 100 > %q; while true; do j=$(cat %q); echo $j >> %q; echo $((j+1)) > %q; sleep 1; done", counterFile2, counterFile2, outputPath2, counterFile2)
	testSpecs, ids := createSpecs(
		sleepCmd,
		[]string{"bash", "-c", script1},
		[]string{"bash", "-c", script2},
	)
	testSpecs[1].Annotations[specutils.ContainerdContainerNameAnnotation] = container1Name
	testSpecs[2].Annotations[specutils.ContainerdContainerNameAnnotation] = container2Name

	tmpfsSource1 := makeTempDir(t, "tmpfs-source-1")
	tmpfsSource2 := makeTempDir(t, "tmpfs-source-2")
	addTmpfsMountToContainer(testSpecs[0], testSpecs[1], "tmpfs1", tmpfsSource1, tmpfsMount1)
	addTmpfsMountToContainer(testSpecs[0], testSpecs[2], "tmpfs2", tmpfsSource2, tmpfsMount2)

	conts, cleanupConts, err := startContainers(conf, testSpecs, ids)
	if err != nil {
		t.Fatalf("error starting containers: %v", err)
	}
	// cleanupConts is replaced on every iteration below, so it must be called
	// through a closure to destroy the containers of the last iteration.
	defer func() { cleanupConts() }()

	// Wait until both applications have run and written initial output.
	if err := waitForFileNotEmpty(outputFile1); err != nil {
		t.Fatalf("Failed to wait for output file 1: %v", err)
	}
	if err := waitForFileNotEmpty(outputFile2); err != nil {
		t.Fatalf("Failed to wait for output file 2: %v", err)
	}

	hostCounter1 := filepath.Join(tmpfsSource1, "counter")
	hostCounter2 := filepath.Join(tmpfsSource2, "counter")
	checkHostFilesAbsent(t, hostCounter1, hostCounter2)

	const iterations = 3
	for iter := 0; iter < iterations; iter++ {
		checkpointDir := filepath.Join(testDir, fmt.Sprintf("checkpoint-%d", iter))
		if err := os.MkdirAll(checkpointDir, 0777); err != nil {
			t.Fatalf("iter %d: os.MkdirAll failed: %v", iter, err)
		}

		checkpointWaiter := make(chan error, 1)
		go func() {
			checkpointWaiter <- conts[1].WaitCheckpoint()
		}()

		// Checkpoint root container with SplitFSCheckpointPaths targeting both
		// sub-containers' tmpfs mounts.
		checkpointOpts := sandbox.CheckpointOpts{
			Compression: statefile.CompressionLevelDefault,
			SplitFSCheckpointPaths: []checkpoint.ResourceID{
				{ContainerName: container1Name, Path: tmpfsMount1},
				{ContainerName: container2Name, Path: tmpfsMount2},
			},
		}
		if err := conts[0].Checkpoint(conf, checkpointDir, checkpointOpts); err != nil {
			t.Fatalf("iter %d: error checkpointing container: %v", iter, err)
		}

		select {
		case waitErr := <-checkpointWaiter:
			if waitErr != nil {
				t.Errorf("iter %d: error waiting for checkpoint to complete: %v", iter, waitErr)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("iter %d: timed out waiting for checkpoint to complete", iter)
		}

		checkFSCheckpointFiles(t, checkpointDir)

		lastNum1, err := readOutputNum(outputPath1, -1)
		if err != nil {
			t.Fatalf("iter %d: error reading outputFile1: %v", iter, err)
		}
		lastNum2, err := readOutputNum(outputPath2, -1)
		if err != nil {
			t.Fatalf("iter %d: error reading outputFile2: %v", iter, err)
		}

		// Destroy the current containers before restoring so there is no
		// identity or resource conflict with the restored ones.
		cleanupConts()
		cleanupConts = func() {}
		conts = nil

		// Delete and recreate output files before restoring.
		outputFile1 = resetOutputFile(t, outputPath1)
		outputFile2 = resetOutputFile(t, outputPath2)

		// Restore into new containers with fresh IDs.
		newIDs := make([]string, 0, len(ids))
		for range ids {
			newIDs = append(newIDs, testutil.RandomContainerID())
		}
		for _, spec := range testSpecs[1:] {
			spec.Annotations[specutils.ContainerdSandboxIDAnnotation] = newIDs[0]
		}

		restoredConts, restoredCleanup, err := restoreContainers(conf, testSpecs, newIDs, checkpointDir)
		if err != nil {
			t.Fatalf("iter %d: error restoring containers: %v", iter, err)
		}
		conts, cleanupConts = restoredConts, restoredCleanup

		// Wait until both applications have run after restore.
		if err := waitForFileNotEmpty(outputFile1); err != nil {
			t.Fatalf("iter %d: failed to wait for outputFile1 after restore: %v", iter, err)
		}
		if err := waitForFileNotEmpty(outputFile2); err != nil {
			t.Fatalf("iter %d: failed to wait for outputFile2 after restore: %v", iter, err)
		}
		checkHostFilesAbsent(t, hostCounter1, hostCounter2)

		firstNum1, err := readOutputNum(outputPath1, 0)
		if err != nil {
			t.Fatalf("iter %d: error reading outputFile1 first num: %v", iter, err)
		}
		firstNum2, err := readOutputNum(outputPath2, 0)
		if err != nil {
			t.Fatalf("iter %d: error reading outputFile2 first num: %v", iter, err)
		}

		if lastNum1+1 != firstNum1 {
			t.Errorf("iter %d: container 1 numbers not in order, previous: %d, next: %d", iter, lastNum1, firstNum1)
		}
		if lastNum2+1 != firstNum2 {
			t.Errorf("iter %d: container 2 numbers not in order, previous: %d, next: %d", iter, lastNum2, firstNum2)
		}

		for _, cont := range conts {
			state := cont.State()
			if state.Status != Running {
				t.Fatalf("iter %d: container %v is not running: %v", iter, cont.ID, state.Status)
			}
		}
	}
}

// resetOutputFile removes path, if it exists, and creates an empty file that
// the sandboxed application can write to. The file is closed when the test
// finishes.
func resetOutputFile(t *testing.T, path string) *os.File {
	t.Helper()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatalf("error removing %q: %v", path, err)
	}
	f, err := createWriteableOutputFile(path)
	if err != nil {
		t.Fatalf("error creating output file %q: %v", path, err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
