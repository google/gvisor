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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/state/checkpointfiles"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/sandbox"
	"gvisor.dev/gvisor/runsc/specutils"
)

// TestCombinedRestore runs a matrix of combined restore test cases.
// It verifies that restoring a container from a Sentry checkpoint (T1) and a
// filesystem checkpoint (T2) works correctly under various path filtering
// configurations and container structures (single and multi-container).
func TestCombinedRestore(t *testing.T) {
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint not supported")
	}

	const (
		rootName = "root-cont"
		subName  = "sub-cont"
	)

	overlay1Dest := filepath.Join(testutil.TmpDir(), "overlay1")
	overlay2Dest := filepath.Join(testutil.TmpDir(), "overlay2")

	testCases := []struct {
		name             string
		t1Writable       map[string]bool
		t2Writable       map[string]bool
		t1Empty          map[string]bool
		paths            []checkpoint.ResourceID
		expectedRestored map[string]bool
	}{
		{
			// "all" restores all filesystems (both rootfs and overlays) for all containers
			// by specifying "all-tmpfs" paths filter.
			name:  "all",
			paths: []checkpoint.ResourceID{{Path: "all-tmpfs"}},
			expectedRestored: map[string]bool{
				"root-cont:/":               true,
				"root-cont:" + overlay1Dest: true,
				"sub-cont:/":                true,
				"sub-cont:" + overlay2Dest:  true,
			},
		},
		{
			// "only-overlay1-no-container" restores only the overlay of the root container
			// (`overlay1Dest`), without specifying the container name in the path filter.
			// Other filesystems should remain at their T1 state.
			name: "only-overlay1-no-container",
			paths: []checkpoint.ResourceID{
				{Path: overlay1Dest},
			},
			expectedRestored: map[string]bool{
				"root-cont:/":               false,
				"root-cont:" + overlay1Dest: true,
				"sub-cont:/":                false,
				"sub-cont:" + overlay2Dest:  false,
			},
		},
		{
			// "only-rootfs-no-container" restores only the root filesystem (`/`) for all
			// containers, without specifying container names. Overlays should remain at
			// their T1 state.
			name: "only-rootfs-no-container",
			paths: []checkpoint.ResourceID{
				{Path: "/"},
			},
			expectedRestored: map[string]bool{
				"root-cont:/":               true,
				"root-cont:" + overlay1Dest: false,
				"sub-cont:/":                true,
				"sub-cont:" + overlay2Dest:  false,
			},
		},
		{
			// "only-root-rootfs" restores only the root filesystem (`/`) of the root container
			// (`root-cont`). Other filesystems (including the root container's overlay and
			// the sub-container's filesystems) should remain at their T1 state.
			name: "only-root-rootfs",
			paths: []checkpoint.ResourceID{
				{ContainerName: rootName, Path: "/"},
			},
			expectedRestored: map[string]bool{
				"root-cont:/":               true,
				"root-cont:" + overlay1Dest: false,
				"sub-cont:/":                false,
				"sub-cont:" + overlay2Dest:  false,
			},
		},
		{
			// "root-rootfs-and-overlay1" restores the root filesystem (`/`) and the overlay
			// (`overlay1Dest`) of the root container (`root-cont`). The sub-container's
			// filesystems should remain at their T1 state.
			name: "root-rootfs-and-overlay1",
			paths: []checkpoint.ResourceID{
				{ContainerName: rootName, Path: "/"},
				{ContainerName: rootName, Path: overlay1Dest},
			},
			expectedRestored: map[string]bool{
				"root-cont:/":               true,
				"root-cont:" + overlay1Dest: true,
				"sub-cont:/":                false,
				"sub-cont:" + overlay2Dest:  false,
			},
		},
		{
			// "overlay1-and-overlay2" restores the overlays of both the root container
			// (`overlay1Dest`) and the sub-container (`overlay2Dest`). The root filesystems
			// of both containers should remain at their T1 state.
			name: "overlay1-and-overlay2",
			paths: []checkpoint.ResourceID{
				{ContainerName: rootName, Path: overlay1Dest},
				{ContainerName: subName, Path: overlay2Dest},
			},
			expectedRestored: map[string]bool{
				"root-cont:/":               false,
				"root-cont:" + overlay1Dest: true,
				"sub-cont:/":                false,
				"sub-cont:" + overlay2Dest:  true,
			},
		},
		{
			// "only-sub-rootfs" restores only the root filesystem (`/`) of the sub-container
			// (`sub-cont`). Other filesystems should remain at their T1 state.
			name: "only-sub-rootfs",
			paths: []checkpoint.ResourceID{
				{ContainerName: subName, Path: "/"},
			},
			expectedRestored: map[string]bool{
				"root-cont:/":               false,
				"root-cont:" + overlay1Dest: false,
				"sub-cont:/":                true,
				"sub-cont:" + overlay2Dest:  false,
			},
		},
		{
			// "only-sub-overlay" restores only the overlay of the sub-container
			// (`overlay2Dest`). Other filesystems should remain at their T1 state.
			name: "only-sub-overlay",
			paths: []checkpoint.ResourceID{
				{ContainerName: subName, Path: overlay2Dest},
			},
			expectedRestored: map[string]bool{
				"root-cont:/":               false,
				"root-cont:" + overlay1Dest: false,
				"sub-cont:/":                false,
				"sub-cont:" + overlay2Dest:  true,
			},
		},
		{
			// "sub-rootfs-and-overlay2" restores the root filesystem and overlay
			// of the sub-container, while leaving the root container at T1.
			name: "sub-rootfs-and-overlay2",
			paths: []checkpoint.ResourceID{
				{ContainerName: subName, Path: "/"},
				{ContainerName: subName, Path: overlay2Dest},
			},
			expectedRestored: map[string]bool{
				"root-cont:/":               false,
				"root-cont:" + overlay1Dest: false,
				"sub-cont:/":                true,
				"sub-cont:" + overlay2Dest:  true,
			},
		},
		{
			// "both-rootfs-explicit" explicitly restores rootfs of both containers
			// by container name.
			name: "both-rootfs-explicit",
			paths: []checkpoint.ResourceID{
				{ContainerName: rootName, Path: "/"},
				{ContainerName: subName, Path: "/"},
			},
			expectedRestored: map[string]bool{
				"root-cont:/":               true,
				"root-cont:" + overlay1Dest: false,
				"sub-cont:/":                true,
				"sub-cont:" + overlay2Dest:  false,
			},
		},
		{
			// "empty-overlay-t1" restores the overlay of the root container which was empty
			// at the time of the full checkpoint (T1), but had a new file written to it at
			// T2. Verifies that combined restore successfully restores the new file even if
			// the overlay was empty at T1.
			name: "empty-overlay-t1",
			t1Empty: map[string]bool{
				"root-cont:" + overlay1Dest: true,
			},
			paths: []checkpoint.ResourceID{
				{ContainerName: rootName, Path: overlay1Dest},
			},
			expectedRestored: map[string]bool{
				"root-cont:/":               false,
				"root-cont:" + overlay1Dest: true,
				"sub-cont:/":                false,
				"sub-cont:" + overlay2Dest:  false,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runCombinedRestoreTest(t, tc.t1Writable, tc.t2Writable, tc.t1Empty, tc.paths, tc.expectedRestored, rootName, subName, overlay1Dest, overlay2Dest)
		})
	}
}

func runCombinedRestoreTest(t *testing.T, t1Writable, t2Writable, t1Empty map[string]bool, paths []checkpoint.ResourceID, expectedRestored map[string]bool, rootName, subName, overlay1Dest, overlay2Dest string) {
	conf := testutil.TestConfig(t)

	rootDir, cleanupRoot, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("Error creating root dir: %v", err)
	}
	defer cleanupRoot()
	conf.RootDir = rootDir

	tempDir, err := os.MkdirTemp(testutil.TmpDir(), "combined-restore-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	checkpointDir1 := filepath.Join(tempDir, "checkpoint1")
	checkpointDir2 := filepath.Join(tempDir, "checkpoint2")
	overlayDir := filepath.Join(tempDir, "overlay")
	overlay1Src := filepath.Join(tempDir, "overlay1-src")
	overlay2Src := filepath.Join(tempDir, "overlay2-src")

	for _, d := range []string{checkpointDir1, checkpointDir2, overlayDir, overlay1Src, overlay2Src} {
		if err := os.MkdirAll(d, 0777); err != nil {
			t.Fatalf("failed to create dir %q: %v", d, err)
		}
		if err := os.Chmod(d, 0777); err != nil {
			t.Fatalf("failed to chmod dir %q: %v", d, err)
		}
	}

	// We must also ensure the destination directories exist on host because they are bind mounted.
	if err := os.MkdirAll(overlay1Dest, 0777); err != nil {
		t.Fatalf("failed to create overlay1 dest: %v", err)
	}
	if err := os.MkdirAll(overlay2Dest, 0777); err != nil {
		t.Fatalf("failed to create overlay2 dest: %v", err)
	}
	defer os.RemoveAll(overlay1Dest)
	defer os.RemoveAll(overlay2Dest)

	t1W := t1Writable
	if t1W == nil {
		t1W = expectedRestored
	}
	t2W := t2Writable
	if t2W == nil {
		t2W = expectedRestored
	}
	t1E := t1Empty
	if t1E == nil {
		t1E = make(map[string]bool)
	}

	// Extract writability flags.
	rootWritableT1 := t1W["root-cont:/"]
	overlay1WritableT1 := t1W["root-cont:"+overlay1Dest]
	subRootWritableT1 := t1W["sub-cont:/"]
	overlay2WritableT1 := t1W["sub-cont:"+overlay2Dest]

	rootWritableT2 := t2W["root-cont:/"]
	overlay1WritableT2 := t2W["root-cont:"+overlay1Dest]
	subRootWritableT2 := t2W["sub-cont:/"]
	overlay2WritableT2 := t2W["sub-cont:"+overlay2Dest]

	conf.Overlay2.Set("all:dir=" + overlayDir)

	// Start two containers which sleep.
	testAppSleepArgv := []string{"sleep", "10000"}
	saveSpecs, ids := createSpecs(testAppSleepArgv, testAppSleepArgv)
	saveSpecs[0].Annotations[specutils.ContainerdContainerNameAnnotation] = rootName
	saveSpecs[1].Annotations[specutils.ContainerdContainerNameAnnotation] = subName

	setupContainerMounts(saveSpecs[0], "overlay1", overlay1WritableT1, overlay1Src, overlay1Dest)
	setupContainerMounts(saveSpecs[1], "overlay2", overlay2WritableT1, overlay2Src, overlay2Dest)
	saveSpecs[0].Root.Readonly = !rootWritableT1
	saveSpecs[1].Root.Readonly = !subRootWritableT1

	var rootWritablePathsT1 []string
	if overlay1WritableT1 {
		rootWritablePathsT1 = append(rootWritablePathsT1, overlay1Dest)
	}
	makeUnconfiguredMountsReadOnly(saveSpecs[0], rootWritablePathsT1)

	var subWritablePathsT1 []string
	if overlay2WritableT1 {
		subWritablePathsT1 = append(subWritablePathsT1, overlay2Dest)
	}
	makeUnconfiguredMountsReadOnly(saveSpecs[1], subWritablePathsT1)

	conts1, cleanupConts1, err := startContainers(conf, saveSpecs, ids)
	if err != nil {
		t.Fatalf("Error starting containers 1: %v", err)
	}
	defer cleanupConts1()

	// 1. Setup T1 files.
	setupT1 := func(cont *Container, mountPath string, writable, empty bool) {
		if !writable || empty {
			return
		}
		modFile := filepath.Join(mountPath, "file_to_modify")
		delFile := filepath.Join(mountPath, "file_to_delete")
		// Ignore safetext/shsprintf linter suggestion.
		cmd := fmt.Sprintf("echo initial > %s && echo delete_me > %s", modFile, delFile)
		if ws, err := execute(conf, cont, "/bin/bash", "-c", cmd); err != nil || ws != 0 {
			t.Fatalf("failed to setup T1 files in %q: err %v, ws %d", mountPath, err, ws)
		}
	}
	setupT1(conts1[0], "/", rootWritableT1, t1E["root-cont:/"])
	setupT1(conts1[0], overlay1Dest, overlay1WritableT1, t1E["root-cont:"+overlay1Dest])
	setupT1(conts1[1], "/", subRootWritableT1, t1E["sub-cont:/"])
	setupT1(conts1[1], overlay2Dest, overlay2WritableT1, t1E["sub-cont:"+overlay2Dest])

	// Checkpoint Sentry T1.
	cOpts := sandbox.CheckpointOpts{
		SplitFSCheckpointPaths: []checkpoint.ResourceID{{Path: "all-tmpfs"}},
	}
	if err := conts1[0].Checkpoint(conf, checkpointDir1, cOpts); err != nil {
		t.Fatalf("failed to checkpoint Sentry T1: %v", err)
	}
	cleanupConts1() // Destroy conts1.

	// 2. Restore conts2 to mutate to T2.
	restoreSpecs, restoreIDs := createSpecs(testAppSleepArgv, testAppSleepArgv)
	restoreSpecs[0].Annotations[specutils.ContainerdContainerNameAnnotation] = rootName
	restoreSpecs[1].Annotations[specutils.ContainerdContainerNameAnnotation] = subName

	setupContainerMounts(restoreSpecs[0], "overlay1", overlay1WritableT2, overlay1Src, overlay1Dest)
	setupContainerMounts(restoreSpecs[1], "overlay2", overlay2WritableT2, overlay2Src, overlay2Dest)
	restoreSpecs[0].Root.Readonly = !rootWritableT2
	restoreSpecs[1].Root.Readonly = !subRootWritableT2

	var rootWritablePathsT2 []string
	if overlay1WritableT2 {
		rootWritablePathsT2 = append(rootWritablePathsT2, overlay1Dest)
	}
	makeUnconfiguredMountsReadOnly(restoreSpecs[0], rootWritablePathsT2)

	var subWritablePathsT2 []string
	if overlay2WritableT2 {
		subWritablePathsT2 = append(subWritablePathsT2, overlay2Dest)
	}
	makeUnconfiguredMountsReadOnly(restoreSpecs[1], subWritablePathsT2)

	fs1Dir := filepath.Join(checkpointDir1, "fs")
	conts2, cleanupConts2, err := restoreContainersWithFSRestore(conf, restoreSpecs, restoreIDs, checkpointDir1, fs1Dir)
	if err != nil {
		t.Fatalf("Error restoring containers 2: %v", err)
	}
	defer cleanupConts2()

	// Verify T1 state in conts2 (sanity check).
	verifyMountState(t, conf, conts2[0], "/", rootWritableT1, t1E["root-cont:/"], rootWritableT2, false)
	verifyMountState(t, conf, conts2[0], overlay1Dest, overlay1WritableT1, t1E["root-cont:"+overlay1Dest], overlay1WritableT2, false)
	verifyMountState(t, conf, conts2[1], "/", subRootWritableT1, t1E["sub-cont:/"], subRootWritableT2, false)
	verifyMountState(t, conf, conts2[1], overlay2Dest, overlay2WritableT1, t1E["sub-cont:"+overlay2Dest], overlay2WritableT2, false)

	// Mutate to T2.
	mutateToT2 := func(cont *Container, mountPath string, t1Writable, t1Empty, t2Writable bool) {
		if !t2Writable {
			return
		}
		newFile := filepath.Join(mountPath, "new_file")
		// Ignore safetext/shsprintf linter suggestion.
		cmd := fmt.Sprintf("echo new > %s", newFile)
		if t1Writable && !t1Empty {
			modFile := filepath.Join(mountPath, "file_to_modify")
			delFile := filepath.Join(mountPath, "file_to_delete")
			// Ignore safetext/shsprintf linter suggestion.
			cmd = fmt.Sprintf("echo modified > %s && rm %s && echo new > %s", modFile, delFile, newFile)
		}
		if ws, err := execute(conf, cont, "/bin/bash", "-c", cmd); err != nil || ws != 0 {
			t.Fatalf("failed to mutate files in %q: err %v, ws %d", mountPath, err, ws)
		}
	}
	mutateToT2(conts2[0], "/", rootWritableT1, t1E["root-cont:/"], rootWritableT2)
	mutateToT2(conts2[0], overlay1Dest, overlay1WritableT1, t1E["root-cont:"+overlay1Dest], overlay1WritableT2)
	mutateToT2(conts2[1], "/", subRootWritableT1, t1E["sub-cont:/"], subRootWritableT2)
	mutateToT2(conts2[1], overlay2Dest, overlay2WritableT1, t1E["sub-cont:"+overlay2Dest], overlay2WritableT2)

	// FSCheckpoint T2 with paths filter.
	if err := conts2[0].FSSave(conf, checkpointDir2, sandbox.FSSaveOpts{
		ExitAfterSaving: true,
		Paths:           paths,
	}); err != nil {
		t.Fatalf("failed to FSCheckpoint T2: %v", err)
	}

	// Wait for conts2 to exit.
	if _, err := conts2[0].Wait(); err != nil {
		t.Fatalf("failed to wait for container 2: %v", err)
	}
	cleanupConts2() // Destroy conts2.

	// 3. Restore conts3 (Sentry T1 + FS T2).
	conts3, cleanupConts3, err := restoreContainersWithFSRestore(conf, restoreSpecs, restoreIDs, checkpointDir1, checkpointDir2)
	if err != nil {
		t.Fatalf("Error restoring containers 3: %v", err)
	}
	defer cleanupConts3()

	// Verify states.
	verifyMountState(t, conf, conts3[0], "/", rootWritableT1, t1E["root-cont:/"], rootWritableT2, expectedRestored["root-cont:/"])
	verifyMountState(t, conf, conts3[0], overlay1Dest, overlay1WritableT1, t1E["root-cont:"+overlay1Dest], overlay1WritableT2, expectedRestored["root-cont:"+overlay1Dest])
	verifyMountState(t, conf, conts3[1], "/", subRootWritableT1, t1E["sub-cont:/"], subRootWritableT2, expectedRestored["sub-cont:/"])
	verifyMountState(t, conf, conts3[1], overlay2Dest, overlay2WritableT1, t1E["sub-cont:"+overlay2Dest], overlay2WritableT2, expectedRestored["sub-cont:"+overlay2Dest])
}

func verifyMountState(t *testing.T, conf *config.Config, cont *Container, mountPath string, t1Writable, t1Empty, t2Writable, restored bool) {
	t.Helper()
	modFile := filepath.Join(mountPath, "file_to_modify")
	delFile := filepath.Join(mountPath, "file_to_delete")
	newFile := filepath.Join(mountPath, "new_file")

	if t2Writable {
		if restored {
			if t1Writable && !t1Empty {
				// Verify modified file has T2 content.
				verifyFileContent(t, conf, cont, modFile, "modified")
				// Verify deleted file does not exist.
				verifyFileNotExists(t, conf, cont, delFile)
			} else {
				verifyFileNotExists(t, conf, cont, modFile)
				verifyFileNotExists(t, conf, cont, delFile)
			}
			// Verify new file exists with T2 content.
			verifyFileContent(t, conf, cont, newFile, "new")
		} else {
			if t1Writable && !t1Empty {
				// Verify modified file has T1 content ("initial").
				verifyFileContent(t, conf, cont, modFile, "initial")
				// Verify deleted file still exists with T1 content ("delete_me").
				verifyFileContent(t, conf, cont, delFile, "delete_me")
			} else {
				verifyFileNotExists(t, conf, cont, modFile)
				verifyFileNotExists(t, conf, cont, delFile)
			}
			// Verify new file does NOT exist.
			verifyFileNotExists(t, conf, cont, newFile)
		}
	} else {
		// If not writable in T2, files should not exist.
		verifyFileNotExists(t, conf, cont, modFile)
		verifyFileNotExists(t, conf, cont, delFile)
		verifyFileNotExists(t, conf, cont, newFile)
	}
}

func setupContainerMounts(spec *specs.Spec, name string, writable bool, src, dest string) {
	options := []string{"bind"}
	if !writable {
		options = append(options, "ro")
	}
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Source:      src,
		Destination: dest,
		Type:        "bind",
		Options:     options,
	})

	if writable {
		spec.Annotations[boot.MountPrefix+name+".source"] = src
		spec.Annotations[boot.MountPrefix+name+".type"] = "bind"
		spec.Annotations[boot.MountPrefix+name+".share"] = "container"
	}
}

func makeUnconfiguredMountsReadOnly(spec *specs.Spec, writablePaths []string) {
	for i := range spec.Mounts {
		m := &spec.Mounts[i]
		if m.Type != "bind" {
			continue
		}
		isWritable := false
		for _, p := range writablePaths {
			if m.Destination == p {
				isWritable = true
				break
			}
		}
		if !isWritable {
			hasRo := false
			for _, opt := range m.Options {
				if opt == "ro" {
					hasRo = true
					break
				}
			}
			if !hasRo {
				m.Options = append(m.Options, "ro")
			}
		}
	}
}

func verifyFileContent(t *testing.T, conf *config.Config, cont *Container, path, expected string) {
	t.Helper()
	// Ignore safetext/shsprintf linter suggestion.
	cmd := fmt.Sprintf("echo -n \"$(<%s)\"", path)
	stdout, err := executeCombinedOutput(conf, cont, nil, "/bin/bash", "-c", cmd)
	if err != nil {
		t.Fatalf("failed to read %q: %v", path, err)
	}
	if got := strings.TrimSpace(string(stdout)); got != expected {
		t.Errorf("file %q content mismatch: got %q, want %q", path, got, expected)
	}
}

func verifyFileSizeZero(t *testing.T, conf *config.Config, cont *Container, path string) {
	t.Helper()
	// Command returns 0 if file exists and has size 0.
	cmd := fmt.Sprintf("[ -f %q ] && [ ! -s %q ]", path, path)
	status, err := execute(conf, cont, "/bin/bash", "-c", cmd)
	if err != nil {
		t.Fatalf("failed to execute check for %q: %v", path, err)
	}
	if status != 0 {
		t.Errorf("file %q does not exist or is not empty (status %d)", path, status)
	}
}

func verifyFileNotExists(t *testing.T, conf *config.Config, cont *Container, path string) {
	t.Helper()
	// Command returns 0 if file does NOT exist.
	cmd := fmt.Sprintf("[ ! -e %q ]", path)
	status, err := execute(conf, cont, "/bin/bash", "-c", cmd)
	if err != nil {
		t.Fatalf("failed to execute check for %q: %v", path, err)
	}
	if status != 0 {
		t.Errorf("file %q exists but should not", path)
	}
}

// TestSplitFSCheckpointRestoreMixed verifies that a single container can be
// successfully restored using a sentry checkpoint from T1 and a filesystem
// checkpoint from T2. It ensures that modifications to host-backed filesystems
// (like overlay) are preserved, while modifications to in-memory filesystems
// (like tmpfs) at T2 are discarded (reverted to T1).
func TestSplitFSCheckpointRestoreMixed(t *testing.T) {
	// We only run this test if checkpoint/restore is supported.
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint not supported")
	}

	tempDir, err := os.MkdirTemp(testutil.TmpDir(), "TestSplitFSCheckpointRestoreMixed")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	checkpointDir1 := filepath.Join(tempDir, "checkpoint1")
	if err := os.MkdirAll(checkpointDir1, 0755); err != nil {
		t.Fatalf("failed to create checkpoint dir 1: %v", err)
	}
	if err := os.Chmod(checkpointDir1, 0777); err != nil {
		t.Fatalf("error chmoding checkpoint dir 1: %v", err)
	}

	checkpointDir2 := filepath.Join(tempDir, "checkpoint2")
	if err := os.MkdirAll(checkpointDir2, 0755); err != nil {
		t.Fatalf("failed to create checkpoint dir 2: %v", err)
	}
	if err := os.Chmod(checkpointDir2, 0777); err != nil {
		t.Fatalf("error chmoding checkpoint dir 2: %v", err)
	}

	overlayDir := filepath.Join(tempDir, "overlay")
	if err := os.MkdirAll(overlayDir, 0755); err != nil {
		t.Fatalf("failed to create overlay dir: %v", err)
	}
	if err := os.Chmod(overlayDir, 0777); err != nil {
		t.Fatalf("error chmoding overlay directory: %v", err)
	}

	bindSrcDir := filepath.Join(tempDir, "bind-src")
	if err := os.MkdirAll(bindSrcDir, 0755); err != nil {
		t.Fatalf("failed to create bind src dir: %v", err)
	}
	if err := os.Chmod(bindSrcDir, 0777); err != nil {
		t.Fatalf("error chmoding bind src directory: %v", err)
	}

	tmpfsMount := "/tmpfs-mount"
	overlayMount := filepath.Join(testutil.TmpDir(), "overlay-mount")

	tmpfsFile := filepath.Join(tmpfsMount, "file.txt")
	overlayFile := filepath.Join(overlayMount, "file.txt")

	spec := testutil.NewSpecWithArgs("sleep", "10000")
	spec.Root.Readonly = true
	spec.Mounts = append(spec.Mounts,
		specs.Mount{
			Destination: tmpfsMount,
			Type:        "tmpfs",
		},
		specs.Mount{
			Destination: overlayMount,
			Type:        "bind",
			Source:      bindSrcDir,
		},
	)

	conf := testutil.TestConfig(t)
	conf.Overlay2.Set("all:dir=" + overlayDir)

	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	cont1, err := New(conf, Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	})
	if err != nil {
		t.Fatalf("failed to create container 1: %v", err)
	}
	defer cont1.Destroy()

	if err := cont1.Start(conf); err != nil {
		t.Fatalf("failed to start container 1: %v", err)
	}

	// Ignore safetext/shsprintf linter suggestion.
	tmpfsCmd := fmt.Sprintf("echo hello-tmpfs > %s", tmpfsFile)
	if ws, err := execute(conf, cont1, "/bin/bash", "-c", tmpfsCmd); err != nil || ws != 0 {
		t.Fatalf("failed to write to tmpfs: err %v, ws %v", err, ws)
	}

	// Ignore safetext/shsprintf linter suggestion.
	overlayCmd := fmt.Sprintf("echo hello-overlay > %s", overlayFile)
	if ws, err := execute(conf, cont1, "/bin/bash", "-c", overlayCmd); err != nil || ws != 0 {
		t.Fatalf("failed to write to overlay: err %v, ws %v", err, ws)
	}

	cOpts := sandbox.CheckpointOpts{
		SplitFSCheckpointPaths: []checkpoint.ResourceID{{Path: "all-tmpfs"}},
	}
	if err := cont1.Checkpoint(conf, checkpointDir1, cOpts); err != nil {
		t.Fatalf("failed to checkpoint container 1: %v", err)
	}

	cont1.Destroy()

	fs1Dir := filepath.Join(checkpointDir1, "fs")
	cont2, err := New(conf, Args{
		ID:                 cont1.ID,
		Spec:               spec,
		BundleDir:          bundleDir,
		FSRestoreImagePath: fs1Dir,
	})
	if err != nil {
		t.Fatalf("failed to create container 2: %v", err)
	}
	defer cont2.Destroy()

	if err := cont2.Restore(conf, checkpointDir1, false, true, nil); err != nil {
		t.Fatalf("failed to restore container 2: %v", err)
	}

	stdout, err := executeCombinedOutput(conf, cont2, nil, "/bin/cat", tmpfsFile)
	if err != nil {
		t.Fatalf("failed to cat tmpfs file: %v", err)
	}
	if got := strings.TrimSpace(string(stdout)); got != "hello-tmpfs" {
		t.Errorf("unexpected tmpfs content: got %q, want %q", got, "hello-tmpfs")
	}

	stdout, err = executeCombinedOutput(conf, cont2, nil, "/bin/cat", overlayFile)
	if err != nil {
		t.Fatalf("failed to cat overlay file: %v", err)
	}
	if got := strings.TrimSpace(string(stdout)); got != "hello-overlay" {
		t.Errorf("unexpected overlay content: got %q, want %q", got, "hello-overlay")
	}

	// Ignore safetext/shsprintf linter suggestion.
	modOverlayCmd := fmt.Sprintf("echo hello-overlay-modified > %s", overlayFile)
	if ws, err := execute(conf, cont2, "/bin/bash", "-c", modOverlayCmd); err != nil || ws != 0 {
		t.Fatalf("failed to modify overlay: err %v, ws %v", err, ws)
	}

	// Ignore safetext/shsprintf linter suggestion.
	modTmpfsCmd := fmt.Sprintf("echo hello-tmpfs-modified > %s", tmpfsFile)
	if ws, err := execute(conf, cont2, "/bin/bash", "-c", modTmpfsCmd); err != nil || ws != 0 {
		t.Fatalf("failed to modify tmpfs: err %v, ws %v", err, ws)
	}

	paths := []checkpoint.ResourceID{
		{Path: "/"},
		{Path: overlayMount},
		{Path: testutil.TmpDir()},
	}
	if err := cont2.FSSave(conf, checkpointDir2, sandbox.FSSaveOpts{
		ExitAfterSaving: true,
		Paths:           paths,
	}); err != nil {
		t.Fatalf("failed to fscheckpoint: %v", err)
	}

	// Wait for container 2 to stop.
	if _, err := cont2.Wait(); err != nil {
		t.Fatalf("failed to wait for container 2: %v", err)
	}
	cont2.Destroy()

	for _, name := range []string{
		checkpointfiles.FSCheckpointManifestFileName,
		checkpointfiles.FSCheckpointMultiTarFileName,
		checkpointfiles.PagesFileName,
		checkpointfiles.PagesMetadataFileName,
	} {
		src := filepath.Join(checkpointDir2, name)
		dst := filepath.Join(fs1Dir, name)
		if err := copyFile(src, dst); err != nil {
			t.Fatalf("failed to copy %s to %s: %v", src, dst, err)
		}
	}

	cont3, err := New(conf, Args{
		ID:                 cont1.ID,
		Spec:               spec,
		BundleDir:          bundleDir,
		CheckpointDirPath:  checkpointDir1,
		FSRestoreImagePath: fs1Dir,
		CombinedFSRestore:  true,
	})
	if err != nil {
		t.Fatalf("failed to create container 3: %v", err)
	}
	defer cont3.Destroy()

	if err := cont3.Restore(conf, checkpointDir1, false, true, nil); err != nil {
		t.Fatalf("failed to restore container 3: %v", err)
	}

	stdout, err = executeCombinedOutput(conf, cont3, nil, "/bin/cat", tmpfsFile)
	if err != nil {
		t.Fatalf("failed to cat tmpfs file: %v", err)
	}
	if got := strings.TrimSpace(string(stdout)); got != "hello-tmpfs" {
		t.Errorf("unexpected tmpfs content: got %q, want %q", got, "hello-tmpfs")
	}

	stdout, err = executeCombinedOutput(conf, cont3, nil, "/bin/cat", overlayFile)
	if err != nil {
		t.Fatalf("failed to cat overlay file: %v", err)
	}
	if got := strings.TrimSpace(string(stdout)); got != "hello-overlay-modified" {
		t.Errorf("unexpected overlay content: got %q, want %q", got, "hello-overlay-modified")
	}
}

// TestSplitFSCheckpointRestoreMixedMmap verifies that combined restore works
// correctly when the container process has mmap'd files in the overlay
// filesystem. It ensures that sentry correctly reconstructs the memory
// mappings using the restored private memory file from the FS checkpoint.
func TestSplitFSCheckpointRestoreMixedMmap(t *testing.T) {
	// We only run this test if checkpoint/restore is supported.
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint not supported")
	}

	tempDir, err := os.MkdirTemp(testutil.TmpDir(), "TestSplitFSCheckpointRestoreMixedMmap2")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	checkpointDir1 := filepath.Join(tempDir, "checkpoint1")
	if err := os.MkdirAll(checkpointDir1, 0755); err != nil {
		t.Fatalf("failed to create checkpoint dir 1: %v", err)
	}
	if err := os.Chmod(checkpointDir1, 0777); err != nil {
		t.Fatalf("error chmoding checkpoint dir 1: %v", err)
	}

	checkpointDir2 := filepath.Join(tempDir, "checkpoint2")
	if err := os.MkdirAll(checkpointDir2, 0755); err != nil {
		t.Fatalf("failed to create checkpoint dir 2: %v", err)
	}
	if err := os.Chmod(checkpointDir2, 0777); err != nil {
		t.Fatalf("error chmoding checkpoint dir 2: %v", err)
	}

	overlayDir := filepath.Join(tempDir, "overlay")
	if err := os.MkdirAll(overlayDir, 0755); err != nil {
		t.Fatalf("failed to create overlay dir: %v", err)
	}
	if err := os.Chmod(overlayDir, 0777); err != nil {
		t.Fatalf("error chmoding overlay directory: %v", err)
	}

	bindSrcDir := filepath.Join(tempDir, "bind-src")
	if err := os.MkdirAll(bindSrcDir, 0755); err != nil {
		t.Fatalf("failed to create bind src dir: %v", err)
	}
	if err := os.Chmod(bindSrcDir, 0777); err != nil {
		t.Fatalf("error chmoding bind src directory: %v", err)
	}

	targetFile := "/file.txt"
	bindMount := filepath.Join(testutil.TmpDir(), "bind-mount")

	readyFileHost := filepath.Join(bindSrcDir, "ready")
	readyFileGuest := filepath.Join(bindMount, "ready")
	goFileHost := filepath.Join(bindSrcDir, "go")
	goFileGuest := filepath.Join(bindMount, "go")
	outputFileHost := filepath.Join(bindSrcDir, "output")
	outputFileGuest := filepath.Join(bindMount, "output")

	testAppPath, err := testutil.FindFile("test/cmd/test_app/test_app")
	if err != nil {
		t.Fatalf("failed to find test_app: %v", err)
	}

	spec1 := testutil.NewSpecWithArgs(
		testAppPath, "mmap-helper",
		"-file", targetFile,
		"-ready", readyFileGuest,
		"-go", goFileGuest,
		"-output", outputFileGuest,
		"-dummy", "/dummy.txt",
		"-content", "hello",
	)
	spec1.Root.Readonly = false
	spec1.Mounts = append(spec1.Mounts,
		specs.Mount{
			Destination: bindMount,
			Type:        "bind",
			Source:      bindSrcDir,
		},
	)

	spec2 := testutil.NewSpecWithArgs(
		testAppPath, "mmap-helper",
		"-file", targetFile,
		"-ready", readyFileGuest,
		"-go", goFileGuest,
		"-output", outputFileGuest,
		"-content", "world",
	)
	spec2.Root.Readonly = false
	spec2.Mounts = append(spec2.Mounts,
		specs.Mount{
			Destination: bindMount,
			Type:        "bind",
			Source:      bindSrcDir,
		},
	)

	conf := testutil.TestConfig(t)
	conf.Overlay2.Set("root:dir=" + overlayDir)

	_, bundleDir1, cleanup1, err := testutil.SetupContainer(spec1, conf)
	if err != nil {
		t.Fatalf("error setting up container 1: %v", err)
	}
	defer cleanup1()

	_, bundleDir2, cleanup2, err := testutil.SetupContainer(spec2, conf)
	if err != nil {
		t.Fatalf("error setting up container 2: %v", err)
	}
	defer cleanup2()

	containerID := testutil.RandomContainerID()

	cont1, err := New(conf, Args{
		ID:        containerID,
		Spec:      spec1,
		BundleDir: bundleDir1,
	})
	if err != nil {
		t.Fatalf("failed to create container 1: %v", err)
	}
	defer cont1.Destroy()

	if err := cont1.Start(conf); err != nil {
		t.Fatalf("failed to start container 1: %v", err)
	}

	// Wait for ready file to be created.
	err = testutil.Poll(func() error {
		if _, err := os.Stat(readyFileHost); err != nil {
			return err
		}
		return nil
	}, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to wait for ready file 1: %v", err)
	}

	// Checkpoint cont1 (SplitFSCheckpointPaths: all-tmpfs)
	cOpts := sandbox.CheckpointOpts{
		SplitFSCheckpointPaths: []checkpoint.ResourceID{{Path: "all-tmpfs"}},
	}
	if err := cont1.Checkpoint(conf, checkpointDir1, cOpts); err != nil {
		t.Fatalf("failed to checkpoint container 1: %v", err)
	}
	cont1.Destroy()

	// Clean up ready file before starting container 2.
	if err := os.Remove(readyFileHost); err != nil {
		t.Fatalf("failed to remove ready file: %v", err)
	}

	// Now we start cont2 FRESH with spec2 (no dummy, content: world).
	cont2, err := New(conf, Args{
		ID:        containerID,
		Spec:      spec2,
		BundleDir: bundleDir2,
	})
	if err != nil {
		t.Fatalf("failed to create container 2: %v", err)
	}
	defer cont2.Destroy()

	if err := cont2.Start(conf); err != nil {
		t.Fatalf("failed to start container 2: %v", err)
	}

	// Wait for ready file to be created.
	err = testutil.Poll(func() error {
		if _, err := os.Stat(readyFileHost); err != nil {
			return err
		}
		return nil
	}, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to wait for ready file 2: %v", err)
	}

	// Save the FS of cont2.
	paths := []checkpoint.ResourceID{{Path: "/"}}
	if err := cont2.FSSave(conf, checkpointDir2, sandbox.FSSaveOpts{
		ExitAfterSaving: true,
		Paths:           paths,
	}); err != nil {
		t.Fatalf("failed to fscheckpoint: %v", err)
	}

	// Wait for container 2 to stop.
	if _, err := cont2.Wait(); err != nil {
		t.Fatalf("failed to wait for container 2: %v", err)
	}
	cont2.Destroy()

	// Copy new FS checkpoint over the old one.
	fs1Dir := filepath.Join(checkpointDir1, "fs")
	for _, name := range []string{
		checkpointfiles.FSCheckpointManifestFileName,
		checkpointfiles.FSCheckpointMultiTarFileName,
		checkpointfiles.PagesFileName,
		checkpointfiles.PagesMetadataFileName,
	} {
		src := filepath.Join(checkpointDir2, name)
		dst := filepath.Join(fs1Dir, name)
		if err := copyFile(src, dst); err != nil {
			t.Fatalf("failed to copy %s to %s: %v", src, dst, err)
		}
	}

	// Now we restore cont3 with mixed checkpoint.
	cont3, err := New(conf, Args{
		ID:                 containerID,
		Spec:               spec1,
		BundleDir:          bundleDir1,
		FSRestoreImagePath: fs1Dir,
	})
	if err != nil {
		t.Fatalf("failed to create container 3: %v", err)
	}
	defer cont3.Destroy()

	// Restore cont3. It will resume waiting for "go" file.
	if err := cont3.Restore(conf, checkpointDir1, false, false, nil); err != nil {
		t.Fatalf("failed to restore container 3: %v", err)
	}

	// Create the go file to let the process resume and read the mapping.
	goFile, err := os.Create(goFileHost)
	if err != nil {
		t.Fatalf("failed to create go file: %v", err)
	}
	goFile.Close()

	// Wait for container 3 to exit.
	ws, err := cont3.Wait()
	if err != nil {
		t.Fatalf("failed to wait for container 3: %v", err)
	}
	if !ws.Exited() || ws.ExitStatus() != 0 {
		t.Errorf("container 3 exited with unexpected status: %v", ws)
	}

	// Read output file.
	outputContent, err := os.ReadFile(outputFileHost)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if got := string(outputContent); got != "world" {
		t.Errorf("unexpected output content: got %q, want %q", got, "world")
	}
}

// TestSplitFSCheckpointRestoreMixedReadMismatched verifies that sentry safely fails
// restore (instead of panicking at runtime) if the FS checkpoint contains a
// mismatched container name. This simulates a user error or mismatch in mixed
// restore setup. Sentry should detect that the private MemoryFile data is missing
// from the FS checkpoint and return a clean error during restore.
func TestSplitFSCheckpointRestoreMixedReadMismatched(t *testing.T) {
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint not supported")
	}

	tempDir, err := os.MkdirTemp(testutil.TmpDir(), "TestSplitFSCheckpointRestoreMixedReadMismatched")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	checkpointDir1 := filepath.Join(tempDir, "checkpoint1")
	checkpointDir2 := filepath.Join(tempDir, "checkpoint2")
	overlayDir := filepath.Join(tempDir, "overlay")

	for _, d := range []string{checkpointDir1, checkpointDir2, overlayDir} {
		if err := os.MkdirAll(d, 0777); err != nil {
			t.Fatalf("failed to create dir %q: %v", d, err)
		}
		if err := os.Chmod(d, 0777); err != nil {
			t.Fatalf("failed to chmod dir %q: %v", d, err)
		}
	}

	spec1 := testutil.NewSpecWithArgs("sleep", "10000")
	spec1.Root.Readonly = false
	if spec1.Annotations == nil {
		spec1.Annotations = make(map[string]string)
	}
	spec1.Annotations[specutils.ContainerdContainerNameAnnotation] = "container-1"

	spec2 := testutil.NewSpecWithArgs("sleep", "10000")
	spec2.Root.Readonly = false
	if spec2.Annotations == nil {
		spec2.Annotations = make(map[string]string)
	}
	spec2.Annotations[specutils.ContainerdContainerNameAnnotation] = "container-2" // Mismatched name

	conf := testutil.TestConfig(t)
	conf.Overlay2.Set("root:dir=" + overlayDir)

	_, bundleDir1, cleanup1, err := testutil.SetupContainer(spec1, conf)
	if err != nil {
		t.Fatalf("error setting up container 1: %v", err)
	}
	defer cleanup1()

	_, bundleDir2, cleanup2, err := testutil.SetupContainer(spec2, conf)
	if err != nil {
		t.Fatalf("error setting up container 2: %v", err)
	}
	defer cleanup2()

	containerID := testutil.RandomContainerID()

	cont1, err := New(conf, Args{
		ID:        containerID,
		Spec:      spec1,
		BundleDir: bundleDir1,
	})
	if err != nil {
		t.Fatalf("failed to create container 1: %v", err)
	}
	defer cont1.Destroy()

	if err := cont1.Start(conf); err != nil {
		t.Fatalf("failed to start container 1: %v", err)
	}

	// Write "a" to /file.txt.
	if ws, err := execute(conf, cont1, "/bin/bash", "-c", "echo a > /file.txt"); err != nil || ws != 0 {
		t.Fatalf("failed to write to /file.txt in cont1: err %v, ws %v", err, ws)
	}

	// Checkpoint cont1 (SplitFSCheckpointPaths: all-tmpfs)
	cOpts := sandbox.CheckpointOpts{
		SplitFSCheckpointPaths: []checkpoint.ResourceID{{Path: "all-tmpfs"}},
	}
	if err := cont1.Checkpoint(conf, checkpointDir1, cOpts); err != nil {
		t.Fatalf("failed to checkpoint container 1: %v", err)
	}
	cont1.Destroy()

	// Now we start cont2 FRESH with spec2.
	cont2, err := New(conf, Args{
		ID:        containerID,
		Spec:      spec2,
		BundleDir: bundleDir2,
	})
	if err != nil {
		t.Fatalf("failed to create container 2: %v", err)
	}
	defer cont2.Destroy()

	if err := cont2.Start(conf); err != nil {
		t.Fatalf("failed to start container 2: %v", err)
	}

	// Write "b" to /file.txt.
	if ws, err := execute(conf, cont2, "/bin/bash", "-c", "echo b > /file.txt"); err != nil || ws != 0 {
		t.Fatalf("failed to write to /file.txt in cont2: err %v, ws %v", err, ws)
	}

	// Save the FS of cont2.
	paths := []checkpoint.ResourceID{{Path: "/"}}
	if err := cont2.FSSave(conf, checkpointDir2, sandbox.FSSaveOpts{
		ExitAfterSaving: true,
		Paths:           paths,
	}); err != nil {
		t.Fatalf("failed to fscheckpoint: %v", err)
	}

	// Wait for container 2 to stop.
	if _, err := cont2.Wait(); err != nil {
		t.Fatalf("failed to wait for container 2: %v", err)
	}
	cont2.Destroy()

	// Copy new FS checkpoint over the old one.
	fs1Dir := filepath.Join(checkpointDir1, "fs")
	for _, name := range []string{
		checkpointfiles.FSCheckpointManifestFileName,
		checkpointfiles.FSCheckpointMultiTarFileName,
		checkpointfiles.PagesFileName,
		checkpointfiles.PagesMetadataFileName,
	} {
		src := filepath.Join(checkpointDir2, name)
		dst := filepath.Join(fs1Dir, name)
		if err := copyFile(src, dst); err != nil {
			t.Fatalf("failed to copy %s to %s: %v", src, dst, err)
		}
	}

	// Now we restore cont3 with mixed checkpoint.
	restoredContainerID := containerID + "-restored"
	spec3 := *spec1
	spec3.Annotations = make(map[string]string)
	for k, v := range spec1.Annotations {
		spec3.Annotations[k] = v
	}
	_, bundleDir3, cleanup3, err := testutil.SetupContainer(&spec3, conf)
	if err != nil {
		t.Fatalf("error setting up container 3: %v", err)
	}
	defer cleanup3()

	cont3, err := New(conf, Args{
		ID:                 restoredContainerID,
		Spec:               &spec3,
		BundleDir:          bundleDir3,
		FSRestoreImagePath: fs1Dir,
	})
	if err != nil {
		t.Fatalf("failed to create container 3: %v", err)
	}
	defer cont3.Destroy()

	// Restore cont3. It must fail because of mismatched container name in FS checkpoint.
	err = cont3.Restore(conf, checkpointDir1, false, false, nil)
	if err == nil {
		t.Fatalf("restore succeeded unexpectedly")
	}
	if !strings.Contains(err.Error(), "neither in FS checkpoint nor in Sentry checkpoint") {
		t.Fatalf("unexpected restore error: %v", err)
	}
}

// TestMultiContainerSplitFSCheckpointRestoreMixed verifies combined restore for a
// multi-container sandbox. It checkpoints the sandbox at T1, restores it,
// modifies the overlays and tmpfs of both containers, takes an FS checkpoint at T2,
// and then restores the sandbox using Sentry T1 + FS T2. It verifies that the
// overlay modifications for both containers are preserved, while tmpfs modifications
// are discarded (reverted to T1).
func TestMultiContainerSplitFSCheckpointRestoreMixed(t *testing.T) {
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint not supported")
	}

	conf := testutil.TestConfig(t)

	tempDir, err := os.MkdirTemp(testutil.TmpDir(), "TestMultiContainerSplitFSCheckpointRestoreMixed")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	checkpointDir1 := filepath.Join(tempDir, "checkpoint1")
	if err := os.MkdirAll(checkpointDir1, 0755); err != nil {
		t.Fatalf("failed to create checkpoint dir 1: %v", err)
	}
	if err := os.Chmod(checkpointDir1, 0777); err != nil {
		t.Fatalf("error chmoding checkpoint dir 1: %v", err)
	}

	checkpointDir2 := filepath.Join(tempDir, "checkpoint2")
	if err := os.MkdirAll(checkpointDir2, 0755); err != nil {
		t.Fatalf("failed to create checkpoint dir 2: %v", err)
	}
	if err := os.Chmod(checkpointDir2, 0777); err != nil {
		t.Fatalf("error chmoding checkpoint dir 2: %v", err)
	}

	overlayDir := filepath.Join(tempDir, "overlay")
	if err := os.MkdirAll(overlayDir, 0755); err != nil {
		t.Fatalf("failed to create overlay dir: %v", err)
	}
	if err := os.Chmod(overlayDir, 0777); err != nil {
		t.Fatalf("error chmoding overlay directory: %v", err)
	}
	conf.Overlay2.Set("all:dir=" + overlayDir)

	rootDir, cleanup, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("error creating root dir: %v", err)
	}
	defer cleanup()
	conf.RootDir = rootDir

	// Create 2 containers.
	appSleepCmd := []string{"/app", "task-tree", "--depth=0"}
	testSpecs, ids := createSpecs(appSleepCmd, appSleepCmd)

	// Configure mounts for both containers.
	// Container 0 (root)
	bindSrcDir0 := filepath.Join(tempDir, "bind-src-0")
	if err := os.MkdirAll(bindSrcDir0, 0755); err != nil {
		t.Fatalf("failed to create bind src dir 0: %v", err)
	}
	tmpfsMount := "/tmpfs-mount"
	overlayMount := "/overlay-mount"

	testSpecs[0].Root.Readonly = true
	testSpecs[0].Mounts = append(testSpecs[0].Mounts,
		specs.Mount{
			Destination: tmpfsMount,
			Type:        "tmpfs",
		},
		specs.Mount{
			Destination: overlayMount,
			Type:        "bind",
			Source:      bindSrcDir0,
		},
	)
	testSpecs[0].Annotations[specutils.ContainerdContainerNameAnnotation] = "container-0"

	// Container 1 (subcontainer)
	bindSrcDir1 := filepath.Join(tempDir, "bind-src-1")
	if err := os.MkdirAll(bindSrcDir1, 0755); err != nil {
		t.Fatalf("failed to create bind src dir 1: %v", err)
	}
	testSpecs[1].Root.Readonly = true
	testSpecs[1].Mounts = append(testSpecs[1].Mounts,
		specs.Mount{
			Destination: tmpfsMount,
			Type:        "tmpfs",
		},
		specs.Mount{
			Destination: overlayMount,
			Type:        "bind",
			Source:      bindSrcDir1,
		},
	)
	testSpecs[1].Annotations[specutils.ContainerdContainerNameAnnotation] = "container-1"

	cleanupRoots, err := setupContainerRoots(testSpecs, ids)
	if err != nil {
		t.Fatalf("error setting up container roots: %v", err)
	}
	defer cleanupRoots()

	conts, cleanupContainers, err := startContainers(conf, testSpecs, ids)
	if err != nil {
		t.Fatalf("error starting containers: %v", err)
	}
	defer cleanupContainers()

	// Write data using test_app fsTreeCreate.
	// Container 0 writes
	if out, err := executeCombinedOutput(conf, conts[0], nil, "/app", "fsTreeCreate", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=1", "--target-dir="+tmpfsMount); err != nil {
		t.Fatalf("failed to write to tmpfs 0: %v, output: %s", err, out)
	}
	if out, err := executeCombinedOutput(conf, conts[0], nil, "/app", "fsTreeCreate", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=1", "--target-dir="+overlayMount); err != nil {
		t.Fatalf("failed to write to overlay 0: %v, output: %s", err, out)
	}

	// Container 1 writes
	if out, err := executeCombinedOutput(conf, conts[1], nil, "/app", "fsTreeCreate", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=1", "--target-dir="+tmpfsMount); err != nil {
		t.Fatalf("failed to write to tmpfs 1: %v, output: %s", err, out)
	}
	if out, err := executeCombinedOutput(conf, conts[1], nil, "/app", "fsTreeCreate", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=1", "--target-dir="+overlayMount); err != nil {
		t.Fatalf("failed to write to overlay 1: %v, output: %s", err, out)
	}

	// Checkpoint sandbox (call Checkpoint on root container).
	cOpts := sandbox.CheckpointOpts{
		SplitFSCheckpointPaths: []checkpoint.ResourceID{{Path: "all-tmpfs"}},
	}
	checkpointWaiter := make(chan error, 1)
	go func() {
		checkpointWaiter <- conts[1].WaitCheckpoint()
	}()

	if err := conts[0].Checkpoint(conf, checkpointDir1, cOpts); err != nil {
		t.Fatalf("failed to checkpoint sandbox: %v", err)
	}

	select {
	case waitErr := <-checkpointWaiter:
		if waitErr != nil {
			t.Errorf("error waiting for checkpoint to complete: %v", waitErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for checkpoint to complete")
	}

	// Destroy old containers.
	cleanupContainers()

	// Restore 1st time.
	newIds := make([]string, 0, len(ids))
	for range ids {
		newIds = append(newIds, testutil.RandomContainerID())
	}
	for _, spec := range testSpecs[1:] {
		if spec.Annotations == nil {
			spec.Annotations = make(map[string]string)
		}
		spec.Annotations[specutils.ContainerdSandboxIDAnnotation] = newIds[0]
	}

	cleanupRootsNew, err := setupContainerRoots(testSpecs, newIds)
	if err != nil {
		t.Fatalf("error setting up container roots: %v", err)
	}
	defer cleanupRootsNew()

	fs1Dir := filepath.Join(checkpointDir1, "fs")
	conts2, cleanupContainers2, err := restoreContainersWithFSRestore(conf, testSpecs, newIds, checkpointDir1, fs1Dir)
	if err != nil {
		t.Fatalf("error restoring containers 1st time: %v", err)
	}
	defer cleanupContainers2()

	// Verify content after 1st restore.
	// Cont 0
	if out, err := executeCombinedOutput(conf, conts2[0], nil, "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=1", "--target-dir="+tmpfsMount); err != nil {
		t.Errorf("tmpfs 0 verification failed: %v, output: %s", err, out)
	}
	if out, err := executeCombinedOutput(conf, conts2[0], nil, "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=1", "--target-dir="+overlayMount); err != nil {
		t.Errorf("overlay 0 verification failed: %v, output: %s", err, out)
	}

	// Cont 1
	if out, err := executeCombinedOutput(conf, conts2[1], nil, "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=1", "--target-dir="+tmpfsMount); err != nil {
		t.Errorf("tmpfs 1 verification failed: %v, output: %s", err, out)
	}
	if out, err := executeCombinedOutput(conf, conts2[1], nil, "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=1", "--target-dir="+overlayMount); err != nil {
		t.Errorf("overlay 1 verification failed: %v, output: %s", err, out)
	}

	// Modify host-backed overlays.
	if out, err := executeCombinedOutput(conf, conts2[0], nil, "/app", "fsTreeCreate", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=2", "--target-dir="+overlayMount); err != nil {
		t.Fatalf("failed to modify overlay 0: %v, output: %s", err, out)
	}
	if out, err := executeCombinedOutput(conf, conts2[1], nil, "/app", "fsTreeCreate", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=2", "--target-dir="+overlayMount); err != nil {
		t.Fatalf("failed to modify overlay 1: %v, output: %s", err, out)
	}

	// Modify in-memory tmpfs (to verify they are discarded).
	if out, err := executeCombinedOutput(conf, conts2[0], nil, "/app", "fsTreeCreate", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=2", "--target-dir="+tmpfsMount); err != nil {
		t.Fatalf("failed to modify tmpfs 0: %v, output: %s", err, out)
	}
	if out, err := executeCombinedOutput(conf, conts2[1], nil, "/app", "fsTreeCreate", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=2", "--target-dir="+tmpfsMount); err != nil {
		t.Fatalf("failed to modify tmpfs 1: %v, output: %s", err, out)
	}

	// Create a new directory and files in overlay of Container 0.
	newDir := filepath.Join(overlayMount, "newdir")
	if out, err := executeCombinedOutput(conf, conts2[0], nil, "/app", "fsTreeCreate", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=3", "--target-dir="+newDir); err != nil {
		t.Fatalf("failed to create new directory in overlay 0: %v, output: %s", err, out)
	}

	// FSSave (fs snapshot).
	paths := []checkpoint.ResourceID{
		{ContainerName: "container-0", Path: overlayMount},
		{ContainerName: "container-1", Path: overlayMount},
		{Path: "/"},
		{Path: testutil.TmpDir()},
	}
	if err := conts2[0].FSSave(conf, checkpointDir2, sandbox.FSSaveOpts{
		ExitAfterSaving: true,
		Paths:           paths,
	}); err != nil {
		t.Fatalf("failed to fscheckpoint: %v", err)
	}

	if _, err := conts2[0].Wait(); err != nil {
		t.Fatalf("failed to wait for root container: %v", err)
	}
	cleanupContainers2()

	// Update first snapshot VFS tar.
	for _, name := range []string{
		checkpointfiles.FSCheckpointManifestFileName,
		checkpointfiles.FSCheckpointMultiTarFileName,
		checkpointfiles.PagesFileName,
		checkpointfiles.PagesMetadataFileName,
	} {
		src := filepath.Join(checkpointDir2, name)
		dst := filepath.Join(fs1Dir, name)
		if err := copyFile(src, dst); err != nil {
			t.Fatalf("failed to copy %s to %s: %v", src, dst, err)
		}
	}

	// Restore 2nd time (mixed).
	newIds2 := make([]string, 0, len(ids))
	for range ids {
		newIds2 = append(newIds2, testutil.RandomContainerID())
	}
	for _, spec := range testSpecs[1:] {
		spec.Annotations[specutils.ContainerdSandboxIDAnnotation] = newIds2[0]
	}

	cleanupRootsNew2, err := setupContainerRoots(testSpecs, newIds2)
	if err != nil {
		t.Fatalf("error setting up container roots: %v", err)
	}
	defer cleanupRootsNew2()

	conts3, cleanupContainers3, err := restoreContainersWithFSRestore(conf, testSpecs, newIds2, checkpointDir1, fs1Dir)
	if err != nil {
		t.Fatalf("error restoring containers 2nd time: %v", err)
	}
	defer cleanupContainers3()

	// Verify content.
	// Cont 0: tmpfs same (seed 1), overlay modified (seed 2)
	if out, err := executeCombinedOutput(conf, conts3[0], nil, "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=1", "--target-dir="+tmpfsMount); err != nil {
		t.Errorf("tmpfs 0 verification failed (should be original): %v, output: %s", err, out)
	}
	if out, err := executeCombinedOutput(conf, conts3[0], nil, "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=2", "--target-dir="+overlayMount); err != nil {
		t.Errorf("overlay 0 verification failed (should be modified): %v, output: %s", err, out)
	}

	if out, err := executeCombinedOutput(conf, conts3[1], nil, "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=1", "--target-dir="+tmpfsMount); err != nil {
		t.Errorf("tmpfs 1 verification failed (should be original): %v, output: %s", err, out)
	}
	if out, err := executeCombinedOutput(conf, conts3[1], nil, "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=2", "--target-dir="+overlayMount); err != nil {
		t.Errorf("overlay 1 verification failed (should be modified): %v, output: %s", err, out)
	}

	// Verify the new directory in Container 0.
	if out, err := executeCombinedOutput(conf, conts3[0], nil, "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=3", "--target-dir="+newDir); err != nil {
		t.Errorf("new directory verification failed in restored overlay 0: %v, output: %s", err, out)
	}
}

// TestMultiContainerSplitFSCheckpointRestorePartial verifies that split filesystem
// checkpoint and restore works when using a partial path filter (only checkpointing
// specific paths for specific containers).
func TestMultiContainerSplitFSCheckpointRestorePartial(t *testing.T) {
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint not supported")
	}

	conf := testutil.TestConfig(t)

	tempDir, err := os.MkdirTemp(testutil.TmpDir(), "TestMultiContainerSplitFSCheckpointRestorePartial")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	checkpointDir := filepath.Join(tempDir, "checkpoint")
	if err := os.MkdirAll(checkpointDir, 0755); err != nil {
		t.Fatalf("failed to create checkpoint dir: %v", err)
	}
	if err := os.Chmod(checkpointDir, 0777); err != nil {
		t.Fatalf("error chmoding checkpoint dir: %v", err)
	}

	overlayDir := filepath.Join(tempDir, "overlay")
	if err := os.MkdirAll(overlayDir, 0755); err != nil {
		t.Fatalf("failed to create overlay dir: %v", err)
	}
	if err := os.Chmod(overlayDir, 0777); err != nil {
		t.Fatalf("error chmoding overlay directory: %v", err)
	}
	conf.Overlay2.Set("all:dir=" + overlayDir)

	rootDir, cleanup, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("error creating root dir: %v", err)
	}
	defer cleanup()
	conf.RootDir = rootDir

	// Create 2 containers.
	appSleepCmd := []string{"/app", "task-tree", "--depth=0"}
	testSpecs, ids := createSpecs(appSleepCmd, appSleepCmd)

	// Configure mounts for both containers.
	bindSrcDir0 := filepath.Join(tempDir, "bind-src-0")
	if err := os.MkdirAll(bindSrcDir0, 0755); err != nil {
		t.Fatalf("failed to create bind src dir 0: %v", err)
	}
	tmpfsMount := "/tmpfs-mount"
	overlayMount := "/overlay-mount"

	testSpecs[0].Root.Readonly = true
	testSpecs[0].Mounts = append(testSpecs[0].Mounts,
		specs.Mount{
			Destination: tmpfsMount,
			Type:        "tmpfs",
		},
		specs.Mount{
			Destination: overlayMount,
			Type:        "bind",
			Source:      bindSrcDir0,
		},
	)
	testSpecs[0].Annotations[specutils.ContainerdContainerNameAnnotation] = "container-0"

	bindSrcDir1 := filepath.Join(tempDir, "bind-src-1")
	if err := os.MkdirAll(bindSrcDir1, 0755); err != nil {
		t.Fatalf("failed to create bind src dir 1: %v", err)
	}
	testSpecs[1].Root.Readonly = true
	testSpecs[1].Mounts = append(testSpecs[1].Mounts,
		specs.Mount{
			Destination: tmpfsMount,
			Type:        "tmpfs",
		},
		specs.Mount{
			Destination: overlayMount,
			Type:        "bind",
			Source:      bindSrcDir1,
		},
	)
	testSpecs[1].Annotations[specutils.ContainerdContainerNameAnnotation] = "container-1"

	cleanupRoots, err := setupContainerRoots(testSpecs, ids)
	if err != nil {
		t.Fatalf("error setting up container roots: %v", err)
	}
	defer cleanupRoots()

	conts, cleanupContainers, err := startContainers(conf, testSpecs, ids)
	if err != nil {
		t.Fatalf("error starting containers: %v", err)
	}
	defer cleanupContainers()

	// Write data for both containers.
	if out, err := executeCombinedOutput(conf, conts[0], nil, "/app", "fsTreeCreate", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=1", "--target-dir="+tmpfsMount); err != nil {
		t.Fatalf("failed to write to tmpfs 0: %v, output: %s", err, out)
	}
	if out, err := executeCombinedOutput(conf, conts[0], nil, "/app", "fsTreeCreate", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=1", "--target-dir="+overlayMount); err != nil {
		t.Fatalf("failed to write to overlay 0: %v, output: %s", err, out)
	}

	if out, err := executeCombinedOutput(conf, conts[1], nil, "/app", "fsTreeCreate", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=1", "--target-dir="+tmpfsMount); err != nil {
		t.Fatalf("failed to write to tmpfs 1: %v, output: %s", err, out)
	}
	if out, err := executeCombinedOutput(conf, conts[1], nil, "/app", "fsTreeCreate", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=1", "--target-dir="+overlayMount); err != nil {
		t.Fatalf("failed to write to overlay 1: %v, output: %s", err, out)
	}

	// Checkpoint sandbox with partial FS checkpoint.
	cOpts := sandbox.CheckpointOpts{
		SplitFSCheckpointPaths: []checkpoint.ResourceID{
			{ContainerName: "container-0", Path: tmpfsMount},
			{ContainerName: "container-1", Path: overlayMount},
		},
	}
	checkpointWaiter := make(chan error, 1)
	go func() {
		checkpointWaiter <- conts[1].WaitCheckpoint()
	}()

	if err := conts[0].Checkpoint(conf, checkpointDir, cOpts); err != nil {
		t.Fatalf("failed to checkpoint sandbox: %v", err)
	}

	select {
	case waitErr := <-checkpointWaiter:
		if waitErr != nil {
			t.Errorf("error waiting for checkpoint to complete: %v", waitErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for checkpoint to complete")
	}

	// Destroy old containers.
	cleanupContainers()

	// Restore.
	newIds := make([]string, 0, len(ids))
	for range ids {
		newIds = append(newIds, testutil.RandomContainerID())
	}
	for _, spec := range testSpecs[1:] {
		if spec.Annotations == nil {
			spec.Annotations = make(map[string]string)
		}
		spec.Annotations[specutils.ContainerdSandboxIDAnnotation] = newIds[0]
	}

	cleanupRootsNew, err := setupContainerRoots(testSpecs, newIds)
	if err != nil {
		t.Fatalf("error setting up container roots: %v", err)
	}
	defer cleanupRootsNew()

	fsDir := filepath.Join(checkpointDir, "fs")
	conts2, cleanupContainers2, err := restoreContainersWithFSRestore(conf, testSpecs, newIds, checkpointDir, fsDir)
	if err != nil {
		t.Fatalf("error restoring containers: %v", err)
	}
	defer cleanupContainers2()

	// Verify content for both containers.
	if out, err := executeCombinedOutput(conf, conts2[0], nil, "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=1", "--target-dir="+tmpfsMount); err != nil {
		t.Errorf("tmpfs 0 verification failed: %v, output: %s", err, out)
	}
	if out, err := executeCombinedOutput(conf, conts2[0], nil, "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=1", "--target-dir="+overlayMount); err != nil {
		t.Errorf("overlay 0 verification failed: %v, output: %s", err, out)
	}

	if out, err := executeCombinedOutput(conf, conts2[1], nil, "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=1", "--target-dir="+tmpfsMount); err != nil {
		t.Errorf("tmpfs 1 verification failed: %v, output: %s", err, out)
	}
	if out, err := executeCombinedOutput(conf, conts2[1], nil, "/app", "fsTreeVerify", "--depth=1", "--file-per-level=1", "--file-size=10", "--seed=1", "--target-dir="+overlayMount); err != nil {
		t.Errorf("overlay 1 verification failed: %v, output: %s", err, out)
	}
}

func restoreContainersWithFSRestore(conf *config.Config, specs []*specs.Spec, ids []string, imagePath string, fsRestoreImagePath string) ([]*Container, func(), error) {
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
		if i == 0 {
			args.FSRestoreImagePath = fsRestoreImagePath
			if fsRestoreImagePath != "" && filepath.Clean(fsRestoreImagePath) != filepath.Clean(filepath.Join(imagePath, checkpointfiles.FSCheckpointDir)) {
				args.CombinedFSRestore = true
			}
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

func setupContainerRoots(specs []*specs.Spec, ids []string) (func(), error) {
	appSrc, err := testutil.FindFile("test/cmd/test_app/test_app")
	if err != nil {
		return nil, fmt.Errorf("error finding test_app: %v", err)
	}

	var cleanupRoots cleanup.Cleanup
	defer cleanupRoots.Clean()
	for i, spec := range specs {
		contRootPath, err := os.MkdirTemp(testutil.TmpDir(), fmt.Sprintf("%s-root", ids[i]))
		if err != nil {
			return nil, fmt.Errorf("error creating root directory for container %d: %v", i, err)
		}
		cleanupRoots.Add(func() { os.RemoveAll(contRootPath) })
		spec.Root.Path = contRootPath
		appDst := filepath.Join(contRootPath, "app")
		if err := copyFile(appSrc, appDst); err != nil {
			return nil, fmt.Errorf("error copying app binary from %q to %q: %v", appSrc, appDst, err)
		}
	}
	return cleanupRoots.Release(), nil
}

// TestCombinedRestoreMountMismatch verifies that combined restore fails if
// there is a mount topology mismatch between checkpoint and restore spec.
func TestCombinedRestoreMountMismatch(t *testing.T) {
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint not supported")
	}

	conf := testutil.TestConfig(t)
	rootDir, cleanupRoot, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("Error creating root dir: %v", err)
	}
	defer cleanupRoot()
	conf.RootDir = rootDir
	if err := conf.RestoreSpecValidation.Set("ignore"); err != nil {
		t.Fatalf("failed to set RestoreSpecValidation to ignore: %v", err)
	}

	tempDir, err := os.MkdirTemp(testutil.TmpDir(), "combined-restore-mismatch")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	checkpointDir1 := filepath.Join(tempDir, "checkpoint1")
	if err := os.MkdirAll(checkpointDir1, 0755); err != nil {
		t.Fatalf("failed to create checkpoint dir 1: %v", err)
	}

	// T1: Read-only rootfs.
	testAppSleepArgv := []string{"sleep", "10000"}
	saveSpecs, ids := createSpecs(testAppSleepArgv, testAppSleepArgv)
	rootName := "root-cont"
	subName := "sub-cont"
	saveSpecs[0].Annotations[specutils.ContainerdContainerNameAnnotation] = rootName
	saveSpecs[1].Annotations[specutils.ContainerdContainerNameAnnotation] = subName

	// Make rootfs read-only.
	saveSpecs[0].Root.Readonly = true
	saveSpecs[1].Root.Readonly = true

	// Configure Overlay2.
	overlayDir := filepath.Join(tempDir, "overlay")
	if err := os.MkdirAll(overlayDir, 0777); err != nil {
		t.Fatalf("failed to create overlay dir: %v", err)
	}
	conf.Overlay2.Set("all:dir=" + overlayDir)

	// Add dummy writable bind mount to satisfy "at least one checkpointable filesystem".
	dummySrc := filepath.Join(tempDir, "dummy-src")
	if err := os.MkdirAll(dummySrc, 0777); err != nil {
		t.Fatalf("failed to create dummy src dir: %v", err)
	}
	dummyDest := filepath.Join(testutil.TmpDir(), "dummy-mount")
	setupContainerMounts(saveSpecs[0], "dummy-mount", true /* writable */, dummySrc, dummyDest)

	conts1, cleanupConts1, err := startContainers(conf, saveSpecs, ids)
	if err != nil {
		t.Fatalf("Error starting containers 1: %v", err)
	}
	defer cleanupConts1()

	// Checkpoint Sentry T1 (split FS).
	cOpts := sandbox.CheckpointOpts{
		SplitFSCheckpointPaths: []checkpoint.ResourceID{{Path: "all-tmpfs"}},
	}
	if err := conts1[0].Checkpoint(conf, checkpointDir1, cOpts); err != nil {
		t.Fatalf("failed to checkpoint Sentry T1: %v", err)
	}
	cleanupConts1() // Destroy conts1.

	// Try to restore with T2 spec (writable rootfs).
	restoreSpecs, restoreIDs := createSpecs(testAppSleepArgv, testAppSleepArgv)
	restoreSpecs[0].Annotations[specutils.ContainerdContainerNameAnnotation] = rootName
	restoreSpecs[1].Annotations[specutils.ContainerdContainerNameAnnotation] = subName
	setupContainerMounts(restoreSpecs[0], "dummy-mount", true /* writable */, dummySrc, dummyDest)

	// Make rootfs writable in restore spec (T2 config).
	restoreSpecs[0].Root.Readonly = false
	restoreSpecs[1].Root.Readonly = false

	fs1Dir := filepath.Join(checkpointDir1, "fs")
	_, cleanupConts2, err := restoreContainersWithFSRestore(conf, restoreSpecs, restoreIDs, checkpointDir1, fs1Dir)
	if err == nil {
		cleanupConts2()
		t.Fatalf("expected restore to fail due to mount mismatch, but it succeeded")
	}

	expectedErr := "was neither in FS checkpoint nor in Sentry checkpoint"
	if !strings.Contains(err.Error(), expectedErr) {
		t.Fatalf("expected error containing %q, got: %v", expectedErr, err)
	}
}
