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

// This file holds the save/restore (checkpoint/restore) tests for a single
// container.

package container

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/sentry/control/controlapi"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/erofs"
	"gvisor.dev/gvisor/pkg/sentry/state/checkpointfiles"
	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/state/statefile"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/sandbox"
	"gvisor.dev/gvisor/runsc/specutils"
)

// TestSignalUnkillablePolicyRestore verifies that the SignalUnkillablePolicy
// is preserved across checkpoint and restore.
func TestSignalUnkillablePolicyRestore(t *testing.T) {
	for name, conf := range configs(t, true /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
			t.Run("LinuxPolicyPreservedAfterRestore", func(t *testing.T) {
				testConf := *conf
				testConf.SignalUnkillablePolicy = config.SignalUnkillableLinux

				spec, _ := sleepSpecConf(t)
				_, bundleDir, cleanup, err := testutil.SetupContainer(spec, &testConf)
				if err != nil {
					t.Fatalf("error setting up container: %v", err)
				}
				defer cleanup()

				args := Args{
					ID:        testutil.RandomContainerID(),
					Spec:      spec,
					BundleDir: bundleDir,
				}
				cont, err := New(&testConf, args)
				if err != nil {
					t.Fatalf("error creating container: %v", err)
				}
				defer cont.Destroy()
				if err := cont.Start(&testConf); err != nil {
					t.Fatalf("error starting container: %v", err)
				}

				if err := waitForProcessCount(cont, 1); err != nil {
					t.Fatalf("timed out waiting for init process: %v", err)
				}

				// Checkpoint running container.
				dir, err := os.MkdirTemp(testutil.TmpDir(), "checkpoint-restore-unkillable")
				if err != nil {
					t.Fatalf("os.MkdirTemp failed: %v", err)
				}
				defer os.RemoveAll(dir)
				if err := os.Chmod(dir, 0777); err != nil {
					t.Fatalf("error chmoding dir: %v", err)
				}

				if err := cont.Checkpoint(&testConf, dir, sandbox.CheckpointOpts{Compression: statefile.CompressionLevelFlateBestSpeed}); err != nil {
					t.Fatalf("error checkpointing container: %v", err)
				}
				cont.Destroy()
				cont = nil

				// Restore into a new container instance.
				cont2, err := New(&testConf, args)
				if err != nil {
					t.Fatalf("error creating restored container: %v", err)
				}
				defer cont2.Destroy()

				if err := cont2.Restore(&testConf, dir, sandbox.DirectIOOff, false /* background */, nil /* networkArgs */); err != nil {
					t.Fatalf("error restoring container: %v", err)
				}

				if err := waitForProcessCount(cont2, 1); err != nil {
					t.Fatalf("timed out waiting for restored init process: %v", err)
				}

				// Exec peer process to send SIGKILL to PID 1.
				ws, err := execute(&testConf, cont2, "/bin/sh", "-c", "kill -9 1")
				if err != nil {
					t.Fatalf("execute kill -9 1 failed after restore: %v", err)
				}
				if ws.ExitStatus() != 0 {
					t.Fatalf("kill command exited with status %d, want 0", ws.ExitStatus())
				}

				// Verify PID 1 survived the peer SIGKILL.
				time.Sleep(100 * time.Millisecond)
				procs, err := cont2.Processes()
				if err != nil || len(procs) != 1 || procs[0].PID != 1 {
					t.Fatalf("expected PID 1 to survive peer SIGKILL after restore, got err=%v, procs=%s", err, procListToString(procs))
				}

				// Host signal must still be able to kill PID 1.
				if err := cont2.SignalProcess(unix.SIGKILL, 1); err != nil {
					t.Fatalf("failed to send host SIGKILL to restored container: %v", err)
				}
				waitStatus, err := cont2.Wait()
				if err != nil {
					t.Fatalf("failed waiting for restored container after host SIGKILL: %v", err)
				}
				if !killedBySIGKILL(waitStatus) {
					t.Fatalf("expected restored container killed by host SIGKILL, got %v (status=%d)", waitStatus, waitStatus.ExitStatus())
				}
			})

			t.Run("NonePolicyPreservedAfterRestore", func(t *testing.T) {
				testConf := *conf
				testConf.SignalUnkillablePolicy = config.SignalUnkillableNone

				spec, _ := sleepSpecConf(t)
				_, bundleDir, cleanup, err := testutil.SetupContainer(spec, &testConf)
				if err != nil {
					t.Fatalf("error setting up container: %v", err)
				}
				defer cleanup()

				args := Args{
					ID:        testutil.RandomContainerID(),
					Spec:      spec,
					BundleDir: bundleDir,
				}
				cont, err := New(&testConf, args)
				if err != nil {
					t.Fatalf("error creating container: %v", err)
				}
				defer cont.Destroy()
				if err := cont.Start(&testConf); err != nil {
					t.Fatalf("error starting container: %v", err)
				}

				if err := waitForProcessCount(cont, 1); err != nil {
					t.Fatalf("timed out waiting for init process: %v", err)
				}

				// Checkpoint running container.
				dir, err := os.MkdirTemp(testutil.TmpDir(), "checkpoint-restore-unkillable-none")
				if err != nil {
					t.Fatalf("os.MkdirTemp failed: %v", err)
				}
				defer os.RemoveAll(dir)
				if err := os.Chmod(dir, 0777); err != nil {
					t.Fatalf("error chmoding dir: %v", err)
				}

				if err := cont.Checkpoint(&testConf, dir, sandbox.CheckpointOpts{Compression: statefile.CompressionLevelFlateBestSpeed}); err != nil {
					t.Fatalf("error checkpointing container: %v", err)
				}
				cont.Destroy()
				cont = nil

				// Restore into a new container instance.
				cont2, err := New(&testConf, args)
				if err != nil {
					t.Fatalf("error creating restored container: %v", err)
				}
				defer cont2.Destroy()

				if err := cont2.Restore(&testConf, dir, sandbox.DirectIOOff, false /* background */, nil /* networkArgs */); err != nil {
					t.Fatalf("error restoring container: %v", err)
				}

				if err := waitForProcessCount(cont2, 1); err != nil {
					t.Fatalf("timed out waiting for restored init process: %v", err)
				}

				// Peer sends SIGKILL; under None policy this kills PID 1.
				_, _ = execute(&testConf, cont2, "/bin/sh", "-c", "kill -9 1")
				ws, err := cont2.Wait()
				if err != nil {
					t.Fatalf("cont2.Wait: %v", err)
				}
				if !killedBySIGKILL(ws) {
					t.Fatalf("expected container killed by SIGKILL under policy=none after restore, got %v (status=%d)", ws, ws.ExitStatus())
				}
			})
		})
	}
}

// testCheckpointRestore creates a container that continuously writes successive
// integers to a file. To test checkpoint and restore functionality, the
// container is checkpointed and the last number printed to the file is
// recorded. Then, it is restored in two new containers and the first number
// printed from these containers is checked. Both should be the next consecutive
// number after the last number from the checkpointed container.
func testCheckpointRestore(t *testing.T, conf *config.Config, compression statefile.CompressionLevel, newSpecWithScript func(string) *specs.Spec) {
	dir, err := os.MkdirTemp(testutil.TmpDir(), "checkpoint-test")
	if err != nil {
		t.Fatalf("os.MkdirTemp failed: %v", err)
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

	script := fmt.Sprintf("i=0; while true; do echo $i >> %q; sleep 1; i=$((i+1)); done", outputPath)
	spec := newSpecWithScript(script)
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	// Create and start the container.
	args := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}
	cont, err := New(conf, args)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer cont.Destroy()
	if err := cont.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}

	// Wait until application has ran.
	if err := waitForFileNotEmpty(outputFile); err != nil {
		t.Fatalf("Failed to wait for output file: %v", err)
	}

	// Checkpoint running container; save state into new file.
	if err := cont.Checkpoint(conf, dir, sandbox.CheckpointOpts{Compression: compression}); err != nil {
		t.Fatalf("error checkpointing container to empty file: %v", err)
	}

	lastNum, err := readOutputNum(outputPath, -1)
	if err != nil {
		t.Fatalf("error with outputFile: %v", err)
	}

	// Delete and recreate file before restoring.
	if err := os.Remove(outputPath); err != nil {
		t.Fatalf("error removing file")
	}
	outputFile2, err := createWriteableOutputFile(outputPath)
	if err != nil {
		t.Fatalf("error creating output file: %v", err)
	}
	defer outputFile2.Close()

	// Restore into a new container with different ID (e.g. clone). Keep the
	// initial container running to ensure no conflict with it.
	args2 := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}
	cont2, err := New(conf, args2)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer cont2.Destroy()

	if err := cont2.Restore(conf, dir, sandbox.DirectIOOff, false /* background */, nil /* networkArgs */); err != nil {
		t.Fatalf("error restoring container: %v", err)
	}

	if !cont2.Sandbox.Restored {
		t.Fatalf("sandbox returned wrong value for Sandbox.Restored, got: false, want: true")
	}

	if cont2.Sandbox.Checkpointed {
		t.Fatalf("sandbox returned wrong value for Sandbox.Checkpointed, got: true, want: false")
	}

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
	cont2.Destroy()
	cont2 = nil

	// Restore into a container using the same ID (e.g. save/resume). It requires
	// the original container to cease to exist because they share the same identity.
	cont.Destroy()
	cont = nil

	// Delete and recreate file before restoring.
	if err := os.Remove(outputPath); err != nil {
		t.Fatalf("error removing file")
	}
	outputFile3, err := createWriteableOutputFile(outputPath)
	if err != nil {
		t.Fatalf("error creating output file: %v", err)
	}
	defer outputFile3.Close()

	cont3, err := New(conf, args)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer cont3.Destroy()

	if err := cont3.Restore(conf, dir, sandbox.DirectIOOff, false /* background */, nil /* networkArgs */); err != nil {
		t.Fatalf("error restoring container: %v", err)
	}

	// Wait until application has ran.
	if err := waitForFileNotEmpty(outputFile3); err != nil {
		t.Fatalf("Failed to wait for output file: %v", err)
	}

	firstNum2, err := readOutputNum(outputPath, 0)
	if err != nil {
		t.Fatalf("error with outputFile: %v", err)
	}

	// Check that lastNum is one less than firstNum and that the container
	// picks up from where it left off.
	if lastNum+1 != firstNum2 {
		t.Errorf("error numbers not in order, previous: %d, next: %d", lastNum, firstNum2)
	}
	cont3.Destroy()
}

// TestCheckpointRestore does the checkpoint/restore test on each platform.
func TestCheckpointRestore(t *testing.T) {
	// Skip overlay because test requires writing to host file.
	for name, conf := range configs(t, true /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
			compressionLevels := []statefile.CompressionLevel{
				statefile.CompressionLevelNone,
				statefile.CompressionLevelFlateBestSpeed,
			}
			for _, compression := range compressionLevels {
				t.Run(string(compression), func(t *testing.T) {
					testCheckpointRestore(t, conf, compression, func(script string) *specs.Spec {
						return testutil.NewSpecWithArgs("bash", "-c", script)
					})
				})
			}
		})
	}
}

// TestCheckpointCPUFeaturesMetadata verifies that the checkpoint metadata
// records the sandbox's CPU features, matching the CPUID FeatureSet saved in
// the state file.
func TestCheckpointCPUFeaturesMetadata(t *testing.T) {
	for name, conf := range configs(t, true /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
			spec, _ := sleepSpecConf(t)
			_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer cleanup()

			cont, err := New(conf, Args{
				ID:        testutil.RandomContainerID(),
				Spec:      spec,
				BundleDir: bundleDir,
			})
			if err != nil {
				t.Fatalf("error creating container: %v", err)
			}
			defer cont.Destroy()
			if err := cont.Start(conf); err != nil {
				t.Fatalf("error starting container: %v", err)
			}
			if err := waitForProcessCount(cont, 1); err != nil {
				t.Fatalf("error waiting for init process: %v", err)
			}

			dir, err := os.MkdirTemp(testutil.TmpDir(), "checkpoint-cpu-features")
			if err != nil {
				t.Fatalf("os.MkdirTemp failed: %v", err)
			}
			defer os.RemoveAll(dir)
			if err := os.Chmod(dir, 0777); err != nil {
				t.Fatalf("error chmoding dir: %v", err)
			}
			if err := cont.Checkpoint(conf, dir, sandbox.CheckpointOpts{Compression: statefile.CompressionLevelFlateBestSpeed}); err != nil {
				t.Fatalf("error checkpointing container: %v", err)
			}

			f, err := os.Open(filepath.Join(dir, checkpointfiles.StateFileName))
			if err != nil {
				t.Fatalf("error opening state file: %v", err)
			}
			defer f.Close()
			r, metadata, err := statefile.NewReader(f, nil /* key */)
			if err != nil {
				t.Fatalf("error reading state file: %v", err)
			}
			defer r.Close()

			got, ok := metadata[sentryapi.CPUFeaturesKey]
			if !ok {
				t.Fatalf("metadata key %q not found", sentryapi.CPUFeaturesKey)
			}
			if got == "" {
				t.Fatalf("metadata[%q] is empty", sentryapi.CPUFeaturesKey)
			}

			// Kernel.saveToLocked saves the CPUID FeatureSet as the first object in
			// the state stream (which Kernel.LoadFrom also relies on).
			var fs cpuid.FeatureSet
			if _, err := state.Load(context.Background(), r, &fs); err != nil {
				t.Fatalf("error loading CPUID FeatureSet from state file: %v", err)
			}
			if want := strings.Join(fs.FeatureNames(), ","); got != want {
				t.Errorf("metadata[%q] = %q, want %q", sentryapi.CPUFeaturesKey, got, want)
			}
			gotMask, err := cpuid.FeatureMaskStringFromNames(strings.Split(got, ","))
			if err != nil {
				t.Fatalf("FeatureMaskStringFromNames(%q) failed: %v", got, err)
			}
			if wantMask := fs.FeatureMaskString(); gotMask != wantMask {
				t.Errorf("FeatureMaskStringFromNames(%q) = %q, want %q", got, gotMask, wantMask)
			}
		})
	}
}

// TestCheckpointRestoreHostname verifies that hostname is updated on restore
// if it was not changed inside the container, and is NOT updated if it was changed.
func TestCheckpointRestoreHostname(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprintf("changed_%t", changed), func(t *testing.T) {
			spec, conf := sleepSpecConf(t)
			spec.Hostname = "old-host"

			_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer cleanup()

			args := Args{
				ID:        testutil.RandomContainerID(),
				Spec:      spec,
				BundleDir: bundleDir,
			}
			cont, err := New(conf, args)
			if err != nil {
				t.Fatalf("error creating container: %v", err)
			}
			defer cont.Destroy()
			if err := cont.Start(conf); err != nil {
				t.Fatalf("error starting container: %v", err)
			}

			// Verify initial hostname.
			out, err := executeCombinedOutput(conf, cont, nil, "/bin/sh", "-c", "read -r name < /proc/sys/kernel/hostname && echo $name")
			if err != nil {
				t.Fatalf("exec failed: %v", err)
			}
			if got, want := strings.TrimSpace(string(out)), "old-host"; got != want {
				t.Fatalf("hostname got %q, want %q", got, want)
			}

			if changed {
				// Change hostname inside container.
				_, err = executeCombinedOutput(conf, cont, nil, "/bin/sh", "-c", "echo user-host > /proc/sys/kernel/hostname")
				if err != nil {
					t.Logf("Failed to write to /proc/sys/kernel/hostname: %v, trying hostname command", err)
					_, err = executeCombinedOutput(conf, cont, nil, "/bin/sh", "-c", "hostname user-host")
					if err != nil {
						t.Fatalf("Failed to change hostname: %v", err)
					}
				}

				// Verify it changed.
				out, err = executeCombinedOutput(conf, cont, nil, "/bin/sh", "-c", "read -r name < /proc/sys/kernel/hostname && echo $name")
				if err != nil {
					t.Fatalf("exec failed: %v", err)
				}
				if got, want := strings.TrimSpace(string(out)), "user-host"; got != want {
					t.Fatalf("hostname got %q, want %q", got, want)
				}
			}

			// Checkpoint.
			dir, err := os.MkdirTemp(testutil.TmpDir(), "checkpoint-test")
			if err != nil {
				t.Fatalf("os.MkdirTemp failed: %v", err)
			}
			defer os.RemoveAll(dir)
			if err := cont.Checkpoint(conf, dir, sandbox.CheckpointOpts{}); err != nil {
				t.Fatalf("error checkpointing: %v", err)
			}

			cont.Destroy()

			// Restore with new spec.
			spec2, _ := sleepSpecConf(t)
			spec2.Hostname = "new-host"

			_, bundleDir2, cleanup2, err := testutil.SetupContainer(spec2, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer cleanup2()

			args2 := Args{
				ID:        args.ID,
				Spec:      spec2,
				BundleDir: bundleDir2,
			}
			cont2, err := New(conf, args2)
			if err != nil {
				t.Fatalf("error creating container: %v", err)
			}
			defer cont2.Destroy()

			if err := cont2.Restore(conf, dir, sandbox.DirectIOOff, false, nil); err != nil {
				t.Fatalf("error restoring: %v", err)
			}

			// Verify hostname.
			out, err = executeCombinedOutput(conf, cont2, nil, "/bin/sh", "-c", "read -r name < /proc/sys/kernel/hostname && echo $name")
			if err != nil {
				t.Fatalf("exec failed: %v", err)
			}
			want := "new-host"
			if changed {
				want = "user-host"
			}
			if got, want := strings.TrimSpace(string(out)), want; got != want {
				t.Fatalf("hostname got %q, want %q", got, want)
			}
		})
	}
}

// TestCheckpointRestoreHostinet does the checkpoint/restore test with host
// networking.
func TestCheckpointRestoreHostinet(t *testing.T) {
	app, err := testutil.FindFile("test/cmd/test_app/test_app")
	if err != nil {
		t.Fatal("error finding test_app:", err)
	}

	// Skip overlay because the test app writes its log to a bind-mounted
	// host file.
	for name, conf := range configs(t, true /* noOverlay */) {
		conf.Network = config.NetworkHost
		t.Run(name, func(t *testing.T) {
			testCheckpointRestoreHostinet(t, conf, app)
		})
	}
}

// TestCheckpointResumeHostinet does the checkpoint --leave-running test with
// host networking.
func TestCheckpointResumeHostinet(t *testing.T) {
	app, err := testutil.FindFile("test/cmd/test_app/test_app")
	if err != nil {
		t.Fatal("error finding test_app:", err)
	}

	// Skip overlay because the test app writes its log to a bind-mounted
	// host file.
	for name, conf := range configs(t, true /* noOverlay */) {
		conf.Network = config.NetworkHost
		t.Run(name, func(t *testing.T) {
			testCheckpointResumeHostinet(t, conf, app)
		})
	}
}

// testCheckpointRestoreHostinet checkpoints a hostinet container and checks
// that connected sockets return ECONNABORTED after restore while the restored
// listener keeps accepting.
func testCheckpointRestoreHostinet(t *testing.T, conf *config.Config, app string) {
	dir, err := os.MkdirTemp(testutil.TmpDir(), "checkpoint-test")
	if err != nil {
		t.Fatalf("os.MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatalf("error chmoding file: %q, %v", dir, err)
	}

	target, connClosed, stopServer := startHostinetSRServer(t)
	defer stopServer()

	logPath := filepath.Join(dir, "hostinet-sr.log")
	spec := testutil.NewSpecWithArgs(app, "hostinet-sr", "--file", logPath, "--target", target)
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	args := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}
	cont, err := New(conf, args)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer cont.Destroy()
	if err := cont.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}

	if err := waitForHostinetSRLog(logPath, "SETUP_DONE", "TCP_WRITE OK", "UDP_WRITE OK", "EPOLL_WAIT TIMEOUT"); err != nil {
		t.Fatalf("wait for setup: %v", err)
	}
	lastCount, err := lastHostinetSRCount(logPath)
	if err != nil {
		t.Fatalf("lastHostinetSRCount pre-restore: %v", err)
	}
	select {
	case <-connClosed:
		t.Fatalf("server connection closed before checkpoint")
	default:
	}

	if err := cont.Checkpoint(conf, dir, sandbox.CheckpointOpts{Compression: statefile.CompressionLevelFlateBestSpeed}); err != nil {
		t.Fatalf("error checkpointing container: %v", err)
	}

	// The remote peer must observe the connection closing when the
	// checkpointed sandbox exits.
	select {
	case <-connClosed:
	case <-time.After(30 * time.Second):
		t.Fatalf("remote peer did not observe connection close after checkpoint")
	}

	args2 := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}
	cont2, err := New(conf, args2)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer cont2.Destroy()
	if err := cont2.Restore(conf, dir, sandbox.DirectIOOff, false /* background */, nil /* networkArgs */); err != nil {
		t.Fatalf("error restoring container: %v", err)
	}
	if !cont2.Sandbox.Restored {
		t.Fatalf("sandbox returned wrong value for Sandbox.Restored, got: false, want: true")
	}

	if err := waitForHostinetSRLog(logPath,
		"TCP_WRITE ERRNO=32",
		"TCP_READ ERRNO=104",
		"UDP_WRITE ERRNO=104",
		"UDP_READ ERRNO=104",
		"EPOLL_EVENT_ERR",
		"EPOLL_EVENT_HUP",
		"SO_ERROR=104",
		"NEW_TCP_WRITE OK"); err != nil {
		t.Fatalf("wait for post-restore socket state: %v", err)
	}
	if err := waitForHostinetSRCountAfter(logPath, lastCount); err != nil {
		t.Fatalf("wait for post-restore progress: %v", err)
	}

	// Dialing the re-created listener must wake the blocked accept.
	listenerAddr, err := hostinetSRListenerAddr(logPath)
	if err != nil {
		t.Fatalf("hostinetSRListenerAddr: %v", err)
	}
	acceptConn, err := net.Dial("tcp", listenerAddr)
	if err != nil {
		t.Fatalf("dialing restored listener %q: %v", listenerAddr, err)
	}
	defer acceptConn.Close()
	if err := waitForHostinetSRLog(logPath, "BLOCKING_ACCEPT OK"); err != nil {
		t.Fatalf("wait for restored listener accept: %v", err)
	}
}

// testCheckpointResumeHostinet checks that checkpoint with Resume leaves the
// container's sockets working.
func testCheckpointResumeHostinet(t *testing.T, conf *config.Config, app string) {
	dir, err := os.MkdirTemp(testutil.TmpDir(), "checkpoint-test")
	if err != nil {
		t.Fatalf("os.MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatalf("error chmoding file: %q, %v", dir, err)
	}

	target, connClosed, stopServer := startHostinetSRServer(t)
	defer stopServer()

	logPath := filepath.Join(dir, "hostinet-sr.log")
	spec := testutil.NewSpecWithArgs(app, "hostinet-sr", "--file", logPath, "--target", target)
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	args := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}
	cont, err := New(conf, args)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer cont.Destroy()
	if err := cont.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}

	if err := waitForHostinetSRLog(logPath, "SETUP_DONE", "TCP_WRITE OK", "UDP_WRITE OK", "EPOLL_WAIT TIMEOUT"); err != nil {
		t.Fatalf("wait for setup: %v", err)
	}
	lastCount, err := lastHostinetSRCount(logPath)
	if err != nil {
		t.Fatalf("lastHostinetSRCount pre-checkpoint: %v", err)
	}

	if err := cont.Checkpoint(conf, dir, sandbox.CheckpointOpts{
		Compression: statefile.CompressionLevelFlateBestSpeed,
		Resume:      true,
	}); err != nil {
		t.Fatalf("error checkpointing container: %v", err)
	}

	// Wait for a few more iterations and check that no socket died. Idle
	// nonblocking reads log EAGAIN, so check specifically for EBADF and
	// ECONNABORTED.
	if err := waitForHostinetSRCountAfter(logPath, lastCount+2); err != nil {
		t.Fatalf("wait for resumed progress: %v", err)
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("error reading log file: %v", err)
	}
	if strings.Contains(string(b), "ERRNO=9\n") {
		t.Errorf("socket returned EBADF after checkpoint --leave-running:\n%s", b)
	}
	if strings.Contains(string(b), "ERRNO=103\n") {
		t.Errorf("socket returned ECONNABORTED after checkpoint --leave-running:\n%s", b)
	}
	select {
	case <-connClosed:
		t.Errorf("server connection closed after checkpoint --leave-running")
	default:
	}
}

// TestCheckpointHostinetRestoreNetworkMismatch checks that a checkpoint taken
// with host networking cannot be restored with sandbox networking.
func TestCheckpointHostinetRestoreNetworkMismatch(t *testing.T) {
	dir, err := os.MkdirTemp(testutil.TmpDir(), "checkpoint-test")
	if err != nil {
		t.Fatalf("os.MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatalf("error chmoding file: %q, %v", dir, err)
	}

	conf := testutil.TestConfig(t)
	conf.Network = config.NetworkHost
	spec := testutil.NewSpecWithArgs("sleep", "1000")
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	args := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}
	cont, err := New(conf, args)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer cont.Destroy()
	if err := cont.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}
	if err := cont.Checkpoint(conf, dir, sandbox.CheckpointOpts{Compression: statefile.CompressionLevelFlateBestSpeed}); err != nil {
		t.Fatalf("error checkpointing container: %v", err)
	}

	restoreConf := *conf
	restoreConf.Network = config.NetworkSandbox
	args2 := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}
	cont2, err := New(&restoreConf, args2)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer cont2.Destroy()
	err = cont2.Restore(&restoreConf, dir, sandbox.DirectIOOff, false /* background */, nil /* networkArgs */)
	if err == nil {
		t.Fatalf("restore with mismatched network type succeeded, want error")
	}
	if !strings.Contains(err.Error(), "cannot be restored with") {
		t.Errorf("restore failed with %v, want network mismatch error", err)
	}
	loaded, err := Load(conf.RootDir, FullID{ContainerID: cont2.ID}, LoadOpts{})
	if err != nil {
		t.Fatalf("error loading container: %v", err)
	}
	if loaded.Status != Stopped {
		t.Errorf("got status %v after failed restore, want %v", loaded.Status, Stopped)
	}
}

// TestCheckpointRestoreExecKilled checks that exec'd processes are killed
// after the container is restored.
func TestCheckpointRestoreExecKilled(t *testing.T) {
	spec, conf := sleepSpecConf(t)
	_, bundleDir, cu, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cu()

	// Create and start the container.
	args := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}
	cont, err := New(conf, args)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer cont.Destroy()
	if err := cont.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}

	execArgs := &controlapi.ExecArgs{
		Filename: "/bin/sleep",
		Argv:     []string{"/bin/sleep", "10000"},
	}
	pid1, err := cont.Execute(conf, execArgs)
	if err != nil {
		t.Fatalf("error executing in container: %v", err)
	}

	// Test exec process with stdio FDs. FDs will not be present after restore and
	// should be ignored.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdioCleanup := cleanup.Make(func() {
		r.Close()
		w.Close()
	})
	defer stdioCleanup.Clean()

	fdMap := map[int]*os.File{0: r, 1: w, 2: w}
	execArgs.FilePayload = controlapi.NewFilePayload(fdMap, nil)
	pid2, err := cont.Execute(conf, execArgs)
	if err != nil {
		t.Fatalf("error executing in container: %v", err)
	}

	// Since both share the same process name, ensure that the exec'd process
	// has a different PID than the init process.
	if pid1 == 1 || pid2 == 1 {
		t.Fatalf("exec'd PID cannot be 1")
	}
	// Wait until the init process and exec'd processes are present.
	expectedPL := []*controlapi.Process{
		newProcessBuilder().Cmd("sleep").PID(1).Process(),
		newProcessBuilder().Cmd("sleep").PID(int32(pid1)).Process(),
		newProcessBuilder().Cmd("sleep").PID(int32(pid2)).Process(),
	}
	if err := waitForProcessList(cont, expectedPL); err != nil {
		t.Fatalf("Failed to kill exec'ed process, err: %v", err)
	}

	// Set the image path, which is where the checkpoint image will be saved.
	dir, err := os.MkdirTemp(testutil.TmpDir(), "checkpoint-test")
	if err != nil {
		t.Fatalf("os.MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatalf("error chmoding file: %q, %v", dir, err)
	}

	// Checkpoint running container.
	if err := cont.Checkpoint(conf, dir, sandbox.CheckpointOpts{Compression: statefile.CompressionLevelFlateBestSpeed}); err != nil {
		t.Fatalf("error checkpointing container: %v", err)
	}
	cont.Destroy()
	cont = nil
	stdioCleanup.Clean()

	cont2, err := New(conf, args)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer cont2.Destroy()

	if err := cont2.Restore(conf, dir, sandbox.DirectIOOff, false /* background */, nil /* networkArgs */); err != nil {
		t.Fatalf("error restoring container: %v", err)
	}

	// Check that only the init process is present and the exec'ed
	// processes were killed.
	expectedPL = []*controlapi.Process{
		newProcessBuilder().Cmd("sleep").PID(1).Process(),
	}
	if err := waitForProcessList(cont2, expectedPL); err != nil {
		t.Fatalf("Failed to kill exec'ed process, err: %v", err)
	}
}

// TestCheckpointRestoreCreateMountPoint tests that mountpoints created during
// container creation are re-created after checkpoint/restore.
func TestCheckpointRestoreCreateMountPoint(t *testing.T) {
	dir, err := os.MkdirTemp(testutil.TmpDir(), "checkpoint-test")
	if err != nil {
		t.Fatalf("os.MkdirTemp() failed: %v", err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatalf("error chmoding file: %q, %v", dir, err)
	}

	spec, conf := sleepSpecConf(t)

	mountDest := filepath.Join(dir, "/foo-dir")
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Destination: mountDest,
		Type:        "tmpfs",
	})

	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	// Create and start the container.
	args := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}
	cont, err := New(conf, args)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer cont.Destroy()
	if err := cont.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}
	if err := waitForProcessCount(cont, 1); err != nil {
		t.Fatal(err)
	}

	// Check that mount point was created.
	if ws, err := execute(conf, cont, "/usr/bin/test", "-d", mountDest); err != nil {
		t.Fatal(err)
	} else if ws != 0 {
		t.Fatalf("directory was not re-created upon restore, ws: %v", ws)
	}

	// Checkpoint running container; save state into new file.
	if err := cont.Checkpoint(conf, dir, sandbox.CheckpointOpts{Compression: statefile.CompressionLevelDefault}); err != nil {
		t.Fatalf("error checkpointing container to file: %v", err)
	}

	// Remove directory created by the container.
	if err := os.RemoveAll(mountDest); err != nil {
		t.Fatalf("error removing mount point directory: %v", err)
	}

	// Destroy the original container to restore it in place.
	cont.Destroy()
	cont = nil

	cont2, err := New(conf, args)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer cont2.Destroy()

	if err := cont2.Restore(conf, dir, sandbox.DirectIOOff, false /* background */, nil /* networkArgs */); err != nil {
		t.Fatalf("error restoring container: %v", err)
	}

	// Check that mount point was re-created after restore.
	if ws, err := execute(conf, cont2, "/usr/bin/test", "-d", mountDest); err != nil {
		t.Fatal(err)
	} else if ws != 0 {
		t.Fatalf("directory was not re-created upon restore, ws: %v", ws)
	}
}

// TestCheckpointRestoreEROFS does the checkpoint/restore test on each platform using
// an EROFS image as the rootfs.
func TestCheckpointRestoreEROFS(t *testing.T) {
	// Skip this test if mkfs.erofs or busybox are not available.
	skipIfNotAvailable(t, "mkfs.erofs", "busybox")

	for _, tc := range []struct{ name, options string }{
		{name: "flat"},
		{name: "chunk-blockmap", options: "--chunksize=8192 -E force-inode-blockmap"},
		{name: "chunk-indexes", options: "--chunksize=8192 -E force-chunk-indexes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testDir, err := os.MkdirTemp(testutil.TmpDir(), "erofs_checkpoint_restore_test_")
			if err != nil {
				t.Fatalf("os.MkdirTemp() failed: %v", err)
			}
			defer os.RemoveAll(testDir)

			rootfsDir, rootfsImage, err := createRootfsEROFS(testDir, tc.options)
			if err != nil {
				t.Fatalf("failed to create EROFS rootfs image: %v", err)
			}

			// Skip overlay because test requires writing to host file.
			for name, conf := range configs(t, true /* noOverlay */) {
				t.Run(name, func(t *testing.T) {
					testCheckpointRestore(t, conf, statefile.CompressionLevelDefault, func(script string) *specs.Spec {
						spec := testutil.NewSpecWithArgs("/busybox", "sh", "-c", script)
						spec.Root = &specs.Root{
							Path:     rootfsDir,
							Readonly: false,
						}
						if spec.Annotations == nil {
							spec.Annotations = make(map[string]string)
						}
						spec.Annotations[sentryapi.RootfsPrefix+"type"] = erofs.Name
						spec.Annotations[sentryapi.RootfsPrefix+"source"] = rootfsImage
						// EROFS does not support creating synthetic directories
						// yet, so let's add a writeable and savable overlay for
						// rootfs, which allows the sentry to create the mount
						// point for the bind mount of the temporary directory
						// shared between host and test container.
						spec.Annotations[sentryapi.RootfsPrefix+"overlay"] = config.MemoryOverlay.String()
						return spec
					})
				})
			}
		})
	}
}

func TestCheckpointResume(t *testing.T) {
	for name, conf := range configs(t, true /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
			dir, err := os.MkdirTemp(testutil.TmpDir(), "checkpoint-test")
			if err != nil {
				t.Fatalf("os.MkdirTemp failed: %v", err)
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

			script := fmt.Sprintf("i=0; while true; do echo $i >> %q; sleep 1; i=$((i+1)); done", outputPath)
			spec := testutil.NewSpecWithArgs("bash", "-c", script)
			_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer cleanup()

			// Create and start the container.
			args := Args{
				ID:        testutil.RandomContainerID(),
				Spec:      spec,
				BundleDir: bundleDir,
			}
			cont, err := New(conf, args)
			if err != nil {
				t.Fatalf("error creating container: %v", err)
			}
			if err := cont.Start(conf); err != nil {
				t.Fatalf("error starting container: %v", err)
			}

			// Wait until application has ran.
			if err := waitForFileNotEmpty(outputFile); err != nil {
				t.Fatalf("Failed to wait for output file: %v", err)
			}

			// Checkpoint running container; save state into new file.
			if err := cont.Checkpoint(conf, dir, sandbox.CheckpointOpts{Resume: true}); err != nil {
				t.Fatalf("error checkpointing container to empty file: %v", err)
			}

			if !cont.Sandbox.Checkpointed {
				t.Fatalf("sandbox returned wrong value for Sandbox.Checkpointed, got: false, want: true")
			}

			if cont.Sandbox.Restored {
				t.Fatalf("sandbox returned wrong value for Sandbox.Restored, got: true, want: false")
			}
			cont.Destroy()
		})
	}
}

func TestSplitFSCheckpointRestore(t *testing.T) {
	// We only run this test if checkpoint/restore is supported.
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint not supported")
	}

	// We only test with overlay enabled.
	conf := testutil.TestConfig(t)
	overlayDir, err := os.MkdirTemp(testutil.TmpDir(), "overlay-dir")
	if err != nil {
		t.Fatalf("failed to create overlay directory: %v", err)
	}
	defer os.RemoveAll(overlayDir)
	if err := os.Chmod(overlayDir, 0777); err != nil {
		t.Fatalf("error chmoding overlay directory: %v", err)
	}
	conf.Overlay2.Set("all:dir=" + overlayDir)

	for _, tc := range []struct {
		name       string
		splitPath  string
		wantPrefix string
	}{
		{
			name:       "DefaultFilePrefix",
			splitPath:  "all-tmpfs",
			wantPrefix: checkpointfiles.FSCheckpointDir,
		},
		{
			name:       "DirectoryPrefix",
			splitPath:  "custom/=all-tmpfs",
			wantPrefix: "custom/",
		},
		{
			name:       "ExplicitFilePrefix",
			splitPath:  "custom=all-tmpfs",
			wantPrefix: "custom",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := os.MkdirTemp(testutil.TmpDir(), "split-checkpoint-test")
			if err != nil {
				t.Fatalf("os.MkdirTemp failed: %v", err)
			}
			defer os.RemoveAll(dir)
			if err := os.Chmod(dir, 0777); err != nil {
				t.Fatalf("error chmoding file: %q, %v", dir, err)
			}

			// The file we will write to is in TmpDir() which is bind-mounted and overlay.
			guestFile := filepath.Join(testutil.TmpDir(), "test_file_"+tc.name)
			script := "echo hello > '" + guestFile + "'; while true; do sleep 1; done"
			spec := testutil.NewSpecWithArgs("bash", "-c", script)

			_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer cleanup()

			args := Args{
				ID:        testutil.RandomContainerID(),
				Spec:      spec,
				BundleDir: bundleDir,
			}
			cont, err := New(conf, args)
			if err != nil {
				t.Fatalf("error creating container: %v", err)
			}
			defer cont.Destroy()
			if err := cont.Start(conf); err != nil {
				t.Fatalf("error starting container: %v", err)
			}

			// Wait for container to start and write the file.
			err = testutil.Poll(func() error {
				ws, err := execute(conf, cont, "/bin/bash", "-c", fmt.Sprintf("[ -s %q ]", guestFile))
				if err != nil {
					return err
				}
				if ws.ExitStatus() != 0 {
					return fmt.Errorf("bash -c '[ -s %q ]' returned %d", guestFile, ws.ExitStatus())
				}
				return nil
			}, 5*time.Second)
			if err != nil {
				t.Fatalf("Failed to wait for %q: %v", guestFile, err)
			}

			// Verify that the file does NOT exist on the host (because of overlay).
			// guestFile path in host is the same because TmpDir() is bind-mounted to same path.
			if _, err := os.Stat(guestFile); !os.IsNotExist(err) {
				t.Errorf("File leaked to host! It should be in overlay only. Path: %q", guestFile)
			}

			// Checkpoint running container with SplitFSCheckpointPaths.
			checkpointOpts := sandbox.CheckpointOpts{
				SplitFSCheckpointPaths: []string{tc.splitPath},
			}
			if err := cont.Checkpoint(conf, dir, checkpointOpts); err != nil {
				t.Fatalf("error checkpointing container: %v", err)
			}

			// Verify that the expected directory (if directory-prefixed) and files are created.
			checkFSCheckpointFiles(t, dir, tc.wantPrefix)

			// Restore into a new container with different ID.
			args2 := Args{
				ID:                testutil.RandomContainerID(),
				Spec:              spec,
				BundleDir:         bundleDir,
				CheckpointDirPath: dir,
			}
			cont2, err := New(conf, args2)
			if err != nil {
				t.Fatalf("error creating container: %v", err)
			}
			defer cont2.Destroy()

			if err := cont2.Restore(conf, dir, sandbox.DirectIOOff, false /* background */, nil /* networkArgs */); err != nil {
				t.Fatalf("error restoring container: %v", err)
			}

			// Verify that the file exists and contains "hello" in the restored container.
			stdout, err := executeCombinedOutput(conf, cont2, nil, "/bin/cat", guestFile)
			if err != nil {
				t.Fatalf("failed to execute cat %q: %v", guestFile, err)
			}
			if got := strings.TrimSpace(string(stdout)); got != "hello" {
				t.Errorf("unexpected content of %q: got %q, want %q", guestFile, got, "hello")
			}

			// Verify again that host file still does not exist.
			if _, err := os.Stat(guestFile); !os.IsNotExist(err) {
				t.Errorf("File leaked to host after restore! Path: %q", guestFile)
			}
		})
	}
}

// allTmpfs selects all the sandbox internal filesystems for the split
// filesystem checkpoint.
const allTmpfs = "all-tmpfs"

// fsCheckpointFiles are the base filenames that make up the filesystem part of
// a split checkpoint image.
var fsCheckpointFiles = []string{
	checkpointfiles.FSCheckpointManifestFileName,
	checkpointfiles.FSCheckpointMultiTarFileName,
	checkpointfiles.PagesFileName,
	checkpointfiles.PagesMetadataFileName,
}

func prefixedFSCheckpointFiles(prefix string) []string {
	var res []string
	for _, name := range fsCheckpointFiles {
		res = append(res, checkpointfiles.PrefixFileName(prefix, name))
	}
	return res
}

// sentryCheckpointFiles are the files that make up the Sentry part of a
// checkpoint image. They are saved at the root of the checkpoint directory.
var sentryCheckpointFiles = []string{
	checkpointfiles.StateFileName,
	checkpointfiles.PagesFileName,
	checkpointfiles.PagesMetadataFileName,
}

// makeTempDir creates a temporary directory that is removed when the test
// finishes. The directory is world-accessible because the sandboxed
// application may run as a different user than the test.
func makeTempDir(t *testing.T, prefix string) string {
	t.Helper()
	dir, err := os.MkdirTemp(testutil.TmpDir(), prefix)
	if err != nil {
		t.Fatalf("os.MkdirTemp(%q) failed: %v", prefix, err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatalf("error chmoding %q: %v", dir, err)
	}
	return dir
}

// overlayTestConfig returns a test config with overlay enabled for all gofer
// mounts, backed by a directory filestore. Split filesystem checkpoint only
// saves filesystems that are internal to the sandbox, so mounts must be
// overlaid for their content to be part of the checkpoint image.
func overlayTestConfig(t *testing.T) *config.Config {
	t.Helper()
	conf := testutil.TestConfig(t)
	conf.Overlay2.Set("all:dir=" + makeTempDir(t, "overlay-dir"))
	return conf
}

// addTmpfsMountToContainer adds a bind mount of source at dest to
// containerSpec, together with the mount hints on rootSpec that make the
// sandbox back the mount with a container private tmpfs. name identifies the
// mount in the annotations and must be unique within rootSpec.
func addTmpfsMountToContainer(rootSpec, containerSpec *specs.Spec, name, source, dest string) {
	containerSpec.Mounts = append(containerSpec.Mounts, specs.Mount{
		Destination: dest,
		Type:        "bind",
		Source:      source,
	})
	if rootSpec.Annotations == nil {
		rootSpec.Annotations = make(map[string]string)
	}
	prefix := "dev.gvisor.spec.mount." + name
	rootSpec.Annotations[prefix+".source"] = source
	rootSpec.Annotations[prefix+".type"] = "tmpfs"
	rootSpec.Annotations[prefix+".share"] = "container"
}

// addTmpfsMount adds a bind mount of source at dest to spec, together with the
// mount hints that make the sandbox back the mount with a container private
// tmpfs. name identifies the mount in the annotations and must be unique
// within the spec.
func addTmpfsMount(spec *specs.Spec, name, source, dest string) {
	addTmpfsMountToContainer(spec, spec, name, source, dest)
}

// setupBundle creates the root and bundle directories for spec and returns the
// bundle directory. Note that it also sets conf.RootDir, so containers created
// afterwards all share the same root directory.
func setupBundle(t *testing.T, conf *config.Config, spec *specs.Spec) string {
	t.Helper()
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	t.Cleanup(cleanup)
	return bundleDir
}

// newContainer creates a container for spec with a random ID. The container is
// destroyed when the test finishes. mutateArgs, if not nil, is called to adjust
// the container arguments before the container is created.
func newContainer(t *testing.T, conf *config.Config, spec *specs.Spec, bundleDir string, mutateArgs func(*Args)) *Container {
	t.Helper()
	args := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}
	if mutateArgs != nil {
		mutateArgs(&args)
	}
	cont, err := New(conf, args)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	t.Cleanup(func() { cont.Destroy() })
	return cont
}

// startContainer creates and starts a container for spec. See newContainer.
func startContainer(t *testing.T, conf *config.Config, spec *specs.Spec, bundleDir string, mutateArgs func(*Args)) *Container {
	t.Helper()
	cont := newContainer(t, conf, spec, bundleDir, mutateArgs)
	if err := cont.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}
	return cont
}

// waitForGuestFiles waits until all paths exist and are not empty inside the
// container.
func waitForGuestFiles(t *testing.T, conf *config.Config, cont *Container, paths ...string) {
	t.Helper()
	tests := make([]string, 0, len(paths))
	for _, path := range paths {
		tests = append(tests, fmt.Sprintf("[ -s %q ]", path))
	}
	script := strings.Join(tests, " && ")
	err := testutil.Poll(func() error {
		ws, err := execute(conf, cont, "/bin/bash", "-c", script)
		if err != nil {
			return err
		}
		if ws.ExitStatus() != 0 {
			return fmt.Errorf("bash -c %q returned %d", script, ws.ExitStatus())
		}
		return nil
	}, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to wait for %v: %v", paths, err)
	}
}

// checkGuestFile checks that path inside the container contains want.
func checkGuestFile(t *testing.T, conf *config.Config, cont *Container, path, want string) {
	t.Helper()
	stdout, err := executeCombinedOutput(conf, cont, nil, "/bin/cat", path)
	if err != nil {
		t.Fatalf("failed to execute cat %q: %v", path, err)
	}
	if got := strings.TrimSpace(string(stdout)); got != want {
		t.Errorf("unexpected content of %q: got %q, want %q", path, got, want)
	}
}

// checkHostFilesAbsent checks that paths don't exist on the host. Files written
// to a filesystem that is internal to the sandbox, e.g. overlay or tmpfs, must
// never be visible to the host.
func checkHostFilesAbsent(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("file leaked to host, it should only exist inside the sandbox: %q", path)
		}
	}
}

// checkFSCheckpointFiles checks that the filesystem part of a split checkpoint
// image with the given prefix was created inside checkpointDir.
func checkFSCheckpointFiles(t *testing.T, checkpointDir, prefix string) {
	t.Helper()
	if strings.HasSuffix(prefix, "/") {
		fsDir := filepath.Join(checkpointDir, prefix)
		if _, err := os.Stat(fsDir); err != nil {
			t.Fatalf("filesystem checkpoint directory %q was not created: %v", fsDir, err)
		}
	}
	for _, name := range prefixedFSCheckpointFiles(prefix) {
		path := filepath.Join(checkpointDir, name)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected file %q was not created: %v", path, err)
		}
	}
}

// copyCheckpointFiles copies names from srcDir into a new temporary directory
// and returns it. Files that don't exist in srcDir are skipped. This is used to
// break a checkpoint image apart into its filesystem and Sentry parts.
func copyCheckpointFiles(t *testing.T, srcDir, dstPrefix string, names []string) string {
	t.Helper()
	dstDir := makeTempDir(t, dstPrefix)
	for _, name := range names {
		src := filepath.Join(srcDir, name)
		data, err := os.ReadFile(src)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatalf("failed to read %q: %v", src, err)
		}
		dst := filepath.Join(dstDir, name)
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			t.Fatalf("failed to create directory %q: %v", filepath.Dir(dst), err)
		}
		if err := os.WriteFile(dst, data, 0644); err != nil {
			t.Fatalf("failed to write %q: %v", dst, err)
		}
	}
	return dstDir
}

// TestPartialSplitFSCheckpointRestore tests that only the mounts listed in
// SplitFSCheckpointPaths are saved into the filesystem image, while the
// remaining ones are saved with the Sentry state:
//  1. Start a container with two tmpfs mounts and write a file to each of them.
//  2. Checkpoint it, passing only the first mount to the split filesystem
//     checkpoint. The second mount is saved as part of the Sentry state.
//  3. Restore into a new container and check that both files were restored,
//     i.e. that the two halves of the image are consistent with each other.
func TestPartialSplitFSCheckpointRestore(t *testing.T) {
	// We only run this test if checkpoint/restore is supported.
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint not supported")
	}

	const tmpfsMount1 = "/tmpfs-split"
	const tmpfsMount2 = "/tmpfs-sentry"

	for _, tc := range []struct {
		name       string
		splitPath  string
		wantPrefix string
	}{
		{
			name:       "DirectoryPrefix",
			splitPath:  "fs/=" + tmpfsMount1,
			wantPrefix: checkpointfiles.FSCheckpointDir + "/",
		},
		{
			name:       "FilePrefix",
			splitPath:  tmpfsMount1,
			wantPrefix: checkpointfiles.FSCheckpointDir,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := overlayTestConfig(t)
			checkpointDir := makeTempDir(t, "partial-split-checkpoint-test")

			tmpfsSourceDir1 := makeTempDir(t, "tmpfs-source-1")
			tmpfsSourceDir2 := makeTempDir(t, "tmpfs-source-2")
			guestFile1 := filepath.Join(tmpfsMount1, "split_file")
			guestFile2 := filepath.Join(tmpfsMount2, "sentry_file")
			hostFile1 := filepath.Join(tmpfsSourceDir1, "split_file")
			hostFile2 := filepath.Join(tmpfsSourceDir2, "sentry_file")

			script := fmt.Sprintf("echo split_data > %q; echo sentry_data > %q; while true; do sleep 1; done", guestFile1, guestFile2)
			spec := testutil.NewSpecWithArgs("bash", "-c", script)
			addTmpfsMount(spec, "tmpfs1", tmpfsSourceDir1, tmpfsMount1)
			addTmpfsMount(spec, "tmpfs2", tmpfsSourceDir2, tmpfsMount2)
			bundleDir := setupBundle(t, conf, spec)

			cont := startContainer(t, conf, spec, bundleDir, nil)
			waitForGuestFiles(t, conf, cont, guestFile1, guestFile2)
			checkHostFilesAbsent(t, hostFile1, hostFile2)

			// Checkpoint the running container with only tmpfsMount1 saved into the
			// filesystem image.
			checkpointOpts := sandbox.CheckpointOpts{
				SplitFSCheckpointPaths: []string{tc.splitPath},
			}
			if err := cont.Checkpoint(conf, checkpointDir, checkpointOpts); err != nil {
				t.Fatalf("error checkpointing container: %v", err)
			}
			checkFSCheckpointFiles(t, checkpointDir, tc.wantPrefix)

			// Restore into a new container, relying on auto-detection of the split
			// filesystem image.
			cont2 := newContainer(t, conf, spec, bundleDir, func(args *Args) {
				args.CheckpointDirPath = checkpointDir
			})
			if err := cont2.Restore(conf, checkpointDir, sandbox.DirectIOOff, false /* background */, nil /* networkArgs */); err != nil {
				t.Fatalf("error restoring container: %v", err)
			}

			checkGuestFile(t, conf, cont2, guestFile1, "split_data")
			checkGuestFile(t, conf, cont2, guestFile2, "sentry_data")
			checkHostFilesAbsent(t, hostFile1, hostFile2)
		})
	}
}

// TestSplitFSCheckpointRestoreOnlyFS tests that the filesystem image of a split
// checkpoint can be consumed independently from the Sentry image. It
// checkpoints a container with a tmpfs mount, copies the filesystem image into
// a directory of its own, and then exercises the ways of restoring it:
//   - StartFreshWithOnlyFS: a brand new container, running a different
//     application and no Sentry image, is started with the filesystem image. It
//     must see the files that the checkpointed container had written.
//   - RestoreWithIsolatedFS: a container is restored from a Sentry image that
//     doesn't contain the filesystem image, which is passed separately.
//   - RestoreWithExplicitPrefixPath: a container is restored by passing
//     <dir>/<prefix> explicitly to FSRestoreImagePath.
func TestSplitFSCheckpointRestoreOnlyFS(t *testing.T) {
	// We only run this test if checkpoint/restore is supported.
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint not supported")
	}

	for _, tc := range []struct {
		name       string
		splitPath  string
		wantPrefix string
	}{
		{
			name:       "DirectoryPrefix",
			splitPath:  "fs/=" + allTmpfs,
			wantPrefix: checkpointfiles.FSCheckpointDir + "/",
		},
		{
			name:       "FilePrefix",
			splitPath:  allTmpfs,
			wantPrefix: checkpointfiles.FSCheckpointDir,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := overlayTestConfig(t)
			checkpointDir := makeTempDir(t, "split-checkpoint-test")

			// Create a host directory that is bind-mounted and then turned into a
			// tmpfs through mount hints.
			tmpfsSourceDir := makeTempDir(t, "tmpfs-source")
			const tmpfsMount = "/tmpfs-mount"
			guestFile := filepath.Join(tmpfsMount, "test_file")

			script := fmt.Sprintf("echo hello > %q; while true; do sleep 1; done", guestFile)
			spec := testutil.NewSpecWithArgs("bash", "-c", script)
			addTmpfsMount(spec, "test-tmpfs", tmpfsSourceDir, tmpfsMount)
			bundleDir := setupBundle(t, conf, spec)

			cont := startContainer(t, conf, spec, bundleDir, nil)
			waitForGuestFiles(t, conf, cont, guestFile)

			checkpointOpts := sandbox.CheckpointOpts{
				SplitFSCheckpointPaths: []string{tc.splitPath},
			}
			if err := cont.Checkpoint(conf, checkpointDir, checkpointOpts); err != nil {
				t.Fatalf("error checkpointing container: %v", err)
			}

			// Copy the filesystem image into a directory that holds nothing else.
			checkFSCheckpointFiles(t, checkpointDir, tc.wantPrefix)
			onlyFSDir := copyCheckpointFiles(t, checkpointDir, "only-fs-dir", prefixedFSCheckpointFiles(tc.wantPrefix))

			t.Run("StartFreshWithOnlyFS", func(t *testing.T) {
				// The fresh container runs a different application and is started from
				// scratch, i.e. no Sentry state is restored.
				specFresh := testutil.NewSpecWithArgs("sleep", "100")
				addTmpfsMount(specFresh, "test-tmpfs", tmpfsSourceDir, tmpfsMount)
				bundleDirFresh := setupBundle(t, conf, specFresh)

				contFresh := startContainer(t, conf, specFresh, bundleDirFresh, func(args *Args) {
					args.FSRestoreImagePaths = []string{onlyFSDir}
				})
				if err := contFresh.WaitFSRestore(); err != nil {
					t.Fatalf("error waiting for filesystem restore: %v", err)
				}

				// The file written by the checkpointed container must be visible in the
				// freshly started container.
				checkGuestFile(t, conf, contFresh, guestFile, "hello")
			})

			t.Run("RestoreWithIsolatedFS", func(t *testing.T) {
				// Copy the Sentry image into a directory that doesn't contain the
				// filesystem image, which is passed to the container separately.
				sentryOnlyDir := copyCheckpointFiles(t, checkpointDir, "sentry-only-dir", sentryCheckpointFiles)

				contRestore := newContainer(t, conf, spec, bundleDir, func(args *Args) {
					args.FSRestoreImagePaths = []string{onlyFSDir}
				})
				if err := contRestore.Restore(conf, sentryOnlyDir, sandbox.DirectIOOff, false /* background */, nil /* networkArgs */); err != nil {
					t.Fatalf("error restoring container with isolated fs checkpoint: %v", err)
				}

				checkGuestFile(t, conf, contRestore, guestFile, "hello")
			})

			t.Run("RestoreWithExplicitPrefixPath", func(t *testing.T) {
				sentryOnlyDir := copyCheckpointFiles(t, checkpointDir, "sentry-only-dir-explicit", sentryCheckpointFiles)

				contRestore := newContainer(t, conf, spec, bundleDir, func(args *Args) {
					args.FSRestoreImagePaths = []string{filepath.Join(onlyFSDir, tc.wantPrefix)}
				})
				if err := contRestore.Restore(conf, sentryOnlyDir, sandbox.DirectIOOff, false /* background */, nil /* networkArgs */); err != nil {
					t.Fatalf("error restoring container with explicit <dir>/<prefix> fs checkpoint: %v", err)
				}

				checkGuestFile(t, conf, contRestore, guestFile, "hello")
			})
		})
	}
}

// TestCheckpointRestoreTUN tests that a TUN device created inside a container
// is preserved across multiple checkpoint (with resume) and restore cycles
// along with its addresses and routes, and can be modified after each restore.
func TestCheckpointRestoreTUN(t *testing.T) {
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint not supported")
	}

	for name, conf := range configs(t, true /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
			spec, _ := sleepSpecConf(t)
			_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer cleanup()

			args := Args{
				ID:        testutil.RandomContainerID(),
				Spec:      spec,
				BundleDir: bundleDir,
			}
			cont, err := New(conf, args)
			if err != nil {
				t.Fatalf("error creating container: %v", err)
			}
			defer cont.Destroy()
			if err := cont.Start(conf); err != nil {
				t.Fatalf("error starting container: %v", err)
			}

			// Create a persistent TUN interface and configure IPv4 and IPv6
			// addresses before checkpointing.
			setupCmd := "ip tuntap add dev tun0 mode tun && ip addr add 10.0.0.1/24 dev tun0 && ip addr add fd00::1/64 dev tun0 && ip link set tun0 up && ip addr show dev tun0"
			out, err := executeCombinedOutput(conf, cont, nil, "/bin/sh", "-c", setupCmd)
			if err != nil {
				t.Fatalf("failed to set up tun0 before checkpoint: %v (output: %s)", err, out)
			}
			if !strings.Contains(string(out), "10.0.0.1/24") || !strings.Contains(string(out), "fd00::1/64") {
				t.Fatalf("unexpected tun0 addresses before checkpoint: %s", out)
			}

			checkpointDir := makeTempDir(t, "checkpoint-tun-test")
			if err := cont.Checkpoint(conf, checkpointDir, sandbox.CheckpointOpts{Resume: true}); err != nil {
				t.Fatalf("error checkpointing container: %v", err)
			}

			// Verify tun0 is still intact in the resumed original container.
			out, err = executeCombinedOutput(conf, cont, nil, "/bin/sh", "-c", "ip addr show dev tun0")
			if err != nil {
				t.Fatalf("failed to query tun0 after resume: %v (output: %s)", err, out)
			}
			if !strings.Contains(string(out), "10.0.0.1/24") || !strings.Contains(string(out), "fd00::1/64") {
				t.Fatalf("unexpected tun0 addresses after resume: %s", out)
			}
			cont.Destroy()

			args2 := Args{
				ID:        testutil.RandomContainerID(),
				Spec:      spec,
				BundleDir: bundleDir,
			}
			cont2, err := New(conf, args2)
			if err != nil {
				t.Fatalf("error creating restored container: %v", err)
			}
			defer cont2.Destroy()

			if err := cont2.Restore(conf, checkpointDir, sandbox.DirectIOOff, false /* background */, nil /* networkArgs */); err != nil {
				t.Fatalf("error restoring container: %v", err)
			}

			// Verify tun0 and its addresses are preserved after restore, and that
			// addresses can be added/removed and new TUN devices can be created.
			verifyCmd := "ip addr show dev tun0 && ip addr add 10.0.0.2/24 dev tun0 && ip addr del 10.0.0.1/24 dev tun0 && ip addr add fd00::2/64 dev tun0 && ip addr del fd00::1/64 dev tun0 && ip tuntap add dev tun1 mode tun && ip addr show dev tun0 && ip link show dev tun1"
			out, err = executeCombinedOutput(conf, cont2, nil, "/bin/sh", "-c", verifyCmd)
			if err != nil {
				t.Fatalf("failed to verify tun0 after restore: %v (output: %s)", err, out)
			}
			if !strings.Contains(string(out), "10.0.0.2/24") || !strings.Contains(string(out), "fd00::2/64") {
				t.Fatalf("expected updated addresses on tun0 after restore, got: %s", out)
			}

			// Checkpoint the restored container a second time with Resume: true.
			checkpointDir2 := makeTempDir(t, "checkpoint-tun-test-2")
			if err := cont2.Checkpoint(conf, checkpointDir2, sandbox.CheckpointOpts{Resume: true}); err != nil {
				t.Fatalf("error checkpointing restored container: %v", err)
			}

			// Verify tun0 and tun1 are still intact in cont2 after the second checkpoint+resume.
			out, err = executeCombinedOutput(conf, cont2, nil, "/bin/sh", "-c", "ip addr show dev tun0 && ip link show dev tun1")
			if err != nil {
				t.Fatalf("failed to query tun0/tun1 after second resume: %v (output: %s)", err, out)
			}
			if !strings.Contains(string(out), "10.0.0.2/24") || !strings.Contains(string(out), "fd00::2/64") {
				t.Fatalf("unexpected tun0 addresses after second resume: %s", out)
			}
			cont2.Destroy()

			args3 := Args{
				ID:        testutil.RandomContainerID(),
				Spec:      spec,
				BundleDir: bundleDir,
			}
			cont3, err := New(conf, args3)
			if err != nil {
				t.Fatalf("error creating second restored container: %v", err)
			}
			defer cont3.Destroy()

			if err := cont3.Restore(conf, checkpointDir2, sandbox.DirectIOOff, false /* background */, nil /* networkArgs */); err != nil {
				t.Fatalf("error restoring container a second time: %v", err)
			}

			// Verify tun0 and tun1 are preserved across the second restore and can be modified.
			verifyCmd2 := "ip addr show dev tun0 && ip link show dev tun1 && ip addr add 10.0.0.3/24 dev tun0 && ip addr del 10.0.0.2/24 dev tun0 && ip addr add fd00::3/64 dev tun0 && ip addr del fd00::2/64 dev tun0 && ip addr add 10.0.1.1/24 dev tun1 && ip link set tun1 up && ip addr show dev tun0 && ip addr show dev tun1"
			out, err = executeCombinedOutput(conf, cont3, nil, "/bin/sh", "-c", verifyCmd2)
			if err != nil {
				t.Fatalf("failed to verify tun0/tun1 after second restore: %v (output: %s)", err, out)
			}
			if !strings.Contains(string(out), "10.0.0.3/24") || !strings.Contains(string(out), "fd00::3/64") || !strings.Contains(string(out), "10.0.1.1/24") {
				t.Fatalf("expected updated addresses on tun0/tun1 after second restore, got: %s", out)
			}
		})
	}
}

// TestMultiBundleSplitFSCheckpointRestore tests saving and restoring multiple
// independent filesystem checkpoint bundles (e.g. rootfs=/ and fs=/dur-data),
// including combining bundles from different checkpoints on fresh container
// start. The workload runs either in the root container of its sandbox or in a
// subcontainer of a sandbox with no root container.
func TestMultiBundleSplitFSCheckpointRestore(t *testing.T) {
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint not supported")
	}
	for _, noRootContainer := range []bool{false, true} {
		t.Run(fmt.Sprintf("noRootContainer=%t", noRootContainer), func(t *testing.T) {
			testMultiBundleSplitFSCheckpointRestore(t, noRootContainer)
		})
	}
}

func testMultiBundleSplitFSCheckpointRestore(t *testing.T, noRootContainer bool) {
	const (
		rootfsPrefix = "rootfs/"
		fsPrefix     = "bundles/fs"
		durMount     = "/dur-data"
		rootFile     = "/rootfs_marker"
	)

	conf := overlayTestConfig(t)
	setupTestRootDir(t, conf)
	fsSaveDir := makeTempDir(t, "multi-bundle-fssave")
	checkpointDir := makeTempDir(t, "multi-bundle-checkpoint")

	tmpfsSourceDir := makeTempDir(t, "dur-source")
	durFile := filepath.Join(durMount, "dur_marker")
	env := splitFSTestEnv{
		conf:            conf,
		noRootContainer: noRootContainer,
		mountSource:     tmpfsSourceDir,
		mountDest:       durMount,
	}

	script := fmt.Sprintf("echo root_val_1 > %q; echo dur_val_1 > %q; while true; do sleep 1; done", rootFile, durFile)
	appArgs := []string{"bash", "-c", script}
	sb, app := env.start(t, nil /* mutateArgs */, appArgs...)
	waitForGuestFiles(t, conf, app, rootFile, durFile)

	bundleSpecs := []string{
		rootfsPrefix + "=/",
		fsPrefix + "=" + durMount,
	}

	// Save an initial multi-bundle filesystem checkpoint while keeping the
	// container running.
	if err := sb.FSSave(conf, fsSaveDir, sandbox.FSSaveOpts{Paths: bundleSpecs}); err != nil {
		t.Fatalf("error saving filesystem checkpoint: %v", err)
	}
	checkFSCheckpointFiles(t, fsSaveDir, rootfsPrefix)
	checkFSCheckpointFiles(t, fsSaveDir, fsPrefix)

	// Mutate both filesystems before taking a full split checkpoint so the two
	// checkpoints have distinct states.
	mutateScript := fmt.Sprintf("echo root_val_2 > %q && echo dur_val_2 > %q", rootFile, durFile)
	if ws, err := execute(conf, app, "/bin/bash", "-c", mutateScript); err != nil || ws.ExitStatus() != 0 {
		t.Fatalf("failed to mutate files before second checkpoint: ws=%v, err=%v", ws, err)
	}

	// Checkpoint with two bundles: rootfs and fs.
	env.checkpoint(t, sb, checkpointDir, sandbox.CheckpointOpts{SplitFSCheckpointPaths: bundleSpecs})
	checkFSCheckpointFiles(t, checkpointDir, rootfsPrefix)
	checkFSCheckpointFiles(t, checkpointDir, fsPrefix)

	rootfsDir := copyCheckpointFiles(t, checkpointDir, "isolated-rootfs", prefixedFSCheckpointFiles(rootfsPrefix))
	durDir := copyCheckpointFiles(t, checkpointDir, "isolated-fs", append(prefixedFSCheckpointFiles(fsPrefix), sentryCheckpointFiles...))

	for _, rtc := range []struct {
		name          string
		restoreDir    string
		fsRestorePath []string
		mutateArgs    func(*Args)
	}{
		{
			name:       "AutoDiscoverBothBundles",
			restoreDir: checkpointDir,
			mutateArgs: func(args *Args) { args.CheckpointDirPath = checkpointDir },
		},
		{
			name:          "IsolatedPrefixPathsRestore",
			restoreDir:    durDir,
			fsRestorePath: []string{filepath.Join(rootfsDir, rootfsPrefix), filepath.Join(durDir, fsPrefix)},
		},
	} {
		t.Run(rtc.name, func(t *testing.T) {
			_, appRestore := env.restore(t, rtc.restoreDir, func(args *Args) {
				args.FSRestoreImagePaths = rtc.fsRestorePath
				if rtc.mutateArgs != nil {
					rtc.mutateArgs(args)
				}
			}, appArgs...)
			checkGuestFile(t, conf, appRestore, rootFile, "root_val_2")
			checkGuestFile(t, conf, appRestore, durFile, "dur_val_2")
		})
	}

	t.Run("StartFreshCombiningBundlesFromDifferentCheckpoints", func(t *testing.T) {
		_, appFresh := env.start(t, func(args *Args) {
			args.FSRestoreImagePaths = []string{
				filepath.Join(fsSaveDir, rootfsPrefix),
				filepath.Join(checkpointDir, fsPrefix),
			}
		}, "sleep", "100")
		if err := appFresh.WaitFSRestore(); err != nil {
			t.Fatalf("error waiting for filesystem restore: %v", err)
		}

		checkGuestFile(t, conf, appFresh, rootFile, "root_val_1")
		checkGuestFile(t, conf, appFresh, durFile, "dur_val_2")
	})
}

// splitFSTestEnv starts, checkpoints and restores the sandboxes of a split
// filesystem checkpoint test.
type splitFSTestEnv struct {
	conf            *config.Config
	noRootContainer bool
	mountSource     string
	mountDest       string
}

func (e *splitFSTestEnv) newSpecs(sbID string, args ...string) (sbSpec, appSpec *specs.Spec) {
	if !e.noRootContainer {
		spec := testutil.NewSpecWithArgs(args...)
		spec.Root.Readonly = false
		addTmpfsMount(spec, "dur-mount", e.mountSource, e.mountDest)
		return spec, spec
	}
	sbSpec = noRootContainerSandboxSpec()
	appSpec = noRootContainerSubSpec(sbID, args...)
	appSpec.Annotations[specutils.ContainerdContainerNameAnnotation] = "app"
	appSpec.Root.Readonly = false
	addTmpfsMountToContainer(sbSpec, appSpec, "dur-mount", e.mountSource, e.mountDest)
	return sbSpec, appSpec
}

func (e *splitFSTestEnv) sandboxArgs(sbID string, mutateArgs func(*Args)) func(*Args) {
	return func(args *Args) {
		args.ID = sbID
		args.NoRootContainer = e.noRootContainer
		if mutateArgs != nil {
			mutateArgs(args)
		}
	}
}

func (e *splitFSTestEnv) start(t *testing.T, mutateArgs func(*Args), args ...string) (sb, app *Container) {
	t.Helper()
	sbID := testutil.RandomContainerID()
	sbSpec, appSpec := e.newSpecs(sbID, args...)
	sb = startContainer(t, e.conf, sbSpec, newBundleDir(t, sbSpec), e.sandboxArgs(sbID, mutateArgs))
	if !e.noRootContainer {
		return sb, sb
	}
	return sb, startContainer(t, e.conf, appSpec, newBundleDir(t, appSpec), nil /* mutateArgs */)
}

func (e *splitFSTestEnv) restore(t *testing.T, imagePath string, mutateArgs func(*Args), args ...string) (sb, app *Container) {
	t.Helper()
	restoreOne := func(spec *specs.Spec, mutateArgs func(*Args)) *Container {
		t.Helper()
		c := newContainer(t, e.conf, spec, newBundleDir(t, spec), mutateArgs)
		if err := c.Restore(e.conf, imagePath, sandbox.DirectIOOff, false /* background */, nil /* networkArgs */); err != nil {
			t.Fatalf("error restoring container: %v", err)
		}
		return c
	}
	sbID := testutil.RandomContainerID()
	sbSpec, appSpec := e.newSpecs(sbID, args...)
	sb = restoreOne(sbSpec, e.sandboxArgs(sbID, mutateArgs))
	if !e.noRootContainer {
		return sb, sb
	}
	app = restoreOne(appSpec, nil /* mutateArgs */)
	if err := sb.WaitRestore(); err != nil {
		t.Fatalf("error waiting for restore: %v", err)
	}
	return sb, app
}

func (e *splitFSTestEnv) checkpoint(t *testing.T, sb *Container, imagePath string, opts sandbox.CheckpointOpts) {
	t.Helper()
	if e.noRootContainer {
		checkpointNoRootContainer(t, e.conf, sb, imagePath, opts)
		return
	}
	if err := sb.Checkpoint(e.conf, imagePath, opts); err != nil {
		t.Fatalf("error checkpointing container: %v", err)
	}
}

func newBundleDir(t *testing.T, spec *specs.Spec) string {
	t.Helper()
	bundleDir, cleanupBundle, err := testutil.SetupBundleDir(spec)
	if err != nil {
		t.Fatalf("error setting up bundle: %v", err)
	}
	t.Cleanup(cleanupBundle)
	return bundleDir
}

func adjustSnapshotMetadata(dir string, updateFn func(map[string]string)) error {
	stateFilePath := filepath.Join(dir, checkpointfiles.StateFileName)
	raw, err := os.ReadFile(stateFilePath)
	if err != nil {
		return err
	}
	const magicLen = 8
	if len(raw) < magicLen+8 {
		return fmt.Errorf("statefile too small")
	}
	magic := raw[:magicLen]
	metaLen := binary.BigEndian.Uint64(raw[magicLen : magicLen+8])
	if uint64(len(raw)) < uint64(magicLen)+8+metaLen {
		return fmt.Errorf("statefile corrupt: metadata length exceeds file size")
	}
	metaBytes := raw[magicLen+8 : uint64(magicLen)+8+metaLen]
	payload := raw[uint64(magicLen)+8+metaLen:]

	var meta map[string]string
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return fmt.Errorf("unmarshaling metadata: %w", err)
	}
	updateFn(meta)

	newMetaBytes, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshaling metadata: %w", err)
	}

	var buf bytes.Buffer
	buf.Write(magic)
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(newMetaBytes)))
	buf.Write(lenBuf[:])
	buf.Write(newMetaBytes)
	buf.Write(payload)

	return os.WriteFile(stateFilePath, buf.Bytes(), 0644)
}

type clockReading struct {
	vdso int64
	sys  int64
	diff int64
	tsc  uint64
}

func parseClockReadings(t *testing.T, data []byte) []clockReading {
	t.Helper()
	var readings []clockReading
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "OK:") {
			continue
		}
		var r clockReading
		// Format: "OK: vdso=%d sys=%d diff=%d tsc=%d"
		_, err := fmt.Sscanf(line, "OK: vdso=%d sys=%d diff=%d tsc=%d", &r.vdso, &r.sys, &r.diff, &r.tsc)
		if err != nil {
			t.Fatalf("failed to parse clock reading line %q: %v", line, err)
		}
		readings = append(readings, r)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("failed to scan clock readings: %v", err)
	}
	return readings
}

func assertMonotonicReadings(t *testing.T, readings []clockReading) {
	t.Helper()
	if len(readings) == 0 {
		t.Fatalf("expected clock readings, got none")
	}
	for i := 1; i < len(readings); i++ {
		prev := readings[i-1]
		curr := readings[i]
		if curr.vdso < prev.vdso {
			t.Fatalf("reading[%d] VDSO went backwards: prev=%d current=%d (delta=%d)", i, prev.vdso, curr.vdso, curr.vdso-prev.vdso)
		}
		if curr.sys < prev.sys {
			t.Fatalf("reading[%d] syscall time went backwards: prev=%d current=%d (delta=%d)", i, prev.sys, curr.sys, curr.sys-prev.sys)
		}
		if curr.tsc < prev.tsc {
			t.Fatalf("reading[%d] RDTSC went backwards: prev=%d current=%d (delta=%d)", i, prev.tsc, curr.tsc, int64(curr.tsc)-int64(prev.tsc))
		}
	}
}

func waitForFileLineCount(f *os.File, minLines int) error {
	return testutil.Poll(func() error {
		data, err := os.ReadFile(f.Name())
		if err != nil {
			return err
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		count := 0
		for _, l := range lines {
			if strings.HasPrefix(l, "OK:") {
				count++
			}
		}
		if count < minLines {
			return fmt.Errorf("file %s has %d OK lines, want at least %d", f.Name(), count, minLines)
		}
		return nil
	}, 10*time.Second)
}

func runAdjustedTSCTest(t *testing.T, conf *config.Config, count int, offsetCycles uint64) {
	t.Helper()
	dir, err := os.MkdirTemp(testutil.TmpDir(), "checkpoint-vdso-test")
	if err != nil {
		t.Fatalf("os.MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatalf("error chmoding dir: %q, %v", dir, err)
	}

	outputPath := filepath.Join(dir, "output")
	outputFile, err := createWriteableOutputFile(outputPath)
	if err != nil {
		t.Fatalf("error creating output file: %v", err)
	}
	defer outputFile.Close()

	app, err := testutil.FindFile("test/cmd/test_app/test_app")
	if err != nil {
		t.Fatalf("error finding test_app: %v", err)
	}

	appArgs := []string{
		"vdso-clock",
		fmt.Sprintf("--file=%s", outputPath),
		fmt.Sprintf("--count=%d", count),
	}

	spec := testutil.NewSpecWithArgs(append([]string{app}, appArgs...)...)
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	args := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}
	cont, err := New(conf, args)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer cont.Destroy()
	if err := cont.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}

	// Wait until application has started and written at least one pre-checkpoint reading.
	if err := waitForFileLineCount(outputFile, 1); err != nil {
		t.Fatalf("failed to wait for output file: %v", err)
	}

	// Checkpoint running container (first save).
	dir1 := filepath.Join(dir, "ckpt1")
	if err := os.MkdirAll(dir1, 0777); err != nil {
		t.Fatalf("os.MkdirAll(dir1) failed: %v", err)
	}
	if err := cont.Checkpoint(conf, dir1, sandbox.CheckpointOpts{}); err != nil {
		t.Fatalf("error checkpointing container (first save): %v", err)
	}

	preData1, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("error reading pre-checkpoint output: %v", err)
	}
	preReadings1 := parseClockReadings(t, preData1)
	if len(preReadings1) == 0 {
		t.Fatalf("expected at least one pre-checkpoint reading")
	}
	lastPreReading1 := preReadings1[len(preReadings1)-1]

	// Adjust the snapshot metadata to simulate a snapshot from a host with a higher TSC.
	if offsetCycles > 0 {
		if err := adjustSnapshotMetadata(dir1, func(meta map[string]string) {
			cycleStr, ok := meta["gvisor_tsc_snapshot_cycle"]
			if !ok {
				t.Fatalf("snapshot missing gvisor_tsc_snapshot_cycle metadata")
			}
			cycle, err := strconv.ParseUint(cycleStr, 10, 64)
			if err != nil {
				t.Fatalf("failed to parse gvisor_tsc_snapshot_cycle %q: %v", cycleStr, err)
			}
			meta["gvisor_tsc_snapshot_cycle"] = strconv.FormatUint(cycle+offsetCycles, 10)
		}); err != nil {
			t.Fatalf("failed to adjust snapshot metadata: %v", err)
		}
	}

	// Restore into a second container (first restore).
	args2 := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}
	cont2, err := New(conf, args2)
	if err != nil {
		t.Fatalf("error creating second container: %v", err)
	}
	defer cont2.Destroy()

	if err := cont2.Restore(conf, dir1, sandbox.DirectIOOff, false /* background */, nil /* networkArgs */); err != nil {
		t.Fatalf("error restoring second container: %v", err)
	}

	// Wait until the restored container has written at least one reading with the adjusted TSC.
	if err := waitForFileLineCount(outputFile, len(preReadings1)+1); err != nil {
		t.Fatalf("failed to wait for post-first-restore output: %v", err)
	}

	// Checkpoint the second container (second save) without manual metadata adjustment.
	// Because cont2 is already running with an adjusted guest TSC, its saved snapshot
	// metadata must record the guest TSC (including cont2's TSC offset) so that
	// restoring into cont3 preserves the offset rather than resetting to the raw host TSC.
	dir2 := filepath.Join(dir, "ckpt2")
	if err := os.MkdirAll(dir2, 0777); err != nil {
		t.Fatalf("os.MkdirAll(dir2) failed: %v", err)
	}
	if err := cont2.Checkpoint(conf, dir2, sandbox.CheckpointOpts{}); err != nil {
		t.Fatalf("error checkpointing second container (second save): %v", err)
	}

	preData2, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("error reading pre-second-checkpoint output: %v", err)
	}
	preReadings2 := parseClockReadings(t, preData2)
	if len(preReadings2) <= len(preReadings1) {
		t.Fatalf("expected readings after first restore, got total=%d pre1=%d", len(preReadings2), len(preReadings1))
	}
	lastPreReading2 := preReadings2[len(preReadings2)-1]

	// Restore into a third container (second restore).
	args3 := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}
	cont3, err := New(conf, args3)
	if err != nil {
		t.Fatalf("error creating third container: %v", err)
	}
	defer cont3.Destroy()

	if err := cont3.Restore(conf, dir2, sandbox.DirectIOOff, false /* background */, nil /* networkArgs */); err != nil {
		t.Fatalf("error restoring third container: %v", err)
	}

	// Wait for third container to finish executing and verify exit status and output.
	ws, err := cont3.Wait()
	if err != nil {
		t.Fatalf("Wait failed: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("error reading output: %v", err)
	}
	t.Logf("Container output:\n%s", string(data))

	if ws.ExitStatus() != 0 {
		t.Fatalf("Container failed with status %v: %s", ws, string(data))
	}
	if strings.Contains(string(data), "FAIL:") {
		t.Fatalf("Failure detected in output: %s", string(data))
	}

	readings := parseClockReadings(t, data)
	if len(readings) <= len(preReadings2) {
		t.Fatalf("expected post-second-restore readings, got none (total %d, pre2 %d)", len(readings), len(preReadings2))
	}
	assertMonotonicReadings(t, readings)

	if offsetCycles > 0 {
		firstPostReading1 := readings[len(preReadings1)]
		wantMinTSC1 := lastPreReading1.tsc + offsetCycles
		if firstPostReading1.tsc < wantMinTSC1 {
			t.Fatalf("RDTSC went backwards across first restore from host with higher TSC: pre+offset=%d, post=%d (delta=%d)",
				wantMinTSC1, firstPostReading1.tsc, int64(firstPostReading1.tsc)-int64(wantMinTSC1))
		}

		firstPostReading2 := readings[len(preReadings2)]
		if firstPostReading2.tsc < lastPreReading2.tsc {
			t.Fatalf("RDTSC went backwards across second restore: pre2=%d, post2=%d (delta=%d)",
				lastPreReading2.tsc, firstPostReading2.tsc, int64(firstPostReading2.tsc)-int64(lastPreReading2.tsc))
		}
	}
}

// TestCheckpointRestoreAdjustedTSC verifies that VDSO clock_gettime and syscall
// clock_gettime remain synchronized and that time does not go backwards when
// restoring a container snapshot with an adjusted TSC, including across chained
// save/restore cycles.
func TestCheckpointRestoreAdjustedTSC(t *testing.T) {
	for name, conf := range configs(t, true /* noOverlay */) {
		t.Run(name, func(t *testing.T) {
			if conf.Platform != "kvm" {
				t.Skip("TSC adjustment is only supported on KVM")
			}
			const offsetCycles = 10_000_000_000 // ~4s
			runAdjustedTSCTest(t, conf, 30 /* count */, offsetCycles)
		})
	}
}
