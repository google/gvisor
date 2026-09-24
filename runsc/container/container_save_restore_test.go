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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/erofs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/state/checkpointfiles"
	"gvisor.dev/gvisor/pkg/state/statefile"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/sandbox"
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

				if err := cont2.Restore(&testConf, dir, false /* direct */, false /* background */, nil /* networkArgs */); err != nil {
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

				if err := cont2.Restore(&testConf, dir, false /* direct */, false /* background */, nil /* networkArgs */); err != nil {
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

	if err := cont2.Restore(conf, dir, false /* direct */, false /* background */, nil /* networkArgs */); err != nil {
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

	if err := cont3.Restore(conf, dir, false /* direct */, false /* background */, nil /* networkArgs */); err != nil {
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

			if err := cont2.Restore(conf, dir, false, false, nil); err != nil {
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
	if err := cont2.Restore(conf, dir, false /* direct */, false /* background */, nil /* networkArgs */); err != nil {
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
	err = cont2.Restore(&restoreConf, dir, false /* direct */, false /* background */, nil /* networkArgs */)
	if err == nil {
		t.Fatalf("restore with mismatched network type succeeded, want error")
	}
	if !strings.Contains(err.Error(), "cannot be restored with") {
		t.Errorf("restore failed with %v, want network mismatch error", err)
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

	execArgs := &control.ExecArgs{
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
	execArgs.FilePayload = control.NewFilePayload(fdMap, nil)
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
	expectedPL := []*control.Process{
		newProcessBuilder().Cmd("sleep").PID(1).Process(),
		newProcessBuilder().Cmd("sleep").PID(kernel.ThreadID(pid1)).Process(),
		newProcessBuilder().Cmd("sleep").PID(kernel.ThreadID(pid2)).Process(),
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

	if err := cont2.Restore(conf, dir, false /* direct */, false /* background */, nil /* networkArgs */); err != nil {
		t.Fatalf("error restoring container: %v", err)
	}

	// Check that only the init process is present and the exec'ed
	// processes were killed.
	expectedPL = []*control.Process{
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

	if err := cont2.Restore(conf, dir, false /* direct */, false /* background */, nil /* networkArgs */); err != nil {
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

	testDir, err := os.MkdirTemp(testutil.TmpDir(), "erofs_checkpoint_restore_test_")
	if err != nil {
		t.Fatalf("os.MkdirTemp() failed: %v", err)
	}
	defer os.RemoveAll(testDir)

	rootfsDir, rootfsImage, err := createRootfsEROFS(testDir)
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
				spec.Annotations[boot.RootfsPrefix+"type"] = erofs.Name
				spec.Annotations[boot.RootfsPrefix+"source"] = rootfsImage
				// EROFS does not support creating synthetic directories yet, so let's add
				// a writeable and savable overlay for rootfs, which allows the sentry to
				// create the mount point for the bind mount of the temporary directory shared
				// between host and test container.
				spec.Annotations[boot.RootfsPrefix+"overlay"] = config.MemoryOverlay.String()
				return spec
			})
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

	dir, err := os.MkdirTemp(testutil.TmpDir(), "split-checkpoint-test")
	if err != nil {
		t.Fatalf("os.MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatalf("error chmoding file: %q, %v", dir, err)
	}

	// The file we will write to is in TmpDir() which is bind-mounted and overlay.
	guestFile := filepath.Join(testutil.TmpDir(), "test_file")
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

	// Checkpoint running container with SplitFSCheckpoint: true.
	checkpointOpts := sandbox.CheckpointOpts{
		SplitFSCheckpointPaths: []checkpoint.ResourceID{{Path: "all-tmpfs"}},
	}
	if err := cont.Checkpoint(conf, dir, checkpointOpts); err != nil {
		t.Fatalf("error checkpointing container: %v", err)
	}

	// Verify that fs/ directory is created and contains the expected files.
	fsDir := filepath.Join(dir, checkpointfiles.FSCheckpointDir)
	if _, err := os.Stat(fsDir); os.IsNotExist(err) {
		t.Fatalf("fs directory was not created")
	}
	for _, name := range []string{
		checkpointfiles.FSCheckpointManifestFileName,
		checkpointfiles.FSCheckpointMultiTarFileName,
		checkpointfiles.PagesFileName,
		checkpointfiles.PagesMetadataFileName,
	} {
		p := filepath.Join(fsDir, name)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			t.Errorf("expected file %q was not created", p)
		}
	}

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

	if err := cont2.Restore(conf, dir, false /* direct */, false /* background */, nil /* networkArgs */); err != nil {
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
}

func TestSplitFSCheckpointRestoreTmpfs(t *testing.T) {
	// We only run this test if checkpoint/restore is supported.
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint not supported")
	}

	conf := testutil.TestConfig(t)

	// Enable overlay with a directory filestore for all gofer mounts.
	overlayDir, err := os.MkdirTemp(testutil.TmpDir(), "overlay-dir")
	if err != nil {
		t.Fatalf("failed to create overlay directory: %v", err)
	}
	defer os.RemoveAll(overlayDir)
	if err := os.Chmod(overlayDir, 0777); err != nil {
		t.Fatalf("error chmoding overlay directory: %v", err)
	}
	conf.Overlay2.Set("all:dir=" + overlayDir)

	dir, err := os.MkdirTemp(testutil.TmpDir(), "split-checkpoint-tmpfs-test")
	if err != nil {
		t.Fatalf("os.MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatalf("error chmoding file: %q, %v", dir, err)
	}

	// Create a host directory that will be bind-mounted and then turned into tmpfs via hint.
	tmpfsSourceDir, err := os.MkdirTemp(testutil.TmpDir(), "tmpfs-source")
	if err != nil {
		t.Fatalf("failed to create tmpfs source directory: %v", err)
	}
	defer os.RemoveAll(tmpfsSourceDir)
	if err := os.Chmod(tmpfsSourceDir, 0777); err != nil {
		t.Fatalf("error chmoding tmpfs source directory: %v", err)
	}

	tmpfsMount := "/tmpfs-mount"
	guestFile := filepath.Join(tmpfsMount, "test_file")
	script := "echo hello > '" + guestFile + "'; while true; do sleep 1; done"
	spec := testutil.NewSpecWithArgs("bash", "-c", script)

	// Add bind mount.
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Destination: tmpfsMount,
		Type:        "bind",
		Source:      tmpfsSourceDir,
	})

	// Add mount hints to turn it into tmpfs with private memory file (via overlay).
	spec.Annotations = map[string]string{
		"dev.gvisor.spec.mount.test-tmpfs.source": tmpfsSourceDir,
		"dev.gvisor.spec.mount.test-tmpfs.type":   "tmpfs",
		"dev.gvisor.spec.mount.test-tmpfs.share":  "container",
	}

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

	// Verify that the file does NOT exist on the host (because of tmpfs).
	hostFile := filepath.Join(tmpfsSourceDir, "test_file")
	if _, err := os.Stat(hostFile); !os.IsNotExist(err) {
		t.Errorf("File leaked to host! It should be in tmpfs only. Path: %q", hostFile)
	}

	// Checkpoint running container with SplitFSCheckpoint: true.
	checkpointOpts := sandbox.CheckpointOpts{
		SplitFSCheckpointPaths: []checkpoint.ResourceID{{Path: "all-tmpfs"}},
	}
	if err := cont.Checkpoint(conf, dir, checkpointOpts); err != nil {
		t.Fatalf("error checkpointing container: %v", err)
	}

	// Verify that fs/ directory is created and contains the expected files.
	fsDir := filepath.Join(dir, checkpointfiles.FSCheckpointDir)
	if _, err := os.Stat(fsDir); os.IsNotExist(err) {
		t.Fatalf("fs directory was not created")
	}
	for _, name := range []string{
		checkpointfiles.FSCheckpointManifestFileName,
		checkpointfiles.FSCheckpointMultiTarFileName,
		checkpointfiles.PagesFileName,
		checkpointfiles.PagesMetadataFileName,
	} {
		p := filepath.Join(fsDir, name)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			t.Errorf("expected file %q was not created", p)
		}
	}

	// Restore into a new container with different ID (relying on auto-detection of split filesystem).
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

	if err := cont2.Restore(conf, dir, false /* direct */, false /* background */, nil /* networkArgs */); err != nil {
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
	if _, err := os.Stat(hostFile); !os.IsNotExist(err) {
		t.Errorf("File leaked to host after restore! Path: %q", hostFile)
	}
}
