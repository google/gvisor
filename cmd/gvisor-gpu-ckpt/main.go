//go:build linux

// Binary gvisor-gpu-ckpt is a SaveRestoreExec binary for gVisor that
// handles GPU checkpoint/restore via NVIDIA's cuCheckpointProcess* API.
//
// gVisor invokes this binary with the GVISOR_SAVE_RESTORE_AUTO_EXEC_MODE
// env var set to "save", "restore", or "resume".
//
// Usage with gVisor:
//
//	runsc --save-restore-exec-argv=/path/to/gvisor-gpu-ckpt checkpoint <container-id>
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	mode := os.Getenv("GVISOR_SAVE_RESTORE_AUTO_EXEC_MODE")
	if mode == "" {
		fmt.Fprintln(os.Stderr, "gvisor-gpu-ckpt: GVISOR_SAVE_RESTORE_AUTO_EXEC_MODE not set")
		os.Exit(1)
	}

	pid, err := getSentryPID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gvisor-gpu-ckpt: failed to determine sentry PID: %v\n", err)
		os.Exit(1)
	}

	if err := loadLibcuda(); err != nil {
		// No CUDA driver available — if there are no GPU contexts,
		// this is expected and not an error.
		fmt.Fprintf(os.Stderr, "gvisor-gpu-ckpt: %v (no GPU contexts to checkpoint)\n", err)
		os.Exit(0)
	}

	switch mode {
	case "save":
		if err := doSave(pid); err != nil {
			fmt.Fprintf(os.Stderr, "gvisor-gpu-ckpt: save failed: %v\n", err)
			os.Exit(1)
		}
	case "restore", "resume":
		if err := doRestore(pid); err != nil {
			fmt.Fprintf(os.Stderr, "gvisor-gpu-ckpt: %s failed: %v\n", mode, err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "gvisor-gpu-ckpt: unknown mode %q\n", mode)
		os.Exit(1)
	}
}

func doSave(pid int) error {
	fmt.Fprintf(os.Stderr, "gvisor-gpu-ckpt: locking GPU contexts for PID %d\n", pid)
	if err := checkpointLock(pid); err != nil {
		if isNoContextError(err) {
			fmt.Fprintf(os.Stderr, "gvisor-gpu-ckpt: no CUDA contexts for PID %d, nothing to checkpoint\n", pid)
			return nil
		}
		return fmt.Errorf("lock: %w", err)
	}

	fmt.Fprintf(os.Stderr, "gvisor-gpu-ckpt: checkpointing GPU state for PID %d\n", pid)
	if err := checkpointCheckpoint(pid); err != nil {
		// Attempt to unlock on checkpoint failure.
		_ = checkpointUnlock(pid)
		return fmt.Errorf("checkpoint: %w", err)
	}

	fmt.Fprintf(os.Stderr, "gvisor-gpu-ckpt: GPU checkpoint complete for PID %d\n", pid)
	return nil
}

func doRestore(pid int) error {
	fmt.Fprintf(os.Stderr, "gvisor-gpu-ckpt: restoring GPU state for PID %d\n", pid)
	if err := checkpointRestore(pid); err != nil {
		return fmt.Errorf("restore: %w", err)
	}

	fmt.Fprintf(os.Stderr, "gvisor-gpu-ckpt: unlocking GPU contexts for PID %d\n", pid)
	if err := checkpointUnlock(pid); err != nil {
		return fmt.Errorf("unlock: %w", err)
	}

	fmt.Fprintf(os.Stderr, "gvisor-gpu-ckpt: GPU restore complete for PID %d\n", pid)
	return nil
}

// isNoContextError returns true if the error indicates the target PID
// has no CUDA contexts (rc=3 = CUDA_ERROR_NOT_INITIALIZED).
func isNoContextError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "rc=3")
}

// getSentryPID returns the PID of the gVisor sentry process that owns
// the GPU contexts. It checks GVISOR_SENTRY_PID env var first, then
// falls back to the parent PID.
func getSentryPID() (int, error) {
	if s := os.Getenv("GVISOR_SENTRY_PID"); s != "" {
		pid, err := strconv.Atoi(s)
		if err != nil {
			return 0, fmt.Errorf("invalid GVISOR_SENTRY_PID %q: %w", s, err)
		}
		return pid, nil
	}
	return os.Getppid(), nil
}
