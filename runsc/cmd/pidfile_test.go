package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWritePidFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()

	// Write new file.

	path := filepath.Join(tempDir, "test.pid")
	if err := WritePidFile(path, 17); err != nil {
		t.Fatalf("failed to write pid file: %v", err)
	}

	pidStr, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read pid file: %v", err)
	}
	if string(pidStr) != "17" {
		t.Fatalf("pid file did not contain pid '17'")
	}

	// Overwrite existing file.

	if err := WritePidFile(path, 19); err != nil {
		t.Fatalf("failed to overwrite write pid file: %v", err)
	}
	pidStr, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read pid file: %v", err)
	}
	if string(pidStr) != "19" {
		t.Fatalf("pid file did not contain pid '19'")
	}
}
