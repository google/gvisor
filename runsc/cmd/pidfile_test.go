// Copyright 2025 The gVisor Authors.
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

	t.Run("Write new file", func(t *testing.T) {
		path := filepath.Join(tempDir, "test-new.pid")
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
	})

	t.Run("Overwrite existing file", func(t *testing.T) {
		path := filepath.Join(tempDir, "test-overwrite.pid")
		if err := os.WriteFile(path, []byte("11"), 0600); err != nil {
			t.Fatalf("failed to write pid file: %v", err)
		}

		if err := WritePidFile(path, 19); err != nil {
			t.Fatalf("failed to overwrite write pid file: %v", err)
		}
		pidStr, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read pid file: %v", err)
		}
		if string(pidStr) != "19" {
			t.Fatalf("pid file did not contain pid '19'")
		}
	})
}
