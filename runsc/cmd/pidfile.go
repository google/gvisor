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
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// WritePidFile writes pid file atomically if possible.
func WritePidFile(path string, pid int) error {
	pidStr := []byte(strconv.Itoa(pid))

	st, err := os.Stat(path)
	if err == nil && !st.Mode().IsRegular() {
		// If not regular file, write in place.
		if err := os.WriteFile(path, pidStr, 0644); err != nil {
			return fmt.Errorf("failed to write pid file %s: %w", path, err)
		}
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("stat file %s failed: %w", path, err)
	}

	// Otherwise write using temp file to make write atomic.
	dir := filepath.Dir(path)
	tempFile, err := os.CreateTemp(dir, "pid-tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp pid file in dir %s: %w", dir, err)
	}

	tempFileRenamed := false
	defer func(tempFile *os.File) {
		_ = tempFile.Close()
		if !tempFileRenamed {
			_ = os.Remove(tempFile.Name())
		}
	}(tempFile)

	if err := os.Chmod(tempFile.Name(), 0644); err != nil {
		return fmt.Errorf("failed to chmod pid file %s: %w", tempFile.Name(), err)
	}

	if _, err := tempFile.Write(pidStr); err != nil {
		return fmt.Errorf("failed to write pid file %s: %w", tempFile.Name(), err)
	}

	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp pid file %s: %w", tempFile.Name(), err)
	}

	if err := os.Rename(tempFile.Name(), path); err != nil {
		return fmt.Errorf("failed to rename temp pid file %s -> %s: %w", tempFile.Name(), path, err)
	}
	tempFileRenamed = true

	return nil
}
