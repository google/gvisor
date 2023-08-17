// Copyright 2023 The gVisor Authors.
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

// Package util contains utility functions for gvisor_k8s_tools.
package util

import (
	"fmt"
	"os"
	"path"
)

// TempDir creates and returns the path to a private temporary directory.
// The caller must call the given cleanup function to clean up the directory.
func TempDir() (string, func(), error) {
	tempDir, err := os.MkdirTemp("", "gvisor_k8s_tool.*.tmp")
	if err != nil {
		return "", nil, err
	}
	// Create a private subdirectory (0700) within the temporary directory.
	privateSubdir := path.Join(tempDir, "tmp")
	if err := os.Mkdir(privateSubdir, 0700); err != nil {
		os.RemoveAll(tempDir)
		return "", nil, fmt.Errorf("cannot create subdir %q: %w", privateSubdir, err)
	}
	return privateSubdir, func() { os.RemoveAll(tempDir) }, nil
}
