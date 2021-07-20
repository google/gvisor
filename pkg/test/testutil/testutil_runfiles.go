// Copyright 2018 The gVisor Authors.
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

//go:build go1.1
// +build go1.1

package testutil

import (
	"fmt"
	"os"
	"path/filepath"
)

// FindFile searchs for a file inside the test run environment. It returns the
// full path to the file. It fails if none or more than one file is found.
func FindFile(path string) (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	// The test root is demarcated by a path element called "__main__". Search for
	// it backwards from the working directory.
	root := wd
	for {
		dir, name := filepath.Split(root)
		if name == "__main__" {
			break
		}
		if len(dir) == 0 {
			return "", fmt.Errorf("directory __main__ not found in %q", wd)
		}
		// Remove ending slash to loop around.
		root = dir[:len(dir)-1]
	}

	// Annoyingly, bazel adds the build type to the directory path for go
	// binaries, but not for c++ binaries. We use two different patterns to
	// to find our file.
	patterns := []string{
		// Try the obvious path first.
		filepath.Join(root, path),
		// If it was a go binary, use a wildcard to match the build
		// type. The pattern is: /test-path/__main__/directories/*/file.
		filepath.Join(root, filepath.Dir(path), "*", filepath.Base(path)),
	}

	for _, p := range patterns {
		matches, err := filepath.Glob(p)
		if err != nil {
			// "The only possible returned error is ErrBadPattern,
			// when pattern is malformed." -godoc
			return "", fmt.Errorf("error globbing %q: %v", p, err)
		}
		switch len(matches) {
		case 0:
			// Try the next pattern.
		case 1:
			// We found it.
			return matches[0], nil
		default:
			return "", fmt.Errorf("more than one match found for %q: %s", path, matches)
		}
	}
	return "", fmt.Errorf("file %q not found", path)
}
