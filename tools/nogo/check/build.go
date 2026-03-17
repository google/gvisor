// Copyright 2019 The gVisor Authors.
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

//go:build !false
// +build !false

package check

import (
	"errors"
	"fmt"
	"go/build"
	"io"
	"io/fs"
	"os"
	"strings"

	"gvisor.dev/gvisor/tools/nogo/flags"
)

func installsuffix() string {
	// This matches the rules_go choices:
	// https://github.com/bazel-contrib/rules_go/blob/ca94a5b1d0fe87678ce01fcb75cb7839343b5f8e/go/private/mode.bzl#L72.
	s := flags.GOOS + "_" + flags.GOARCH
	if flags.Race {
		s += "_race"
	}
	if flags.MSAN {
		s += "_msan"
	}
	return s
}

// findStdPkg needs to find the bundled standard library packages.
func findStdPkg(path string) (io.ReadCloser, error) {
	// Attempt to use the root, if available.
	root, envErr := flags.Env("GOROOT")
	if envErr != nil {
		return nil, fmt.Errorf("unable to resolve GOROOT: %w", envErr)
	}

	// Attempt to resolve the library, and propagate this error.
	f, err := os.Open(fmt.Sprintf("%s/pkg/%s/%s.a", root, installsuffix(), path))
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("unable to find %q archive", path)
	}
	return f, err
}

// FilterStdPackages returns a package source map including only packages that
// are also present in GOROOT.
//
// The bazel GOROOT contains only exported packages and their dependencies.
//
// On the other hand, srcPkgs comes from rudimentary processing of the full std
// sources and thus includes things like test only and experimental packages.
// These packages will fail to analyze without an archive in GOROOT, but we
// won't need those anyway, so filter them out.
func FilterStdPackages(srcPkgs map[string][]string) (map[string][]string, error) {
	goroot, envErr := flags.Env("GOROOT")
	if envErr != nil {
		return nil, fmt.Errorf("unable to resolve GOROOT: %w", envErr)
	}

	root, err := os.OpenRoot(fmt.Sprintf("%s/pkg/%s/", goroot, installsuffix()))
	if err != nil {
		return nil, fmt.Errorf("error opening GOROOT: %v", err)
	}

	// Gather all stdlib packages in the zip.
	pkgNames := make(map[string]struct{})
	err = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		// path is "<path>.a".
		path, ok := strings.CutSuffix(path, ".a")
		if !ok {
			return fmt.Errorf("unexpected file %s in GOROOT", path)
		}
		pkgNames[path] = struct{}{}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("error walking GOROOT: %v", err)
	}

	pkgs := make(map[string][]string)
	for path := range pkgNames {
		pkg, ok := srcPkgs[path]
		if !ok {
			return nil, fmt.Errorf("package %q present in stdlib GOROOT but not in source", path)
		}
		pkgs[path] = pkg
	}

	// Drop runtime/cgo, which is only necessary for cgo even though
	// shouldInclude matches it without cgo.
	delete(pkgs, "runtime/cgo")

	// Drop runtime/race (even in -race mode). It requires cgo but has no
	// API, so it won't actually be imported anywhere.
	delete(pkgs, "runtime/race")

	return pkgs, nil
}

// releaseTags returns the default release tags.
func releaseTags() ([]string, error) {
	return build.Default.ReleaseTags, nil
}
