// Copyright 2018 Google Inc.
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

// Package testutil contains utility functions for runsc tests.
package testutil

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/runsc/boot"
	"gvisor.googlesource.com/gvisor/runsc/specutils"
)

// ConfigureExePath configures the executable for runsc in the test environment.
func ConfigureExePath() error {

	// runsc is in a directory like: 'runsc/linux_amd64_pure_stripped/runsc'.
	// Since I don't want to construct 'linux_amd64_pure_stripped' based on the
	// build type, do a quick search for: 'runsc/*/runsc'
	exePath := ""
	lv1 := "./runsc"
	lv1fis, err := ioutil.ReadDir(lv1)
	if err != nil {
		return err
	}
	for _, fi := range lv1fis {
		if !fi.IsDir() {
			continue
		}
		lv2fis, err := ioutil.ReadDir(filepath.Join(lv1, fi.Name()))
		if err != nil {
			return err
		}
		for _, candidate := range lv2fis {
			if !candidate.IsDir() && candidate.Name() == "runsc" {
				exePath, err = filepath.Abs(filepath.Join(lv1, fi.Name(), candidate.Name()))
				if err != nil {
					return err
				}
				break
			}
		}
	}
	if exePath == "" {
		return fmt.Errorf("path to runsc not found")
	}
	specutils.ExePath = exePath
	return nil
}

// NewSpecWithArgs creates a simple spec with the given args suitable for use
// in tests.
func NewSpecWithArgs(args ...string) *specs.Spec {
	spec := &specs.Spec{
		// The host filesystem root is the container root.
		Root: &specs.Root{
			Path:     "/",
			Readonly: true,
		},
		Process: &specs.Process{
			Args: args,
			Env: []string{
				"PATH=" + os.Getenv("PATH"),
			},
		},
	}
	return spec
}

// SetupRootDir creates a root directory for containers.
func SetupRootDir() (string, error) {
	rootDir, err := ioutil.TempDir("", "containers")
	if err != nil {
		return "", fmt.Errorf("error creating root dir: %v", err)
	}
	return rootDir, nil
}

// SetupContainer creates a bundle and root dir for the container, generates a
// test config, and writes the spec to config.json in the bundle dir.
func SetupContainer(spec *specs.Spec) (rootDir, bundleDir string, conf *boot.Config, err error) {
	rootDir, err = SetupRootDir()
	if err != nil {
		return "", "", nil, err
	}
	bundleDir, conf, err = SetupContainerInRoot(rootDir, spec)
	return rootDir, bundleDir, conf, err
}

// SetupContainerInRoot creates a bundle for the container, generates a test
// config, and writes the spec to config.json in the bundle dir.
func SetupContainerInRoot(rootDir string, spec *specs.Spec) (bundleDir string, conf *boot.Config, err error) {
	bundleDir, err = ioutil.TempDir("", "bundle")
	if err != nil {
		return "", nil, fmt.Errorf("error creating bundle dir: %v", err)
	}

	if err = writeSpec(bundleDir, spec); err != nil {
		return "", nil, fmt.Errorf("error writing spec: %v", err)
	}

	conf = &boot.Config{
		Debug:          true,
		LogFormat:      "text",
		LogPackets:     true,
		Network:        boot.NetworkNone,
		RootDir:        rootDir,
		Strace:         true,
		MultiContainer: true,
	}

	return bundleDir, conf, nil
}

// writeSpec writes the spec to disk in the given directory.
func writeSpec(dir string, spec *specs.Spec) error {
	b, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filepath.Join(dir, "config.json"), b, 0755)
}

// UniqueContainerID generates a unique container id for each test.
//
// The container id is used to create an abstract unix domain socket, which must
// be unique.  While the container forbids creating two containers with the same
// name, sometimes between test runs the socket does not get cleaned up quickly
// enough, causing container creation to fail.
func UniqueContainerID() string {
	return fmt.Sprintf("test-container-%d", time.Now().UnixNano())
}

// Copy copies file from src to dst.
func Copy(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
