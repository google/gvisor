// Copyright 2023 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package drivers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
)

// TestVersionInstalled tests when the version is already installed.
func TestVersionInstalled(t *testing.T) {
	ctx := context.Background()
	versionContent := []byte("some cool content")
	checksum := fmt.Sprintf("%x", sha256.Sum256(versionContent))
	version := nvproxy.NewDriverVersion(1, 2, 3)
	getFunction := func() (nvproxy.DriverVersion, error) { return version, nil }
	downloadFunction := func(context.Context, string) (io.ReadCloser, error) { return nil, fmt.Errorf("should not get here") }
	installer := &Installer{
		requestedVersion:       version,
		getSupportedDriverFunc: func() map[nvproxy.DriverVersion]string { return map[nvproxy.DriverVersion]string{version: checksum} },
		getCurrentDriverFunc:   getFunction,
		downloadFunction:       downloadFunction,
	}
	if err := installer.MaybeInstall(ctx); err != nil {
		t.Fatalf("Installation failed: %v", err)
	}
}

// TestVersionNotSupported tests when the version is not supported.
func TestVersionNotSupported(t *testing.T) {
	ctx := context.Background()
	unsupportedVersion := nvproxy.NewDriverVersion(1, 2, 3)
	installer := &Installer{
		requestedVersion: unsupportedVersion,
		getSupportedDriverFunc: func() map[nvproxy.DriverVersion]string {
			return map[nvproxy.DriverVersion]string{
				nvproxy.NewDriverVersion(2, 3, 4): "other version",
			}
		},
	}
	err := installer.MaybeInstall(ctx)
	if err == nil {
		t.Fatalf("Installation succeeded, want error")
	}
	if !strings.Contains(err.Error(), "not supported") {
		t.Errorf("Installation failed, want error containing 'not supported' got: %s", err.Error())
	}
}

// TestShaMismatch tests when a checksum of a driver doesn't match what's in the map.
func TestShaMismatch(t *testing.T) {
	ctx := context.Background()
	version := nvproxy.NewDriverVersion(1, 2, 3)
	installer := &Installer{
		requestedVersion: version,
		getCurrentDriverFunc: func() (nvproxy.DriverVersion, error) {
			return nvproxy.DriverVersion{}, nil
		},
		getSupportedDriverFunc: func() map[nvproxy.DriverVersion]string {
			return map[nvproxy.DriverVersion]string{
				version: "mismatched checksum",
			}
		},
		downloadFunction: func(context.Context, string) (io.ReadCloser, error) {
			reader := bytes.NewReader([]byte("some content"))
			return io.NopCloser(reader), nil
		},
	}
	err := installer.MaybeInstall(ctx)
	if err == nil {
		t.Fatalf("Installation succeeded, want error")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("Installation failed, want error containing 'mismatch checksum' got: %s", err.Error())
	}
}

// TestDriverInstalls tests the successful installation of a driver.
func TestDriverInstalls(t *testing.T) {
	ctx := context.Background()
	content := []byte("some content")
	checksum := fmt.Sprintf("%x", sha256.Sum256(content))
	version := nvproxy.NewDriverVersion(1, 2, 3)
	installer := &Installer{
		requestedVersion: version,
		getCurrentDriverFunc: func() (nvproxy.DriverVersion, error) {
			return nvproxy.DriverVersion{}, nil
		},
		getSupportedDriverFunc: func() map[nvproxy.DriverVersion]string {
			return map[nvproxy.DriverVersion]string{
				version: checksum,
			}
		},
		downloadFunction: func(context.Context, string) (io.ReadCloser, error) {
			reader := bytes.NewReader(content)
			return io.NopCloser(reader), nil
		},
		installFunction: func(_ string) error {
			return nil
		},
	}
	if err := installer.MaybeInstall(ctx); err != nil {
		t.Fatalf("Installation failed: %v", err)
	}
}
