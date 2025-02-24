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
	downloadFunction := func(context.Context, string, CPUArchitecture) (io.ReadCloser, error) {
		return nil, fmt.Errorf("should not get here")
	}
	installer := &Installer{
		requestedVersion: version,
		expectedChecksumFunc: func(v nvproxy.DriverVersion) (string, string, bool) {
			if v == version {
				return checksum, checksum, true
			}
			return "", "", false
		},
		getCurrentDriverFunc: getFunction,
		downloadFunc:         downloadFunction,
	}
	if err := installer.MaybeInstall(ctx, X86_64); err != nil {
		t.Fatalf("Installation failed: %v", err)
	}
}

// TestVersionNotSupported tests when the version is not supported.
func TestVersionNotSupported(t *testing.T) {
	ctx := context.Background()
	unsupportedVersion := nvproxy.NewDriverVersion(1, 2, 3)
	installer := &Installer{
		requestedVersion: unsupportedVersion,
		expectedChecksumFunc: func(v nvproxy.DriverVersion) (string, string, bool) {
			return "", "", false
		},
	}
	err := installer.MaybeInstall(ctx, X86_64)
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
	content := []byte("some content")
	checksum := fmt.Sprintf("%x", sha256.Sum256(content))
	installer := &Installer{
		requestedVersion: version,
		getCurrentDriverFunc: func() (nvproxy.DriverVersion, error) {
			return nvproxy.DriverVersion{}, nil
		},
		expectedChecksumFunc: func(v nvproxy.DriverVersion) (string, string, bool) {
			if v == version {
				return "mismatch", "mismatch", true
			}
			return checksum, checksum, false
		},
		downloadFunc: func(context.Context, string, CPUArchitecture) (io.ReadCloser, error) {
			reader := bytes.NewReader([]byte("some content"))
			return io.NopCloser(reader), nil
		},
	}
	err := installer.MaybeInstall(ctx, X86_64)
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
	for _, arch := range []CPUArchitecture{X86_64, ARM64} {
		t.Run(fmt.Sprintf("%s", arch), func(t *testing.T) {
			testDriverInstalls(ctx, t, arch)
		})
	}
}

func testDriverInstalls(ctx context.Context, t *testing.T, arch CPUArchitecture) {
	version := nvproxy.NewDriverVersion(1, 2, 3)
	installer := &Installer{
		requestedVersion: version,
		getCurrentDriverFunc: func() (nvproxy.DriverVersion, error) {
			return nvproxy.DriverVersion{}, nil
		},
		expectedChecksumFunc: func(v nvproxy.DriverVersion) (string, string, bool) {
			checksumX86_64 := fmt.Sprintf("%x", sha256.Sum256([]byte(X86_64)))
			checksumARM64 := fmt.Sprintf("%x", sha256.Sum256([]byte(ARM64)))
			if v == version {
				return checksumX86_64, checksumARM64, true
			}
			return "garbage", "garbage", false
		},
		downloadFunc: func(context.Context, string, CPUArchitecture) (io.ReadCloser, error) {
			reader := bytes.NewReader([]byte(arch))
			return io.NopCloser(reader), nil
		},
		installFunc: func(_ string) error {
			return nil
		},
	}
	if err := installer.MaybeInstall(ctx, arch); err != nil {
		t.Fatalf("Installation failed: %v", err)
	}
}
