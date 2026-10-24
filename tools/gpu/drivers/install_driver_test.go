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
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"

	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
)

func TestVersionNotSupported(t *testing.T) {
	_, err := NewInstaller("1.2.3", false)
	if err == nil {
		t.Fatal("NewInstaller accepted an unsupported version")
	}
	if got, want := err.Error(), "not supported"; !strings.Contains(got, want) {
		t.Errorf("NewInstaller error = %q, want %q", got, want)
	}
}

func TestHostDriverRequiresChecksum(t *testing.T) {
	version := nvconf.NewDriverVersion(1, 2, 3)
	for _, value := range []string{"", nvproxy.ChecksumNoDriver} {
		if _, err := hostDriver(version, nvproxy.NewChecksums(value, value)); err == nil {
			t.Errorf("hostDriver accepted unavailable checksum %q", value)
		}
	}
	want := checksum("driver")
	got, err := hostDriver(version, nvproxy.NewChecksums(want, want))
	if err != nil {
		t.Fatalf("hostDriver: %v", err)
	}
	if got, want := got.version, version; !got.Equals(want) {
		t.Errorf("version = %v, want %v", got, want)
	}
	if got, want := got.checksum, want; got != want {
		t.Errorf("checksum = %q, want %q", got, want)
	}
	checksums := nvproxy.NewChecksums(want, want)
	// Availability on the other architecture must not hide this host's driver.
	switch runtime.GOARCH {
	case archAMD64:
		checksums.NoPublicARM64Installer = true
	case archARM64:
		checksums.NoPublicX86_64Installer = true
	default:
		t.Fatalf("unsupported test architecture %q", runtime.GOARCH)
	}
	if _, err := hostDriver(version, checksums); err != nil {
		t.Fatalf("hostDriver with available host installer: %v", err)
	}
	checksums.NoPublicX86_64Installer = true
	checksums.NoPublicARM64Installer = true
	if _, err := hostDriver(version, checksums); err == nil {
		t.Error("hostDriver accepted a known hash without a public installer")
	}
	retained, err := checksums.Checksum()
	if err != nil {
		t.Fatalf("Checksum: %v", err)
	}
	if got, want := retained, want; got != want {
		t.Errorf("retained checksum = %q, want %q", got, want)
	}
}

func TestDriverInstalls(t *testing.T) {
	const content = "#!/bin/sh\nexit 0\n"
	version := nvconf.NewDriverVersion(1, 2, 3)
	oldVersion := nvconf.NewDriverVersion(1, 2, 2)
	inspectionError := errors.New("unknown current driver")
	hostError := errors.New("host has no NVIDIA GPU")
	installError := errors.New("install failed")
	uninstallError := errors.New("uninstall failed")
	for _, test := range []struct {
		name         string
		current      nvconf.DriverVersion
		inspectErr   error
		hostErr      error
		readErr      error
		wantChecksum string
		uninstallErr error
		installErr   error
		wantErr      error
		mismatch     bool
		wantSteps    string
	}{
		{name: "already_installed", current: version, wantChecksum: checksum(content), wantSteps: "inspect"},
		{name: "absent", wantChecksum: checksum(content), wantSteps: "inspect preflight download install"},
		{name: "replace", current: oldVersion, wantChecksum: checksum(content), wantSteps: "inspect preflight download uninstall install"},
		{name: "inspection_failure", current: version, inspectErr: inspectionError, wantChecksum: checksum(content), wantErr: inspectionError, wantSteps: "inspect"},
		{name: "unsuitable_host", current: oldVersion, hostErr: hostError, wantChecksum: checksum(content), wantErr: hostError, wantSteps: "inspect preflight"},
		{name: "read_failure", current: oldVersion, readErr: io.ErrUnexpectedEOF, wantChecksum: checksum(content), wantErr: io.ErrUnexpectedEOF, wantSteps: "inspect preflight download"},
		{name: "checksum_failure", current: oldVersion, wantChecksum: "wrong", mismatch: true, wantSteps: "inspect preflight download"},
		{name: "uninstall_failure", current: oldVersion, wantChecksum: checksum(content), uninstallErr: uninstallError, wantErr: uninstallError, wantSteps: "inspect preflight download uninstall"},
		{name: "install_failure", current: oldVersion, wantChecksum: checksum(content), installErr: installError, wantErr: installError, wantSteps: "inspect preflight download uninstall install"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			var steps []string
			var body *responseBody
			dir := t.TempDir()
			checkPrepared := func(path string) error {
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				if got, want := data, []byte(content); !bytes.Equal(got, want) {
					return fmt.Errorf("installer contents = %q, want %q", got, want)
				}
				// Direct execution also requires the file to be executable
				// and no longer open for writing.
				return exec.CommandContext(ctx, path).Run()
			}
			installer := &Installer{
				requestedVersion: version,
				checksum:         test.wantChecksum,
				tempDir:          dir,
				getCurrentDriverFunc: func(context.Context) (nvconf.DriverVersion, error) {
					steps = append(steps, "inspect")
					return test.current, test.inspectErr
				},
				checkHostFunc: func(context.Context) error {
					steps = append(steps, "preflight")
					return test.hostErr
				},
				downloader: Downloader{client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					steps = append(steps, "download")
					reader := iotest.DataErrReader(strings.NewReader(content))
					if test.readErr != nil {
						reader = iotest.ErrReader(test.readErr)
					}
					body = &responseBody{Reader: reader}
					return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
				})}},
				uninstallFunc: func(context.Context) error {
					if body == nil {
						return errors.New("uninstall began without a download")
					}
					if got, want := body.closes, 1; got != want {
						t.Errorf("response closes before uninstall = %d, want %d", got, want)
					}
					steps = append(steps, "uninstall")
					entries, err := os.ReadDir(dir)
					if err != nil {
						return err
					}
					if got, want := len(entries), 1; got != want {
						return fmt.Errorf("prepared installers = %d, want %d", got, want)
					}
					if err := checkPrepared(filepath.Join(dir, entries[0].Name())); err != nil {
						return err
					}
					return test.uninstallErr
				},
				installFunc: func(_ context.Context, path string) error {
					steps = append(steps, "install")
					if err := checkPrepared(path); err != nil {
						return err
					}
					return test.installErr
				},
			}
			err := installer.MaybeInstall(ctx)
			if test.mismatch {
				if err == nil {
					t.Fatal("MaybeInstall accepted a checksum mismatch")
				}
				if got, want := err.Error(), "checksum mismatch"; !strings.Contains(got, want) {
					t.Errorf("MaybeInstall error = %q, want %q", got, want)
				}
			} else if !errors.Is(err, test.wantErr) {
				t.Errorf("MaybeInstall error = %v, want %v", err, test.wantErr)
			}
			if got, want := strings.Join(steps, " "), test.wantSteps; got != want {
				t.Errorf("steps = %q, want %q", got, want)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatalf("ReadDir: %v", err)
			}
			if got, want := len(entries), 0; got != want {
				t.Errorf("temporary files remaining = %d, want %d", got, want)
			}
			if body != nil {
				if got, want := body.closes, 1; got != want {
					t.Errorf("response closes = %d, want %d", got, want)
				}
			}
		})
	}
}

func TestListSupportedDrivers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "drivers")
	if err := ListSupportedDrivers(path); err != nil {
		t.Fatalf("create driver list: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if err := os.WriteFile(path, append(first, []byte("stale suffix")...), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := ListSupportedDrivers(path); err != nil {
		t.Fatalf("replace driver list: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if got, want := string(second), string(first); got != want {
		t.Errorf("replacement list = %q, want %q", got, want)
	}
}
