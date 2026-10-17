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

package drivers

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
)

const (
	archAMD64 = "amd64"
	archARM64 = "arm64"
)

// Downloader copies NVIDIA .run installers and computes their SHA256 checksums.
// Its zero value uses the default HTTP client.
type Downloader struct {
	client *http.Client
}

type downloadStatusError struct {
	code   int
	status string
}

func (e *downloadStatusError) Error() string {
	return fmt.Sprintf("driver download returned HTTP %d: %s", e.code, e.status)
}

func driverURL(version nvconf.DriverVersion, arch string) (string, error) {
	switch arch {
	case archAMD64:
		return fmt.Sprintf("https://us.download.nvidia.com/tesla/%s/NVIDIA-Linux-x86_64-%s.run", version, version), nil
	case archARM64:
		return fmt.Sprintf("https://us.download.nvidia.com/XFree86/aarch64/%s/NVIDIA-Linux-aarch64-%s.run", version, version), nil
	default:
		return "", fmt.Errorf("unsupported driver architecture %q", arch)
	}
}

// Download writes the complete NVIDIA .run installer to dst and returns its
// SHA256 checksum.
// A failed transfer returns no checksum, even if some bytes reached dst.
func (d *Downloader) Download(ctx context.Context, version nvconf.DriverVersion, arch string, dst io.Writer) (string, error) {
	url, err := driverURL(version, arch)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create driver request: %w", err)
	}
	client := d.client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to download driver %q on arch %q: %w", version, arch, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", &downloadStatusError{code: resp.StatusCode, status: resp.Status}
	}
	checksum := sha256.New()
	if _, err := io.Copy(io.MultiWriter(dst, checksum), resp.Body); err != nil {
		return "", fmt.Errorf("failed to copy driver %q on arch %q: %w", version, arch, err)
	}
	return fmt.Sprintf("%x", checksum.Sum(nil)), nil
}

func checkChecksum(version nvconf.DriverVersion, arch, got, want string) error {
	if got != want {
		return fmt.Errorf("driver %q on arch %q checksum mismatch: got %q, want %q", version, arch, got, want)
	}
	return nil
}

// ValidateChecksum checks the public NVIDIA .run installer or its declared
// absence for each architecture. An absent public installer does not validate
// a retained hash or skip checking the other architecture.
func (d *Downloader) ValidateChecksum(ctx context.Context, version nvconf.DriverVersion, checksums nvproxy.Checksums) error {
	targets := []struct {
		arch        string
		checksum    string
		unavailable bool
	}{
		{arch: archAMD64, checksum: checksums.X86_64},
		{arch: archARM64, checksum: checksums.ARM64},
	}
	for i := range targets {
		unavailable, err := checksums.PublicInstallerUnavailable(targets[i].arch)
		if err != nil {
			return fmt.Errorf("invalid installer metadata for driver %q: %w", version, err)
		}
		targets[i].unavailable = unavailable
	}
	for _, target := range targets {
		got, err := d.Download(ctx, version, target.arch, io.Discard)
		if target.unavailable {
			if status, ok := errors.AsType[*downloadStatusError](err); ok && status.code == http.StatusNotFound {
				if target.checksum == nvproxy.ChecksumNoDriver {
					log.Infof("NVIDIA .run installer does not exist for driver %q arch: %q", version, target.arch)
				} else {
					log.Infof("NVIDIA .run installer is unavailable at the public URL for driver %q arch: %q; registered checksum: %q", version, target.arch, target.checksum)
				}
				continue
			}
			if err == nil {
				return fmt.Errorf("unexpected NVIDIA .run installer for driver %q on arch %q", version, target.arch)
			}
		}
		if err != nil {
			return fmt.Errorf("failed to get checksum for driver %q on arch %q: %w", version, target.arch, err)
		}
		if err := checkChecksum(version, target.arch, got, target.checksum); err != nil {
			return err
		}
		log.Infof("Checksum for driver %q arch: %q: %q", version, target.arch, got)
	}
	return nil
}
