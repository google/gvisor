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

// Package drivers contains methods to download and install drivers.
package drivers

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
)

const (
	nvidiaSMIPath       = "/usr/bin/nvidia-smi"
	nvidiaUninstallPath = "/usr/bin/nvidia-uninstall"
	nvidiaBaseURLX86_64 = "https://us.download.nvidia.com/tesla/%s/NVIDIA-Linux-x86_64-%s.run"
	nvidiaARM64BaseURL  = "https://us.download.nvidia.com/XFree86/aarch64/%s/NVIDIA-Linux-aarch64-%s.run"

	archAMD64 = "amd64"
	archARM64 = "arm64"
)

func init() {
	nvproxy.Init()
}

func getNvidiaBaseURL(driverVersion, arch string) string {
	switch arch {
	case archARM64:
		return fmt.Sprintf(nvidiaARM64BaseURL, driverVersion, driverVersion)
	case archAMD64:
		return fmt.Sprintf(nvidiaBaseURLX86_64, driverVersion, driverVersion)
	}
	panic(fmt.Sprintf("unsupported arch: %q", arch))
}

// Installer handles the logic to install drivers.
type Installer struct {
	requestedVersion nvconf.DriverVersion
	// include functions so they can be mocked in tests.
	expectedChecksumFunc func(nvconf.DriverVersion) (nvproxy.Checksums, bool)
	getCurrentDriverFunc func() (nvconf.DriverVersion, error)
	downloadFunc         func(context.Context, string, string) (io.ReadCloser, error)
	installFunc          func(string) error
}

// NewInstaller returns a driver installer instance.
func NewInstaller(requestedVersion string, latest bool) (*Installer, error) {

	ret := &Installer{
		expectedChecksumFunc: nvproxy.ExpectedDriverChecksum,
		getCurrentDriverFunc: getCurrentDriver,
		downloadFunc:         DownloadDriver,
		installFunc:          installDriver,
	}
	switch {
	case latest:
		ret.requestedVersion = nvproxy.LatestDriver()
	default:
		d, err := nvconf.DriverVersionFrom(requestedVersion)
		if err != nil {
			return nil, fmt.Errorf("failed to parse requested driver version: %w", err)
		}
		ret.requestedVersion = d
	}
	return ret, nil
}

// MaybeInstall installs a driver if 1) no driver is present on the system already or 2) the
// driver currently installed does not match the requested version.
func (i *Installer) MaybeInstall(ctx context.Context) error {
	// If we don't support the driver, don't attempt to install it.
	if _, ok := i.expectedChecksumFunc(i.requestedVersion); !ok {
		return fmt.Errorf("requested driver %q is not supported", i.requestedVersion)
	}

	existingDriver, err := i.getCurrentDriverFunc()
	if err != nil {
		log.Warningf("failed to get current driver: %v", err)
	}
	if existingDriver.Equals(i.requestedVersion) {
		log.Infof("Driver already installed: %s", i.requestedVersion)
		return nil
	}

	if !existingDriver.Equals(nvconf.DriverVersion{}) {
		log.Infof("Uninstalling driver: %s", existingDriver)
		if err := i.uninstallDriver(ctx, existingDriver.String()); err != nil {
			return fmt.Errorf("failed to uninstall driver: %w", err)
		}
		log.Infof("Driver uninstalled: %s", i.requestedVersion)
	}

	log.Infof("Downloading driver: %s", i.requestedVersion)
	reader, err := i.downloadFunc(ctx, i.requestedVersion.String(), runtime.GOARCH)
	if err != nil {
		return fmt.Errorf("failed to download driver: %w", err)
	}

	f, err := os.CreateTemp("", "")
	if err != nil {
		return fmt.Errorf("failed to open driver file: %w", err)
	}
	defer os.Remove(f.Name())
	if err := i.writeAndCheck(f, reader); err != nil {
		f.Close()
		return fmt.Errorf("writeAndCheck: %w", err)
	}
	if err := f.Chmod(0755); err != nil {
		return fmt.Errorf("failed to chmod: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close driver file: %w", err)
	}
	log.Infof("Driver downloaded: %s", i.requestedVersion)
	log.Infof("Installing driver: %s", i.requestedVersion)
	if err := i.installFunc(f.Name()); err != nil {
		return fmt.Errorf("failed to install driver: %w", err)
	}
	log.Infof("Installation Complete!")
	return nil
}

func (i *Installer) uninstallDriver(ctx context.Context, driverVersion string) error {
	exec.Command(nvidiaUninstallPath, "-s", driverVersion)
	cmd := exec.Command(nvidiaUninstallPath, "-s")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run nvidia-uninstall: %w", err)
	}
	return nil
}

func (i *Installer) writeAndCheck(f *os.File, reader io.ReadCloser) error {
	checksum := sha256.New()
	buf := make([]byte, 1024*1024)
	for {
		n, err := reader.Read(buf[0:])
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read: %w", err)
		}
		if n == 0 || err == io.EOF {
			break
		}
		if _, err := checksum.Write(buf[:n]); err != nil {
			return fmt.Errorf("failed to write: %w", err)
		}
		if _, err := f.Write(buf[:n]); err != nil {
			return fmt.Errorf("failed to write: %w", err)
		}
	}
	gotChecksum := fmt.Sprintf("%x", checksum.Sum(nil))
	c, ok := i.expectedChecksumFunc(i.requestedVersion)
	if !ok {
		return fmt.Errorf("requested driver %q is not supported", i.requestedVersion)
	}

	wantChecksum, err := c.Checksum()
	if err != nil {
		return fmt.Errorf("failed to get checksum for driver %q: %v", i.requestedVersion, err)
	}

	if gotChecksum != wantChecksum {
		return fmt.Errorf("driver %q checksum mismatch: got %q, want %q", i.requestedVersion, gotChecksum, wantChecksum)
	}
	return nil
}

func getCurrentDriver() (nvconf.DriverVersion, error) {
	_, err := os.Stat(nvidiaSMIPath)
	// If the nvidia-smi executable does not exist, then we don't have a driver installed.
	if os.IsNotExist(err) {
		return nvconf.DriverVersion{}, fmt.Errorf("nvidia-smi does not exist at path: %q", nvidiaSMIPath)
	}
	if err != nil {
		return nvconf.DriverVersion{}, fmt.Errorf("failed to stat nvidia-smi: %w", err)
	}
	out, err := exec.Command(nvidiaSMIPath, []string{"--query-gpu", "driver_version", "--format=csv,noheader"}...).CombinedOutput()
	if err != nil {
		log.Warningf("failed to run nvidia-smi: %v", err)
		return nvconf.DriverVersion{}, fmt.Errorf("failed to run nvidia-smi: %w", err)
	}
	// If there are multiple GPUs, there will be one version per line.
	// Make sure they are all the same version.
	sameVersion := ""
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if sameVersion == "" {
			sameVersion = line
			continue
		}
		if line != sameVersion {
			return nvconf.DriverVersion{}, fmt.Errorf("multiple driver versions found: %q and %q", sameVersion, line)
		}
	}
	if sameVersion == "" {
		return nvconf.DriverVersion{}, fmt.Errorf("no driver version found")
	}
	return nvconf.DriverVersionFrom(sameVersion)
}

// ListSupportedDrivers prints the driver to stderr in a format that can be
// consumed by the Makefile to iterate tests across drivers.
func ListSupportedDrivers(outfile string) error {
	out := os.Stdout
	if outfile != "" {
		f, err := os.OpenFile(outfile, os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open outfile: %w", err)
		}
		defer f.Close()
		out = f
	}

	var list []string
	nvproxy.ForEachSupportDriver(func(version nvconf.DriverVersion, _ nvproxy.Checksums) {
		list = append(list, version.String())
	})
	sort.Strings(list)
	if _, err := out.WriteString(strings.Join(list, " ") + "\n"); err != nil {
		return fmt.Errorf("failed to write to outfile: %w", err)
	}
	return nil
}

// ChecksumDriver downloads and returns the SHA265 checksum of the driver.
func (i *Installer) ChecksumDriver(ctx context.Context, arch string) (string, error) {
	f, err := DownloadDriver(ctx, i.requestedVersion.String(), arch)
	if err != nil {
		return "", fmt.Errorf("failed to download driver: %w", err)
	}
	checksum := sha256.New()
	for {
		n, err := io.Copy(checksum, f)
		if err == io.EOF || n == 0 {
			break
		}
		if err != nil {
			return "", fmt.Errorf("failed to copy driver: %w", err)
		}
	}
	return fmt.Sprintf("%x", checksum.Sum(nil)), nil
}

// DownloadDriver downloads the requested driver and returns the binary as a []byte so it can be
// checked before written to disk.
func DownloadDriver(ctx context.Context, driverVersion, arch string) (io.ReadCloser, error) {
	url := getNvidiaBaseURL(driverVersion, arch)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download driver: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download driver with statusCode: %d: status: %s", resp.StatusCode, resp.Status)
	}
	return resp.Body, nil
}

func installDriver(driverPath string) error {
	// Certain VMs can be broken if we attempt to install drivers on them. Do a simple check of the
	// PCI device to ensure we have a GPU attached.
	out, err := exec.Command("lspci").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to run lspci: %w out: %s", err, string(out))
	}
	if !strings.Contains(string(out), "NVIDIA") {
		return fmt.Errorf("no NVIDIA PCI device on host:\n%s", string(out))
	}

	driverArgs := strings.Split("--dkms -a -s --no-drm --install-libglvnd -m=kernel-open", " ")
	cmd := exec.Command(driverPath, driverArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if osIsUbuntu2204() {
		// As of this writing (2024), current Ubuntu 22.04 kernels are built
		// with gcc-12, but Ubuntu 22.04 defaults to gcc-11, so unless we force
		// the former, building the kernel driver will fail with
		// `cc: error: unrecognized command-line option '-ftrivial-auto-var-init=zero'`.
		cmd.Env = append(cmd.Environ(), "CC=/usr/bin/gcc-12")
	}
	if err := cmd.Run(); err != nil {
		tryToPrintFailureLogs()
		return fmt.Errorf("failed to run nvidia-install: %w out: %s", err, string(out))
	}

	cmd = exec.Command(nvidiaSMIPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run nvidia-smi post install: %w out: %s", err, string(out))
	}
	return nil
}

func tryToPrintFailureLogs() {
	// nvidia driver installers print failure logs to this path.
	const logPath = "/var/log/nvidia-installer.log"
	f, err := os.OpenFile(logPath, os.O_RDONLY, 0644)
	if err != nil {
		log.Warningf("failed to stat nvidia-installer.log: %v", err)
		return
	}
	defer f.Close()

	out, err := io.ReadAll(f)
	if err != nil {
		log.Warningf("failed to read nvidia-installer.log: %v", err)
		return
	}

	for _, line := range strings.Split(string(out), "\n") {
		fmt.Printf("[nvidia-installer]: %s\n", line)
	}
}

// ValidateChecksum validates the checksum of the driver.
func ValidateChecksum(ctx context.Context, version string, checksums nvproxy.Checksums) error {
	for _, arch := range []string{archAMD64, archARM64} {
		wantChecksum := checksums.X86_64()
		if arch == archARM64 {
			wantChecksum = checksums.Arm64()
		}
		installer, err := NewInstaller(version, false)
		if err != nil {
			return fmt.Errorf("failed to create installer for driver %q: %v", version, err)
		}
		gotChecksum, err := installer.ChecksumDriver(ctx, arch)
		if wantChecksum == nvproxy.ChecksumNoDriver {
			log.Infof("Runfile does not exist for driver %q arch: %q", version, arch)
			if err == nil || !strings.Contains(err.Error(), "failed to download driver with statusCode: 404") {
				return fmt.Errorf("checksum mismatch for driver %q: got %q, want %q", version, gotChecksum, wantChecksum)
			}
			return nil
		}
		log.Infof("Checksum for driver %q arch: %q: %q", version, arch, gotChecksum)
		if err != nil {
			return fmt.Errorf("failed to get checksum for driver %q: %v", version, err)
		}
		if gotChecksum != wantChecksum {
			return fmt.Errorf("checksum mismatch for driver %q: got %q, want %q", version, gotChecksum, wantChecksum)
		}
	}
	return nil
}

func osIsUbuntu2204() bool {
	m, err := getOSRelease()
	if err != nil {
		log.Warningf("Failed to determine Linux distribution: %v", err)
		return false
	}
	return m["ID"] == "ubuntu" && m["VERSION_ID"] == "22.04"
}

func getOSRelease() (map[string]string, error) {
	const path = "/etc/os-release"
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", path, err)
	}
	m := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		if kv := strings.SplitN(line, "=", 2); len(kv) == 2 {
			m[kv[0]] = strings.Trim(kv[1], "\"")
		}
	}
	return m, nil
}
