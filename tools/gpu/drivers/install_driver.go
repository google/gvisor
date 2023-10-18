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
	"strings"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
)

const (
	nvidiaSMIPath       = "/usr/bin/nvidia-smi"
	nvidiaUninstallPath = "/usr/bin/nvidia-uninstall"
	nvidiaBaseURL       = "https://us.download.nvidia.com/tesla/"
)

func init() {
	nvproxy.Init()
}

// Installer handles the logic to install drivers.
type Installer struct {
	requestedVersion nvproxy.DriverVersion
	// include functions so they can be mocked in tests.
	getSupportedDriverFunc func() map[nvproxy.DriverVersion]string
	getCurrentDriverFunc   func() (nvproxy.DriverVersion, error)
	downloadFunction       func(context.Context, string) (io.ReadCloser, error)
	installFunction        func(string) error
}

// NewInstaller returns a driver installer instance.
func NewInstaller(requestedVersion string, latest bool) (*Installer, error) {
	ret := &Installer{
		getSupportedDriverFunc: nvproxy.GetSupportedDriversAndChecksums,
		getCurrentDriverFunc:   getCurrentDriver,
		downloadFunction:       DownloadDriver,
		installFunction:        installDriver,
	}
	switch {
	case latest:
		for v := range ret.getSupportedDriverFunc() {
			ret.requestedVersion = v.IsGreaterThan(ret.requestedVersion)
		}
	default:
		d, err := nvproxy.DriverVersionFrom(requestedVersion)
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
	driver, supported := i.getRequestedDriver()
	if !supported {
		return fmt.Errorf("requested driver %q is not supported", i.requestedVersion)
	}

	existingDriver, err := i.getCurrentDriverFunc()
	if err != nil {
		log.Warningf("failed to get current driver: %v", err)
	}
	if existingDriver.Equals(driver) {
		log.Infof("Driver already installed: %s", i.requestedVersion)
		return nil
	}

	if !existingDriver.Equals(nvproxy.DriverVersion{}) {
		log.Infof("Uninstalling driver: %s", existingDriver)
		if err := i.uninstallDriver(ctx, existingDriver.String()); err != nil {
			return fmt.Errorf("failed to uninstall driver: %w", err)
		}
		log.Infof("Driver uninstalled: %s", i.requestedVersion)
	}

	log.Infof("Downloading driver: %s", i.requestedVersion)
	reader, err := i.downloadFunction(ctx, i.requestedVersion.String())
	if err != nil {
		return fmt.Errorf("failed to download driver: %w", err)
	}

	f, err := os.CreateTemp("", "")
	if err != nil {
		return fmt.Errorf("failed to open driver file: %w", err)
	}
	defer os.Remove(f.Name())
	if err := i.writeAndCheck(f, reader, driver); err != nil {
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
	if err := i.installFunction(f.Name()); err != nil {
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

func (i *Installer) writeAndCheck(f *os.File, reader io.ReadCloser, driverVersion nvproxy.DriverVersion) error {
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
	wantChecksum := i.getSupportedDriverFunc()[driverVersion]
	if gotChecksum != wantChecksum {
		return fmt.Errorf("driver %q checksum mismatch: got %q, want %q", driverVersion, gotChecksum, wantChecksum)
	}
	return nil
}

func getCurrentDriver() (nvproxy.DriverVersion, error) {
	_, err := os.Stat(nvidiaSMIPath)
	// If the nvidia-smi executable does not exist, then we don't have a driver installed.
	if os.IsNotExist(err) {
		return nvproxy.DriverVersion{}, fmt.Errorf("nvidia-smi does not exist at path: %q", nvidiaSMIPath)
	}
	if err != nil {
		return nvproxy.DriverVersion{}, fmt.Errorf("failed to stat nvidia-smi: %w", err)
	}
	out, err := exec.Command(nvidiaSMIPath, []string{"--query-gpu", "driver_version", "--format=csv,noheader"}...).CombinedOutput()
	if err != nil {
		log.Warningf("failed to run nvidia-smi: %v", err)
		return nvproxy.DriverVersion{}, fmt.Errorf("failed to run nvidia-smi: %w", err)
	}
	return nvproxy.DriverVersionFrom(strings.TrimSpace(string(out)))
}

func (i *Installer) getRequestedDriver() (nvproxy.DriverVersion, bool) {
	for version := range i.getSupportedDriverFunc() {
		if version == i.requestedVersion {
			return version, true
		}
	}
	return nvproxy.DriverVersion{}, false
}

// ListSupportedDrivers prints the driver to stderr in a format that can be
// consumed by the Makefile to iterate tests across drivers.
func ListSupportedDrivers() {
	supportedDrivers := nvproxy.GetSupportedDriversAndChecksums()
	list := make([]string, 0, len(supportedDrivers))
	for version := range nvproxy.GetSupportedDriversAndChecksums() {
		list = append(list, version.String())
	}
	fmt.Println(strings.Join(list, " "))
}

// ChecksumDriver downloads and returns the SHA265 checksum of the driver.
func ChecksumDriver(ctx context.Context, driverVersion string) (string, error) {
	f, err := DownloadDriver(ctx, driverVersion)
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
func DownloadDriver(ctx context.Context, driverVersion string) (io.ReadCloser, error) {
	url := fmt.Sprintf("%s%s/NVIDIA-Linux-x86_64-%s.run", nvidiaBaseURL, driverVersion, driverVersion)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download driver: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download driver with status: %w", err)
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

	driverArgs := strings.Split("--dkms -a -s --no-drm --install-libglvnd", " ")
	cmd := exec.Command(driverPath, driverArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	/*
		cmd.Env = append(os.Environ(),
			"IGNORE_CC_MISMATCH=1",
			"LLVM=1",
			"LLVM_IS=1",
		)
	*/
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run nvidia-install: %w out: %s", err, string(out))
	}

	cmd = exec.Command(nvidiaSMIPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run nvidia-install: %w out: %s", err, string(out))
	}
	return nil
}
