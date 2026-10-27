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
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
)

const (
	nvidiaSMIPath       = "/usr/bin/nvidia-smi"
	nvidiaUninstallPath = "/usr/bin/nvidia-uninstall"
)

func init() {
	nvproxy.Init()
}

// Installer installs one supported driver on the host architecture.
type Installer struct {
	requestedVersion nvconf.DriverVersion
	checksum         string
	downloader       Downloader
	tempDir          string

	getCurrentDriverFunc func(context.Context) (nvconf.DriverVersion, error)
	checkHostFunc        func(context.Context) error
	uninstallFunc        func(context.Context) error
	installFunc          func(context.Context, string) error
}

type installableDriver struct {
	version  nvconf.DriverVersion
	checksum string
}

func hostDriver(version nvconf.DriverVersion, checksums nvproxy.Checksums) (installableDriver, error) {
	unavailable, err := checksums.PublicInstallerUnavailable(runtime.GOARCH)
	if err != nil {
		return installableDriver{}, fmt.Errorf("invalid installer metadata for driver %q: %w", version, err)
	}
	if unavailable {
		return installableDriver{}, fmt.Errorf("driver %q has no public NVIDIA .run installer for arch %q", version, runtime.GOARCH)
	}
	checksum, err := checksums.Checksum()
	if err != nil {
		return installableDriver{}, fmt.Errorf("failed to get checksum for driver %q: %w", version, err)
	}
	return installableDriver{version, checksum}, nil
}

// installableDrivers is the common host-architecture selection for installation
// and listing. Registered ABIs without a public installer are excluded.
func installableDrivers() []installableDriver {
	var drivers []installableDriver
	nvproxy.ForEachSupportDriver(func(version nvconf.DriverVersion, checksums nvproxy.Checksums) {
		if driver, err := hostDriver(version, checksums); err == nil {
			drivers = append(drivers, driver)
		}
	})
	return drivers
}

// NewInstaller selects a supported, publicly installable driver for this host.
func NewInstaller(requestedVersion string, latest bool) (*Installer, error) {
	var selected installableDriver
	if latest {
		for _, driver := range installableDrivers() {
			if driver.version.IsGreaterThan(selected.version) {
				selected = driver
			}
		}
		if selected.checksum == "" {
			return nil, fmt.Errorf("no installable driver found for arch %q", runtime.GOARCH)
		}
	} else {
		version, err := nvconf.DriverVersionFrom(requestedVersion)
		if err != nil {
			return nil, fmt.Errorf("failed to parse requested driver version: %w", err)
		}
		checksums, ok := nvproxy.ExpectedDriverChecksum(version)
		if !ok {
			return nil, fmt.Errorf("requested driver %q is not supported", version)
		}
		selected, err = hostDriver(version, checksums)
		if err != nil {
			return nil, err
		}
	}
	return &Installer{
		requestedVersion:     selected.version,
		checksum:             selected.checksum,
		getCurrentDriverFunc: getCurrentDriver,
		checkHostFunc:        checkHost,
		uninstallFunc:        uninstallDriver,
		installFunc:          installDriver,
	}, nil
}

// MaybeInstall replaces an absent or different driver with the requested
// version. The replacement is downloaded and verified before any uninstall.
func (i *Installer) MaybeInstall(ctx context.Context) error {
	existingDriver, err := i.getCurrentDriverFunc(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current driver: %w", err)
	}
	if existingDriver.Equals(i.requestedVersion) {
		log.Infof("Driver already installed: %s", i.requestedVersion)
		return nil
	}
	if err := i.checkHostFunc(ctx); err != nil {
		return fmt.Errorf("host cannot install the requested driver: %w", err)
	}

	f, err := os.CreateTemp(i.tempDir, "nvidia-driver-*.run")
	if err != nil {
		return fmt.Errorf("failed to open driver file: %w", err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	log.Infof("Downloading driver: %s", i.requestedVersion)
	checksum, err := i.downloader.Download(ctx, i.requestedVersion, runtime.GOARCH, f)
	if err != nil {
		return err
	}
	if err := checkChecksum(i.requestedVersion, runtime.GOARCH, checksum, i.checksum); err != nil {
		return err
	}
	if err := f.Chmod(0755); err != nil {
		return fmt.Errorf("failed to chmod driver file: %w", err)
	}
	// An executable cannot be run while it is still open for writing.
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close driver file: %w", err)
	}
	log.Infof("Driver downloaded: %s", i.requestedVersion)

	if !existingDriver.Equals(nvconf.DriverVersion{}) {
		log.Infof("Uninstalling driver: %s", existingDriver)
		if err := i.uninstallFunc(ctx); err != nil {
			return fmt.Errorf("failed to uninstall driver: %w", err)
		}
		log.Infof("Driver uninstalled: %s", existingDriver)
	}
	log.Infof("Installing driver: %s", i.requestedVersion)
	if err := i.installFunc(ctx, f.Name()); err != nil {
		return fmt.Errorf("failed to install driver: %w", err)
	}
	log.Infof("Installation Complete!")
	return nil
}

func driverCommand(ctx context.Context, path string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

func uninstallDriver(ctx context.Context) error {
	if err := driverCommand(ctx, nvidiaUninstallPath, "-s").Run(); err != nil {
		return fmt.Errorf("failed to run nvidia-uninstall: %w", err)
	}
	return nil
}

func getCurrentDriver(ctx context.Context) (nvconf.DriverVersion, error) {
	_, err := os.Stat(nvidiaSMIPath)
	// A missing nvidia-smi is treated as no managed driver. Other inspection
	// failures must not be mistaken for absence.
	if os.IsNotExist(err) {
		return nvconf.DriverVersion{}, nil
	}
	if err != nil {
		return nvconf.DriverVersion{}, fmt.Errorf("failed to stat nvidia-smi: %w", err)
	}
	out, err := exec.CommandContext(ctx, nvidiaSMIPath, "--query-gpu", "driver_version", "--format=csv,noheader").CombinedOutput()
	if err != nil {
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

// ListSupportedDrivers prints the publicly installable drivers for this host in
// a format that can be consumed by the Makefile to iterate tests across drivers.
func ListSupportedDrivers(outfile string) error {
	var list []string
	for _, driver := range installableDrivers() {
		list = append(list, driver.version.String())
	}
	slices.Sort(list)
	data := strings.Join(list, " ") + "\n"
	var err error
	if outfile == "" {
		_, err = os.Stdout.WriteString(data)
	} else {
		err = os.WriteFile(outfile, []byte(data), 0644)
	}
	if err != nil {
		return fmt.Errorf("failed to write supported drivers: %w", err)
	}
	return nil
}

// checkHost rejects unsupported machines before downloading or uninstalling.
func checkHost(ctx context.Context) error {
	// Require an NVIDIA PCI device before modifying installed drivers.
	out, err := exec.CommandContext(ctx, "lspci").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to run lspci: %w out: %s", err, string(out))
	}
	if !strings.Contains(string(out), "NVIDIA") {
		return fmt.Errorf("no NVIDIA PCI device on host:\n%s", string(out))
	}

	return nil
}

func installDriver(ctx context.Context, driverPath string) error {
	driverArgs := []string{"--dkms", "-a", "-s", "--no-drm", "--install-libglvnd", "-m=kernel-open"}
	cmd := driverCommand(ctx, driverPath, driverArgs...)
	if osIsUbuntu2204() {
		// As of this writing (2024), current Ubuntu 22.04 kernels are built
		// with gcc-12, but Ubuntu 22.04 defaults to gcc-11, so unless we force
		// the former, building the kernel driver will fail with
		// `cc: error: unrecognized command-line option '-ftrivial-auto-var-init=zero'`.
		cmd.Env = append(cmd.Environ(), "CC=/usr/bin/gcc-12")
	}
	if err := cmd.Run(); err != nil {
		tryToPrintFailureLogs()
		return fmt.Errorf("failed to run nvidia-install: %w", err)
	}

	cmd = driverCommand(ctx, nvidiaSMIPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run nvidia-smi post install: %w", err)
	}
	return nil
}

func tryToPrintFailureLogs() {
	// nvidia driver installers print failure logs to this path.
	const logPath = "/var/log/nvidia-installer.log"
	out, err := os.ReadFile(logPath)
	if err != nil {
		log.Warningf("failed to read nvidia-installer.log: %v", err)
		return
	}

	for _, line := range strings.Split(string(out), "\n") {
		fmt.Printf("[nvidia-installer]: %s\n", line)
	}
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
