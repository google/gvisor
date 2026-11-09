// Copyright 2026 The gVisor Authors.
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

package nvconf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/log"
)

// MIGCapability describes an instance access capability in the host driver.
//
// +stateify savable
type MIGCapability struct {
	// Minor is the host nvidia-caps device minor.
	Minor uint32
	// Mode is the mode advertised by DeviceFileMode.
	Mode uint32
}

// HostSettings contains properties of the host Nvidia driver that must be
// observed before filter installation, or entering a chroot or pivot_root.
type HostSettings struct {
	// MIGCapabilities contains only explicitly granted GI and CI access
	// capabilities, keyed by path relative to /proc/driver/nvidia.
	MIGCapabilities map[string]MIGCapability

	// ProcDriverNvidiaParams is the contents of /proc/driver/nvidia/params.
	ProcDriverNvidiaParams string

	// If HaveFabricIMEXManagement is true, FabricIMEXManagementDevMinor is the
	// device minor number advertised in
	// /proc/driver/nvidia/capabilities/fabric-imex-mgmt.
	HaveFabricIMEXManagement     bool
	FabricIMEXManagementDevMinor uint32

	// If HaveMNCCManagement is true, MNCCManagementDevMinor is the device minor
	// number advertised in /proc/driver/nvidia/capabilities/mncc-mgmt.
	HaveMNCCManagement     bool
	MNCCManagementDevMinor uint32
}

// HostSettingsOptions holds arguments to GetHostSettings.
type HostSettingsOptions struct {
	// MIGDeviceMinors contains explicitly granted host nvidia-caps minors.
	// An empty list disables MIG capability discovery.
	MIGDeviceMinors []uint32

	// If WantFabricIMEXManagement is true, ensure that
	// HaveFabricIMEXManagement and FabricIMEXManagementDevMinor are set in the
	// returned HostSettings.
	WantFabricIMEXManagement bool
}

// GetHostSettings returns HostSettings.
func GetHostSettings(opts HostSettingsOptions) (*HostSettings, error) {
	settings := &HostSettings{}

	params, err := os.ReadFile("/proc/driver/nvidia/params")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/driver/nvidia/params: %w", err)
	}
	settings.ProcDriverNvidiaParams = string(params)

	if opts.WantFabricIMEXManagement {
		fabricImexMgmt, err := os.ReadFile("/proc/driver/nvidia/capabilities/fabric-imex-mgmt")
		if err != nil {
			return nil, fmt.Errorf("failed to read /proc/driver/nvidia/capabilities/fabric-imex-mgmt: %w", err)
		}
		minorRe := regexp.MustCompile(`DeviceFileMinor: (\d+)`)
		m := minorRe.FindSubmatch(fabricImexMgmt)
		if m == nil {
			return nil, fmt.Errorf("failed to find DeviceFileMinor in /proc/driver/nvidia/capabilities/fabric-imex-mgmt")
		}
		minor, err := strconv.ParseUint(string(m[1]), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DeviceFileMinor %s: %w", string(m[1]), err)
		}
		settings.HaveFabricIMEXManagement = true
		settings.FabricIMEXManagementDevMinor = uint32(minor)

		if mnccMgmt, err := os.ReadFile("/proc/driver/nvidia/capabilities/mncc-mgmt"); err == nil {
			m := minorRe.FindSubmatch(mnccMgmt)
			if m == nil {
				return nil, fmt.Errorf("failed to find DeviceFileMinor in /proc/driver/nvidia/capabilities/mncc-mgmt")
			}
			mnccMinor, err := strconv.ParseUint(string(m[1]), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("failed to parse DeviceFileMinor %s: %w", string(m[1]), err)
			}
			settings.HaveMNCCManagement = true
			settings.MNCCManagementDevMinor = uint32(mnccMinor)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("failed to read /proc/driver/nvidia/capabilities/mncc-mgmt: %w", err)
		}
	}

	if len(opts.MIGDeviceMinors) != 0 {
		settings.MIGCapabilities, err = getMIGCapabilities("/proc/driver/nvidia", opts.MIGDeviceMinors)
		if err != nil {
			return nil, err
		}
	}
	return settings, nil
}

// getMIGCapabilities reads only instance access capabilities. Global MIG
// configuration and monitoring capabilities are not instance access rights.
func getMIGCapabilities(root string, minors []uint32) (map[string]MIGCapability, error) {
	granted := make(map[uint32]bool, len(minors))
	for _, minor := range minors {
		granted[minor] = true
	}
	capabilities := make(map[string]MIGCapability)
	validPath := regexp.MustCompile(`^capabilities/gpu[0-9]+/mig/gi[0-9]+(/ci[0-9]+)?/access$`)
	for _, pattern := range []string{"capabilities/gpu*/mig/gi*/access", "capabilities/gpu*/mig/gi*/ci*/access"} {
		paths, err := filepath.Glob(filepath.Join(root, pattern))
		if err != nil {
			return nil, err
		}
		for _, path := range paths {
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return nil, err
			}
			if !validPath.MatchString(relative) {
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("reading MIG capability %s: %w", path, err)
			}
			fields := make(map[string]uint32)
			for _, line := range strings.Split(string(data), "\n") {
				key, value, ok := strings.Cut(line, ":")
				if !ok || (key != "DeviceFileMinor" && key != "DeviceFileMode") {
					continue
				}
				if _, ok := fields[key]; ok {
					return nil, fmt.Errorf("duplicate %s in %s", key, path)
				}
				parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
				if err != nil {
					return nil, fmt.Errorf("invalid %s in %s: %w", key, path, err)
				}
				fields[key] = uint32(parsed)
			}
			minor, ok := fields["DeviceFileMinor"]
			if !ok {
				return nil, fmt.Errorf("missing DeviceFileMinor in %s", path)
			}
			if !granted[minor] {
				continue
			}
			mode, ok := fields["DeviceFileMode"]
			if !ok || mode & ^uint32(0777) != 0 {
				return nil, fmt.Errorf("invalid DeviceFileMode in %s", path)
			}
			capabilities[relative] = MIGCapability{Minor: minor, Mode: mode}
		}
	}
	return capabilities, nil
}

// IMEXChannelCount returns the number of IMEX channels indicated by
// /proc/driver/nvidia/params. See description of NVreg_ImexChannelCount in the
// Nvidia GPU driver's kernel-open/nvidia/nv-reg.h.
func (s *HostSettings) IMEXChannelCount() uint32 {
	m := regexp.MustCompile(`ImexChannelCount: (\d+)`).FindStringSubmatch(s.ProcDriverNvidiaParams)
	if m == nil {
		return 0
	}
	imexChannelCount, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil {
		log.Warningf("Failed to parse ImexChannelCount %s: %v", m[1], err)
		return 0
	}
	return uint32(imexChannelCount)
}
