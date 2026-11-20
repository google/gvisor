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
	"bufio"
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

	return settings, nil
}

// GetMIGCapabilities resolves explicitly granted nvidia-caps minors to MIG
// instance access records. Global configuration and monitoring capabilities
// do not grant access to an instance.
func GetMIGCapabilities(minors []uint32) (map[string]MIGCapability, error) {
	return getMIGCapabilities("/proc/driver", minors)
}

func getMIGCapabilities(root string, minors []uint32) (map[string]MIGCapability, error) {
	if len(minors) == 0 {
		return nil, nil
	}
	indexPath := filepath.Join(root, "nvidia-caps/mig-minors")
	index, err := os.Open(indexPath)
	if errors.Is(err, os.ErrNotExist) {
		// Hosts without a MIG index can still expose other nvidia-caps devices.
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("opening MIG capability index %q: %w", indexPath, err)
	}
	defer index.Close()

	granted := make(map[uint32]struct{}, len(minors))
	for _, minor := range minors {
		granted[minor] = struct{}{}
	}
	capabilities := make(map[string]MIGCapability, len(granted))
	matched := make(map[uint32]string, len(granted))
	validEntry := regexp.MustCompile(`^gpu[0-9]+/gi[0-9]+(/ci[0-9]+)?/access$`)
	scanner := bufio.NewScanner(index)
	for scanner.Scan() {
		entry, minorText, ok := strings.Cut(scanner.Text(), " ")
		if !ok {
			continue
		}
		value, err := strconv.ParseUint(strings.TrimSpace(minorText), 10, 32)
		if err != nil {
			continue
		}
		minor := uint32(value)
		if _, ok := granted[minor]; !ok || !validEntry.MatchString(entry) {
			continue
		}
		// The index includes possible instances that have no access record.
		// Read only the records for the requested minors.
		gpu, instance, _ := strings.Cut(entry, "/")
		relative := "capabilities/" + gpu + "/mig/" + instance
		if previous, ok := matched[minor]; ok {
			return nil, fmt.Errorf("MIG capability index maps minor %d to both %q and %q", minor, previous, relative)
		}
		path := filepath.Join(root, "nvidia", relative)
		capability, err := readMIGCapability(path)
		if err != nil {
			return nil, fmt.Errorf("reading assigned MIG capability minor %d at %q: %w", minor, path, err)
		}
		if capability.Minor != minor {
			return nil, fmt.Errorf("assigned MIG capability at %q advertises minor %d, want %d from the index", path, capability.Minor, minor)
		}
		matched[minor] = relative
		capabilities[relative] = capability
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading MIG capability index %q: %w", indexPath, err)
	}
	return capabilities, nil
}

func readMIGCapability(path string) (MIGCapability, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return MIGCapability{}, err
	}
	fields := make(map[string]uint32, 2)
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || (key != "DeviceFileMinor" && key != "DeviceFileMode") {
			continue
		}
		if _, ok := fields[key]; ok {
			return MIGCapability{}, fmt.Errorf("duplicate %s", key)
		}
		parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
		if err != nil {
			return MIGCapability{}, fmt.Errorf("invalid %s: %w", key, err)
		}
		fields[key] = uint32(parsed)
	}
	minor, ok := fields["DeviceFileMinor"]
	if !ok {
		return MIGCapability{}, fmt.Errorf("missing DeviceFileMinor")
	}
	mode, ok := fields["DeviceFileMode"]
	if !ok || mode > 0777 {
		return MIGCapability{}, fmt.Errorf("invalid DeviceFileMode")
	}
	return MIGCapability{Minor: minor, Mode: mode}, nil
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
