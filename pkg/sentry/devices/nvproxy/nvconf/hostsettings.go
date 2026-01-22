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
	"fmt"
	"os"
	"regexp"
	"strconv"

	"gvisor.dev/gvisor/pkg/log"
)

// HostSettings contains properties of the host Nvidia driver that must be
// observed before filter installation, or entering a chroot or pivot_root.
type HostSettings struct {
	// ProcDriverNvidiaParams is the contents of /proc/driver/nvidia/params.
	ProcDriverNvidiaParams string

	// If HaveFabricIMEXManagement is true, FabricIMEXManagementDevMinor is the
	// device minor number advertised in
	// /proc/driver/nvidia/capabilities/fabric-imex-mgmt.
	HaveFabricIMEXManagement     bool
	FabricIMEXManagementDevMinor uint32
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
		m := regexp.MustCompile(`DeviceFileMinor: (\d+)`).FindSubmatch(fabricImexMgmt)
		if m == nil {
			return nil, fmt.Errorf("failed to find DeviceFileMinor in /proc/driver/nvidia/capabilities/fabric-imex-mgmt")
		}
		minor, err := strconv.ParseUint(string(m[1]), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DeviceFileMinor %s: %w", string(m[1]), err)
		}
		settings.HaveFabricIMEXManagement = true
		settings.FabricIMEXManagementDevMinor = uint32(minor)
	}

	return settings, nil
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
