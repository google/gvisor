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

	// If HaveTraceDevice is true, TraceDeviceDevMinor is the device minor
	// number advertised in /proc/driver/nvidia/capabilities/trace-device.
	// This capability gates allocation of TRACE_DEVICE_EVENT, which only
	// exists in driver versions >= 610.43.02, so hosts running older drivers
	// legitimately lack it.
	HaveTraceDevice     bool
	TraceDeviceDevMinor uint32
}

// HostSettingsOptions holds arguments to GetHostSettings.
type HostSettingsOptions struct {
	// If WantFabricIMEXManagement is true, ensure that
	// HaveFabricIMEXManagement and FabricIMEXManagementDevMinor are set in the
	// returned HostSettings.
	WantFabricIMEXManagement bool

	// If WantTraceDevice is true, set HaveTraceDevice and TraceDeviceDevMinor
	// in the returned HostSettings if the host driver advertises the
	// trace-device capability. Unlike WantFabricIMEXManagement, the capability
	// being unavailable is not an error, since it does not exist in driver
	// versions < 610.43.02.
	WantTraceDevice bool
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
		minor, err := capabilityDevMinor("fabric-imex-mgmt")
		if err != nil {
			return nil, err
		}
		settings.HaveFabricIMEXManagement = true
		settings.FabricIMEXManagementDevMinor = minor
	}

	if opts.WantTraceDevice {
		minor, err := capabilityDevMinor("trace-device")
		if err != nil {
			// The trace-device capability was added in driver version
			// 610.43.02; older drivers do not have it. Applications that
			// require it will fail when allocating TRACE_DEVICE_EVENT, which
			// is the same behavior as on the host.
			log.Infof("nvproxy: trace-device capability is unavailable: %v", err)
		} else {
			settings.HaveTraceDevice = true
			settings.TraceDeviceDevMinor = minor
		}
	}

	return settings, nil
}

// deviceFileMinorRE matches the DeviceFileMinor line in files under
// /proc/driver/nvidia/capabilities/, as written by
// kernel-open/nvidia/nv-caps.c:nv_cap_procfs_read().
var deviceFileMinorRE = regexp.MustCompile(`DeviceFileMinor: (\d+)`)

// capabilityDevMinor returns the device minor number in /dev/nvidia-caps/ that
// corresponds to the capability named by the given file in
// /proc/driver/nvidia/capabilities/.
func capabilityDevMinor(name string) (uint32, error) {
	path := "/proc/driver/nvidia/capabilities/" + name
	contents, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("failed to read %s: %w", path, err)
	}
	m := deviceFileMinorRE.FindSubmatch(contents)
	if m == nil {
		return 0, fmt.Errorf("failed to find DeviceFileMinor in %s", path)
	}
	minor, err := strconv.ParseUint(string(m[1]), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("failed to parse DeviceFileMinor %s in %s: %w", string(m[1]), path, err)
	}
	return uint32(minor), nil
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
