// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cgroup

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"

	systemdDbus "github.com/coreos/go-systemd/v22/dbus"
	dbus "github.com/godbus/dbus/v5"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// ErrBadResourceSpec indicates that a cgroupSystemd function was
// passed a specs.LinuxResources object that is impossible or illegal
// to process.
var ErrBadResourceSpec = errors.New("misconfigured resource spec")

// cgroupSystemd represents a cgroup managed by systemd.
type cgroupSystemd struct {
	// Name is the name of the of the systemd scope that controls the cgroups.
	Name string `json:"name"`
	// Mountpoint is the unified mount point of cgroupV2.
	Mountpoint string `json:"mountpoint"`
	// Path is the relative path to the unified mountpoint.
	Path string `json:"path"`
	// Controllers is the list of supported controllers.
	Controllers []string `json:"controllers"`
	// OwnedPaths is the list of owned paths created when installing this cgroup.
	OwnedPaths []string `json:"owned_paths"`

	properties []systemdDbus.Property
	dbusConn   *systemdDbus.Conn
}

// Install creates and configures a scope unit with the specified resource
// limits.
func (c *cgroupSystemd) Install(res *specs.LinuxResources) error {
	slice := path.Base(c.Path)
	ext := path.Ext(slice)
	if ext != ".slice" {
		return fmt.Errorf("invalid systemd path %s does not end in a parent slice: %w", c.Path, ErrInvalidGroupPath)
	}
	c.properties = append(c.properties, systemdDbus.PropSlice(slice))
	c.properties = append(c.properties, systemdDbus.PropDescription("runsc container "+c.Name))
	pid := os.Getpid()
	c.properties = append(c.properties, systemdDbus.PropPids(uint32(pid)))
	// We always want proper accounting for the container for reporting resource
	// usage.
	c.addProp("MemoryAccounting", true)
	c.addProp("CPUAccounting", true)
	c.addProp("TasksAccounting", true)
	c.addProp("IOAccounting", true)
	// Delegate must be true so that the container can manage its own cgroups.
	c.addProp("Delegate", true)
	return c.genResourceControl(res)
}

// MakePath builds a path to the given controller.
func (c *cgroupSystemd) MakePath(string) string {
	return filepath.Join(c.Mountpoint, c.Path)
}

func (c *cgroupSystemd) genResourceControl(res *specs.LinuxResources) error {
	if res == nil {
		return nil
	}
	var (
		mem = res.Memory
		cpu = res.CPU
		io  = res.BlockIO
	)
	if res.Pids != nil {
		c.addProp("TasksMax", res.Pids.Limit)
	}
	if mem != nil {
		if mem.Swap != nil {
			if mem.Limit == nil {
				return ErrBadResourceSpec
			}
			swap, err := convertMemorySwapToCgroupV2Value(*mem.Swap, *mem.Limit)
			if err != nil {
				return err
			}
			c.addProp("MemorySwapMax", strconv.FormatInt(swap, 10))
		}
		if mem.Limit != nil {
			c.addProp("MemoryMax", *mem.Limit)
		}
		if mem.Reservation != nil {
			c.addProp("MemoryLow", *mem.Reservation)
		}
	}
	if cpu != nil {
		if cpu.Shares != nil {
			weight := convertCPUSharesToCgroupV2Value(*cpu.Shares)
			if weight != 0 {
				c.addProp("CPUShares", weight)
			}
		}

		if cpu.Quota != nil && *cpu.Quota > 0 {
			c.addProp("CPUQuota", strconv.FormatInt(*cpu.Quota, 10)+"%")
		}
		var period uint64
		if cpu.Period != nil && *cpu.Period != 0 {
			period = *cpu.Period
		} else {
			period = defaultPeriod
		}
		// period is in microseconds, so we have to divide by 10 to convert
		// to the milliseconds that systemd expects.
		c.addProp("CPUQuotaPeriodSec", strconv.FormatUint(period/10, 10)+"ms")
		if cpu.Cpus != "" {
			c.addProp("AllowedCPUs", cpu.Cpus)
		}
		if cpu.Mems != "" {
			c.addProp("AllowedMemoryNodes", cpu.Mems)
		}
	}
	if io != nil {
		if io.Weight != nil {
			c.addProp("IOWeight", *io.Weight)
		}
		for _, dev := range io.WeightDevice {
			val := fmt.Sprintf("%d:%d %d", dev.Major, dev.Minor, *dev.Weight)
			c.addProp("IODevice", val)
		}
		c.addIOProps("IOReadBandwidth", io.ThrottleReadBpsDevice)
		c.addIOProps("IOWriteBandwidth", io.ThrottleWriteBpsDevice)
		c.addIOProps("IOReadIOPS", io.ThrottleReadIOPSDevice)
		c.addIOProps("IOWriteIOPS", io.ThrottleWriteIOPSDevice)
	}
	return nil
}

func (c *cgroupSystemd) addIOProps(name string, devs []specs.LinuxThrottleDevice) {
	for _, dev := range devs {
		val := fmt.Sprintf("%d:%d %d", dev.Major, dev.Minor, dev.Rate)
		c.addProp(name, val)
	}
}

func (c *cgroupSystemd) addProp(name string, value interface{}) {
	if value == nil {
		return
	}
	c.properties = append(c.properties, newProp(name, value))
}

func newProp(name string, units interface{}) systemdDbus.Property {
	return systemdDbus.Property{
		Name:  name,
		Value: dbus.MakeVariant(units),
	}
}
