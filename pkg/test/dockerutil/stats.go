// Copyright 2022 The gVisor Authors.
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

package dockerutil

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/runsc/cgroup"
)

const (
	clockTicksPerSecond  = 100
	nanoSecondsPerSecond = 1e9
	cgroupPath           = "/sys/fs/cgroup"
)

func containerCpuUsage(id string) (uint64, error) {
	var path string
	var value uint64

	useSystemd, err := UsingSystemdCgroup()
	if err != nil {
		return 0, fmt.Errorf("check systemd cgroup failed: %v", err)
	}

	if cgroup.IsOnlyV2() {
		path = filepath.Join(cgroupPath, "docker", id, "cpu.stat")
		if useSystemd {
			path = filepath.Join(cgroupPath, "system.slice/docker-"+id+".scope", "cpu.stat")
		}

		content, err := ioutil.ReadFile(path)
		if err != nil {
			return 0, err
		}

		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			parts := strings.Fields(line)
			if parts[0] == "usage_usec" {
				value, err = strconv.ParseUint(parts[1], 10, 64)
				if err != nil {
					return 0, fmt.Errorf("Unable to convert value %s to uint64: %s", parts[1], err)
				}
			}
		}

		return value * 1000, nil
	}

	path = filepath.Join(cgroupPath, "cpu/docker", id, "cpuacct.usage")
	if useSystemd {
		path = filepath.Join(cgroupPath, "cpu/system.slice/docker-"+id+".scope", "cpuacct.usage")
	}

	content, err := ioutil.ReadFile(path)
	if err != nil {
		return 0, err
	}
	value, err = strconv.ParseUint(strings.TrimSuffix(string(content), "\n"), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("Unable to convert value %s to uint64: %s", string(content), err)
	}
	return value, nil
}

func systemStatTime() (uint64, error) {
	content, err := ioutil.ReadFile("/proc/stat")
	if err != nil {
		return 0, err
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		switch parts[0] {
		case "cpu":
			if len(parts) < 8 {
				return 0, fmt.Errorf("invalid number of cpu fields")
			}
			var totalClockTicks uint64
			for _, i := range parts[1:8] {
				v, err := strconv.ParseUint(i, 10, 64)
				if err != nil {
					return 0, fmt.Errorf("Unable to convert value %s to int: %s", i, err)
				}
				totalClockTicks += v
			}
			return (totalClockTicks * nanoSecondsPerSecond) /
				clockTicksPerSecond, nil
		}
	}
	return 0, fmt.Errorf("invalid stat format. Error trying to parse the '/proc/stat' file")
}
