// Copyright 2026 The gVisor Authors.
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

package container

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/sentry/platform/platformdesc"
	"gvisor.dev/gvisor/runsc/cgroup"
	"gvisor.dev/gvisor/runsc/cmd/sandboxsetup"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

// sandboxDeviceRules returns the device cgroup rules for the host devices that
// runsc, the sentry and the gofer open on behalf of a container with the given
// spec.
func sandboxDeviceRules(conf *config.Config, spec *specs.Spec) ([]cgroup.DeviceRule, error) {
	rules := []cgroup.DeviceRule{
		// runsc runs in the sandbox cgroup while it spawns the sandbox processes
		// when it cannot clone them directly into the cgroup, and opens
		// /dev/null and pseudo-terminals for them.
		{Type: "c", Major: 1, Minor: 3, Access: "rw"},
		{Type: "c", Major: 5, Minor: 2, Access: "rw"},
		{Type: "c", Major: 136, Minor: cgroup.DeviceAny, Access: "rw"},
		// The gofer creates overlayfs whiteouts in overlay upper layers.
		{Type: "c", Major: 0, Minor: 0, Access: "m"},
	}
	// A device that does not exist is left to whatever opens it later, which
	// reports the error.
	add := func(path, access string) error {
		r, err := deviceRuleForPath(path, access)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		rules = append(rules, r)
		return nil
	}
	// The sentry holds /dev/cpu_dma_latency open to cap host CPU idle states.
	if err := add("/dev/cpu_dma_latency", "w"); err != nil {
		return nil, err
	}
	// runsc opens the platform's device and donates it to the sentry.
	p, err := platformdesc.Lookup(conf.Platform)
	if err != nil {
		return nil, err
	}
	if p.Device != "" {
		path := conf.PlatformDeviceFor(conf.Platform)
		if path == "" {
			path = p.Device
		}
		if err := add(path, "rw"); err != nil {
			return nil, err
		}
	}
	// The gofer opens the devices that the sentry proxies to the container.
	for _, dev := range sandboxsetup.ExposedDevices(spec, conf) {
		if err := add(dev.Path, "rw"); err != nil {
			return nil, err
		}
	}
	if specutils.GPUFunctionalityRequestedViaHook(spec, conf) {
		// nvidia-container-cli, which may run in the sandbox cgroup, creates
		// the device files for the GPUs visible to the container inside its
		// rootfs, where the image can forge them. Allow the NVIDIA drivers'
		// devices by major number instead.
		majors, err := nvidiaCharMajors()
		if err != nil {
			return nil, err
		}
		for _, major := range majors {
			rules = append(rules, cgroup.DeviceRule{Type: "c", Major: major, Minor: cgroup.DeviceAny, Access: "rwm"})
		}
	}
	return rules, nil
}

func deviceRuleForPath(path, access string) (cgroup.DeviceRule, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return cgroup.DeviceRule{}, fmt.Errorf("stat(%q): %w", path, err)
	}
	r := cgroup.DeviceRule{
		Major:  int64(unix.Major(st.Rdev)),
		Minor:  int64(unix.Minor(st.Rdev)),
		Access: access,
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFCHR:
		r.Type = "c"
	case unix.S_IFBLK:
		r.Type = "b"
	default:
		return r, fmt.Errorf("%q is not a device", path)
	}
	return r, nil
}

// nvidiaCharMajors returns the character device major numbers of the NVIDIA
// drivers whose devices nvproxy exposes.
func nvidiaCharMajors() ([]int64, error) {
	f, err := os.Open("/proc/devices")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// The frontend driver's major number is fixed; the other drivers' are
	// allocated dynamically.
	majors, err := parseCharMajors(f, []string{"nvidia-uvm", "nvidia-caps", "nvidia-caps-imex-channels"})
	if err != nil {
		return nil, err
	}
	return append([]int64{nvgpu.NV_MAJOR_DEVICE_NUMBER}, majors...), nil
}

// parseCharMajors returns the major numbers of the named character devices
// listed in /proc/devices.
func parseCharMajors(r io.Reader, names []string) ([]int64, error) {
	var majors []int64
	chars := false
	s := bufio.NewScanner(r)
	for s.Scan() {
		line := s.Text()
		if strings.HasSuffix(line, "devices:") {
			chars = line == "Character devices:"
			continue
		}
		fields := strings.Fields(line)
		if !chars || len(fields) != 2 || !slices.Contains(names, fields[1]) {
			continue
		}
		major, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing /proc/devices line %q: %w", line, err)
		}
		majors = append(majors, major)
	}
	return majors, s.Err()
}

// allowSandboxDevices extends the sandbox's device cgroup with the host devices
// that c's spec exposes.
func (c *Container) allowSandboxDevices(conf *config.Config) error {
	cg := c.Sandbox.CgroupJSON.Cgroup
	if cg == nil {
		return nil
	}
	rules, err := sandboxDeviceRules(conf, c.Spec)
	if err != nil {
		return err
	}
	if err := cg.AllowDevices(rules); err != nil {
		return handleCgroupInstallErr(conf, "device cgroup", err)
	}
	return nil
}
