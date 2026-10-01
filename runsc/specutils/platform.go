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

package specutils

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/runsc/config"
)

// hostEnv holds the host and workload properties that --platform=auto uses to
// choose a platform.
type hostEnv struct {
	// inVM is true inside a virtual machine.
	inVM bool
	// hasGPU is true if the container uses NVIDIA GPUs.
	hasGPU bool
}

// String implements fmt.Stringer.
func (e hostEnv) String() string {
	return fmt.Sprintf("in VM: %t, GPU: %t", e.inVM, e.hasGPU)
}

// autoPlatform is a platform that --platform=auto may choose. autoPlatforms
// lists them, most preferred first.
type autoPlatform struct {
	// name is the platform name, as given to --platform.
	name string
	// allowed returns why the platform does not suit env, or nil if it does.
	// It is nil if the platform suits every host.
	allowed func(hostEnv) error
	// device is the device file that the platform opens. It is empty if the
	// platform needs no device file.
	device string
}

// kvmAllowed skips KVM inside a VM, where it needs nested virtualization, and
// for GPU workloads, where cudaMallocManaged() is flaky on KVM (see
// gvisor.dev/docs/user_guide/gpu/#platforms).
func kvmAllowed(e hostEnv) error {
	switch {
	case e.inVM:
		return errors.New("inside a VM")
	case e.hasGPU:
		return errors.New("GPU workload")
	}
	return nil
}

// probeFunc returns nil if platform p can run on this host, or the reason it
// cannot.
type probeFunc func(p autoPlatform) error

// fallbackPlatform is the platform that --platform=auto uses when no platform
// in autoPlatforms qualifies.
const fallbackPlatform = "systrap"

// ResolvePlatform replaces --platform=auto in conf with the best platform for
// this host and spec, and sets conf.PlatformDevicePath to its device file. If
// no platform qualifies, it warns and uses systrap. spec may be nil.
//
// cli.Main calls ResolvePlatform for every runsc command. Code that skips
// cli.Main, such as tests, must call it.
func ResolvePlatform(conf *config.Config, spec *specs.Spec) error {
	if conf.Platform != config.PlatformAuto {
		return nil
	}
	if conf.PlatformDevicePath != "" {
		return fmt.Errorf("--platform_device_path cannot be used with --platform=%s", config.PlatformAuto)
	}
	env := detectHostEnv(usesGPU(spec, conf))
	name, device, skipped := choosePlatform(env, probePlatform)
	if name == "" {
		log.Warningf("--platform=%s found no usable platform (%v): %s; using %q", config.PlatformAuto, env, strings.Join(skipped, "; "), fallbackPlatform)
		name = fallbackPlatform
	} else {
		log.Infof("--platform=%s chose %q with device %q (%v, skipped: %q)", config.PlatformAuto, name, device, env, skipped)
	}
	conf.Platform = name
	conf.PlatformDevicePath = device
	return nil
}

// detectHostEnv returns the hostEnv for this host. hasGPU reports whether the
// container uses NVIDIA GPUs.
func detectHostEnv(hasGPU bool) hostEnv {
	return hostEnv{
		inVM:   inVM(),
		hasGPU: hasGPU,
	}
}

// usesGPU reports whether the sandbox uses NVIDIA GPUs. spec is nil for
// commands that do not operate on a container; --nvproxy still counts then.
func usesGPU(spec *specs.Spec, conf *config.Config) bool {
	return conf.NVProxy || (spec != nil && NVProxyEnabled(spec, conf))
}

// choosePlatform returns the first platform in autoPlatforms that env allows
// and that passes probe, with its device file. It returns "" if no platform
// qualifies. It also returns why each earlier platform was skipped.
func choosePlatform(env hostEnv, probe probeFunc) (name, device string, skipped []string) {
	for _, p := range autoPlatforms {
		if p.allowed != nil {
			if err := p.allowed(env); err != nil {
				skipped = append(skipped, fmt.Sprintf("%s: %v", p.name, err))
				continue
			}
		}
		if err := probe(p); err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", p.name, err))
			continue
		}
		return p.name, p.device, skipped
	}
	return "", "", skipped
}

// probePlatform implements probeFunc. The platform must be linked into this
// binary and its device file, if any, must open read-write. It avoids the
// platform's OpenDevice, which may change the host (e.g. load a kernel module).
func probePlatform(p autoPlatform) error {
	if _, err := platform.Lookup(p.name); err != nil {
		return err
	}
	if p.device == "" {
		return nil
	}
	f, err := os.OpenFile(p.device, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	return f.Close()
}

// inVM reports whether runsc runs inside a virtual machine. Either of two
// vendor-neutral signs is enough:
//   - The x86 "hypervisor" CPU flag (CPUID leaf 1, ECX bit 31), which
//     hypervisors set to tell a guest that it runs in a VM.
//   - The SMBIOS "virtual machine" bit, which VM firmware on any architecture
//     can set. Reading the SMBIOS table needs root.
//
// A missing sign proves nothing: arm64 has no such CPU flag, and some VM
// firmware leaves the SMBIOS bit unset.
func inVM() bool {
	// /proc/cpuinfo is read directly because the cpuid package is not
	// initialized at this point.
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil && hypervisorFlagSet(string(b)) {
		return true
	}
	b, err := os.ReadFile("/sys/firmware/dmi/tables/DMI")
	return err == nil && smbiosVMBitSet(b)
}

// hypervisorFlagSet reports whether the first "flags" line in cpuinfo, the
// contents of /proc/cpuinfo, lists the "hypervisor" flag.
func hypervisorFlagSet(cpuinfo string) bool {
	for _, line := range strings.Split(cpuinfo, "\n") {
		if strings.HasPrefix(line, "flags") {
			return slices.Contains(strings.Fields(line), "hypervisor")
		}
	}
	return false
}

// smbiosVMBitSet reports whether table, an SMBIOS structure table, sets the
// "virtual machine" bit in its BIOS Information (type 0) structure. The bit is
// bit 4 of BIOS characteristics extension byte 2, at offset 0x13. See DMTF
// DSP0134.
func smbiosVMBitSet(table []byte) bool {
	const (
		biosInfoType = 0
		ext2Offset   = 0x13
		vmBit        = 1 << 4
	)
	for len(table) >= 4 {
		typ, size := table[0], int(table[1])
		if size < 4 || size > len(table) {
			return false
		}
		if typ == biosInfoType {
			return size > ext2Offset && table[ext2Offset]&vmBit != 0
		}
		// Skip the formatted area and the strings after it, which end with
		// two NUL bytes.
		n := bytes.Index(table[size:], []byte{0, 0})
		if n < 0 {
			return false
		}
		table = table[size+n+2:]
	}
	return false
}
