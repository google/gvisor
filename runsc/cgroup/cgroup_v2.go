// Copyright The runc Authors.
// Copyright The containerd Authors.
// Copyright 2021 The gVisor Authors.
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
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/coreos/go-systemd/v22/dbus"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/log"
)

const (
	subtreeControl  = "cgroup.subtree_control"
	controllersFile = "cgroup.controllers"
	cgroup2Key      = "cgroup2"

	// https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html
	defaultPeriod = 100000
)

var (
	ErrInvalidFormat    = errors.New("cgroup: parsing file with invalid format failed")
	ErrInvalidGroupPath = errors.New("cgroup: invalid group path")

	// controllers2 is the group of all supported cgroupv2 controllers
	controllers2 = map[string]controllerv2{
		"cpu":     &cpu2{},
		"cpuset":  &cpuset2{},
		"io":      &io2{},
		"memory":  &memory2{},
		"pids":    &pid2{},
		"hugetlb": &hugeTLB2{},
	}
)

// cgroupV2 represents a cgroup inside supported all cgroupV2 controllers
type cgroupV2 struct {
	// Mountpoint is the unified mount point of cgroupV2
	Mountpoint string `json:"mountpoint"`
	// Path is the relative path to the unified mountpoint
	Path string `json:"path"`
	// Controllers is the list of supported controllers
	Controllers []string `json:"controllers"`
	// Own is the list of owned path created when install this cgroup
	Own []string `json:"own"`
}

func newCgroupV2(mountpoint, group string, useSystemd bool) (Cgroup, error) {
	data, err := ioutil.ReadFile(filepath.Join(mountpoint, "cgroup.controllers"))
	if err != nil {
		return nil, err
	}
	cg := &cgroupV2{
		Mountpoint:  mountpoint,
		Path:        group,
		Controllers: strings.Fields(string(data)),
	}
	if useSystemd {
		return newCgroupV2Systemd(cg)
	}
	return cg, err
}

func (c *cgroupV2) createCgroupPaths() (bool, error) {
	// setup all known controllers for the current subtree
	// For example, given path /foo/bar and mount /sys/fs/cgroup, we need to write
	// the controllers to:
	//	* /sys/fs/cgroup/cgroup.subtree_control
	//	* /sys/fs/cgroup/foo/cgroup.subtree_control
	val := "+" + strings.Join(c.Controllers, " +")
	elements := strings.Split(c.Path, "/")
	current := c.Mountpoint
	created := false

	for i, e := range elements {
		current = filepath.Join(current, e)
		if i > 0 {
			if err := os.Mkdir(current, 0o755); err != nil {
				if !os.IsExist(err) {
					return false, err
				}
			} else {
				created = true
				c.Own = append(c.Own, current)
			}
		}
		// enable all known controllers for subtree
		if i < len(elements)-1 {
			if err := writeFile(filepath.Join(current, subtreeControl), []byte(val), 0700); err != nil {
				return false, err
			}
		}
	}
	return created, nil
}

// Install creates and configures cgroups.
func (c *cgroupV2) Install(res *specs.LinuxResources) error {
	log.Debugf("Installing cgroup path %q", c.MakePath(""))
	// Clean up partially created cgroups on error. Errors during cleanup itself
	// are ignored.
	clean := cleanup.Make(func() { _ = c.Uninstall() })
	defer clean.Clean()

	created, err := c.createCgroupPaths()
	if err != nil {
		return err
	}
	if created {
		// If we created our final cgroup path then we can set the resources.
		for controllerName, ctrlr := range controllers2 {
			// First check if our controller is found in the system.
			found := false
			for _, knownController := range c.Controllers {
				if controllerName == knownController {
					found = true
				}
			}

			// In case we don't have the controller.
			if found {
				if err := ctrlr.set(res, c.MakePath("")); err != nil {
					return err
				}
				continue
			}
			if ctrlr.optional() {
				if err := ctrlr.skip(res); err != nil {
					return err
				}
			} else {
				return fmt.Errorf("mandatory cgroup controller %q is missing for %q", controllerName, c.MakePath(""))
			}
		}
	}

	clean.Release()
	return nil
}

// Uninstall removes the settings done in Install(). If cgroup path already
// existed when Install() was called, Uninstall is a noop.
func (c *cgroupV2) Uninstall() error {
	log.Debugf("Deleting cgroup %q", c.MakePath(""))

	// If we try to remove the cgroup too soon after killing the sandbox we
	// might get EBUSY, so we retry for a few seconds until it succeeds.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b := backoff.WithContext(backoff.NewConstantBackOff(100*time.Millisecond), ctx)

	// Deletion must occur reverse order, because they may contain ancestors.
	for i := len(c.Own) - 1; i >= 0; i-- {
		current := c.Own[i]
		log.Debugf("Removing cgroup for path=%q", current)

		fn := func() error {
			err := unix.Rmdir(current)
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if err := backoff.Retry(fn, b); err != nil {
			return fmt.Errorf("removing cgroup path %q: %w", current, err)
		}
	}

	return nil
}

// Join adds the current process to the all controllers. Returns function that
// restores cgroup to the original state.
func (c *cgroupV2) Join() (func(), error) {
	// First save the current state so it can be restored.
	paths, err := loadPaths("self")
	if err != nil {
		return nil, err
	}
	// Since this is unified, get the first path of current process's cgroup is
	// enough.
	undoPath := filepath.Join(c.Mountpoint, paths[cgroup2Key])

	cu := cleanup.Make(func() {
		log.Debugf("Restoring cgroup %q", undoPath)
		// Writing the value 0 to a cgroup.procs file causes
		// the writing process to be moved to the corresponding
		// cgroup. - cgroups(7).
		if err := setValue(undoPath, "cgroup.procs", "0"); err != nil {
			log.Warningf("Error restoring cgroup %q: %v", undoPath, err)
		}
	})
	defer cu.Clean()

	// now join the cgroup
	if err := setValue(c.MakePath(""), "cgroup.procs", "0"); err != nil {
		return nil, err
	}

	return cu.Release(), nil
}

// CPUQuota returns the CFS CPU quota.
func (c *cgroupV2) CPUQuota() (float64, error) {
	cpuMax, err := getValue(c.MakePath(""), "cpu.max")
	if err != nil {
		return -1, err
	}

	return parseCPUQuota(cpuMax)
}

func parseCPUQuota(cpuMax string) (float64, error) {
	data := strings.SplitN(strings.TrimSpace(cpuMax), " ", 2)
	if len(data) != 2 {
		return -1, fmt.Errorf("invalid cpu.max data %q", cpuMax)
	}

	// no cpu limit if quota is max
	if data[0] == "max" {
		return -1, nil
	}

	quota, err := strconv.ParseInt(data[0], 10, 64)
	if err != nil {
		return -1, err
	}

	period, err := strconv.ParseInt(data[1], 10, 64)
	if err != nil {
		return -1, err
	}

	if quota <= 0 || period <= 0 {
		return -1, err
	}
	return float64(quota) / float64(period), nil

}

// CPUUsage returns the total CPU usage of the cgroup.
func (c *cgroupV2) CPUUsage() (uint64, error) {
	cpuStat, err := getValue(c.MakePath(""), "cpu.stat")
	if err != nil {
		return 0, err
	}

	sc := bufio.NewScanner(strings.NewReader(cpuStat))
	for sc.Scan() {
		key, value, err := parseKeyValue(sc.Text())
		if err != nil {
			return 0, err
		}
		if key == "usage_usec" {
			return value, nil
		}
	}

	return 0, nil
}

// NumCPU returns the number of CPUs configured in 'cpuset/cpuset.cpus'.
func (c *cgroupV2) NumCPU() (int, error) {
	cpuset, err := getValue(c.MakePath(""), "cpuset.cpus.effective")
	if err != nil {
		return 0, err
	}
	return countCpuset(strings.TrimSpace(cpuset))
}

// MemoryLimit returns the memory limit.
func (c *cgroupV2) MemoryLimit() (uint64, error) {
	limStr, err := getValue(c.MakePath(""), "memory.max")
	if err != nil {
		return 0, err
	}
	limStr = strings.TrimSpace(limStr)
	if limStr == "max" {
		return math.MaxUint64, nil
	}
	return strconv.ParseUint(limStr, 10, 64)
}

// MakePath builds a path to the given controller.
func (c *cgroupV2) MakePath(controllerName string) string {
	return filepath.Join(c.Mountpoint, c.Path)
}

type controllerv2 interface {
	controller
	generateProperties(spec *specs.LinuxResources) ([]dbus.Property, error)
}

type cpu2 struct {
	mandatory
}

func (*cpu2) generateProperties(spec *specs.LinuxResources) ([]dbus.Property, error) {
	props := []dbus.Property{}
	if spec == nil || spec.CPU == nil {
		return props, nil
	}
	cpu := spec.CPU
	if cpu.Shares != nil {
		weight := convertCPUSharesToCgroupV2Value(*cpu.Shares)
		if weight != 0 {
			props = append(props, newProp("CPUWeight", weight))
		}
	}
	var (
		period uint64
		quota  int64
	)
	if cpu.Period != nil {
		period = *cpu.Period
	}
	if cpu.Quota != nil {
		quota = *cpu.Quota
	}
	if period != 0 {
		props = append(props, newProp("CPUQuotaPeriodUSec", period))
	}
	if quota != 0 || period != 0 {
		// Corresponds to USEC_INFINITY in systemd.
		cpuQuotaPerSecUSec := uint64(math.MaxUint64)
		if quota > 0 {
			if period == 0 {
				// Assume the default.
				period = defaultPeriod
			}
			// systemd converts CPUQuotaPerSecUSec (microseconds per CPU second) to
			// CPUQuota (integer percentage of CPU) internally. This means that if a
			// fractional percent of CPU is indicated by spec.CPU.Quota, we need to
			// round up to the nearest 10ms (1% of a second) such that child cgroups
			// can set the cpu.cfs_quota_us they expect.
			cpuQuotaPerSecUSec = uint64(quota*1000000) / period
			if cpuQuotaPerSecUSec%10000 != 0 {
				cpuQuotaPerSecUSec = ((cpuQuotaPerSecUSec / 10000) + 1) * 10000
			}
		}
		props = append(props, newProp("CPUQuotaPerSecUSec", cpuQuotaPerSecUSec))
	}
	return props, nil
}

func (*cpu2) set(spec *specs.LinuxResources, path string) error {
	if spec == nil || spec.CPU == nil {
		return nil
	}

	if spec.CPU.Shares != nil {
		weight := convertCPUSharesToCgroupV2Value(*spec.CPU.Shares)
		if weight != 0 {
			if err := setValue(path, "cpu.weight", strconv.FormatUint(weight, 10)); err != nil {
				return err
			}
		}
	}

	if spec.CPU.Period != nil || spec.CPU.Quota != nil {
		v := "max"
		if spec.CPU.Quota != nil && *spec.CPU.Quota > 0 {
			v = strconv.FormatInt(*spec.CPU.Quota, 10)
		}

		var period uint64
		if spec.CPU.Period != nil && *spec.CPU.Period != 0 {
			period = *spec.CPU.Period
		} else {
			period = defaultPeriod
		}

		v += " " + strconv.FormatUint(period, 10)
		if err := setValue(path, "cpu.max", v); err != nil {
			return err
		}
	}

	return nil
}

type cpuset2 struct {
	mandatory
}

func (*cpuset2) generateProperties(spec *specs.LinuxResources) ([]dbus.Property, error) {
	props := []dbus.Property{}
	if spec == nil || spec.CPU == nil {
		return props, nil
	}
	cpu := spec.CPU
	if cpu.Cpus == "" && cpu.Mems == "" {
		return props, nil
	}
	cpus := cpu.Cpus
	mems := cpu.Mems
	if cpus != "" {
		bits, err := RangeToBits(cpus)
		if err != nil {
			return nil, fmt.Errorf("%w: cpus=%q conversion error: %v", ErrBadResourceSpec, cpus, err)
		}
		props = append(props, newProp("AllowedCPUs", bits))
	}
	if mems != "" {
		bits, err := RangeToBits(mems)
		if err != nil {
			return nil, fmt.Errorf("%w: mems=%q conversion error: %v", ErrBadResourceSpec, mems, err)
		}
		props = append(props, newProp("AllowedMemoryNodes", bits))
	}
	return props, nil
}

func (*cpuset2) set(spec *specs.LinuxResources, path string) error {
	if spec == nil || spec.CPU == nil {
		return nil
	}

	if spec.CPU.Cpus != "" {
		if err := setValue(path, "cpuset.cpus", spec.CPU.Cpus); err != nil {
			return err
		}
	}

	if spec.CPU.Mems != "" {
		if err := setValue(path, "cpuset.mems", spec.CPU.Mems); err != nil {
			return err
		}
	}

	return nil
}

type memory2 struct {
	mandatory
}

func (*memory2) generateProperties(spec *specs.LinuxResources) ([]dbus.Property, error) {
	props := []dbus.Property{}
	if spec == nil || spec.Memory == nil {
		return props, nil
	}
	mem := spec.Memory
	if mem.Swap != nil {
		if mem.Limit == nil {
			return nil, ErrBadResourceSpec
		}
		swap, err := convertMemorySwapToCgroupV2Value(*mem.Swap, *mem.Limit)
		if err != nil {
			return nil, err
		}
		props = append(props, newProp("MemorySwapMax", uint64(swap)))
	}
	if mem.Limit != nil {
		props = append(props, newProp("MemoryMax", uint64(*mem.Limit)))
	}
	if mem.Reservation != nil {
		props = append(props, newProp("MemoryLow", uint64(*mem.Reservation)))
	}
	return props, nil
}

func (*memory2) set(spec *specs.LinuxResources, path string) error {
	if spec == nil || spec.Memory == nil {
		return nil
	}

	if spec.Memory.Swap != nil {
		// in cgroup v2, we set memory and swap separately, but the spec specifies
		// Swap field as memory+swap, so we need memory limit here to be set in
		// order to get the correct swap value.
		if spec.Memory.Limit == nil {
			return errors.New("cgroup: Memory.Swap is set without Memory.Limit")
		}

		swap, err := convertMemorySwapToCgroupV2Value(*spec.Memory.Swap, *spec.Memory.Limit)
		if err != nil {
			return nil
		}
		swapStr := numToStr(swap)
		// memory and memorySwap set to the same value -- disable swap
		if swapStr == "" && swap == 0 && *spec.Memory.Swap > 0 {
			swapStr = "0"
		}
		// never write empty string to `memory.swap.max`, it means set to 0.
		if swapStr != "" {
			if err := setValue(path, "memory.swap.max", swapStr); err != nil {
				return err
			}
		}
	}

	if spec.Memory.Limit != nil {
		if val := numToStr(*spec.Memory.Limit); val != "" {
			if err := setValue(path, "memory.max", val); err != nil {
				return err
			}
		}
	}

	if spec.Memory.Reservation != nil {
		if val := numToStr(*spec.Memory.Reservation); val != "" {
			if err := setValue(path, "memory.low", val); err != nil {
				return err
			}
		}
	}

	return nil
}

type pid2 struct {
	mandatory
}

func (*pid2) generateProperties(spec *specs.LinuxResources) ([]dbus.Property, error) {
	if spec != nil && spec.Pids != nil {
		return []dbus.Property{newProp("TasksMax", uint64(spec.Pids.Limit))}, nil
	}
	return []dbus.Property{}, nil
}

func (*pid2) set(spec *specs.LinuxResources, path string) error {
	if spec == nil || spec.Pids == nil {
		return nil
	}

	if val := numToStr(spec.Pids.Limit); val != "" {
		return setValue(path, "pids.max", val)
	}

	return nil
}

type io2 struct {
	mandatory
}

func (*io2) generateProperties(spec *specs.LinuxResources) ([]dbus.Property, error) {
	props := []dbus.Property{}
	if spec == nil || spec.BlockIO == nil {
		return props, nil
	}
	io := spec.BlockIO
	if io != nil {
		if io.Weight != nil && *io.Weight != 0 {
			ioWeight := convertBlkIOToIOWeightValue(*io.Weight)
			props = append(props, newProp("IOWeight", ioWeight))
		}
		for _, dev := range io.WeightDevice {
			val := fmt.Sprintf("%d:%d %d", dev.Major, dev.Minor, *dev.Weight)
			props = append(props, newProp("IODeviceWeight", val))
		}
		props = addIOProps(props, "IOReadBandwidthMax", io.ThrottleReadBpsDevice)
		props = addIOProps(props, "IOWriteBandwidthMax", io.ThrottleWriteBpsDevice)
		props = addIOProps(props, "IOReadIOPSMax", io.ThrottleReadIOPSDevice)
		props = addIOProps(props, "IOWriteIOPSMax", io.ThrottleWriteIOPSDevice)
	}
	return props, nil
}

func (*io2) set(spec *specs.LinuxResources, path string) error {
	if spec == nil || spec.BlockIO == nil {
		return nil
	}
	blkio := spec.BlockIO

	var (
		err error
		bfq *os.File
	)

	// If BFQ IO scheduler is available, use it.
	if blkio.Weight != nil || len(blkio.WeightDevice) > 0 {
		bfq, err = os.Open(filepath.Join(path, "io.bfq.weight"))
		if err == nil {
			defer bfq.Close()
		} else if !os.IsNotExist(err) {
			return err
		}

	}

	if blkio.Weight != nil && *blkio.Weight != 0 {
		if bfq != nil {
			if _, err := bfq.WriteString(strconv.FormatUint(uint64(*blkio.Weight), 10)); err != nil {
				return err
			}
		} else {
			// bfq io scheduler is not available, fallback to io.weight with
			// a conversion scheme
			ioWeight := convertBlkIOToIOWeightValue(*blkio.Weight)
			if err = setValue(path, "io.weight", strconv.FormatUint(ioWeight, 10)); err != nil {
				return err
			}
		}
	}

	if bfqDeviceWeightSupported(bfq) {
		// ignore leaf weight, does not apply to cgroupv2
		for _, dev := range blkio.WeightDevice {
			if dev.Weight != nil {
				val := fmt.Sprintf("%d:%d %d\n", dev.Major, dev.Minor, *dev.Weight)
				if _, err := bfq.WriteString(val); err != nil {
					return fmt.Errorf("failed to set device weight %q: %w", val, err)
				}
			}
		}
	}

	if err := setThrottle2(path, "rbps", blkio.ThrottleReadBpsDevice); err != nil {
		return err
	}

	if err := setThrottle2(path, "wbps", blkio.ThrottleWriteBpsDevice); err != nil {
		return err
	}

	if err := setThrottle2(path, "riops", blkio.ThrottleReadIOPSDevice); err != nil {
		return err
	}

	if err := setThrottle2(path, "wiops", blkio.ThrottleWriteIOPSDevice); err != nil {
		return err
	}

	return nil
}

func setThrottle2(path, name string, devs []specs.LinuxThrottleDevice) error {
	for _, dev := range devs {
		val := fmt.Sprintf("%d:%d %s=%d", dev.Major, dev.Minor, name, dev.Rate)
		if err := setValue(path, "io.max", val); err != nil {
			return err
		}
	}
	return nil
}

type hugeTLB2 struct {
}

func (*hugeTLB2) optional() bool {
	return true
}

func (*hugeTLB2) skip(spec *specs.LinuxResources) error {
	if spec != nil && len(spec.HugepageLimits) > 0 {
		return fmt.Errorf("HugepageLimits set but hugetlb cgroup controller not found")
	}
	return nil
}

func (*hugeTLB2) generateProperties(spec *specs.LinuxResources) ([]dbus.Property, error) {
	return nil, nil
}

func (*hugeTLB2) set(spec *specs.LinuxResources, path string) error {
	if spec == nil {
		return nil
	}
	for _, limit := range spec.HugepageLimits {
		name := fmt.Sprintf("hugetlb.%s.limit_in_bytes", limit.Pagesize)
		val := strconv.FormatUint(limit.Limit, 10)
		if err := setValue(path, name, val); err != nil {
			return err
		}
	}
	return nil
}

// Since the OCI spec is designed for cgroup v1, in some cases
// there is need to convert from the cgroup v1 configuration to cgroup v2
// the formula for cpuShares is y = (1 + ((x - 2) * 9999) / 262142)
// convert from [2-262144] to [1-10000]
// 262144 comes from Linux kernel definition "#define MAX_SHARES (1UL << 18)"
func convertCPUSharesToCgroupV2Value(cpuShares uint64) uint64 {
	if cpuShares == 0 {
		return 0
	}
	return (1 + ((cpuShares-2)*9999)/262142)
}

// convertMemorySwapToCgroupV2Value converts MemorySwap value from OCI spec
// for use by cgroup v2 drivers. A conversion is needed since
// Resources.MemorySwap is defined as memory+swap combined, while in cgroup v2
// swap is a separate value.
func convertMemorySwapToCgroupV2Value(memorySwap, memory int64) (int64, error) {
	// for compatibility with cgroup1 controller, set swap to unlimited in
	// case the memory is set to unlimited, and swap is not explicitly set,
	// treating the request as "set both memory and swap to unlimited".
	if memory == -1 && memorySwap == 0 {
		return -1, nil
	}
	if memorySwap == -1 || memorySwap == 0 {
		// -1 is "max", 0 is "unset", so treat as is.
		return memorySwap, nil
	}
	// sanity checks
	if memory == 0 || memory == -1 {
		return 0, errors.New("unable to set swap limit without memory limit")
	}
	if memory < 0 {
		return 0, fmt.Errorf("invalid memory value: %d", memory)
	}
	if memorySwap < memory {
		return 0, errors.New("memory+swap limit should be >= memory limit")
	}

	return memorySwap - memory, nil
}

// Since the OCI spec is designed for cgroup v1, in some cases
// there is need to convert from the cgroup v1 configuration to cgroup v2
// the formula for BlkIOWeight to IOWeight is y = (1 + (x - 10) * 9999 / 990)
// convert linearly from [10-1000] to [1-10000]
func convertBlkIOToIOWeightValue(blkIoWeight uint16) uint64 {
	if blkIoWeight == 0 {
		return 0
	}
	return 1 + (uint64(blkIoWeight)-10)*9999/990
}

// numToStr converts an int64 value to a string for writing to a
// cgroupv2 files with .min, .max, .low, or .high suffix.
// The value of -1 is converted to "max" for cgroupv1 compatibility
// (which used to write -1 to remove the limit).
func numToStr(value int64) (ret string) {
	switch {
	case value == 0:
		ret = ""
	case value == -1:
		ret = "max"
	default:
		ret = strconv.FormatInt(value, 10)
	}
	return ret
}

// bfqDeviceWeightSupported checks for per-device BFQ weight support (added
// in kernel v5.4, commit 795fe54c2a8) by reading from "io.bfq.weight".
func bfqDeviceWeightSupported(bfq *os.File) bool {
	if bfq == nil {
		return false
	}

	if _, err := bfq.Seek(0, 0); err != nil {
		return false
	}

	buf := make([]byte, 32)
	if _, err := bfq.Read(buf); err != nil {
		return false
	}
	// If only a single number (default weight) if read back, we have older
	// kernel.
	_, err := strconv.ParseInt(string(bytes.TrimSpace(buf)), 10, 64)
	return err != nil
}

// parseKeyValue parses a space-separated "name value" kind of cgroup
// parameter and returns its key as a string, and its value as uint64
// (ParseUint is used to convert the value). For example,
// "io_service_bytes 1234" will be returned as "io_service_bytes", 1234.
func parseKeyValue(t string) (string, uint64, error) {
	parts := strings.SplitN(t, " ", 3)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("line %q is not in key value format", t)
	}

	value, err := parseUint(parts[1], 10, 64)
	if err != nil {
		return "", 0, err
	}

	return parts[0], value, nil
}

// parseUint converts a string to an uint64 integer.
// Negative values are returned at zero as, due to kernel bugs,
// some of the memory cgroup stats can be negative.
func parseUint(s string, base, bitSize int) (uint64, error) {
	value, err := strconv.ParseUint(s, base, bitSize)
	if err != nil {
		intValue, intErr := strconv.ParseInt(s, base, bitSize)
		// 1. Handle negative values greater than MinInt64 (and)
		// 2. Handle negative values lesser than MinInt64
		if intErr == nil && intValue < 0 {
			return 0, nil
		} else if errors.Is(intErr, strconv.ErrRange) && intValue < 0 {
			return 0, nil
		}

		return value, err
	}

	return value, nil
}

// RangeToBits converts a text representation of a CPU mask (as written to
// or read from cgroups' cpuset.* files, e.g. "1,3-5") to a slice of bytes
// with the corresponding bits set (as consumed by systemd over dbus as
// AllowedCPUs/AllowedMemoryNodes unit property value).
// Copied from runc.
func RangeToBits(str string) ([]byte, error) {
	bits := &big.Int{}

	for _, r := range strings.Split(str, ",") {
		// allow extra spaces around
		r = strings.TrimSpace(r)
		// allow empty elements (extra commas)
		if r == "" {
			continue
		}
		ranges := strings.SplitN(r, "-", 2)
		if len(ranges) > 1 {
			start, err := strconv.ParseUint(ranges[0], 10, 32)
			if err != nil {
				return nil, err
			}
			end, err := strconv.ParseUint(ranges[1], 10, 32)
			if err != nil {
				return nil, err
			}
			if start > end {
				return nil, errors.New("invalid range: " + r)
			}
			for i := start; i <= end; i++ {
				bits.SetBit(bits, int(i), 1)
			}
		} else {
			val, err := strconv.ParseUint(ranges[0], 10, 32)
			if err != nil {
				return nil, err
			}
			bits.SetBit(bits, int(val), 1)
		}
	}

	ret := bits.Bytes()
	if len(ret) == 0 {
		// do not allow empty values
		return nil, errors.New("empty value")
	}
	return ret, nil
}
