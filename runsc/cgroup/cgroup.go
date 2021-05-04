// Copyright 2018 The gVisor Authors.
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

// Package cgroup provides an interface to read and write configuration to
// cgroup.
package cgroup

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	libcontainercgroups "github.com/opencontainers/runc/libcontainer/cgroups"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/log"
)

const (
	cgroupRoot = "/sys/fs/cgroup"
)

var controllers = map[string]config{
	"blkio":    {ctrlr: &blockIO{}},
	"cpu":      {ctrlr: &cpu{}},
	"cpuset":   {ctrlr: &cpuSet{}},
	"hugetlb":  {ctrlr: &hugeTLB{}, optional: true},
	"memory":   {ctrlr: &memory{}},
	"net_cls":  {ctrlr: &networkClass{}},
	"net_prio": {ctrlr: &networkPrio{}},
	"pids":     {ctrlr: &pids{}},

	// These controllers either don't have anything in the OCI spec or is
	// irrelevant for a sandbox.
	"devices":    {ctrlr: &noop{}},
	"freezer":    {ctrlr: &noop{}},
	"perf_event": {ctrlr: &noop{}},
	"rdma":       {ctrlr: &noop{}, optional: true},
	"systemd":    {ctrlr: &noop{}},
}

// IsOnlyV2 checks whether cgroups V2 is enabled and V1 is not.
func IsOnlyV2() bool {
	var stat unix.Statfs_t
	if err := unix.Statfs(cgroupRoot, &stat); err != nil {
		// It's not used for anything important, assume not V2 on failure.
		return false
	}
	return stat.Type == unix.CGROUP2_SUPER_MAGIC
}

func setOptionalValueInt(path, name string, val *int64) error {
	if val == nil || *val == 0 {
		return nil
	}
	str := strconv.FormatInt(*val, 10)
	return setValue(path, name, str)
}

func setOptionalValueUint(path, name string, val *uint64) error {
	if val == nil || *val == 0 {
		return nil
	}
	str := strconv.FormatUint(*val, 10)
	return setValue(path, name, str)
}

func setOptionalValueUint32(path, name string, val *uint32) error {
	if val == nil || *val == 0 {
		return nil
	}
	str := strconv.FormatUint(uint64(*val), 10)
	return setValue(path, name, str)
}

func setOptionalValueUint16(path, name string, val *uint16) error {
	if val == nil || *val == 0 {
		return nil
	}
	str := strconv.FormatUint(uint64(*val), 10)
	return setValue(path, name, str)
}

func setValue(path, name, data string) error {
	fullpath := filepath.Join(path, name)

	// Retry writes on EINTR; see:
	//    https://github.com/golang/go/issues/38033
	for {
		err := ioutil.WriteFile(fullpath, []byte(data), 0700)
		if err == nil {
			return nil
		} else if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

func getValue(path, name string) (string, error) {
	fullpath := filepath.Join(path, name)
	out, err := ioutil.ReadFile(fullpath)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func getInt(path, name string) (int, error) {
	s, err := getValue(path, name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(s))
}

// fillFromAncestor sets the value of a cgroup file from the first ancestor
// that has content. It does nothing if the file in 'path' has already been set.
func fillFromAncestor(path string) (string, error) {
	out, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	val := strings.TrimSpace(string(out))
	if val != "" {
		// File is set, stop here.
		return val, nil
	}

	// File is not set, recurse to parent and then set here.
	name := filepath.Base(path)
	parent := filepath.Dir(filepath.Dir(path))
	val, err = fillFromAncestor(filepath.Join(parent, name))
	if err != nil {
		return "", err
	}

	// Retry writes on EINTR; see:
	//    https://github.com/golang/go/issues/38033
	for {
		err := ioutil.WriteFile(path, []byte(val), 0700)
		if err == nil {
			break
		} else if !errors.Is(err, unix.EINTR) {
			return "", err
		}
	}
	return val, nil
}

// countCpuset returns the number of CPU in a string formatted like:
// 		"0-2,7,12-14  # bits 0, 1, 2, 7, 12, 13, and 14 set" - man 7 cpuset
func countCpuset(cpuset string) (int, error) {
	var count int
	for _, p := range strings.Split(cpuset, ",") {
		interval := strings.Split(p, "-")
		switch len(interval) {
		case 1:
			if _, err := strconv.Atoi(interval[0]); err != nil {
				return 0, err
			}
			count++

		case 2:
			start, err := strconv.Atoi(interval[0])
			if err != nil {
				return 0, err
			}
			end, err := strconv.Atoi(interval[1])
			if err != nil {
				return 0, err
			}
			if start < 0 || end < 0 || start > end {
				return 0, fmt.Errorf("invalid cpuset: %q", p)
			}
			count += end - start + 1

		default:
			return 0, fmt.Errorf("invalid cpuset: %q", p)
		}
	}
	return count, nil
}

// LoadPaths loads cgroup paths for given 'pid', may be set to 'self'.
func LoadPaths(pid string) (map[string]string, error) {
	f, err := os.Open(filepath.Join("/proc", pid, "cgroup"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return loadPathsHelper(f)
}

func loadPathsHelper(cgroup io.Reader) (map[string]string, error) {
	// For nested containers, in /proc/self/cgroup we see paths from host,
	// which don't exist in container, so recover the container paths here by
	// double-checking with /proc/pid/mountinfo
	mountinfo, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer mountinfo.Close()

	if libcontainercgroups.IsCgroup2UnifiedMode() {
		return loadPathsHelperV2WithMountinfo(cgroup, mountinfo)
	}

	return loadPathsHelperWithMountinfo(cgroup, mountinfo)
}

func loadPathsHelperV2WithMountinfo(cgroup, mountinfo io.Reader) (map[string]string, error) {
	paths := make(map[string]string)
	controller := "cgroup2"

	scanner := bufio.NewScanner(cgroup)
	for scanner.Scan() {
		// Format: ID::path
		// Example: 0::/user.slice
		tokens := strings.Split(scanner.Text(), ":")
		if len(tokens) != 3 || len(tokens[1]) != 0 {
			return nil, fmt.Errorf("invalid cgroups file, line: %q", scanner.Text())
		}
		paths[controller] = tokens[2]
		break
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	mfScanner := bufio.NewScanner(mountinfo)
	for mfScanner.Scan() {
		txt := mfScanner.Text()
		fields := strings.Fields(txt)
		if len(fields) < 9 || fields[len(fields)-3] != "cgroup2" {
			continue
		}
		root := fields[3]
		cgroupPath := paths[controller]
		relCgroupPath, err := filepath.Rel(root, cgroupPath)
		if err != nil {
			return nil, err
		}
		paths[controller] = relCgroupPath
	}
	if err := mfScanner.Err(); err != nil {
		return nil, err
	}

	return paths, nil
}

func loadPathsHelperWithMountinfo(cgroup, mountinfo io.Reader) (map[string]string, error) {
	paths := make(map[string]string)

	scanner := bufio.NewScanner(cgroup)
	for scanner.Scan() {
		// Format: ID:[name=]controller1,controller2:path
		// Example: 2:cpu,cpuacct:/user.slice
		tokens := strings.Split(scanner.Text(), ":")
		if len(tokens) != 3 {
			return nil, fmt.Errorf("invalid cgroups file, line: %q", scanner.Text())
		}
		if len(tokens[1]) == 0 {
			continue
		}
		for _, ctrlr := range strings.Split(tokens[1], ",") {
			// Remove prefix for cgroups with no controller, eg. systemd.
			ctrlr = strings.TrimPrefix(ctrlr, "name=")
			paths[ctrlr] = tokens[2]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	mfScanner := bufio.NewScanner(mountinfo)
	for mfScanner.Scan() {
		txt := mfScanner.Text()
		fields := strings.Fields(txt)
		if len(fields) < 9 || fields[len(fields)-3] != "cgroup" {
			continue
		}
		for _, opt := range strings.Split(fields[len(fields)-1], ",") {
			// Remove prefix for cgroups with no controller, eg. systemd.
			opt = strings.TrimPrefix(opt, "name=")
			if cgroupPath, ok := paths[opt]; ok {
				root := fields[3]
				relCgroupPath, err := filepath.Rel(root, cgroupPath)
				if err != nil {
					return nil, err
				}
				paths[opt] = relCgroupPath
			}
		}
	}
	if err := mfScanner.Err(); err != nil {
		return nil, err
	}

	return paths, nil
}

// Cgroup represents a group inside all controllers. For example:
//   Name='/foo/bar' maps to /sys/fs/cgroup/<controller>/foo/bar on
//   all controllers.
type Cgroup struct {
	Name    string            `json:"name"`
	Parents map[string]string `json:"parents"`
	Own     map[string]bool   `json:"own"`

	v2manager *cgroupV2Manager
}

// New creates a new Cgroup instance if the spec includes a cgroup path.
// Returns nil otherwise.
func New(spec *specs.Spec) (*Cgroup, error) {
	if spec.Linux == nil || spec.Linux.CgroupsPath == "" {
		return nil, nil
	}
	return NewFromPath(spec.Linux.CgroupsPath)
}

// NewFromPath creates a new Cgroup instance.
func NewFromPath(cgroupsPath string) (*Cgroup, error) {
	var parents map[string]string
	if !filepath.IsAbs(cgroupsPath) {
		var err error
		parents, err = LoadPaths("self")
		if err != nil {
			return nil, fmt.Errorf("finding current cgroups: %w", err)
		}
	}
	own := make(map[string]bool)

	return &Cgroup{
		Name:    cgroupsPath,
		Parents: parents,
		Own:     own,
	}, nil
}

func (c *Cgroup) cgroupv2Manager() (*cgroupV2Manager, error) {
	if c.v2manager != nil {
		return c.v2manager, nil
	}
	m, err := NewCgroupV2Manager(c.Name)
	if err != nil {
		return nil, err
	}
	c.v2manager = m
	return c.v2manager, nil
}

// Install creates and configures cgroups according to 'res'. If cgroup path
// already exists, it means that the caller has already provided a
// pre-configured cgroups, and 'res' is ignored.
func (c *Cgroup) Install(res *specs.LinuxResources) error {
	log.Debugf("Creating cgroup %q", c.Name)

	if libcontainercgroups.IsCgroup2UnifiedMode() {
		m, err := c.cgroupv2Manager()
		if err != nil {
			return err
		}

		owned, err := m.Install(c.Name, res)
		// Mark that cgroup resources are owned by me.
		for key, _ := range controllers {
			c.Own[key] = owned
		}
		return err
	}

	// The Cleanup object cleans up partially created cgroups when an error occurs.
	// Errors occuring during cleanup itself are ignored.
	clean := cleanup.Make(func() { _ = c.Uninstall() })
	defer clean.Clean()

	for key, cfg := range controllers {
		path := c.makePath(key)
		if _, err := os.Stat(path); err == nil {
			// If cgroup has already been created; it has been setup by caller. Don't
			// make any changes to configuration, just join when sandbox/gofer starts.
			log.Debugf("Using pre-created cgroup %q", path)
			continue
		}

		// Mark that cgroup resources are owned by me.
		c.Own[key] = true

		if err := os.MkdirAll(path, 0755); err != nil {
			if cfg.optional && errors.Is(err, unix.EROFS) {
				log.Infof("Skipping cgroup %q", key)
				continue
			}
			return err
		}
		if err := cfg.ctrlr.set(res, path); err != nil {
			return err
		}
	}
	clean.Release()
	return nil
}

// Uninstall removes the settings done in Install(). If cgroup path already
// existed when Install() was called, Uninstall is a noop.
func (c *Cgroup) Uninstall() error {
	log.Debugf("Deleting cgroup %q", c.Name)

	if libcontainercgroups.IsCgroup2UnifiedMode() {
		m, err := c.cgroupv2Manager()
		if err != nil {
			return err
		}

		var owned bool
		for _, v := range c.Own {
			owned = v
			break
		}
		return m.Uninstall(c.Name, owned)
	}

	for key := range controllers {
		if !c.Own[key] {
			// cgroup is managed by caller, don't touch it.
			continue
		}
		path := c.makePath(key)
		log.Debugf("Removing cgroup controller for key=%q path=%q", key, path)

		// If we try to remove the cgroup too soon after killing the
		// sandbox we might get EBUSY, so we retry for a few seconds
		// until it succeeds.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		b := backoff.WithContext(backoff.NewConstantBackOff(100*time.Millisecond), ctx)
		fn := func() error {
			err := unix.Rmdir(path)
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if err := backoff.Retry(fn, b); err != nil {
			return fmt.Errorf("removing cgroup path %q: %w", path, err)
		}
	}
	return nil
}

// Join adds the current process to the all controllers. Returns function that
// restores cgroup to the original state.
func (c *Cgroup) Join() (func(), error) {
	if libcontainercgroups.IsCgroup2UnifiedMode() {
		m, err := c.cgroupv2Manager()
		if err != nil {
			return func() {}, err
		}

		return m.Join(c.Name)
	}

	// First save the current state so it can be restored.
	undo := func() {}
	paths, err := LoadPaths("self")
	if err != nil {
		return undo, err
	}
	var undoPaths []string
	for ctrlr, path := range paths {
		// Skip controllers we don't handle.
		if _, ok := controllers[ctrlr]; ok {
			fullPath := filepath.Join(cgroupRoot, ctrlr, path)
			undoPaths = append(undoPaths, fullPath)
		}
	}

	// Replace empty undo with the real thing before changes are made to cgroups.
	undo = func() {
		for _, path := range undoPaths {
			log.Debugf("Restoring cgroup %q", path)
			// Writing the value 0 to a cgroup.procs file causes
			// the writing process to be moved to the corresponding
			// cgroup. - cgroups(7).
			if err := setValue(path, "cgroup.procs", "0"); err != nil {
				log.Warningf("Error restoring cgroup %q: %v", path, err)
			}
		}
	}

	// Now join the cgroups.
	for key, cfg := range controllers {
		path := c.makePath(key)
		log.Debugf("Joining cgroup %q", path)
		// Writing the value 0 to a cgroup.procs file causes the
		// writing process to be moved to the corresponding cgroup.
		// - cgroups(7).
		if err := setValue(path, "cgroup.procs", "0"); err != nil {
			if cfg.optional && os.IsNotExist(err) {
				continue
			}
			return undo, err
		}
	}
	return undo, nil
}

// CPUQuota returns the CFS CPU quota.
func (c *Cgroup) CPUQuota() (float64, error) {
	if libcontainercgroups.IsCgroup2UnifiedMode() {
		m, err := c.cgroupv2Manager()
		if err != nil {
			return -1, err
		}

		return m.CPUQuota(c.Name)
	}

	path := c.makePath("cpu")
	quota, err := getInt(path, "cpu.cfs_quota_us")
	if err != nil {
		return -1, err
	}
	period, err := getInt(path, "cpu.cfs_period_us")
	if err != nil {
		return -1, err
	}
	if quota <= 0 || period <= 0 {
		return -1, err
	}
	return float64(quota) / float64(period), nil
}

// CPUUsage returns the total CPU usage of the cgroup.
func (c *Cgroup) CPUUsage() (uint64, error) {
	path := c.makePath("cpuacct")
	usage, err := getValue(path, "cpuacct.usage")
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(usage), 10, 64)
}

// NumCPU returns the number of CPUs configured in 'cpuset/cpuset.cpus'.
func (c *Cgroup) NumCPU() (int, error) {
	if libcontainercgroups.IsCgroup2UnifiedMode() {
		m, err := c.cgroupv2Manager()
		if err != nil {
			return 0, err
		}

		return m.NumCPU(c.Name)
	}

	path := c.makePath("cpuset")
	cpuset, err := getValue(path, "cpuset.cpus")
	if err != nil {
		return 0, err
	}
	return countCpuset(strings.TrimSpace(cpuset))
}

// MemoryLimit returns the memory limit.
func (c *Cgroup) MemoryLimit() (uint64, error) {
	if libcontainercgroups.IsCgroup2UnifiedMode() {
		m, err := c.cgroupv2Manager()
		if err != nil {
			return 0, err
		}

		return m.MemoryLimit(c.Name)
	}

	path := c.makePath("memory")
	limStr, err := getValue(path, "memory.limit_in_bytes")
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(limStr), 10, 64)
}

func (c *Cgroup) makePath(controllerName string) string {
	path := c.Name
	if parent, ok := c.Parents[controllerName]; ok {
		path = filepath.Join(parent, c.Name)
	}
	return filepath.Join(cgroupRoot, controllerName, path)
}

type config struct {
	ctrlr    controller
	optional bool
}

type controller interface {
	set(*specs.LinuxResources, string) error
}

type noop struct{}

func (*noop) set(*specs.LinuxResources, string) error {
	return nil
}

type memory struct{}

func (*memory) set(spec *specs.LinuxResources, path string) error {
	if spec == nil || spec.Memory == nil {
		return nil
	}
	if err := setOptionalValueInt(path, "memory.limit_in_bytes", spec.Memory.Limit); err != nil {
		return err
	}
	if err := setOptionalValueInt(path, "memory.soft_limit_in_bytes", spec.Memory.Reservation); err != nil {
		return err
	}
	if err := setOptionalValueInt(path, "memory.memsw.limit_in_bytes", spec.Memory.Swap); err != nil {
		return err
	}
	if err := setOptionalValueInt(path, "memory.kmem.limit_in_bytes", spec.Memory.Kernel); err != nil {
		return err
	}
	if err := setOptionalValueInt(path, "memory.kmem.tcp.limit_in_bytes", spec.Memory.KernelTCP); err != nil {
		return err
	}
	if err := setOptionalValueUint(path, "memory.swappiness", spec.Memory.Swappiness); err != nil {
		return err
	}

	if spec.Memory.DisableOOMKiller != nil && *spec.Memory.DisableOOMKiller {
		if err := setValue(path, "memory.oom_control", "1"); err != nil {
			return err
		}
	}
	return nil
}

type cpu struct{}

func (*cpu) set(spec *specs.LinuxResources, path string) error {
	if spec == nil || spec.CPU == nil {
		return nil
	}
	if err := setOptionalValueUint(path, "cpu.shares", spec.CPU.Shares); err != nil {
		return err
	}
	if err := setOptionalValueInt(path, "cpu.cfs_quota_us", spec.CPU.Quota); err != nil {
		return err
	}
	if err := setOptionalValueUint(path, "cpu.cfs_period_us", spec.CPU.Period); err != nil {
		return err
	}
	if err := setOptionalValueUint(path, "cpu.rt_period_us", spec.CPU.RealtimePeriod); err != nil {
		return err
	}
	return setOptionalValueInt(path, "cpu.rt_runtime_us", spec.CPU.RealtimeRuntime)
}

type cpuSet struct{}

func (*cpuSet) set(spec *specs.LinuxResources, path string) error {
	// cpuset.cpus and mems are required fields, but are not set on a new cgroup.
	// If not set in the spec, get it from one of the ancestors cgroup.
	if spec == nil || spec.CPU == nil || spec.CPU.Cpus == "" {
		if _, err := fillFromAncestor(filepath.Join(path, "cpuset.cpus")); err != nil {
			return err
		}
	} else {
		if err := setValue(path, "cpuset.cpus", spec.CPU.Cpus); err != nil {
			return err
		}
	}

	if spec == nil || spec.CPU == nil || spec.CPU.Mems == "" {
		_, err := fillFromAncestor(filepath.Join(path, "cpuset.mems"))
		return err
	}
	return setValue(path, "cpuset.mems", spec.CPU.Mems)
}

type blockIO struct{}

func (*blockIO) set(spec *specs.LinuxResources, path string) error {
	if spec == nil || spec.BlockIO == nil {
		return nil
	}

	if err := setOptionalValueUint16(path, "blkio.weight", spec.BlockIO.Weight); err != nil {
		return err
	}
	if err := setOptionalValueUint16(path, "blkio.leaf_weight", spec.BlockIO.LeafWeight); err != nil {
		return err
	}

	for _, dev := range spec.BlockIO.WeightDevice {
		if dev.Weight != nil {
			val := fmt.Sprintf("%d:%d %d", dev.Major, dev.Minor, *dev.Weight)
			if err := setValue(path, "blkio.weight_device", val); err != nil {
				return err
			}
		}
		if dev.LeafWeight != nil {
			val := fmt.Sprintf("%d:%d %d", dev.Major, dev.Minor, *dev.LeafWeight)
			if err := setValue(path, "blkio.leaf_weight_device", val); err != nil {
				return err
			}
		}
	}
	if err := setThrottle(path, "blkio.throttle.read_bps_device", spec.BlockIO.ThrottleReadBpsDevice); err != nil {
		return err
	}
	if err := setThrottle(path, "blkio.throttle.write_bps_device", spec.BlockIO.ThrottleWriteBpsDevice); err != nil {
		return err
	}
	if err := setThrottle(path, "blkio.throttle.read_iops_device", spec.BlockIO.ThrottleReadIOPSDevice); err != nil {
		return err
	}
	return setThrottle(path, "blkio.throttle.write_iops_device", spec.BlockIO.ThrottleWriteIOPSDevice)
}

func setThrottle(path, name string, devs []specs.LinuxThrottleDevice) error {
	for _, dev := range devs {
		val := fmt.Sprintf("%d:%d %d", dev.Major, dev.Minor, dev.Rate)
		if err := setValue(path, name, val); err != nil {
			return err
		}
	}
	return nil
}

type networkClass struct{}

func (*networkClass) set(spec *specs.LinuxResources, path string) error {
	if spec == nil || spec.Network == nil {
		return nil
	}
	return setOptionalValueUint32(path, "net_cls.classid", spec.Network.ClassID)
}

type networkPrio struct{}

func (*networkPrio) set(spec *specs.LinuxResources, path string) error {
	if spec == nil || spec.Network == nil {
		return nil
	}
	for _, prio := range spec.Network.Priorities {
		val := fmt.Sprintf("%s %d", prio.Name, prio.Priority)
		if err := setValue(path, "net_prio.ifpriomap", val); err != nil {
			return err
		}
	}
	return nil
}

type pids struct{}

func (*pids) set(spec *specs.LinuxResources, path string) error {
	if spec == nil || spec.Pids == nil || spec.Pids.Limit <= 0 {
		return nil
	}
	val := strconv.FormatInt(spec.Pids.Limit, 10)
	return setValue(path, "pids.max", val)
}

type hugeTLB struct{}

func (*hugeTLB) set(spec *specs.LinuxResources, path string) error {
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
