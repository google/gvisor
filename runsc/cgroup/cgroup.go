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
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/log"
)

const (
	cgroupRoot = "/sys/fs/cgroup"
)

var controllers = map[string]controller{
	"blkio":    &blockIO{},
	"cpu":      &cpu{},
	"cpuset":   &cpuSet{},
	"hugetlb":  &hugeTLB{},
	"memory":   &memory{},
	"net_cls":  &networkClass{},
	"net_prio": &networkPrio{},
	"pids":     &pids{},

	// These controllers either don't have anything in the OCI spec or is
	// irrelevant for a sandbox.
	"cpuacct":    &noop{},
	"devices":    &noop{},
	"freezer":    &noop{},
	"perf_event": &noop{},
	"rdma":       &noop{isOptional: true},
	"systemd":    &noop{},
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

// loadPaths loads cgroup paths for given 'pid', may be set to 'self'.
func loadPaths(pid string) (map[string]string, error) {
	procCgroup, err := os.Open(filepath.Join("/proc", pid, "cgroup"))
	if err != nil {
		return nil, err
	}
	defer procCgroup.Close()

	// Load mountinfo for the current process, because it's where cgroups is
	// being accessed from.
	mountinfo, err := os.Open(filepath.Join("/proc/self/mountinfo"))
	if err != nil {
		return nil, err
	}
	defer mountinfo.Close()

	return loadPathsHelper(procCgroup, mountinfo)
}

func loadPathsHelper(cgroup, mountinfo io.Reader) (map[string]string, error) {
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
			// Discard unknown controllers.
			if _, ok := controllers[ctrlr]; ok {
				paths[ctrlr] = tokens[2]
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// For nested containers, in /proc/[pid]/cgroup we see paths from host,
	// which don't exist in container, so recover the container paths here by
	// double-checking with /proc/[pid]/mountinfo
	mountScanner := bufio.NewScanner(mountinfo)
	for mountScanner.Scan() {
		// Format: ID parent major:minor root mount-point options opt-fields - fs-type source super-options
		// Example: 39 32 0:34 / /sys/fs/cgroup/devices rw,noexec shared:18 - cgroup cgroup rw,devices
		fields := strings.Fields(mountScanner.Text())
		if len(fields) < 9 || fields[len(fields)-3] != "cgroup" {
			// Skip mounts that are not cgroup mounts.
			continue
		}
		// Cgroup controller type is in the super-options field.
		superOptions := strings.Split(fields[len(fields)-1], ",")
		for _, opt := range superOptions {
			// Remove prefix for cgroups with no controller, eg. systemd.
			opt = strings.TrimPrefix(opt, "name=")

			// Only considers cgroup controllers that are registered, and skip other
			// irrelevant options, e.g. rw.
			if cgroupPath, ok := paths[opt]; ok {
				rootDir := fields[3]
				if rootDir != "/" {
					// When cgroup is in submount, remove repeated path components from
					// cgroup path to avoid duplicating them.
					relCgroupPath, err := filepath.Rel(rootDir, cgroupPath)
					if err != nil {
						return nil, err
					}
					paths[opt] = relCgroupPath
				}
			}
		}
	}
	if err := mountScanner.Err(); err != nil {
		return nil, err
	}

	return paths, nil
}

// Cgroup represents a group inside all controllers. For example:
//   Name='/foo/bar' maps to /sys/fs/cgroup/<controller>/foo/bar on
//   all controllers.
//
// If Name is relative, it uses the parent cgroup path to determine the
// location. For example:
//   Name='foo/bar' and Parent[ctrl]="/user.slice", then it will map to
//   /sys/fs/cgroup/<ctrl>/user.slice/foo/bar
type Cgroup struct {
	Name    string            `json:"name"`
	Parents map[string]string `json:"parents"`
	Own     map[string]bool   `json:"own"`
}

// NewFromSpec creates a new Cgroup instance if the spec includes a cgroup path.
// Returns nil otherwise. Cgroup paths are loaded based on the current process.
func NewFromSpec(spec *specs.Spec) (*Cgroup, error) {
	if spec.Linux == nil || spec.Linux.CgroupsPath == "" {
		return nil, nil
	}
	return new("self", spec.Linux.CgroupsPath)
}

// NewFromPid loads cgroup for the given process.
func NewFromPid(pid int) (*Cgroup, error) {
	return new(strconv.Itoa(pid), "")
}

func new(pid, cgroupsPath string) (*Cgroup, error) {
	var parents map[string]string

	// If path is relative, load cgroup paths for the process to build the
	// relative paths.
	if !filepath.IsAbs(cgroupsPath) {
		var err error
		parents, err = loadPaths(pid)
		if err != nil {
			return nil, fmt.Errorf("finding current cgroups: %w", err)
		}
	}
	cg := &Cgroup{
		Name:    cgroupsPath,
		Parents: parents,
		Own:     make(map[string]bool),
	}
	log.Debugf("New cgroup for pid: %s, %+v", pid, cg)
	return cg, nil
}

// Install creates and configures cgroups according to 'res'. If cgroup path
// already exists, it means that the caller has already provided a
// pre-configured cgroups, and 'res' is ignored.
func (c *Cgroup) Install(res *specs.LinuxResources) error {
	log.Debugf("Installing cgroup path %q", c.Name)

	// Clean up partially created cgroups on error. Errors during cleanup itself
	// are ignored.
	clean := cleanup.Make(func() { _ = c.Uninstall() })
	defer clean.Clean()

	// Controllers can be symlinks to a group of controllers (e.g. cpu,cpuacct).
	// So first check what directories need to be created. Otherwise, when
	// the directory for one of the controllers in a group is created, it will
	// make it seem like the directory already existed and it's not owned by the
	// other controllers in the group.
	var missing []string
	for key := range controllers {
		path := c.MakePath(key)
		if _, err := os.Stat(path); err != nil {
			missing = append(missing, key)
		} else {
			log.Debugf("Using pre-created cgroup %q: %q", key, path)
		}
	}
	for _, key := range missing {
		ctrlr := controllers[key]
		path := c.MakePath(key)
		log.Debugf("Creating cgroup %q: %q", key, path)
		if err := os.MkdirAll(path, 0755); err != nil {
			if ctrlr.optional() && errors.Is(err, unix.EROFS) {
				if err := ctrlr.skip(res); err != nil {
					return err
				}
				log.Infof("Skipping cgroup %q", key)
				continue
			}
			return err
		}

		// Only set controllers that were created by me.
		c.Own[key] = true
		if err := ctrlr.set(res, path); err != nil {
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
	for key := range controllers {
		if !c.Own[key] {
			// cgroup is managed by caller, don't touch it.
			continue
		}
		path := c.MakePath(key)
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
	// First save the current state so it can be restored.
	paths, err := loadPaths("self")
	if err != nil {
		return nil, err
	}
	var undoPaths []string
	for ctrlr, path := range paths {
		// Skip controllers we don't handle.
		if _, ok := controllers[ctrlr]; ok {
			fullPath := filepath.Join(cgroupRoot, ctrlr, path)
			undoPaths = append(undoPaths, fullPath)
		}
	}

	cu := cleanup.Make(func() {
		for _, path := range undoPaths {
			log.Debugf("Restoring cgroup %q", path)
			// Writing the value 0 to a cgroup.procs file causes
			// the writing process to be moved to the corresponding
			// cgroup. - cgroups(7).
			if err := setValue(path, "cgroup.procs", "0"); err != nil {
				log.Warningf("Error restoring cgroup %q: %v", path, err)
			}
		}
	})
	defer cu.Clean()

	// Now join the cgroups.
	for key, ctrlr := range controllers {
		path := c.MakePath(key)
		log.Debugf("Joining cgroup %q", path)
		// Writing the value 0 to a cgroup.procs file causes the writing process to
		// be moved to the corresponding cgroup - cgroups(7).
		if err := setValue(path, "cgroup.procs", "0"); err != nil {
			if ctrlr.optional() && os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
	}
	return cu.Release(), nil
}

// CPUQuota returns the CFS CPU quota.
func (c *Cgroup) CPUQuota() (float64, error) {
	path := c.MakePath("cpu")
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
	path := c.MakePath("cpuacct")
	usage, err := getValue(path, "cpuacct.usage")
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(usage), 10, 64)
}

// NumCPU returns the number of CPUs configured in 'cpuset/cpuset.cpus'.
func (c *Cgroup) NumCPU() (int, error) {
	path := c.MakePath("cpuset")
	cpuset, err := getValue(path, "cpuset.cpus")
	if err != nil {
		return 0, err
	}
	return countCpuset(strings.TrimSpace(cpuset))
}

// MemoryLimit returns the memory limit.
func (c *Cgroup) MemoryLimit() (uint64, error) {
	path := c.MakePath("memory")
	limStr, err := getValue(path, "memory.limit_in_bytes")
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(limStr), 10, 64)
}

// MakePath builds a path to the given controller.
func (c *Cgroup) MakePath(controllerName string) string {
	path := c.Name
	if parent, ok := c.Parents[controllerName]; ok {
		path = filepath.Join(parent, c.Name)
	}
	return filepath.Join(cgroupRoot, controllerName, path)
}

type controller interface {
	// optional controllers don't fail if not found.
	optional() bool
	// set applies resource limits to controller.
	set(*specs.LinuxResources, string) error
	// skip is called when controller is not found to check if it can be safely
	// skipped or not based on the spec.
	skip(*specs.LinuxResources) error
}

type noop struct {
	isOptional bool
}

func (n *noop) optional() bool {
	return n.isOptional
}

func (*noop) set(*specs.LinuxResources, string) error {
	return nil
}

func (n *noop) skip(*specs.LinuxResources) error {
	if !n.isOptional {
		panic("cgroup controller is not optional")
	}
	return nil
}

type mandatory struct{}

func (*mandatory) optional() bool {
	return false
}

func (*mandatory) skip(*specs.LinuxResources) error {
	panic("cgroup controller is not optional")
}

type memory struct {
	mandatory
}

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

type cpu struct {
	mandatory
}

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

type cpuSet struct {
	mandatory
}

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

type blockIO struct {
	mandatory
}

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

func (*networkClass) optional() bool {
	return true
}

func (*networkClass) set(spec *specs.LinuxResources, path string) error {
	if spec == nil || spec.Network == nil {
		return nil
	}
	return setOptionalValueUint32(path, "net_cls.classid", spec.Network.ClassID)
}

func (*networkClass) skip(spec *specs.LinuxResources) error {
	if spec != nil && spec.Network != nil && spec.Network.ClassID != nil {
		return fmt.Errorf("Network.ClassID set but net_cls cgroup controller not found")
	}
	return nil
}

type networkPrio struct{}

func (*networkPrio) optional() bool {
	return true
}

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

func (*networkPrio) skip(spec *specs.LinuxResources) error {
	if spec != nil && spec.Network != nil && len(spec.Network.Priorities) > 0 {
		return fmt.Errorf("Network.Priorities set but net_prio cgroup controller not found")
	}
	return nil
}

type pids struct {
	mandatory
}

func (*pids) set(spec *specs.LinuxResources, path string) error {
	if spec == nil || spec.Pids == nil || spec.Pids.Limit <= 0 {
		return nil
	}
	val := strconv.FormatInt(spec.Pids.Limit, 10)
	return setValue(path, "pids.max", val)
}

type hugeTLB struct{}

func (*hugeTLB) optional() bool {
	return true
}

func (*hugeTLB) skip(spec *specs.LinuxResources) error {
	if spec != nil && len(spec.HugepageLimits) > 0 {
		return fmt.Errorf("HugepageLimits set but hugetlb cgroup controller not found")
	}
	return nil
}

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
