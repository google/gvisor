// Copyright 2018 Google LLC
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
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cenkalti/backoff"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/runsc/specutils"
)

const (
	cgroupRoot = "/sys/fs/cgroup"
)

var controllers = map[string]controller{
	"blkio":    &blockIO{},
	"cpu":      &cpu{},
	"cpuset":   &cpuSet{},
	"memory":   &memory{},
	"net_cls":  &networkClass{},
	"net_prio": &networkPrio{},

	// These controllers either don't have anything in the OCI spec or is
	// irrevalant for a sandbox, e.g. pids.
	"devices":    &noop{},
	"freezer":    &noop{},
	"perf_event": &noop{},
	"pids":       &noop{},
	"systemd":    &noop{},
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
	return ioutil.WriteFile(fullpath, []byte(data), 0700)
}

func getValue(path, name string) (string, error) {
	fullpath := filepath.Join(path, name)
	out, err := ioutil.ReadFile(fullpath)
	if err != nil {
		return "", err
	}
	return string(out), nil
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

	// File is not set, recurse to parent and then  set here.
	name := filepath.Base(path)
	parent := filepath.Dir(filepath.Dir(path))
	val, err = fillFromAncestor(filepath.Join(parent, name))
	if err != nil {
		return "", err
	}
	if err := ioutil.WriteFile(path, []byte(val), 0700); err != nil {
		return "", err
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

// Cgroup represents a group inside all controllers. For example: Name='/foo/bar'
// maps to /sys/fs/cgroup/<controller>/foo/bar on all controllers.
type Cgroup struct {
	Name string `json:"name"`
	Own  bool   `json:"own"`
}

// New creates a new Cgroup instance if the spec includes a cgroup path.
// Otherwise it returns nil and false.
func New(spec *specs.Spec) (*Cgroup, bool) {
	if spec.Linux == nil || spec.Linux.CgroupsPath == "" {
		return nil, false
	}
	return &Cgroup{Name: spec.Linux.CgroupsPath}, true
}

// Install creates and configures cgroups according to 'res'. If cgroup path
// already exists, it means that the caller has already provided a
// pre-configured cgroups, and 'res' is ignored.
func (c *Cgroup) Install(res *specs.LinuxResources) error {
	if _, err := os.Stat(c.makePath("memory")); err == nil {
		// If cgroup has already been created; it has been setup by caller. Don't
		// make any changes to configuration, just join when sandbox/gofer starts.
		log.Debugf("Using pre-created cgroup %q", c.Name)
		return nil
	}

	// Mark that cgroup resources are owned by me.
	log.Debugf("Creating cgroup %q", c.Name)
	c.Own = true
	// The Cleanup object cleans up partially created cgroups when an error occurs.
	// Errors occuring during cleanup itself are ignored.
	clean := specutils.MakeCleanup(func() { _ = c.Uninstall() })
	defer clean.Clean()

	for key, ctrl := range controllers {
		path := c.makePath(key)
		if err := os.MkdirAll(path, 0755); err != nil {
			return err
		}
		if res != nil {
			if err := ctrl.set(res, path); err != nil {
				return err
			}
		}
	}
	clean.Release()
	return nil
}

// Uninstall removes the settings done in Install(). If cgroup path already
// existed when Install() was called, Uninstall is a noop.
func (c *Cgroup) Uninstall() error {
	if !c.Own {
		// cgroup is managed by caller, don't touch it.
		return nil
	}
	log.Debugf("Deleting cgroup %q", c.Name)
	for key := range controllers {
		path := c.makePath(key)
		log.Debugf("Removing cgroup controller for key=%q path=%q", key, path)

		// If we try to remove the cgroup too soon after killing the
		// sandbox we might get EBUSY, so we retry for a few seconds
		// until it succeeds.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		b := backoff.WithContext(backoff.NewConstantBackOff(100*time.Millisecond), ctx)
		if err := backoff.Retry(func() error {
			return syscall.Rmdir(path)
		}, b); err != nil {
			return fmt.Errorf("error removing cgroup path %q: %v", path, err)
		}
	}
	return nil
}

// Add adds given process to all controllers.
func (c *Cgroup) Add(pid int) error {
	for key := range controllers {
		if err := setValue(c.makePath(key), "cgroup.procs", strconv.Itoa(pid)); err != nil {
			return err
		}
	}
	return nil
}

// NumCPU returns the number of CPUs configured in 'cpuset/cpuset.cpus'.
func (c *Cgroup) NumCPU() (int, error) {
	path := c.makePath("cpuset")
	cpuset, err := getValue(path, "cpuset.cpus")
	if err != nil {
		return 0, err
	}
	return countCpuset(strings.TrimSpace(cpuset))
}

// MemoryLimit returns the memory limit.
func (c *Cgroup) MemoryLimit() (uint64, error) {
	path := c.makePath("memory")
	limStr, err := getValue(path, "memory.limit_in_bytes")
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(limStr), 10, 64)
}

func (c *Cgroup) makePath(controllerName string) string {
	return filepath.Join(cgroupRoot, controllerName, c.Name)
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
	if spec.Memory == nil {
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
	if spec.CPU == nil {
		return nil
	}
	if err := setOptionalValueUint(path, "cpu.shares", spec.CPU.Shares); err != nil {
		return err
	}
	if err := setOptionalValueInt(path, "cpu.cfs_quota_us", spec.CPU.Quota); err != nil {
		return err
	}
	return setOptionalValueUint(path, "cpu.cfs_period_us", spec.CPU.Period)
}

type cpuSet struct{}

func (*cpuSet) set(spec *specs.LinuxResources, path string) error {
	// cpuset.cpus and mems are required fields, but are not set on a new cgroup.
	// If not set in the spec, get it from one of the ancestors cgroup.
	if spec.CPU == nil || spec.CPU.Cpus == "" {
		if _, err := fillFromAncestor(filepath.Join(path, "cpuset.cpus")); err != nil {
			return err
		}
	} else {
		if err := setValue(path, "cpuset.cpus", spec.CPU.Cpus); err != nil {
			return err
		}
	}

	if spec.CPU == nil || spec.CPU.Mems == "" {
		_, err := fillFromAncestor(filepath.Join(path, "cpuset.mems"))
		return err
	}
	mems := spec.CPU.Mems
	return setValue(path, "cpuset.mems", mems)
}

type blockIO struct{}

func (*blockIO) set(spec *specs.LinuxResources, path string) error {
	if spec.BlockIO == nil {
		return nil
	}

	if err := setOptionalValueUint16(path, "blkio.weight", spec.BlockIO.Weight); err != nil {
		return err
	}
	if err := setOptionalValueUint16(path, "blkio.leaf_weight", spec.BlockIO.LeafWeight); err != nil {
		return err
	}

	for _, dev := range spec.BlockIO.WeightDevice {
		val := fmt.Sprintf("%d:%d %d", dev.Major, dev.Minor, dev.Weight)
		if err := setValue(path, "blkio.weight_device", val); err != nil {
			return err
		}
		val = fmt.Sprintf("%d:%d %d", dev.Major, dev.Minor, dev.LeafWeight)
		if err := setValue(path, "blkio.leaf_weight_device", val); err != nil {
			return err
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
	if spec.Network == nil {
		return nil
	}
	return setOptionalValueUint32(path, "net_cls.classid", spec.Network.ClassID)
}

type networkPrio struct{}

func (*networkPrio) set(spec *specs.LinuxResources, path string) error {
	if spec.Network == nil {
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
