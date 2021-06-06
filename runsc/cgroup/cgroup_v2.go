package cgroup

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	libcontainercgroups "github.com/opencontainers/runc/libcontainer/cgroups"
	cgroupfs2 "github.com/opencontainers/runc/libcontainer/cgroups/fs2"
	fscommon "github.com/opencontainers/runc/libcontainer/cgroups/fscommon"
	libcontainerconfigs "github.com/opencontainers/runc/libcontainer/configs"
	libcontainerutils "github.com/opencontainers/runc/libcontainer/utils"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/log"
)

type cgroupV2Manager struct {
	manager libcontainercgroups.Manager
	Path    string `json:"path"`
	Own     bool   `json:"own"`
}

// NewCgroupV2Manager returns the cgroupv2 manager. It accepts an absolute path
// in the cgroupv2 hierrachy
func NewCgroupV2Manager(cgPath string) (*cgroupV2Manager, error) {
	c := &cgroupV2Manager{
		Path: cgPath,
	}
	_, err := c.getManager(c.Path)
	if err != nil {
		return nil, err
	}
	log.Debugf("New cgroup v2 for path: %s, %+v", cgPath, c)
	return c, nil
}

// Install creates and configures cgroups according to 'res'. If cgroup path
// already exists, it means that the caller has already provided a
// pre-configured cgroups, and 'res' is ignored.
func (c *cgroupV2Manager) Install(res *specs.LinuxResources) (err error) {
	log.Debugf("Creating cgroup %q", c.Path)

	manager, err := c.getManager(c.Path)
	if err != nil {
		return err
	}

	// The Cleanup object cleans up partially created cgroups when an error occurs.
	// Errors occuring during cleanup itself are ignored.
	clean := cleanup.Make(func() { _ = c.Uninstall() })
	defer clean.Clean()

	// in unified mode, we only need to look at one path
	path := c.MakePath("")
	if _, err := os.Stat(path); err == nil {
		// If cgroup has already been created; it has been setup by caller. Don't
		// make any changes to configuration, just join when sandbox/gofer starts.
		log.Debugf("Using pre-created cgroup %q", path)
	} else {
		c.Own = true
		// Apply(-1) is a hack to create the cgroup directories for each resource
		// subsystem. The function [cgroups.Manager.apply()] applies cgroup
		// configuration to the process with the specified pid.
		// It creates cgroup files for each subsystems and writes the pid
		// in the tasks file. We use the function to create all the required
		// cgroup files but not attach any "real" pid to the cgroup.
		log.Debugf("applied cgroup %q %v %s", path, manager, c.Path)
		if err := manager.Apply(-1); err != nil {
			return err
		}

		log.Debugf("applied cgroup %q", path)

		// Update the resources config after creation
		resourcesConfig := convertResources(res)
		if err := manager.Set(resourcesConfig); err != nil {
			return err
		}
		log.Debugf("set cgroup %q", path)
	}

	clean.Release()
	return nil
}

// Uninstall removes the settings done in Install(). If cgroup path already
// existed when Install() was called, Uninstall is a noop.
func (c *cgroupV2Manager) Uninstall() error {
	log.Debugf("Deleting cgroup %q", c.Path)

	if !c.Own {
		// cgroup is managed by caller, don't touch it.
		return nil
	}

	manager, err := c.getManager(c.Path)
	if err != nil {
		return err
	}

	// If we try to remove the cgroup too soon after killing the
	// sandbox we might get EBUSY, so we retry for a few seconds
	// until it succeeds.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b := backoff.WithContext(backoff.NewConstantBackOff(100*time.Millisecond), ctx)
	fn := func() error {
		err := manager.Destroy()
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := backoff.Retry(fn, b); err != nil {
		return fmt.Errorf("removing cgroup %q: %w", c.Path, err)
	}
	return nil
}

// Join adds the current process to the all controllers. Returns function that
// restores cgroup to the original state.
func (c *cgroupV2Manager) Join() (func(), error) {
	// First save the current state so it can be restored.
	undo := func() {}
	var currentCgroup string
	currentCgroupPaths, err := loadPaths("self")
	if err != nil {
		return undo, err
	}

	// since this is unified, get the first path of current process's cgroup is enough
	currentCgroup = filepath.Join(cgroupRoot, currentCgroupPaths[cgroup2])

	// Replace empty undo with the real thing before changes are made to cgroups.
	undo = func() {
		log.Debugf("Restoring cgroup %q", currentCgroup)
		undoManager, err := cgroupfs2.NewManager(nil, currentCgroup, false)
		if err != nil {
			log.Warningf("Error restoring cgroup v2 %q: failed to create cgroupfs2 manager %v", currentCgroup, err)
		}
		if err := undoManager.Apply(0); err != nil {
			log.Warningf("Error restoring cgroup v2 %q: %v", currentCgroup, err)
		}
	}

	manager, err := c.getManager(c.Path)
	if err != nil {
		return undo, err
	}

	log.Warningf("joining cgroup %+v: %s", c.manager, c.Path)
	// Now join the cgroups.
	err = manager.Apply(0)
	return undo, err
}

// CPUQuota returns the CFS CPU quota.
func (c *cgroupV2Manager) CPUQuota() (float64, error) {
	manager, err := c.getManager(c.Path)
	if err != nil {
		return -1, err
	}
	cpuMax, err := getValue(manager.Path(""), "cpu.max")
	if err != nil {
		return -1, err
	}

	data := strings.SplitN(cpuMax, " ", 2)
	if len(data) != 2 {
		return -1, fmt.Errorf("invalid cpu.max data %q", cpuMax)
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

func (c *cgroupV2Manager) CPUUsage() (uint64, error) {
	manager, err := c.getManager(c.Path)
	if err != nil {
		return 0, err
	}
	cpuStat, err := getValue(manager.Path(""), "cpu.stat")
	if err != nil {
		return 0, err
	}

	sc := bufio.NewScanner(strings.NewReader(cpuStat))
	for sc.Scan() {
		key, value, err := fscommon.ParseKeyValue(sc.Text())
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
func (c *cgroupV2Manager) NumCPU() (int, error) {
	manager, err := c.getManager(c.Path)
	if err != nil {
		return -1, err
	}
	cpuset, err := getValue(manager.Path(""), "cpuset.cpus.effective")
	if err != nil {
		return 0, err
	}
	return countCpuset(strings.TrimSpace(cpuset))
}

// MemoryLimit returns the memory limit.
func (c *cgroupV2Manager) MemoryLimit() (uint64, error) {
	manager, err := c.getManager(c.Path)
	if err != nil {
		return 0, err
	}
	limStr, err := getValue(manager.Path(""), "memory.max")
	if err != nil {
		return 0, err
	}
	limStr = strings.TrimSpace(limStr)
	if limStr == "max" {
		return math.MaxUint64, nil
	}
	return strconv.ParseUint(limStr, 10, 64)
}

// MakePath returns the absolute path for the cgroup in unified hierrachy
func (c *cgroupV2Manager) MakePath(_ string) string {
	return filepath.Join(cgroupRoot, c.Path)
}

func (c *cgroupV2Manager) getManager(p string) (libcontainercgroups.Manager, error) {
	if c.manager == nil {
		dirPath := filepath.Join(cgroupRoot, p)
		manager, err := cgroupfs2.NewManager(newCgroupConfig(p), dirPath, false)
		if err != nil {
			return nil, err
		}
		c.manager = manager
	}

	return c.manager, nil
}

func newCgroupConfig(p string) *libcontainerconfigs.Cgroup {
	p = libcontainerutils.CleanPath(p)
	return &libcontainerconfigs.Cgroup{
		Resources: &libcontainerconfigs.Resources{SkipDevices: true},
		Path:      p,
	}
}

func convertResources(r *specs.LinuxResources) *libcontainerconfigs.Resources {
	c := &libcontainerconfigs.Resources{SkipDevices: true}
	if r == nil {
		return c
	}

	// We do not support setting kernel memory limit
	// https://github.com/opencontainers/runc/pull/2840
	if r.Memory != nil {
		if r.Memory.Limit != nil {
			c.Memory = *r.Memory.Limit
		}
		if r.Memory.Reservation != nil {
			c.MemoryReservation = *r.Memory.Reservation
		}
		if r.Memory.Swap != nil {
			c.MemorySwap = *r.Memory.Swap
		}
		if r.Memory.DisableOOMKiller != nil {
			c.OomKillDisable = *r.Memory.DisableOOMKiller
		}
	}
	if r.CPU != nil {
		if r.CPU.Shares != nil {
			c.CpuShares = *r.CPU.Shares

			//CpuWeight is used for cgroupv2 and should be converted
			c.CpuWeight = libcontainercgroups.ConvertCPUSharesToCgroupV2Value(c.CpuShares)
		}
		if r.CPU.Quota != nil {
			c.CpuQuota = *r.CPU.Quota
		}
		if r.CPU.Period != nil {
			c.CpuPeriod = *r.CPU.Period
		}
		if r.CPU.RealtimeRuntime != nil {
			c.CpuRtRuntime = *r.CPU.RealtimeRuntime
		}
		if r.CPU.RealtimePeriod != nil {
			c.CpuRtPeriod = *r.CPU.RealtimePeriod
		}
		if r.CPU.Cpus != "" {
			c.CpusetCpus = r.CPU.Cpus
		}
		if r.CPU.Mems != "" {
			c.CpusetMems = r.CPU.Mems
		}
	}
	if r.Pids != nil {
		c.PidsLimit = r.Pids.Limit
	}
	if r.BlockIO != nil {
		if r.BlockIO.Weight != nil {
			c.BlkioWeight = *r.BlockIO.Weight
		}
		if r.BlockIO.LeafWeight != nil {
			c.BlkioLeafWeight = *r.BlockIO.LeafWeight
		}
		if r.BlockIO.WeightDevice != nil {
			for _, wd := range r.BlockIO.WeightDevice {
				var weight, leafWeight uint16
				if wd.Weight != nil {
					weight = *wd.Weight
				}
				if wd.LeafWeight != nil {
					leafWeight = *wd.LeafWeight
				}
				weightDevice := libcontainerconfigs.NewWeightDevice(wd.Major, wd.Minor, weight, leafWeight)
				c.BlkioWeightDevice = append(c.BlkioWeightDevice, weightDevice)
			}
		}
		if r.BlockIO.WeightDevice != nil {
			for _, wd := range r.BlockIO.WeightDevice {
				var weight, leafWeight uint16
				if wd.Weight != nil {
					weight = *wd.Weight
				}
				if wd.LeafWeight != nil {
					leafWeight = *wd.LeafWeight
				}
				weightDevice := libcontainerconfigs.NewWeightDevice(wd.Major, wd.Minor, weight, leafWeight)
				c.BlkioWeightDevice = append(c.BlkioWeightDevice, weightDevice)
			}
		}
		if r.BlockIO.ThrottleReadBpsDevice != nil {
			for _, td := range r.BlockIO.ThrottleReadBpsDevice {
				rate := td.Rate
				throttleDevice := libcontainerconfigs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.BlkioThrottleReadBpsDevice = append(c.BlkioThrottleReadBpsDevice, throttleDevice)
			}
		}
		if r.BlockIO.ThrottleWriteBpsDevice != nil {
			for _, td := range r.BlockIO.ThrottleWriteBpsDevice {
				rate := td.Rate
				throttleDevice := libcontainerconfigs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.BlkioThrottleWriteBpsDevice = append(c.BlkioThrottleWriteBpsDevice, throttleDevice)
			}
		}
		if r.BlockIO.ThrottleReadIOPSDevice != nil {
			for _, td := range r.BlockIO.ThrottleReadIOPSDevice {
				rate := td.Rate
				throttleDevice := libcontainerconfigs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.BlkioThrottleReadIOPSDevice = append(c.BlkioThrottleReadIOPSDevice, throttleDevice)
			}
		}
		if r.BlockIO.ThrottleWriteIOPSDevice != nil {
			for _, td := range r.BlockIO.ThrottleWriteIOPSDevice {
				rate := td.Rate
				throttleDevice := libcontainerconfigs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.BlkioThrottleWriteIOPSDevice = append(c.BlkioThrottleWriteIOPSDevice, throttleDevice)
			}
		}
	}
	for _, l := range r.HugepageLimits {
		c.HugetlbLimit = append(c.HugetlbLimit, &libcontainerconfigs.HugepageLimit{
			Pagesize: l.Pagesize,
			Limit:    l.Limit,
		})
	}
	if r.Network != nil {
		if r.Network.ClassID != nil {
			c.NetClsClassid = *r.Network.ClassID
		}
		for _, m := range r.Network.Priorities {
			c.NetPrioIfpriomap = append(c.NetPrioIfpriomap, &libcontainerconfigs.IfPrioMap{
				Interface: m.Name,
				Priority:  int64(m.Priority),
			})
		}
	}

	return c
}
