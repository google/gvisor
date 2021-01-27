package cgroup

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	libcontainercgroups "github.com/opencontainers/runc/libcontainer/cgroups"
	cgroupfs2 "github.com/opencontainers/runc/libcontainer/cgroups/fs2"
	libcontainerconfigs "github.com/opencontainers/runc/libcontainer/configs"
	libcontainerutils "github.com/opencontainers/runc/libcontainer/utils"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/log"
)

type cgroupV2Manager struct {
	manager libcontainercgroups.Manager
}

func NewCgroupV2Manager(name string) (*cgroupV2Manager, error) {
	config := newCgroupConfig(name)
	manager, err := cgroupfs2.NewManager(config, "", false)
	if err != nil {
		return nil, err
	}

	log.Debugf("got manager in NEW %v %s", manager, name)
	return &cgroupV2Manager{
		manager: manager,
	}, nil
}

// Install creates and configures cgroups according to 'res'. If cgroup path
// already exists, it means that the caller has already provided a
// pre-configured cgroups, and 'res' is ignored.
func (c *cgroupV2Manager) Install(name string, res *specs.LinuxResources) (owned bool, err error) {
	log.Debugf("Creating cgroup %q", name)

	manager, err := c.getManager(name)
	if err != nil {
		return false, err
	}

	// The Cleanup object cleans up partially created cgroups when an error occurs.
	// Errors occuring during cleanup itself are ignored.
	clean := cleanup.Make(func() { _ = c.Uninstall(name, owned) })
	defer clean.Clean()

	// in unified mode, we only need to look at one path
	path := buildCgroupUnifiedPath(name)
	if _, err := os.Stat(path); err == nil {
		// If cgroup has already been created; it has been setup by caller. Don't
		// make any changes to configuration, just join when sandbox/gofer starts.
		log.Debugf("Using pre-created cgroup %q", path)
	} else {
		owned = true
		// Apply(-1) is a hack to create the cgroup directories for each resource
		// subsystem. The function [cgroups.Manager.apply()] applies cgroup
		// configuration to the process with the specified pid.
		// It creates cgroup files for each subsystems and writes the pid
		// in the tasks file. We use the function to create all the required
		// cgroup files but not attach any "real" pid to the cgroup.
		log.Debugf("applied cgroup %q %v %s", path, manager, name)
		if err := manager.Apply(-1); err != nil {
			return owned, err
		}

		log.Debugf("applied cgroup %q", path)

		// Update the resources config after creation
		resourcesConfig, err := createCgroupConfigFromResources(name, res)
		if err != nil {
			return owned, err
		}

		if err := manager.Set(&libcontainerconfigs.Config{
			Cgroups: resourcesConfig,
		}); err != nil {
			return owned, err
		}
		log.Debugf("set cgroup %q", path)
	}

	clean.Release()
	return owned, nil
}

// Uninstall removes the settings done in Install(). If cgroup path already
// existed when Install() was called, Uninstall is a noop.
func (c *cgroupV2Manager) Uninstall(name string, owned bool) error {
	log.Debugf("Deleting cgroup %q", name)

	if !owned {
		// cgroup is managed by caller, don't touch it.
		return nil
	}

	manager, err := c.getManager(name)
	if err != nil {
		return err
	}

	return manager.Destroy()
}

// Join adds the current process to the all controllers. Returns function that
// restores cgroup to the original state.
func (c *cgroupV2Manager) Join(name string) (func(), error) {
	// First save the current state so it can be restored.
	undo := func() {}
	var currentCgroup string
	currentCgroupPaths, err := LoadPaths("self")
	if err != nil {
		return undo, err
	}

	// since this is unified, get the first path of current process's cgroup is enough
	for _, v := range currentCgroupPaths {
		currentCgroup = filepath.Join(cgroupRoot, v)
		break
	}

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

	manager, err := c.getManager(name)
	if err != nil {
		return undo, err
	}

	log.Warningf("joining cgroup %+v: %s", c.manager, name)
	// Now join the cgroups.
	err = manager.Apply(0)
	return undo, err
}

// CPUQuota returns the CFS CPU quota.
func (c *cgroupV2Manager) CPUQuota(name string) (float64, error) {
	manager, err := c.getManager(name)
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

// NumCPU returns the number of CPUs configured in 'cpuset/cpuset.cpus'.
func (c *cgroupV2Manager) NumCPU(name string) (int, error) {
	manager, err := c.getManager(name)
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
func (c *cgroupV2Manager) MemoryLimit(name string) (uint64, error) {
	manager, err := c.getManager(name)
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

func (c *cgroupV2Manager) getManager(name string) (libcontainercgroups.Manager, error) {
	if c.manager == nil {
		manager, err := cgroupfs2.NewManager(newCgroupConfig(name), "", false)
		if err != nil {
			return nil, err
		}
		c.manager = manager
	}

	return c.manager, nil
}

func newCgroupConfig(name string) *libcontainerconfigs.Cgroup {
	name = libcontainerutils.CleanPath(name)
	return &libcontainerconfigs.Cgroup{
		Resources: &libcontainerconfigs.Resources{SkipDevices: true},
		Name:      name,
	}
}

func createCgroupConfigFromResources(name string, r *specs.LinuxResources) (*libcontainerconfigs.Cgroup, error) {
	c := &libcontainerconfigs.Cgroup{
		Name:      name,
		Resources: &libcontainerconfigs.Resources{SkipDevices: true},
	}

	if r == nil {
		return c, nil
	}

	if r.Memory != nil {
		if r.Memory.Limit != nil {
			c.Resources.Memory = *r.Memory.Limit
		}
		if r.Memory.Reservation != nil {
			c.Resources.MemoryReservation = *r.Memory.Reservation
		}
		if r.Memory.Swap != nil {
			c.Resources.MemorySwap = *r.Memory.Swap
		}
		if r.Memory.Kernel != nil {
			c.Resources.KernelMemory = *r.Memory.Kernel
		}
		if r.Memory.KernelTCP != nil {
			c.Resources.KernelMemoryTCP = *r.Memory.KernelTCP
		}
		if r.Memory.Swappiness != nil {
			c.Resources.MemorySwappiness = r.Memory.Swappiness
		}
		if r.Memory.DisableOOMKiller != nil {
			c.Resources.OomKillDisable = *r.Memory.DisableOOMKiller
		}
	}
	if r.CPU != nil {
		if r.CPU.Shares != nil {
			c.Resources.CpuShares = *r.CPU.Shares

			//CpuWeight is used for cgroupv2 and should be converted
			c.Resources.CpuWeight = libcontainercgroups.ConvertCPUSharesToCgroupV2Value(c.Resources.CpuShares)
		}
		if r.CPU.Quota != nil {
			c.Resources.CpuQuota = *r.CPU.Quota
		}
		if r.CPU.Period != nil {
			c.Resources.CpuPeriod = *r.CPU.Period
		}
		if r.CPU.RealtimeRuntime != nil {
			c.Resources.CpuRtRuntime = *r.CPU.RealtimeRuntime
		}
		if r.CPU.RealtimePeriod != nil {
			c.Resources.CpuRtPeriod = *r.CPU.RealtimePeriod
		}
		if r.CPU.Cpus != "" {
			c.Resources.CpusetCpus = r.CPU.Cpus
		}
		if r.CPU.Mems != "" {
			c.Resources.CpusetMems = r.CPU.Mems
		}
	}
	if r.Pids != nil {
		c.Resources.PidsLimit = r.Pids.Limit
	}
	if r.BlockIO != nil {
		if r.BlockIO.Weight != nil {
			c.Resources.BlkioWeight = *r.BlockIO.Weight
		}
		if r.BlockIO.LeafWeight != nil {
			c.Resources.BlkioLeafWeight = *r.BlockIO.LeafWeight
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
				c.Resources.BlkioWeightDevice = append(c.Resources.BlkioWeightDevice, weightDevice)
			}
		}
		if r.BlockIO.ThrottleReadBpsDevice != nil {
			for _, td := range r.BlockIO.ThrottleReadBpsDevice {
				rate := td.Rate
				throttleDevice := libcontainerconfigs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.Resources.BlkioThrottleReadBpsDevice = append(c.Resources.BlkioThrottleReadBpsDevice, throttleDevice)
			}
		}
		if r.BlockIO.ThrottleWriteBpsDevice != nil {
			for _, td := range r.BlockIO.ThrottleWriteBpsDevice {
				rate := td.Rate
				throttleDevice := libcontainerconfigs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.Resources.BlkioThrottleWriteBpsDevice = append(c.Resources.BlkioThrottleWriteBpsDevice, throttleDevice)
			}
		}
		if r.BlockIO.ThrottleReadIOPSDevice != nil {
			for _, td := range r.BlockIO.ThrottleReadIOPSDevice {
				rate := td.Rate
				throttleDevice := libcontainerconfigs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.Resources.BlkioThrottleReadIOPSDevice = append(c.Resources.BlkioThrottleReadIOPSDevice, throttleDevice)
			}
		}
		if r.BlockIO.ThrottleWriteIOPSDevice != nil {
			for _, td := range r.BlockIO.ThrottleWriteIOPSDevice {
				rate := td.Rate
				throttleDevice := libcontainerconfigs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.Resources.BlkioThrottleWriteIOPSDevice = append(c.Resources.BlkioThrottleWriteIOPSDevice, throttleDevice)
			}
		}
	}
	for _, l := range r.HugepageLimits {
		c.Resources.HugetlbLimit = append(c.Resources.HugetlbLimit, &libcontainerconfigs.HugepageLimit{
			Pagesize: l.Pagesize,
			Limit:    l.Limit,
		})
	}
	if r.Network != nil {
		if r.Network.ClassID != nil {
			c.Resources.NetClsClassid = *r.Network.ClassID
		}
		for _, m := range r.Network.Priorities {
			c.Resources.NetPrioIfpriomap = append(c.Resources.NetPrioIfpriomap, &libcontainerconfigs.IfPrioMap{
				Interface: m.Name,
				Priority:  int64(m.Priority),
			})
		}
	}

	return c, nil
}

func buildCgroupUnifiedPath(name string) string {
	return filepath.Join(cgroupRoot, name)
}
