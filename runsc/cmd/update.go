// Copyright 2022 The gVisor Authors.
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

package cmd

import (
	"context"
	"encoding/json"
	"os"
	"strconv"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

func i64Ptr(i int64) *int64   { return &i }
func u64Ptr(i uint64) *uint64 { return &i }
func u16Ptr(i uint16) *uint16 { return &i }
func boolPtr(b bool) *bool    { return &b }

// Update implements subcommands.Command for the "update" command.
type Update struct {
	resources string

	blkioWeight int

	cpuBurst     string
	cpuIdle      string
	cpuPeriod    string
	cpuQuota     string
	cpuRtPeriod  string
	cpuRtRuntime string
	cpuShares    string
	cpusetCpus   string
	cpusetMems   string

	memory            string
	memoryReservation string
	memorySwap        string

	pidsLimit int64

	l3CacheSchema string
	memBwSchema   string
}

// Name implements subcommands.Command.Name.
func (*Update) Name() string {
	return "update"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Update) Synopsis() string {
	return "update container resource constraints"
}

// Usage implements subcommands.Command.Usage.
func (*Update) Usage() string {
	return `update [flags] <container id> - update container resource constraints
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (u *Update) SetFlags(f *flag.FlagSet) {
	f.StringVar(&u.resources, "resources", "", `path to the file containing the resources to update or '-' to read from the standard input.

The default value means resources will be read from the remaining flags.

The accepted format is as follows (unchanged values can be omitted):

{
  "memory": {
    "limit": 0,
    "reservation": 0,
    "swap": 0,
    "checkBeforeUpdate": true
  },
  "cpu": {
    "shares": 0,
    "quota": 0,
    "burst": 0,
    "period": 0,
    "realtimeRuntime": 0,
    "realtimePeriod": 0,
    "cpus": "",
    "mems": "",
    "idle": 0
  },
  "blockIO": {
    "weight": 0
  }
}

Note: if data is to be read from a file or the standard input, all
other options are ignored.
`)

	f.IntVar(&u.blkioWeight, "blkio-weight", 0, "Specifies per cgroup weight, range is from 10 to 1000")

	f.StringVar(&u.cpuBurst, "cpu-burst", "", "CPU CFS hardcap burst limit (in usecs). Allowed accumulated cpu time additionally for burst a given period")
	f.StringVar(&u.cpuIdle, "cpu-idle", "", "set cgroup SCHED_IDLE or not, 0: default behavior, 1: SCHED_IDLE")
	f.StringVar(&u.cpuPeriod, "cpu-period", "", "CPU CFS period to be used for hardcapping (in usecs). 0 to use system default")
	f.StringVar(&u.cpuQuota, "cpu-quota", "", "CPU CFS hardcap limit (in usecs). Allowed cpu time in a given period")
	f.StringVar(&u.cpuRtPeriod, "cpu-rt-period", "", "CPU realtime period to be used for hardcapping (in usecs). 0 to use system default")
	f.StringVar(&u.cpuRtRuntime, "cpu-rt-runtime", "", "CPU realtime hardcap limit (in usecs). Allowed cpu time in a given period")
	f.StringVar(&u.cpuShares, "cpu-share", "", "CPU shares (relative weight vs. other containers)")
	f.StringVar(&u.cpusetCpus, "cpuset-cpus", "", "CPU(s) to use")
	f.StringVar(&u.cpusetMems, "cpuset-mems", "", "Memory node(s) to use")

	f.StringVar(&u.memory, "memory", "", "Memory limit (in bytes)")
	f.StringVar(&u.memoryReservation, "memory-reservation", "", "Memory reservation or soft_limit (in bytes)")
	f.StringVar(&u.memorySwap, "memory-swap", "", "Total memory usage (memory + swap); set '-1' to enable unlimited swap")

	f.Int64Var(&u.pidsLimit, "pids-limit", 0, "Maximum number of pids allowed in the container")

	f.StringVar(&u.l3CacheSchema, "l3-cache-schema", "", "The string of Intel RDT/CAT L3 cache schema")
	f.StringVar(&u.memBwSchema, "mem-bw-schema", "", "The string of Intel RDT/MBA memory bandwidth schema")
}

// Execute implements subcommands.Command.Execute.
func (u *Update) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	id := f.Arg(0)
	conf := args[0].(*config.Config)

	c, err := container.Load(conf.RootDir, container.FullID{ContainerID: id}, container.LoadOpts{})
	if err != nil {
		util.Fatalf("loading container %v", err)
	}

	r := specs.LinuxResources{
		Memory: &specs.LinuxMemory{
			CheckBeforeUpdate: boolPtr(false),
		},
		CPU:     &specs.LinuxCPU{},
		BlockIO: &specs.LinuxBlockIO{},
		Pids:    nil,
	}
	if in := u.resources; in != "" {
		var (
			f   *os.File
			err error
		)
		switch in {
		case "-":
			f = os.Stdin
		default:
			if f, err = os.Open(in); err != nil {
				return util.Errorf("opening %q: %v", in, err)
			}
			defer f.Close()
		}
		if err := json.NewDecoder(f).Decode(&r); err != nil {
			return util.Errorf("decoding %q: %v", in, err)
		}
	} else {
		if u.l3CacheSchema != "" || u.memBwSchema != "" {
			return util.Errorf("Intel RDT support is not yet implemented")
		}

		if u.blkioWeight != 0 {
			r.BlockIO.Weight = u16Ptr(uint16(u.blkioWeight))
		}

		r.CPU.Cpus = u.cpusetCpus
		r.CPU.Mems = u.cpusetMems

		for _, pair := range []struct {
			strval string
			dest   **uint64
		}{
			{u.cpuBurst, &r.CPU.Burst},
			{u.cpuPeriod, &r.CPU.Period},
			{u.cpuRtPeriod, &r.CPU.RealtimePeriod},
			{u.cpuShares, &r.CPU.Shares},
		} {
			if pair.strval == "" {
				continue
			}
			v, err := strconv.ParseUint(pair.strval, 10, 64)
			if err != nil {
				return util.Errorf("invalid value for %s: %v", pair.strval, err)
			}
			*pair.dest = &v
		}

		for _, pair := range []struct {
			strval string
			dest   **int64
		}{
			{u.cpuIdle, &r.CPU.Idle},
			{u.cpuQuota, &r.CPU.Quota},
			{u.cpuRtRuntime, &r.CPU.RealtimeRuntime},
		} {
			if pair.strval == "" {
				continue
			}
			v, err := strconv.ParseInt(pair.strval, 10, 64)
			if err != nil {
				return util.Errorf("invalid value for %s: %v", pair.strval, err)
			}
			*pair.dest = &v
		}

		for _, pair := range []struct {
			strval string
			dest   **int64
		}{
			{u.memory, &r.Memory.Limit},
			{u.memoryReservation, &r.Memory.Reservation},
			{u.memorySwap, &r.Memory.Swap},
		} {
			if pair.strval == "" {
				continue
			}
			v, err := strconv.ParseInt(pair.strval, 10, 64)
			if err != nil {
				return util.Errorf("invalid value for %s: %v", pair.strval, err)
			}
			*pair.dest = &v
		}

		if u.pidsLimit > 0 {
			r.Pids = &specs.LinuxPids{Limit: u.pidsLimit}
		}
	}

	prev := c.Spec.Linux.Resources
	// Retain existing values if not set
	if prev.CPU != nil {
		if r.CPU.Burst == nil {
			r.CPU.Burst = prev.CPU.Burst
		}
		if r.CPU.Idle == nil {
			r.CPU.Idle = prev.CPU.Idle
		}
		if r.CPU.Period == nil {
			r.CPU.Period = prev.CPU.Period
		}
		if r.CPU.Quota == nil {
			r.CPU.Quota = prev.CPU.Quota
		}
		if r.CPU.RealtimePeriod == nil {
			r.CPU.RealtimePeriod = prev.CPU.RealtimePeriod
		}
		if r.CPU.RealtimeRuntime == nil {
			r.CPU.RealtimeRuntime = prev.CPU.RealtimeRuntime
		}
		if r.CPU.Shares == nil {
			r.CPU.Shares = prev.CPU.Shares
		}
	}

	if prev.Memory != nil {
		if r.Memory.Limit == nil {
			r.Memory.Limit = prev.Memory.Limit
		}
		if r.Memory.Reservation == nil {
			r.Memory.Reservation = prev.Memory.Reservation
		}
		if r.Memory.Swap == nil {
			r.Memory.Swap = prev.Memory.Swap
		}
	}

	if prev.BlockIO != nil {
		if r.BlockIO.Weight == nil {
			r.BlockIO.Weight = prev.BlockIO.Weight
		}
	}

	if err := c.Set(&r); err != nil {
		return util.Errorf("setting resources: %v", err)
	}

	return subcommands.ExitSuccess
}
