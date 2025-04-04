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

	cpuPeriod    uint64
	cpuQuota     int64
	cpuBurst     uint64
	cpuShares    uint64
	cpuRtPeriod  uint64
	cpuRtRuntime int64
	cpusetCpus   string // can this be string or this has to be list of smth?
	cpusetMems   string
	cpuIdle      int64

	memory            int64
	memoryReservation int64
	memorySwap        int64

	blkioWeight int

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

	f.Uint64Var(&u.cpuPeriod, "cpu-period", 0, "CPU CFS period to be used for hardcapping (in usecs). 0 to use system default")
	f.Int64Var(&u.cpuQuota, "cpu-quota", 0, "CPU CFS hardcap limit (in usecs). Allowed cpu time in a given period")
	f.Uint64Var(&u.cpuBurst, "cpu-burst", 0, "CPU CFS hardcap burst limit (in usecs). Allowed accumulated cpu time additionally for burst a given period")
	f.Uint64Var(&u.cpuShares, "cpu-share", 0, "CPU shares (relative weight vs. other containers)")
	f.Uint64Var(&u.cpuRtPeriod, "cpu-rt-period", 0, "CPU realtime period to be used for hardcapping (in usecs). 0 to use system default")
	f.Int64Var(&u.cpuRtRuntime, "cpu-rt-runtime", 0, "CPU realtime hardcap limit (in usecs). Allowed cpu time in a given period")
	f.StringVar(&u.cpusetCpus, "cpuset-cpus", "", "CPU(s) to use")
	f.StringVar(&u.cpusetMems, "cpuset-mems", "", "Memory node(s) to use")
	f.Int64Var(&u.cpuIdle, "cpu-idle", 0, "set cgroup SCHED_IDLE or not, 0: default behavior, 1: SCHED_IDLE")

	f.Int64Var(&u.memory, "memory", 0, "Memory limit (in bytes)")
	f.Int64Var(&u.memoryReservation, "memory-reservation", 0, "Memory reservation or soft_limit (in bytes)")
	f.Int64Var(&u.memorySwap, "memory-swap", 0, "Total memory usage (memory + swap); set '-1' to enable unlimited swap")

	f.IntVar(&u.blkioWeight, "blkio-weight", 0, "Specifies per cgroup weight, range is from 10 to 1000")

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
			Limit:             i64Ptr(0),
			Reservation:       i64Ptr(0),
			Swap:              i64Ptr(0),
			CheckBeforeUpdate: boolPtr(false),
		},
		CPU: &specs.LinuxCPU{
			Shares:          u64Ptr(0),
			Quota:           i64Ptr(0),
			Burst:           u64Ptr(0),
			Period:          u64Ptr(0),
			RealtimeRuntime: i64Ptr(0),
			RealtimePeriod:  u64Ptr(0),
			Cpus:            "",
			Mems:            "",
		},
		BlockIO: &specs.LinuxBlockIO{
			Weight: u16Ptr(0),
		},
		Pids: &specs.LinuxPids{
			Limit: 0,
		},
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
			f, err = os.Open(in)
			if err != nil {
				return util.Errorf("opening %q: %v", in, err)
			}
			defer f.Close()
		}
		err = json.NewDecoder(f).Decode(&r)
		if err != nil {
			return util.Errorf("decoding %q: %v", in, err)
		}
	} else {
		r.Memory.Limit = i64Ptr(u.memory)
		r.Memory.Reservation = i64Ptr(u.memoryReservation)
		r.Memory.Swap = i64Ptr(u.memorySwap)

		r.CPU.Shares = u64Ptr(u.cpuShares)
		r.CPU.Quota = i64Ptr(u.cpuQuota)
		r.CPU.Burst = u64Ptr(u.cpuBurst)
		r.CPU.Period = u64Ptr(u.cpuPeriod)
		r.CPU.RealtimeRuntime = i64Ptr(u.cpuRtRuntime)
		r.CPU.RealtimePeriod = u64Ptr(u.cpuRtPeriod)
		r.CPU.Cpus = u.cpusetCpus
		r.CPU.Mems = u.cpusetMems

		r.BlockIO.Weight = u16Ptr(uint16(u.blkioWeight))

		r.Pids.Limit = u.pidsLimit
	}

	if err = c.Set(&r); err != nil {
		return util.Errorf("setting resources: %v", err)
	}

	return subcommands.ExitSuccess
}
