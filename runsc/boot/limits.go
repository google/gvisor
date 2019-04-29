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

package boot

import (
	"fmt"
	"sync"
	"syscall"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/limits"
)

// Mapping from linux resource names to limits.LimitType.
var fromLinuxResource = map[string]limits.LimitType{
	"RLIMIT_AS":         limits.AS,
	"RLIMIT_CORE":       limits.Core,
	"RLIMIT_CPU":        limits.CPU,
	"RLIMIT_DATA":       limits.Data,
	"RLIMIT_FSIZE":      limits.FileSize,
	"RLIMIT_LOCKS":      limits.Locks,
	"RLIMIT_MEMLOCK":    limits.MemoryLocked,
	"RLIMIT_MSGQUEUE":   limits.MessageQueueBytes,
	"RLIMIT_NICE":       limits.Nice,
	"RLIMIT_NOFILE":     limits.NumberOfFiles,
	"RLIMIT_NPROC":      limits.ProcessCount,
	"RLIMIT_RSS":        limits.Rss,
	"RLIMIT_RTPRIO":     limits.RealTimePriority,
	"RLIMIT_RTTIME":     limits.Rttime,
	"RLIMIT_SIGPENDING": limits.SignalsPending,
	"RLIMIT_STACK":      limits.Stack,
}

func findName(lt limits.LimitType) string {
	for k, v := range fromLinuxResource {
		if v == lt {
			return k
		}
	}
	return "unknown"
}

var defaults defs

type defs struct {
	mu  sync.Mutex
	set *limits.LimitSet
	err error
}

func (d *defs) get() (*limits.LimitSet, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.err != nil {
		return nil, d.err
	}
	if d.set == nil {
		if err := d.initDefaults(); err != nil {
			d.err = err
			return nil, err
		}
	}
	return d.set, nil
}

func (d *defs) initDefaults() error {
	ls, err := limits.NewLinuxLimitSet()
	if err != nil {
		return err
	}

	// Set default limits based on what containers get by default, ex:
	// $ docker run --rm debian prlimit
	ls.SetUnchecked(limits.AS, limits.Limit{Cur: limits.Infinity, Max: limits.Infinity})
	ls.SetUnchecked(limits.Core, limits.Limit{Cur: limits.Infinity, Max: limits.Infinity})
	ls.SetUnchecked(limits.CPU, limits.Limit{Cur: limits.Infinity, Max: limits.Infinity})
	ls.SetUnchecked(limits.Data, limits.Limit{Cur: limits.Infinity, Max: limits.Infinity})
	ls.SetUnchecked(limits.FileSize, limits.Limit{Cur: limits.Infinity, Max: limits.Infinity})
	ls.SetUnchecked(limits.Locks, limits.Limit{Cur: limits.Infinity, Max: limits.Infinity})
	ls.SetUnchecked(limits.MemoryLocked, limits.Limit{Cur: 65536, Max: 65536})
	ls.SetUnchecked(limits.MessageQueueBytes, limits.Limit{Cur: 819200, Max: 819200})
	ls.SetUnchecked(limits.Nice, limits.Limit{Cur: 0, Max: 0})
	ls.SetUnchecked(limits.NumberOfFiles, limits.Limit{Cur: 1048576, Max: 1048576})
	ls.SetUnchecked(limits.ProcessCount, limits.Limit{Cur: limits.Infinity, Max: limits.Infinity})
	ls.SetUnchecked(limits.Rss, limits.Limit{Cur: limits.Infinity, Max: limits.Infinity})
	ls.SetUnchecked(limits.RealTimePriority, limits.Limit{Cur: 0, Max: 0})
	ls.SetUnchecked(limits.Rttime, limits.Limit{Cur: limits.Infinity, Max: limits.Infinity})
	ls.SetUnchecked(limits.SignalsPending, limits.Limit{Cur: 0, Max: 0})
	ls.SetUnchecked(limits.Stack, limits.Limit{Cur: 8388608, Max: limits.Infinity})

	// Read host limits that directly affect the sandbox and adjust the defaults
	// based on them.
	for _, res := range []int{syscall.RLIMIT_FSIZE, syscall.RLIMIT_NOFILE} {
		var hl syscall.Rlimit
		if err := syscall.Getrlimit(res, &hl); err != nil {
			return err
		}

		lt, ok := limits.FromLinuxResource[res]
		if !ok {
			return fmt.Errorf("unknown rlimit type %v", res)
		}
		hostLimit := limits.Limit{
			Cur: limits.FromLinux(hl.Cur),
			Max: limits.FromLinux(hl.Max),
		}

		defaultLimit := ls.Get(lt)
		if hostLimit.Cur != limits.Infinity && hostLimit.Cur < defaultLimit.Cur {
			log.Warningf("Host limit is lower than recommended, resource: %q, host: %d, recommended: %d", findName(lt), hostLimit.Cur, defaultLimit.Cur)
		}
		if hostLimit.Cur != defaultLimit.Cur || hostLimit.Max != defaultLimit.Max {
			log.Infof("Setting limit from host, resource: %q {soft: %d, hard: %d}", findName(lt), hostLimit.Cur, hostLimit.Max)
			ls.SetUnchecked(lt, hostLimit)
		}
	}

	d.set = ls
	return nil
}

func createLimitSet(spec *specs.Spec) (*limits.LimitSet, error) {
	ls, err := defaults.get()
	if err != nil {
		return nil, err
	}

	// Then apply overwrites on top of defaults.
	for _, rl := range spec.Process.Rlimits {
		lt, ok := fromLinuxResource[rl.Type]
		if !ok {
			return nil, fmt.Errorf("unknown resource %q", rl.Type)
		}
		ls.SetUnchecked(lt, limits.Limit{
			Cur: rl.Soft,
			Max: rl.Hard,
		})
	}
	return ls, nil
}
