// Copyright 2018 Google Inc.
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

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/pkg/sentry/limits"
)

// Mapping from linux resource names to limits.LimitType.
var fromLinuxResource = map[string]limits.LimitType{
	"RLIMIT_CPU":        limits.CPU,
	"RLIMIT_FSIZE":      limits.FileSize,
	"RLIMIT_DATA":       limits.Data,
	"RLIMIT_STACK":      limits.Stack,
	"RLIMIT_CORE":       limits.Core,
	"RLIMIT_RSS":        limits.Rss,
	"RLIMIT_NPROC":      limits.ProcessCount,
	"RLIMIT_NOFILE":     limits.NumberOfFiles,
	"RLIMIT_MEMLOCK":    limits.MemoryPagesLocked,
	"RLIMIT_AS":         limits.AS,
	"RLIMIT_LOCKS":      limits.Locks,
	"RLIMIT_SIGPENDING": limits.SignalsPending,
	"RLIMIT_MSGQUEUE":   limits.MessageQueueBytes,
	"RLIMIT_NICE":       limits.Nice,
	"RLIMIT_RTPRIO":     limits.RealTimePriority,
	"RLIMIT_RTTIME":     limits.Rttime,
}

func createLimitSet(spec *specs.Spec) (*limits.LimitSet, error) {
	ls, err := limits.NewLinuxDistroLimitSet()
	if err != nil {
		return nil, err
	}
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
