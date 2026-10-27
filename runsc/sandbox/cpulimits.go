// Copyright 2026 The gVisor Authors.
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

package sandbox

import (
	"fmt"
	"maps"
	"math"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/cgroup"
	"gvisor.dev/gvisor/runsc/config"
)

// CPULimits are the CPU limits of the sandbox cgroup.
type CPULimits struct {
	// App applies while the application runs.
	App specs.LinuxCPU `json:"app"`

	// Creation applies while a new sandbox is created and started.
	Creation specs.LinuxCPU `json:"creation"`

	// Lifecycle applies during checkpoint, restore, and teardown.
	Lifecycle specs.LinuxCPU `json:"lifecycle"`

	// WillRestore is set when creating the sandbox restores application
	// data, so Creation is the lifecycle limit.
	WillRestore bool `json:"willRestore,omitempty"`
}

// NewCPULimits returns the CPU limits for `res` under the `creation` and
// `lifecycle` policies, or nil if the OCI spec limit applies throughout.
func NewCPULimits(creation, lifecycle config.SandboxCPUPolicy, res *specs.LinuxResources) *CPULimits {
	if (!creation.Enabled() && !lifecycle.Enabled()) || res == nil {
		return nil
	}
	var quota int64
	period := uint64(cgroup.DefaultCPUPeriod)
	if res.CPU != nil {
		if res.CPU.Quota != nil {
			quota = *res.CPU.Quota
		}
		if res.CPU.Period != nil && *res.CPU.Period != 0 {
			period = *res.CPU.Period
		}
	}
	if cpuMax, ok := res.Unified["cpu.max"]; ok {
		unifiedQuota, unifiedPeriod, err := cgroup.ParseCPUMax(cpuMax)
		if err != nil {
			log.Warningf("Not applying --sandbox-creation-cpu-policy=%v and --sandbox-lifecycle-cpu-policy=%v: cannot parse unified cpu.max: %v", creation, lifecycle, err)
			return nil
		}
		quota, period = unifiedQuota, uint64(unifiedPeriod)
	}
	if quota <= 0 {
		return nil
	}
	creationQuota := creation.Quota(quota, period)
	lifecycleQuota := lifecycle.Quota(quota, period)
	if creationQuota == quota && lifecycleQuota == quota {
		return nil
	}
	return &CPULimits{
		App:       specs.LinuxCPU{Quota: &quota, Period: &period},
		Creation:  specs.LinuxCPU{Quota: &creationQuota, Period: &period},
		Lifecycle: specs.LinuxCPU{Quota: &lifecycleQuota, Period: &period},
	}
}

// CreationResources returns a copy of `res` with the creation CPU limit.
func (l *CPULimits) CreationResources(res *specs.LinuxResources) *specs.LinuxResources {
	var cpu specs.LinuxCPU
	if res.CPU != nil {
		cpu = *res.CPU
	}
	cpu.Quota, cpu.Period = l.Creation.Quota, l.Creation.Period
	creationRes := *res
	creationRes.CPU = &cpu
	if _, ok := res.Unified["cpu.max"]; ok {
		creationRes.Unified = maps.Clone(res.Unified)
		delete(creationRes.Unified, "cpu.max")
	}
	return &creationRes
}

// lifecycleCPUNum returns the number of CPUs that the lifecycle CPU limit lets
// the sandbox use, out of the `cgCPUNum` CPUs that its cgroup can run on.
func (l *CPULimits) lifecycleCPUNum(cgCPUNum int) int {
	quota, period := *l.Lifecycle.Quota, *l.Lifecycle.Period
	if quota < 0 {
		return cgCPUNum
	}
	return min(cgCPUNum, int(math.Ceil(float64(quota)/float64(period))))
}

// cpuPhase is a phase of the sandbox with its own CPU limit.
type cpuPhase int

const (
	cpuPhaseApp cpuPhase = iota
	cpuPhaseCreation
	cpuPhaseLifecycle
)

// String implements fmt.Stringer.
func (p cpuPhase) String() string {
	switch p {
	case cpuPhaseApp:
		return "application"
	case cpuPhaseCreation:
		return "creation"
	case cpuPhaseLifecycle:
		return "lifecycle"
	default:
		panic(fmt.Sprintf("invalid CPU phase %d", int(p)))
	}
}

func (l *CPULimits) limit(p cpuPhase) specs.LinuxCPU {
	switch p {
	case cpuPhaseApp:
		return l.App
	case cpuPhaseCreation:
		return l.Creation
	case cpuPhaseLifecycle:
		return l.Lifecycle
	default:
		panic(fmt.Sprintf("invalid CPU phase %d", int(p)))
	}
}

// switchCPULimit replaces the `from` CPU limit of the sandbox cgroup with the
// `to` one. No-op if they are the same.
func (s *Sandbox) switchCPULimit(from, to cpuPhase) error {
	if s.CPULimits == nil {
		return nil
	}
	cpu := s.CPULimits.limit(to)
	if *s.CPULimits.limit(from).Quota == *cpu.Quota {
		return nil
	}
	if err := s.CgroupJSON.Cgroup.Update(&specs.LinuxResources{CPU: &cpu}); err != nil {
		return fmt.Errorf("cannot apply %v CPU limit: %w", to, err)
	}
	log.Infof("[Lifecycle CPU] Applied %v CPU limit: quota=%d period=%d", to, *cpu.Quota, *cpu.Period)
	return nil
}

// applyAppCPULimit switches the running application from the `from` CPU limit to
// its own. If that fails, it stops the sandbox rather than let the application
// run beyond its OCI spec limit.
func (s *Sandbox) applyAppCPULimit(from cpuPhase) error {
	if err := s.switchCPULimit(from, cpuPhaseApp); err != nil {
		return s.DestroyOverCPULimit(err)
	}
	return nil
}

// DestroyOverCPULimit stops the sandbox because `err` prevents runsc from
// keeping its application within its OCI spec CPU limit.
func (s *Sandbox) DestroyOverCPULimit(err error) error {
	log.Warningf("[Lifecycle CPU] Destroying sandbox %q: cannot keep it within its CPU limit: %v", s.ID, err)
	if destroyErr := s.destroy(); destroyErr != nil {
		return fmt.Errorf("%w; cannot stop the sandbox: %v", err, destroyErr)
	}
	return fmt.Errorf("%w; stopped the sandbox", err)
}

// MarkCreated clears Creating and applies the application CPU limit. No-op if
// Creating is not set.
func (s *Sandbox) MarkCreated() error {
	if !s.Creating {
		return nil
	}
	s.Creating = false
	return s.switchCPULimit(cpuPhaseCreation, cpuPhaseApp)
}
