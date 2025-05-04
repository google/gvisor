//go:build darwin && arm64
// +build darwin,arm64

package vf

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

type vf struct{}

var _ platform.Platform = &vf{}

// CooperativelySchedulesAddressSpace implements platform.Platform.
func (v *vf) CooperativelySchedulesAddressSpace() bool {
	panic("unimplemented")
}

// DetectsCPUPreemption implements platform.Platform.
func (v *vf) DetectsCPUPreemption() bool {
	panic("unimplemented")
}

// GlobalMemoryBarrier implements platform.Platform.
func (v *vf) GlobalMemoryBarrier() error {
	panic("unimplemented")
}

// HaveGlobalMemoryBarrier implements platform.Platform.
func (v *vf) HaveGlobalMemoryBarrier() bool {
	panic("unimplemented")
}

// MapUnit implements platform.Platform.
func (v *vf) MapUnit() uint64 {
	panic("unimplemented")
}

// MaxUserAddress implements platform.Platform.
func (v *vf) MaxUserAddress() hostarch.Addr {
	panic("unimplemented")
}

// MinUserAddress implements platform.Platform.
func (v *vf) MinUserAddress() hostarch.Addr {
	panic("unimplemented")
}

// NewAddressSpace implements platform.Platform.
func (v *vf) NewAddressSpace(mappingsID any) (platform.AddressSpace, <-chan struct{}, error) {
	panic("unimplemented")
}

// NewContext implements platform.Platform.
func (v *vf) NewContext(context.Context) platform.Context {
	panic("unimplemented")
}

// PreemptAllCPUs implements platform.Platform.
func (v *vf) PreemptAllCPUs() error {
	panic("unimplemented")
}

// SeccompInfo implements platform.Platform.
func (v *vf) SeccompInfo() platform.SeccompInfo {
	panic("unimplemented")
}

// SupportsAddressSpaceIO implements platform.Platform.
func (v *vf) SupportsAddressSpaceIO() bool {
	panic("unimplemented")
}
