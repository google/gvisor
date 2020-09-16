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

package linux

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/syserror"
)

func lookupCaps(t *kernel.Task, tid kernel.ThreadID) (permitted, inheritable, effective auth.CapabilitySet, err error) {
	if tid < 0 {
		err = syserror.EINVAL
		return
	}
	if tid > 0 {
		t = t.PIDNamespace().TaskWithID(tid)
	}
	if t == nil {
		err = syserror.ESRCH
		return
	}
	creds := t.Credentials()
	permitted, inheritable, effective = creds.PermittedCaps, creds.InheritableCaps, creds.EffectiveCaps
	return
}

// Capget implements Linux syscall capget.
func Capget(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	hdrAddr := args[0].Pointer()
	dataAddr := args[1].Pointer()

	var hdr linux.CapUserHeader
	if _, err := hdr.CopyIn(t, hdrAddr); err != nil {
		return 0, nil, err
	}
	// hdr.Pid doesn't need to be valid if this capget() is a "version probe"
	// (hdr.Version is unrecognized and dataAddr is null), so we can't do the
	// lookup yet.
	switch hdr.Version {
	case linux.LINUX_CAPABILITY_VERSION_1:
		if dataAddr == 0 {
			return 0, nil, nil
		}
		p, i, e, err := lookupCaps(t, kernel.ThreadID(hdr.Pid))
		if err != nil {
			return 0, nil, err
		}
		data := linux.CapUserData{
			Effective:   uint32(e),
			Permitted:   uint32(p),
			Inheritable: uint32(i),
		}
		_, err = data.CopyOut(t, dataAddr)
		return 0, nil, err

	case linux.LINUX_CAPABILITY_VERSION_2, linux.LINUX_CAPABILITY_VERSION_3:
		if dataAddr == 0 {
			return 0, nil, nil
		}
		p, i, e, err := lookupCaps(t, kernel.ThreadID(hdr.Pid))
		if err != nil {
			return 0, nil, err
		}
		data := [2]linux.CapUserData{
			{
				Effective:   uint32(e),
				Permitted:   uint32(p),
				Inheritable: uint32(i),
			},
			{
				Effective:   uint32(e >> 32),
				Permitted:   uint32(p >> 32),
				Inheritable: uint32(i >> 32),
			},
		}
		_, err = linux.CopyCapUserDataSliceOut(t, dataAddr, data[:])
		return 0, nil, err

	default:
		hdr.Version = linux.HighestCapabilityVersion
		if _, err := hdr.CopyOut(t, hdrAddr); err != nil {
			return 0, nil, err
		}
		if dataAddr != 0 {
			return 0, nil, syserror.EINVAL
		}
		return 0, nil, nil
	}
}

// Capset implements Linux syscall capset.
func Capset(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	hdrAddr := args[0].Pointer()
	dataAddr := args[1].Pointer()

	var hdr linux.CapUserHeader
	if _, err := hdr.CopyIn(t, hdrAddr); err != nil {
		return 0, nil, err
	}
	switch hdr.Version {
	case linux.LINUX_CAPABILITY_VERSION_1:
		if tid := kernel.ThreadID(hdr.Pid); tid != 0 && tid != t.ThreadID() {
			return 0, nil, syserror.EPERM
		}
		var data linux.CapUserData
		if _, err := data.CopyIn(t, dataAddr); err != nil {
			return 0, nil, err
		}
		p := auth.CapabilitySet(data.Permitted) & auth.AllCapabilities
		i := auth.CapabilitySet(data.Inheritable) & auth.AllCapabilities
		e := auth.CapabilitySet(data.Effective) & auth.AllCapabilities
		return 0, nil, t.SetCapabilitySets(p, i, e)

	case linux.LINUX_CAPABILITY_VERSION_2, linux.LINUX_CAPABILITY_VERSION_3:
		if tid := kernel.ThreadID(hdr.Pid); tid != 0 && tid != t.ThreadID() {
			return 0, nil, syserror.EPERM
		}
		var data [2]linux.CapUserData
		if _, err := linux.CopyCapUserDataSliceIn(t, dataAddr, data[:]); err != nil {
			return 0, nil, err
		}
		p := (auth.CapabilitySet(data[0].Permitted) | (auth.CapabilitySet(data[1].Permitted) << 32)) & auth.AllCapabilities
		i := (auth.CapabilitySet(data[0].Inheritable) | (auth.CapabilitySet(data[1].Inheritable) << 32)) & auth.AllCapabilities
		e := (auth.CapabilitySet(data[0].Effective) | (auth.CapabilitySet(data[1].Effective) << 32)) & auth.AllCapabilities
		return 0, nil, t.SetCapabilitySets(p, i, e)

	default:
		hdr.Version = linux.HighestCapabilityVersion
		if _, err := hdr.CopyOut(t, hdrAddr); err != nil {
			return 0, nil, err
		}
		return 0, nil, syserror.EINVAL
	}
}
