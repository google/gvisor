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

package linux

import (
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// copyInSigSet copies in a sigset_t, checks its size, and ensures that KILL and
// STOP are clear.
func copyInSigSet(t *kernel.Task, sigSetAddr usermem.Addr, size uint) (linux.SignalSet, error) {
	if size != linux.SignalSetSize {
		return 0, syscall.EINVAL
	}
	b := t.CopyScratchBuffer(8)
	if _, err := t.CopyInBytes(sigSetAddr, b); err != nil {
		return 0, err
	}
	mask := usermem.ByteOrder.Uint64(b[:])
	return linux.SignalSet(mask) &^ kernel.UnblockableSignals, nil
}

// copyOutSigSet copies out a sigset_t.
func copyOutSigSet(t *kernel.Task, sigSetAddr usermem.Addr, mask linux.SignalSet) error {
	b := t.CopyScratchBuffer(8)
	usermem.ByteOrder.PutUint64(b, uint64(mask))
	_, err := t.CopyOutBytes(sigSetAddr, b)
	return err
}

// copyInSigSetWithSize copies in a structure as below
//
//   struct {
//       sigset_t* sigset_addr;
//       size_t sizeof_sigset;
//   };
//
// and returns sigset_addr and size.
func copyInSigSetWithSize(t *kernel.Task, addr usermem.Addr) (usermem.Addr, uint, error) {
	switch t.Arch().Width() {
	case 8:
		in := t.CopyScratchBuffer(16)
		if _, err := t.CopyInBytes(addr, in); err != nil {
			return 0, 0, err
		}
		maskAddr := usermem.Addr(usermem.ByteOrder.Uint64(in[0:]))
		maskSize := uint(usermem.ByteOrder.Uint64(in[8:]))
		return maskAddr, maskSize, nil
	default:
		return 0, 0, syserror.ENOSYS
	}
}
