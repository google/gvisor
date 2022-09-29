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
	"math"

	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/usermem"
)

const (
	_GRND_NONBLOCK = 0x1
	_GRND_RANDOM   = 0x2
)

// GetRandom implements the linux syscall getrandom(2).
//
// In a multi-tenant/shared environment, the only valid implementation is to
// fetch data from the urandom pool, otherwise starvation attacks become
// possible. The urandom pool is also expected to have plenty of entropy, thus
// the GRND_RANDOM flag is ignored. The GRND_NONBLOCK flag does not apply, as
// the pool will already be initialized.
func GetRandom(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	length := args[1].SizeT()
	flags := args[2].Int()

	// Flags are checked for validity but otherwise ignored. See above.
	if flags & ^(_GRND_NONBLOCK|_GRND_RANDOM) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	if length > math.MaxInt32 {
		length = math.MaxInt32
	}
	ar, ok := addr.ToRange(uint64(length))
	if !ok {
		return 0, nil, linuxerr.EFAULT
	}

	n, err := t.MemoryManager().CopyOutFrom(t, hostarch.AddrRangeSeqOf(ar), safemem.FromIOReader{rand.Reader}, usermem.IOOpts{})
	if n > 0 {
		return uintptr(n), nil, nil
	}
	return 0, nil, err
}
