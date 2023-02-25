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

package devpts

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// Terminal is a pseudoterminal.
//
// +stateify savable
type Terminal struct {
	// n is the terminal index. It is immutable.
	n uint32

	// ld is the line discipline of the terminal. It is immutable.
	ld *lineDiscipline

	// masterKTTY contains the controlling process of the master end of
	// this terminal. This field is immutable.
	masterKTTY *kernel.TTY

	// replicaKTTY contains the controlling process of the replica end of this
	// terminal. This field is immutable.
	replicaKTTY *kernel.TTY
}

func newTerminal(n uint32) *Terminal {
	t := &Terminal{
		n:           n,
		masterKTTY:  &kernel.TTY{Index: n},
		replicaKTTY: &kernel.TTY{Index: n},
	}
	t.ld = newLineDiscipline(linux.DefaultReplicaTermios, t)

	return t
}
