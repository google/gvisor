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

package kernel

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
)

func TestAnyFatalPending(t *testing.T) {
	// customHandler is any non-SIG_DFL handler: what a signal looks like once
	// the app has installed its own disposition for it.
	customHandler := linux.SigAction{Handler: 1}

	for _, test := range []struct {
		name       string
		pendingSet uint64
		mask       linux.SignalSet
		actions    map[linux.Signal]linux.SigAction
		want       bool
	}{
		{
			name:       "empty pendingSet",
			pendingSet: 0,
			want:       false,
		},
		{
			name:       "SIGKILL is always fatal",
			pendingSet: uint64(linux.SignalSetOf(linux.SIGKILL)),
			want:       true,
		},
		{
			name:       "default-disposition SIGTERM is fatal",
			pendingSet: uint64(linux.SignalSetOf(linux.SIGTERM)),
			want:       true,
		},
		{
			name:       "SIGTERM with a custom handler is not fatal",
			pendingSet: uint64(linux.SignalSetOf(linux.SIGTERM)),
			actions:    map[linux.Signal]linux.SigAction{linux.SIGTERM: customHandler},
			want:       false,
		},
		{
			name:       "ignored-by-default SIGCHLD is not fatal",
			pendingSet: uint64(linux.SignalSetOf(linux.SIGCHLD)),
			want:       false,
		},
		{
			name:       "core-dump-default SIGQUIT is not fatal (deferred until thaw)",
			pendingSet: uint64(linux.SignalSetOf(linux.SIGQUIT)),
			want:       false,
		},
		{
			name:       "a lower-numbered non-fatal signal doesn't hide a higher-numbered fatal one",
			pendingSet: uint64(linux.MakeSignalSet(linux.SIGUSR1, linux.SIGTERM)), // SIGUSR1(10) < SIGTERM(15)
			actions:    map[linux.Signal]linux.SigAction{linux.SIGUSR1: customHandler},
			want:       true,
		},
		{
			name:       "the only fatal signal is masked (blocked)",
			pendingSet: uint64(linux.SignalSetOf(linux.SIGTERM)),
			mask:       linux.SignalSetOf(linux.SIGTERM),
			want:       false,
		},
		{
			name:       "mask does not affect unrelated bits",
			pendingSet: uint64(linux.MakeSignalSet(linux.SIGUSR1, linux.SIGTERM)),
			mask:       linux.SignalSetOf(linux.SIGUSR1),
			want:       true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := anyFatalPending(test.pendingSet, test.mask, test.actions); got != test.want {
				t.Errorf("anyFatalPending(%#x, %#x, %v) = %v, want %v", test.pendingSet, test.mask, test.actions, got, test.want)
			}
		})
	}
}
