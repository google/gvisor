// Copyright 2020 The gVisor Authors.
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

//go:build arm64
// +build arm64

package linux

import (
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// Clone implements linux syscall clone(2).
// sys_clone has so many flavors, and we implement the default one in linux 3.11
// arm64(kernel/fork.c with CONFIG_CLONE_BACKWARDS defined in the config file):
//    sys_clone(clone_flags, newsp, parent_tidptr, tls_val, child_tidptr)
func Clone(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	flags := int(args[0].Int())
	stack := args[1].Pointer()
	parentTID := args[2].Pointer()
	tls := args[3].Pointer()
	childTID := args[4].Pointer()
	return clone(t, flags, stack, parentTID, childTID, tls)
}
