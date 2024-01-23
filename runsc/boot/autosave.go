// Copyright 2024 The gVisor Authors.
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
	"os"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/state"
	"gvisor.dev/gvisor/pkg/sentry/strace"
	"gvisor.dev/gvisor/pkg/sync"
)

// EnableAutosave enables auto save restore in syscall tests.
func EnableAutosave(l *Loader, f *os.File) error {
	var once sync.Once // Used by target.
	target := func(k *kernel.Kernel) {
		once.Do(func() {
			t, _ := state.CPUTime()
			log.Infof("Before save CPU usage: %s", t.String())
			saveOpts := state.SaveOpts{
				Destination: f,
				Key:         nil,
				Callback: func(err error) {
					t1, _ := state.CPUTime()
					log.Infof("Save CPU usage: %s", (t1 - t).String())
					if err == nil {
						log.Infof("Save succeeded: exiting...")
						k.SetSaveSuccess(true)
					} else {
						log.Warningf("Save failed: exiting... %v", err)
						k.SetSaveError(err)
					}

					// Kill the sandbox.
					k.Kill(linux.WaitStatusExit(0))
				},
			}
			saveOpts.Save(k.SupervisorContext(), k, l.watchdog)
		})
	}

	for _, table := range kernel.SyscallTables() {
		sys, ok := strace.Lookup(table.OS, table.Arch)
		if !ok {
			continue
		}
		if err := configureSyscalls(table, sys, []string{"init_module"}, kernel.ExternalAfterEnable); err != nil {
			return err
		}
		// Set external args to our closure above.
		table.External = target
	}

	return nil
}

func configureSyscalls(table *kernel.SyscallTable, sys strace.SyscallMap, syscalls []string, syscallFlag uint32) error {
	sl := make(map[uintptr]bool)
	for _, name := range syscalls {
		sysno, err := parseSyscall(sys, name)
		if err != nil {
			return err
		}
		sl[sysno] = true
	}
	table.FeatureEnable.Enable(syscallFlag, sl, false)
	table.ExternalFilterBefore = func(*kernel.Task, uintptr, arch.SyscallArguments) bool {
		return false
	}
	table.ExternalFilterAfter = func(_ *kernel.Task, _ uintptr, _ arch.SyscallArguments) bool {
		return true
	}
	return nil
}

// parseSyscall parses a single syscall string. It returns corresponding syscall
// number for the given sycall map, an argument matcher if one exists, and the
// / skip count.
//
// Format:
//
//	syscall
//	syscall{skip_count}
//	syscall(arg0_filter, arg1_filter, ...)
//	syscall(arg0_filter, arg1_filter, ...){skip_count}
func parseSyscall(sys strace.SyscallMap, name string) (uintptr, error) {
	// Process the optional skip count.
	skip := 0
	if l := len(name); l > 0 && name[l-1] == '}' {
		last := strings.LastIndex(name, "{")
		if last == -1 {
			return 0, fmt.Errorf("syscall filter is malformed: %s", name)
		}
		s, err := strconv.Atoi(name[last+1 : l-1])
		if err != nil || s < 0 {
			return 0, fmt.Errorf("syscall filter contains invalid skip count: %s", name)
		}
		skip = s
		name = name[:last]
	}

	baseName := name
	var args string

	// Check if there are arguments to be parsed.
	if left := strings.Index(name, "("); left >= 0 {
		// Look for matching parenthesis.
		if name[len(name)-1] != ')' {
			return 0, fmt.Errorf("syscall filter is malformed: %s", name)
		}
		baseName = name[:left]
		args = name[left+1 : len(name)-1]
	}

	sysno, ok := sys.ConvertToSysno(baseName)
	if !ok {
		return 0, fmt.Errorf("syscall %q not found", baseName)
	}
	if len(args) == 0 {
		// There are no argument filters, matcher lookup isn't necessary.
		return sysno, nil
	}

	log.Infof("sysno %v skip %v", sysno, skip)
	return sysno, nil
}

func splitAndTrim(s, sep string) []string {
	ret := strings.Split(s, sep)
	for i, untrimmed := range ret {
		ret[i] = strings.TrimSpace(untrimmed)
	}
	return ret
}
