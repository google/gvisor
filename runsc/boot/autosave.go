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

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/state"
	"gvisor.dev/gvisor/pkg/sentry/strace"
	"gvisor.dev/gvisor/pkg/sync"
)

func checkResume(f *os.File) error {
	// Check state file size is greater than zero and
	// clear the state file before returning.
	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat error %v", err)
	}

	size := st.Size()
	if size <= 0 {
		return fmt.Errorf("state file size is zero")
	}
	if err := f.Truncate(0); err != nil {
		return fmt.Errorf("error in truncating %v", err)
	}
	f.Seek(0, 0)

	newSt, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat error %v", err)
	}
	if sz := newSt.Size(); sz != 0 {
		return fmt.Errorf("state file size is not zero")
	}

	return nil
}

// EnableAutosave enables auto save restore in syscall tests.
func EnableAutosave(l *Loader, f *os.File, isResume bool) error {
	var once sync.Once // Used by target.
	target := func(k *kernel.Kernel) {
		once.Do(func() {
			t, _ := state.CPUTime()
			log.Infof("Before save CPU usage: %s", t.String())
			saveOpts := state.SaveOpts{
				Destination: f,
				Key:         nil,
				Resume:      isResume,
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

					if isResume {
						if err := checkResume(f); err != nil {
							log.Warningf("Save resume failed: exiting... %v", err)
							k.SetSaveError(err)
						}
					} else {
						// Kill the sandbox.
						k.Kill(linux.WaitStatusExit(0))
					}
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
		if err := configureInitSyscall(table, sys, "init_module", kernel.ExternalAfterEnable); err != nil {
			return err
		}
		// Set external args to our closure above.
		table.External = target
	}

	return nil
}

// configureInitSyscall sets the trigger for the S/R syscall tests and the callback
// method to be called after the sycall is executed.
func configureInitSyscall(table *kernel.SyscallTable, sys strace.SyscallMap, initSyscall string, syscallFlag uint32) error {
	sl := make(map[uintptr]bool)
	sysno, ok := sys.ConvertToSysno(initSyscall)
	if !ok {
		return fmt.Errorf("syscall %q not found", initSyscall)
	}
	sl[sysno] = true
	log.Infof("sysno %v name %v", sysno, initSyscall)
	table.FeatureEnable.Enable(syscallFlag, sl, false)
	table.ExternalFilterBefore = func(*kernel.Task, uintptr, arch.SyscallArguments) bool {
		return false
	}
	// Sets ExternalFilterAfter to true which calls the closure assigned to
	// External after the syscall is executed.
	table.ExternalFilterAfter = func(*kernel.Task, uintptr, arch.SyscallArguments) bool {
		return true
	}
	return nil
}
