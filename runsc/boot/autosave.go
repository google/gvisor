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
	"bytes"
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/state"
	"gvisor.dev/gvisor/pkg/sentry/strace"
	"gvisor.dev/gvisor/pkg/sync"
)

func getSaveOpts(l *Loader, k *kernel.Kernel, isResume bool) state.SaveOpts {
	t, _ := state.CPUTime()
	log.Infof("Before save CPU usage: %s", t.String())
	saveOpts := state.SaveOpts{
		Key:    nil,
		Resume: isResume,
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

			if !isResume {
				// Kill the sandbox.
				k.Kill(linux.WaitStatusExit(0))
			}
		},
	}
	return saveOpts
}

func getTargetForSaveResume(l *Loader) func(k *kernel.Kernel) {
	return func(k *kernel.Kernel) {
		saveOpts := getSaveOpts(l, k, true /* isResume */)
		// Store the state file contents in a buffer for save-resume.
		// There is no need to verify the state file, we just need the
		// sandbox to continue running after save.
		var buf bytes.Buffer
		saveOpts.Destination = &buf
		saveOpts.Save(k.SupervisorContext(), k, l.watchdog)
	}
}

func getTargetForSaveRestore(l *Loader, files []*fd.FD) func(k *kernel.Kernel) {
	if len(files) != 1 && len(files) != 3 {
		panic(fmt.Sprintf("Unexpected number of files: %v", len(files)))
	}

	var once sync.Once
	return func(k *kernel.Kernel) {
		once.Do(func() {
			saveOpts := getSaveOpts(l, k, false /* isResume */)
			saveOpts.Destination = files[0]
			if len(files) == 3 {
				saveOpts.PagesMetadata = files[1]
				saveOpts.PagesFile = files[2]
			}

			saveOpts.Save(k.SupervisorContext(), k, l.watchdog)
		})
	}
}

// enableAutosave enables auto save restore in syscall tests.
func enableAutosave(l *Loader, isResume bool, files []*fd.FD) error {
	var target func(k *kernel.Kernel)
	if isResume {
		target = getTargetForSaveResume(l)
	} else {
		target = getTargetForSaveRestore(l, files)
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
