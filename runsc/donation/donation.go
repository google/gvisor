// Copyright 2022 The gVisor Authors.
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

// Package donation tracks files that are being donated to a child process and
// using flags to notified the child process where the FDs are.
package donation

import (
	"fmt"
	"os"
	"os/exec"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/specutils"
)

// LogDonations logs the FDs we are donating in the command.
func LogDonations(cmd *exec.Cmd) {
	for i, f := range cmd.ExtraFiles {
		log.Debugf("Donating FD %d: %q", i+3, f.Name())
	}
}

// Agency keeps track of files that need to be donated to a child process.
type Agency struct {
	donations    []donation
	closePending []*os.File
}

type donation struct {
	flag  string
	files []*os.File
}

// Donate sets up the given files to be donated to another process. The FD
// in which the new file will appear in the child process is added as a flag to
// the child process, e.g. --flag=3. In case the file is nil, -1 is used for the
// flag value and no file is donated to the next process.
func (f *Agency) Donate(flag string, files ...*os.File) {
	f.donations = append(f.donations, donation{flag: flag, files: files})
}

// DonateAndClose does the same as Donate, but takes ownership of the files
// passed in.
func (f *Agency) DonateAndClose(flag string, files ...*os.File) {
	f.Donate(flag, files...)
	f.closePending = append(f.closePending, files...)
}

// OpenAndDonate is similar to DonateAndClose but handles the opening of the
// file for convenience. It's a noop, if path is empty.
func (f *Agency) OpenAndDonate(flag, path string, flags int) error {
	if len(path) == 0 {
		return nil
	}
	file, err := os.OpenFile(path, flags, 0644)
	if err != nil {
		return err
	}
	f.DonateAndClose(flag, file)
	return nil
}

// DonateDebugLogFile is similar to DonateAndClose but handles the opening of
// the file using specutils.DebugLogFile() for convenience. It's a noop, if
// path is empty.
func (f *Agency) DonateDebugLogFile(flag, logPattern, command, test string) error {
	if len(logPattern) == 0 {
		return nil
	}
	file, err := specutils.DebugLogFile(logPattern, command, test)
	if err != nil {
		return fmt.Errorf("opening debug log file in %q: %v", logPattern, err)
	}
	f.DonateAndClose(flag, file)
	return nil
}

// Transfer sets up all files and flags to cmd. It can be called multiple times
// to partially transfer files to cmd.
func (f *Agency) Transfer(cmd *exec.Cmd, nextFD int) int {
	for _, d := range f.donations {
		for _, file := range d.files {
			fd := -1
			if file != nil {
				cmd.ExtraFiles = append(cmd.ExtraFiles, file)
				fd = nextFD
				nextFD++
			}
			cmd.Args = append(cmd.Args, fmt.Sprintf("--%s=%d", d.flag, fd))
		}
	}
	// Reset donations made so far in case more transfers are needed.
	f.donations = nil
	return nextFD
}

// Close closes any files the agency has taken ownership over.
func (f *Agency) Close() {
	for _, file := range f.closePending {
		if file != nil {
			_ = file.Close()
		}
	}
	f.closePending = nil
}
