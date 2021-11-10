// Copyright 2021 The gVisor Authors.
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

package seccheck

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// ExecveInfo contains information used by the Execve checkpoint.
//
// +fieldenum Execve
type ExecveInfo struct {
	// Invoker identifies the invoking thread.
	Invoker TaskInfo

	// Credentials are the invoking thread's credentials.
	Credentials *auth.Credentials

	// BinaryPath is a path to the executable binary file being switched to in
	// the mount namespace in which it was opened.
	BinaryPath string

	// Argv is the new process image's argument vector.
	Argv []string

	// Env is the new process image's environment variables.
	Env []string

	// BinaryMode is the executable binary file's mode.
	BinaryMode uint16

	// BinarySHA256 is the SHA-256 hash of the executable binary file.
	//
	// Note that this requires reading the entire file into memory, which is
	// likely to be extremely slow.
	BinarySHA256 [32]byte
}

// ExecveReq returns fields required by the Execve checkpoint.
func (s *State) ExecveReq() ExecveFieldSet {
	return s.execveReq.Load()
}

// Execve is called at the Execve checkpoint.
func (s *State) Execve(ctx context.Context, mask ExecveFieldSet, info *ExecveInfo) error {
	for _, c := range s.getCheckers() {
		if err := c.Execve(ctx, mask, *info); err != nil {
			return err
		}
	}
	return nil
}
