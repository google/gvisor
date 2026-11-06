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

package ipc

type contextID int

// CtxIPCNamespace is the context.Value key used to retrieve an IPC namespace.
// We define it here because it's needed in several packages, and is not
// possible to use otherwise without causing a circular dependency.
const CtxIPCNamespace contextID = iota

// PID records a process's number in each PID namespace where it is visible.
// Namespace inode numbers survive checkpoint and do not keep exited processes
// or their namespaces alive.
//
// +stateify savable
type PID struct {
	namespaceIno uint64
	number       int32
	next         *PID
}

// WithNumber returns a snapshot that also includes number in namespaceIno.
func (pid *PID) WithNumber(namespaceIno uint64, number int32) *PID {
	return &PID{namespaceIno: namespaceIno, number: number, next: pid}
}

// In returns the PID visible in namespaceIno, or zero if none is visible.
func (pid *PID) In(namespaceIno uint64) int32 {
	for ; pid != nil; pid = pid.next {
		if pid.namespaceIno == namespaceIno {
			return pid.number
		}
	}
	return 0
}
