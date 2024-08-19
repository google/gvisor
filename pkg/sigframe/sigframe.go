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

// Package sigframe implements a mechanism to create a signal frame on the
// stack and execute a user-defined callback function within that context. The
// callback function can use the `sigreturn` system call to resuming the
// current thread with the state from the signal frame. This functionality can
// be helpful in scenarios where you need to simulate a signal handler-like
// behavior without triggering a signal.
package sigframe
