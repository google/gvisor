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

//go:build loong64
// +build loong64

package safecopy

// initializeArchAddresses is a no-op on LoongArch64. The "begin/end" range
// of every safecopy function is computed in package-level initializeAddresses()
// via runtime.FuncForPC(addrOfXxx()), so no extra setup is required.
func initializeArchAddresses() {
}
