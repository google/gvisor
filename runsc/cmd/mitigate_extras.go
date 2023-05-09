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

//go:build go1.1
// +build go1.1

package cmd

import (
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/mitigate"
)

// usage returns any extra bits of the usage string.
func (m *Mitigate) usage() string {
	return ""
}

// setFlags sets extra flags for the command Mitigate.
func (m *Mitigate) setFlags(f *flag.FlagSet) {}

// postMitigate handles any postMitigate actions.
func (m *Mitigate) postMitigate(_ mitigate.CPUSet) error {
	return nil
}
