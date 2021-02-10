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

package mitigate

import (
	"gvisor.dev/gvisor/runsc/flag"
)

type mitigate struct {
}

// usage returns the usage string portion for the mitigate.
func (m mitigate) usage() string { return "" }

// setFlags sets additional flags for the Mitigate command.
func (m mitigate) setFlags(f *flag.FlagSet) {}

// execute performs additional parts of Execute for Mitigate.
func (m mitigate) execute(set cpuSet, dryrun bool) error {
	return nil
}

func (m mitigate) vulnerable(other *thread) bool {
	return other.isVulnerable()
}
