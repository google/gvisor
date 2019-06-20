// Copyright 2018 The gVisor Authors.
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

package state

import (
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/log"
)

// The save metadata keys for timestamp.
const (
	cpuUsage          = "cpu_usage"
	metadataTimestamp = "timestamp"
)

func addSaveMetadata(m map[string]string) {
	t, err := CPUTime()
	if err != nil {
		log.Warningf("Error getting cpu time: %v", err)
	}
	if previousMetadata != nil {
		p, err := time.ParseDuration(previousMetadata[cpuUsage])
		if err != nil {
			log.Warningf("Error parsing previous runs' cpu time: %v", err)
		}
		t += p
	}
	m[cpuUsage] = t.String()

	m[metadataTimestamp] = fmt.Sprintf("%v", time.Now())
}
