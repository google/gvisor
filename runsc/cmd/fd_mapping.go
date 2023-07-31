// Copyright 2023 The gVisor Authors.
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

package cmd

import (
	"fmt"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/runsc/boot"
)

// fdMappings can be used with flags that appear multiple times.
type fdMappings []boot.FDMapping

// String implements flag.Value.
func (i *fdMappings) String() string {
	var mappings []string
	for _, m := range *i {
		mappings = append(mappings, fmt.Sprintf("%v:%v", m.Host, m.Guest))
	}
	return strings.Join(mappings, ",")
}

// Get implements flag.Value.
func (i *fdMappings) Get() any {
	return i
}

// GetArray returns an array of mappings.
func (i *fdMappings) GetArray() []boot.FDMapping {
	return *i
}

// Set implements flag.Value and appends a mapping from the command line to the
// mappings array. Set(String()) should be idempotent.
func (i *fdMappings) Set(s string) error {
	for _, m := range strings.Split(s, ",") {
		split := strings.Split(m, ":")
		if len(split) != 2 {
			// Split returns a slice of length 1 if its first argument does not
			// contain the separator. An additional length check is not necessary.
			// In case no separator is used and the argument is a valid integer, we
			// assume that host FD and guest FD should be identical.
			fd, err := strconv.Atoi(split[0])
			if err != nil {
				return fmt.Errorf("invalid flag value: must be an integer or a mapping of format M:N")
			}
			*i = append(*i, boot.FDMapping{
				Host:  fd,
				Guest: fd,
			})
			return nil
		}

		fdHost, err := strconv.Atoi(split[0])
		if err != nil {
			return fmt.Errorf("invalid flag host value: %v", err)
		}
		if fdHost < 0 {
			return fmt.Errorf("flag host value must be >= 0: %d", fdHost)
		}

		fdGuest, err := strconv.Atoi(split[1])
		if err != nil {
			return fmt.Errorf("invalid flag guest value: %v", err)
		}
		if fdGuest < 0 {
			return fmt.Errorf("flag guest value must be >= 0: %d", fdGuest)
		}

		*i = append(*i, boot.FDMapping{
			Host:  fdHost,
			Guest: fdGuest,
		})
	}
	return nil
}
