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

package boot

import (
	"fmt"
	"strconv"
	"strings"
)

// NvidiaDevMinors can be used to pass nvidia device minors via flags.
type NvidiaDevMinors []uint32

// String implements flag.Value.
func (n *NvidiaDevMinors) String() string {
	minors := make([]string, 0, len(*n))
	for _, minor := range *n {
		minors = append(minors, strconv.Itoa(int(minor)))
	}
	return strings.Join(minors, ",")
}

// Get implements flag.Value.
func (n *NvidiaDevMinors) Get() any {
	return n
}

// Set implements flag.Value and appends a device minor from the command
// line to the device minors array. Set(String()) should be idempotent.
func (n *NvidiaDevMinors) Set(s string) error {
	minors := strings.Split(s, ",")
	for _, minor := range minors {
		minorVal, err := strconv.Atoi(minor)
		if err != nil {
			return fmt.Errorf("invalid device minor value (%d): %v", minorVal, err)
		}
		*n = append(*n, uint32(minorVal))
	}
	return nil
}
