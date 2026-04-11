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

// Package sandboxsetup provides helpers for setting up gVisor sandboxes.
package sandboxsetup

import (
	"fmt"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/fd"
)

// IntFlags can be used with int flags that appear multiple times. It
// supports comma-separated lists too.
type IntFlags []int

// String implements flag.Value.
func (i *IntFlags) String() string {
	sInts := make([]string, 0, len(*i))
	for _, fd := range *i {
		sInts = append(sInts, strconv.Itoa(fd))
	}
	return strings.Join(sInts, ",")
}

// Get implements flag.Value.
func (i *IntFlags) Get() any {
	return i
}

// GetArray returns an array of ints.
func (i *IntFlags) GetArray() []int {
	return *i
}

// GetFDs returns an array of *fd.FD.
func (i *IntFlags) GetFDs() []*fd.FD {
	rv := make([]*fd.FD, 0, len(*i))
	for _, val := range *i {
		rv = append(rv, fd.New(val))
	}
	return rv
}

// Set implements flag.Value. Set(String()) should be idempotent.
func (i *IntFlags) Set(s string) error {
	for _, sFD := range strings.Split(s, ",") {
		fd, err := strconv.Atoi(sFD)
		if err != nil {
			return fmt.Errorf("invalid flag value: %v", err)
		}
		if fd < -1 {
			return fmt.Errorf("flag value must be >= -1: %d", fd)
		}
		*i = append(*i, fd)
	}
	return nil
}
