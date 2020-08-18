// Copyright 2020 The gVisor Authors.
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

// Package tags is a utility for parsing build tags.
package tags

import (
	"fmt"
	"io/ioutil"
	"strings"
)

// OrSet is a set of tags on a single line.
//
// Note that tags may include ",", and we don't distinguish this case in the
// logic below. Ideally, this constraints can be split into separate top-level
// build tags in order to resolve any issues.
type OrSet []string

// Line returns the line for this or.
func (or OrSet) Line() string {
	return fmt.Sprintf("// +build %s", strings.Join([]string(or), " "))
}

// AndSet is the set of all OrSets.
type AndSet []OrSet

// Lines returns the lines to be printed.
func (and AndSet) Lines() (ls []string) {
	for _, or := range and {
		ls = append(ls, or.Line())
	}
	return
}

// Join joins this AndSet with another.
func (and AndSet) Join(other AndSet) AndSet {
	return append(and, other...)
}

// Tags returns the unique set of +build tags.
//
// Derived form the runtime's canBuild.
func Tags(file string) (tags AndSet) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil
	}
	// Check file contents for // +build lines.
	for _, p := range strings.Split(string(data), "\n") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "//") {
			break
		}
		if !strings.Contains(p, "+build") {
			continue
		}
		fields := strings.Fields(p[2:])
		if len(fields) < 1 || fields[0] != "+build" {
			continue
		}
		tags = append(tags, OrSet(fields[1:]))
	}
	return tags
}

// Aggregate aggregates all tags from a set of files.
//
// Note that these may be in conflict, in which case the build will fail.
func Aggregate(files []string) (tags AndSet) {
	for _, file := range files {
		tags = tags.Join(Tags(file))
	}
	return tags
}
