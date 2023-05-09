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

// Package cleanup provides utilities to clean "stuff" on defers.
package cleanup

// Cleanup allows defers to be aborted when cleanup needs to happen
// conditionally. Usage:
//
//		 cu := cleanup.Make(func() { f.Close() })
//		 defer cu.Clean() // failure before release is called will close the file.
//		 ...
//	   cu.Add(func() { f2.Close() })  // Adds another cleanup function
//	   ...
//		 cu.Release() // on success, aborts closing the file.
//		 return f
type Cleanup struct {
	cleaners []func()
}

// Make creates a new Cleanup object.
func Make(f func()) Cleanup {
	return Cleanup{cleaners: []func(){f}}
}

// Add adds a new function to be called on Clean().
func (c *Cleanup) Add(f func()) {
	c.cleaners = append(c.cleaners, f)
}

// Clean calls all cleanup functions in reverse order.
func (c *Cleanup) Clean() {
	clean(c.cleaners)
	c.cleaners = nil
}

// Release releases the cleanup from its duties, i.e. cleanup functions are not
// called after this point. Returns a function that calls all registered
// functions in case the caller has use for them.
func (c *Cleanup) Release() func() {
	old := c.cleaners
	c.cleaners = nil
	return func() { clean(old) }
}

func clean(cleaners []func()) {
	for i := len(cleaners) - 1; i >= 0; i-- {
		cleaners[i]()
	}
}
