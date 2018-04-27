// Copyright 2018 Google Inc.
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

package fs

import (
	"testing"
)

func TestDirentCache(t *testing.T) {
	const maxSize = 5

	c := NewDirentCache(maxSize)

	// Size starts at 0.
	if got, want := c.Size(), uint64(0); got != want {
		t.Errorf("c.Size() got %v, want %v", got, want)
	}

	// Create a Dirent d.
	d := NewNegativeDirent("")

	// c does not contain d.
	if got, want := c.contains(d), false; got != want {
		t.Errorf("c.contains(d) got %v want %v", got, want)
	}

	// Add d to the cache.
	c.Add(d)

	// Size is now 1.
	if got, want := c.Size(), uint64(1); got != want {
		t.Errorf("c.Size() got %v, want %v", got, want)
	}

	// c contains d.
	if got, want := c.contains(d), true; got != want {
		t.Errorf("c.contains(d) got %v want %v", got, want)
	}

	// Add maxSize-1 more elements.  d should be oldest element.
	for i := 0; i < maxSize-1; i++ {
		c.Add(NewNegativeDirent(""))
	}

	// Size is maxSize.
	if got, want := c.Size(), uint64(maxSize); got != want {
		t.Errorf("c.Size() got %v, want %v", got, want)
	}

	// c contains d.
	if got, want := c.contains(d), true; got != want {
		t.Errorf("c.contains(d) got %v want %v", got, want)
	}

	// "Bump" d to the front by re-adding it.
	c.Add(d)

	// Size is maxSize.
	if got, want := c.Size(), uint64(maxSize); got != want {
		t.Errorf("c.Size() got %v, want %v", got, want)
	}

	// c contains d.
	if got, want := c.contains(d), true; got != want {
		t.Errorf("c.contains(d) got %v want %v", got, want)
	}

	// Add maxSize-1 more elements.  d should again be oldest element.
	for i := 0; i < maxSize-1; i++ {
		c.Add(NewNegativeDirent(""))
	}

	// Size is maxSize.
	if got, want := c.Size(), uint64(maxSize); got != want {
		t.Errorf("c.Size() got %v, want %v", got, want)
	}

	// c contains d.
	if got, want := c.contains(d), true; got != want {
		t.Errorf("c.contains(d) got %v want %v", got, want)
	}

	// Add one more element, which will bump d from the cache.
	c.Add(NewNegativeDirent(""))

	// Size is maxSize.
	if got, want := c.Size(), uint64(maxSize); got != want {
		t.Errorf("c.Size() got %v, want %v", got, want)
	}

	// c does not contain d.
	if got, want := c.contains(d), false; got != want {
		t.Errorf("c.contains(d) got %v want %v", got, want)
	}

	// Invalidating causes size to be 0 and list to be empty.
	c.Invalidate()
	if got, want := c.Size(), uint64(0); got != want {
		t.Errorf("c.Size() got %v, want %v", got, want)
	}
	if got, want := c.list.Empty(), true; got != want {
		t.Errorf("c.list.Empty() got %v, want %v", got, want)
	}

	// Fill cache with maxSize dirents.
	for i := 0; i < maxSize; i++ {
		c.Add(NewNegativeDirent(""))
	}
}

// TestNilDirentCache tests that a nil cache supports all cache operations, but
// treats them as noop.
func TestNilDirentCache(t *testing.T) {
	// Create a nil cache.
	var c *DirentCache

	// Size is zero.
	if got, want := c.Size(), uint64(0); got != want {
		t.Errorf("c.Size() got %v, want %v", got, want)
	}

	// Call Add.
	c.Add(NewNegativeDirent(""))

	// Size is zero.
	if got, want := c.Size(), uint64(0); got != want {
		t.Errorf("c.Size() got %v, want %v", got, want)
	}

	// Call Remove.
	c.Remove(NewNegativeDirent(""))

	// Size is zero.
	if got, want := c.Size(), uint64(0); got != want {
		t.Errorf("c.Size() got %v, want %v", got, want)
	}

	// Call Invalidate.
	c.Invalidate()

	// Size is zero.
	if got, want := c.Size(), uint64(0); got != want {
		t.Errorf("c.Size() got %v, want %v", got, want)
	}
}
