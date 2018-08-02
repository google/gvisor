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

package usermem

import (
	"syscall"
)

// AccessType specifies memory access types. This is used for
// setting mapping permissions, as well as communicating faults.
type AccessType struct {
	// Read is read access.
	Read bool

	// Write is write access.
	Write bool

	// Execute is executable access.
	Execute bool
}

// String returns a pretty representation of access. This looks like the
// familiar r-x, rw-, etc. and can be relied on as such.
func (a AccessType) String() string {
	bits := [3]byte{'-', '-', '-'}
	if a.Read {
		bits[0] = 'r'
	}
	if a.Write {
		bits[1] = 'w'
	}
	if a.Execute {
		bits[2] = 'x'
	}
	return string(bits[:])
}

// Any returns true iff at least one of Read, Write or Execute is true.
func (a AccessType) Any() bool {
	return a.Read || a.Write || a.Execute
}

// Prot returns the system prot (syscall.PROT_READ, etc.) for this access.
func (a AccessType) Prot() int {
	var prot int
	if a.Read {
		prot |= syscall.PROT_READ
	}
	if a.Write {
		prot |= syscall.PROT_WRITE
	}
	if a.Execute {
		prot |= syscall.PROT_EXEC
	}
	return prot
}

// SupersetOf returns true iff the access types in a are a superset of the
// access types in other.
func (a AccessType) SupersetOf(other AccessType) bool {
	if !a.Read && other.Read {
		return false
	}
	if !a.Write && other.Write {
		return false
	}
	if !a.Execute && other.Execute {
		return false
	}
	return true
}

// Intersect returns the access types set in both a and other.
func (a AccessType) Intersect(other AccessType) AccessType {
	return AccessType{
		Read:    a.Read && other.Read,
		Write:   a.Write && other.Write,
		Execute: a.Execute && other.Execute,
	}
}

// Effective returns the set of effective access types allowed by a, even if
// some types are not explicitly allowed.
func (a AccessType) Effective() AccessType {
	// In Linux, Write and Execute access generally imply Read access. See
	// mm/mmap.c:protection_map.
	//
	// The notable exception is get_user_pages, which only checks against
	// the original vma flags. That said, most user memory accesses do not
	// use GUP.
	if a.Write || a.Execute {
		a.Read = true
	}
	return a
}

// Convenient access types.
var (
	NoAccess  = AccessType{}
	Read      = AccessType{Read: true}
	Write     = AccessType{Write: true}
	Execute   = AccessType{Execute: true}
	ReadWrite = AccessType{Read: true, Write: true}
	AnyAccess = AccessType{Read: true, Write: true, Execute: true}
)
