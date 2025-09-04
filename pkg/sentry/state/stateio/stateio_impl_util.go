// Copyright 2025 The gVisor Authors.
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

package stateio

import (
	"golang.org/x/sys/unix"
)

// This file contains utilities for implementors of AsyncReader.

// NoRegisterClientFD implements AsyncReader.NeedRegisterDestinationFD and
// AsyncReader.RegisterDestinationFD for implementations of AsyncReader that
// don't require client FD registration.
type NoRegisterClientFD struct{}

// NeedRegisterDestinationFD implements AsyncReader.NeedRegisterDestinationFD.
func (NoRegisterClientFD) NeedRegisterDestinationFD() bool {
	return false
}

// RegisterDestinationFD implements AsyncReader.RegisterDestinationFD.
func (NoRegisterClientFD) RegisterDestinationFD(fd int32, size uint64, settings []ClientFileRangeSetting) (DestinationFile, error) {
	return nil, nil
}

// Submission contains inputs to AsyncReader.StartRead or
// AsyncReader.StartReadv that are relevant to implementations that ignore the
// destination file and FileRanges, and instead only use the provided
// destination mappings.
type Submission struct {
	ID     int
	Offset int64
	Total  uint64
	// Exactly one of the following should be non-nil:
	Mapping []byte
	Iovecs  []unix.Iovec
}

// NumMappings returns the number of mappings represented by s.
func (s *Submission) NumMappings() int {
	if s.Mapping != nil {
		return 1
	}
	return len(s.Iovecs)
}

// Mappings iterates the mappings represented by s.
func (s *Submission) Mappings(yield func(i int, m []byte) bool) {
	if s.Mapping != nil {
		yield(0, s.Mapping)
		return
	}
	for i, iov := range s.Iovecs {
		if !yield(i, SliceFromIovec(iov)) {
			return
		}
	}
}

// CompletionChanWait implements AsyncReader.Wait by receiving from a channel
// of completions.
func CompletionChanWait(ch <-chan Completion, cs []Completion, minCompletions int) ([]Completion, error) {
	for minCompletions > 0 {
		cs = append(cs, <-ch)
		minCompletions--
	}
	for {
		select {
		case c := <-ch:
			cs = append(cs, c)
		default:
			return cs, nil
		}
	}
}
