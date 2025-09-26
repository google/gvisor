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

// This file contains utilities for implementors of AsyncReader and
// AsyncWriter.

// NoRegisterClientFD implements AsyncReader.NeedRegisterDestinationFD,
// AsyncReader.RegisterDestinationFD, AsyncWriter.NeedRegisterSourceFD, and
// AsyncWriter.RegisterSourceFD for implementations of AsyncReader and
// AsyncWriter that don't require client FD registration.
type NoRegisterClientFD struct{}

// NeedRegisterDestinationFD implements AsyncReader.NeedRegisterDestinationFD.
func (NoRegisterClientFD) NeedRegisterDestinationFD() bool {
	return false
}

// RegisterDestinationFD implements AsyncReader.RegisterDestinationFD.
func (NoRegisterClientFD) RegisterDestinationFD(fd int32, size uint64, settings []ClientFileRangeSetting) (DestinationFile, error) {
	return nil, nil
}

// NeedRegisterSourceFD implements AsyncWriter.NeedRegisterSourceFD.
func (NoRegisterClientFD) NeedRegisterSourceFD() bool {
	return false
}

// RegisterSourceFD implements AsyncWriter.RegisterSourceFD.
func (NoRegisterClientFD) RegisterSourceFD(fd int32, size uint64, settings []ClientFileRangeSetting) (SourceFile, error) {
	return nil, nil
}

// LocalClientRanges holds mappings as passed to AsyncReader.AddRead,
// AsyncReader.AddReadv, AsyncWriter.AddWrite, or AsyncWriter.AddWritev, for
// use by implementations that ignore the Destination/SourceFile and FileRanges
// and instead use only the provided mappings.
type LocalClientRanges struct {
	// At most one of the following is non-nil:
	Mapping []byte
	Iovecs  []unix.Iovec
}

// LocalClientMapping returns a LocalClientRanges representing the given
// mapping.
func LocalClientMapping(m []byte) LocalClientRanges {
	return LocalClientRanges{Mapping: m}
}

// LocalClientMappings returns a LocalClientRanges representing the given
// mappings.
func LocalClientMappings(iovecs []unix.Iovec) LocalClientRanges {
	return LocalClientRanges{Iovecs: iovecs}
}

// NumMappings returns the number of mappings represented by r.
func (r *LocalClientRanges) NumMappings() int {
	if r.Mapping != nil {
		return 1
	}
	return len(r.Iovecs)
}

// Mappings iterates the mappings represented by r.
func (r *LocalClientRanges) Mappings(yield func(i int, m []byte) bool) {
	if r.Mapping != nil {
		yield(0, r.Mapping)
		return
	}
	for i, iov := range r.Iovecs {
		if !yield(i, SliceFromIovec(iov)) {
			return
		}
	}
}

// DropFirst returns a LocalClientRanges equivalent to r, but with the first n
// bytes omitted. If n >= the total number of bytes in r, DropFirst returns a
// LocalClientRanges representing no mappings.
func (r *LocalClientRanges) DropFirst(n uint64) (r2 LocalClientRanges) {
	for i, m := range r.Mappings {
		if uint64(len(m)) <= n {
			n -= uint64(len(m))
			continue
		}
		m = m[n:]
		n = 0
		if r2.Iovecs == nil && i+1 == r.NumMappings() {
			r2.Mapping = m
			return
		}
		r2.Iovecs = append(r2.Iovecs, unix.Iovec{
			Base: &m[0],
			Len:  uint64(len(m)),
		})
	}
	return
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
