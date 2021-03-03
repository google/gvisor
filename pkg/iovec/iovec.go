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

// +build linux

// Package iovec provides helpers to interact with vectorized I/O on host
// system.
package iovec

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
)

// MaxIovs is the maximum number of iovecs host platform can accept.
var MaxIovs = linux.UIO_MAXIOV

// Builder is a builder for slice of unix.Iovec.
type Builder struct {
	iovec   []unix.Iovec
	storage [8]unix.Iovec

	// overflow tracks the last buffer when iovec length is at MaxIovs.
	overflow []byte
}

// Add adds buf to b preparing to be written. Zero-length buf won't be added.
func (b *Builder) Add(buf []byte) {
	if len(buf) == 0 {
		return
	}
	if b.iovec == nil {
		b.iovec = b.storage[:0]
	}
	if len(b.iovec) >= MaxIovs {
		b.addByAppend(buf)
		return
	}
	b.iovec = append(b.iovec, unix.Iovec{
		Base: &buf[0],
		Len:  uint64(len(buf)),
	})
	// Keep the last buf if iovec is at max capacity. We will need to append to it
	// for later bufs.
	if len(b.iovec) == MaxIovs {
		n := len(buf)
		b.overflow = buf[:n:n]
	}
}

func (b *Builder) addByAppend(buf []byte) {
	b.overflow = append(b.overflow, buf...)
	b.iovec[len(b.iovec)-1] = unix.Iovec{
		Base: &b.overflow[0],
		Len:  uint64(len(b.overflow)),
	}
}

// Build returns the final Iovec slice. The length of returned iovec will not
// excceed MaxIovs.
func (b *Builder) Build() []unix.Iovec {
	return b.iovec
}
