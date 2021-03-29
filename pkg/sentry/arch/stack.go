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

package arch

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal/primitive"

	"gvisor.dev/gvisor/pkg/usermem"
)

// Stack is a simple wrapper around a hostarch.IO and an address. Stack
// implements marshal.CopyContext, and marshallable values can be pushed or
// popped from the stack through the marshal.Marshallable interface.
//
// Stack is not thread-safe.
type Stack struct {
	// Our arch info.
	// We use this for automatic Native conversion of hostarch.Addrs during
	// Push() and Pop().
	Arch Context

	// The interface used to actually copy user memory.
	IO usermem.IO

	// Our current stack bottom.
	Bottom hostarch.Addr

	// Scratch buffer used for marshalling to avoid having to repeatedly
	// allocate scratch memory.
	scratchBuf []byte
}

// scratchBufLen is the default length of Stack.scratchBuf. The
// largest structs the stack regularly serializes are arch.SignalInfo
// and arch.UContext64. We'll set the default size as the larger of
// the two, arch.UContext64.
var scratchBufLen = (*UContext64)(nil).SizeBytes()

// CopyScratchBuffer implements marshal.CopyContext.CopyScratchBuffer.
func (s *Stack) CopyScratchBuffer(size int) []byte {
	if len(s.scratchBuf) < size {
		s.scratchBuf = make([]byte, size)
	}
	return s.scratchBuf[:size]
}

// StackBottomMagic is the special address callers must past to all stack
// marshalling operations to cause the src/dst address to be computed based on
// the current end of the stack.
const StackBottomMagic = ^hostarch.Addr(0) // hostarch.Addr(-1)

// CopyOutBytes implements marshal.CopyContext.CopyOutBytes. CopyOutBytes
// computes an appropriate address based on the current end of the
// stack. Callers use the sentinel address StackBottomMagic to marshal methods
// to indicate this.
func (s *Stack) CopyOutBytes(sentinel hostarch.Addr, b []byte) (int, error) {
	if sentinel != StackBottomMagic {
		panic("Attempted to copy out to stack with absolute address")
	}
	c := len(b)
	n, err := s.IO.CopyOut(context.Background(), s.Bottom-hostarch.Addr(c), b, usermem.IOOpts{})
	if err == nil && n == c {
		s.Bottom -= hostarch.Addr(n)
	}
	return n, err
}

// CopyInBytes implements marshal.CopyContext.CopyInBytes. CopyInBytes computes
// an appropriate address based on the current end of the stack. Callers must
// use the sentinel address StackBottomMagic to marshal methods to indicate
// this.
func (s *Stack) CopyInBytes(sentinel hostarch.Addr, b []byte) (int, error) {
	if sentinel != StackBottomMagic {
		panic("Attempted to copy in from stack with absolute address")
	}
	n, err := s.IO.CopyIn(context.Background(), s.Bottom, b, usermem.IOOpts{})
	if err == nil {
		s.Bottom += hostarch.Addr(n)
	}
	return n, err
}

// Align aligns the stack to the given offset.
func (s *Stack) Align(offset int) {
	if s.Bottom%hostarch.Addr(offset) != 0 {
		s.Bottom -= (s.Bottom % hostarch.Addr(offset))
	}
}

// PushNullTerminatedByteSlice writes bs to the stack, followed by an extra null
// byte at the end. On error, the contents of the stack and the bottom cursor
// are undefined.
func (s *Stack) PushNullTerminatedByteSlice(bs []byte) (int, error) {
	// Note: Stack grows up, so write the terminal null byte first.
	nNull, err := primitive.CopyUint8Out(s, StackBottomMagic, 0)
	if err != nil {
		return 0, err
	}
	n, err := primitive.CopyByteSliceOut(s, StackBottomMagic, bs)
	if err != nil {
		return 0, err
	}
	return n + nNull, nil
}

// StackLayout describes the location of the arguments and environment on the
// stack.
type StackLayout struct {
	// ArgvStart is the beginning of the argument vector.
	ArgvStart hostarch.Addr

	// ArgvEnd is the end of the argument vector.
	ArgvEnd hostarch.Addr

	// EnvvStart is the beginning of the environment vector.
	EnvvStart hostarch.Addr

	// EnvvEnd is the end of the environment vector.
	EnvvEnd hostarch.Addr
}

// Load pushes the given args, env and aux vector to the stack using the
// well-known format for a new executable. It returns the start and end
// of the argument and environment vectors.
func (s *Stack) Load(args []string, env []string, aux Auxv) (StackLayout, error) {
	l := StackLayout{}

	// Make sure we start with a 16-byte alignment.
	s.Align(16)

	// Push the environment vector so the end of the argument vector is adjacent to
	// the beginning of the environment vector.
	// While the System V abi for x86_64 does not specify an ordering to the
	// Information Block (the block holding the arg, env, and aux vectors),
	// support features like setproctitle(3) naturally expect these segments
	// to be in this order. See: https://www.uclibc.org/docs/psABI-x86_64.pdf
	// page 29.
	l.EnvvEnd = s.Bottom
	envAddrs := make([]hostarch.Addr, len(env))
	for i := len(env) - 1; i >= 0; i-- {
		if _, err := s.PushNullTerminatedByteSlice([]byte(env[i])); err != nil {
			return StackLayout{}, err
		}
		envAddrs[i] = s.Bottom
	}
	l.EnvvStart = s.Bottom

	// Push our strings.
	l.ArgvEnd = s.Bottom
	argAddrs := make([]hostarch.Addr, len(args))
	for i := len(args) - 1; i >= 0; i-- {
		if _, err := s.PushNullTerminatedByteSlice([]byte(args[i])); err != nil {
			return StackLayout{}, err
		}
		argAddrs[i] = s.Bottom
	}
	l.ArgvStart = s.Bottom

	// We need to align the arguments appropriately.
	//
	// We must finish on a 16-byte alignment, but we'll play it
	// conservatively and finish at 32-bytes. It would be nice to be able
	// to call Align here, but unfortunately we need to align the stack
	// with all the variable sized arrays pushed. So we just need to do
	// some calculations.
	argvSize := s.Arch.Width() * uint(len(args)+1)
	envvSize := s.Arch.Width() * uint(len(env)+1)
	auxvSize := s.Arch.Width() * 2 * uint(len(aux)+1)
	total := hostarch.Addr(argvSize) + hostarch.Addr(envvSize) + hostarch.Addr(auxvSize) + hostarch.Addr(s.Arch.Width())
	expectedBottom := s.Bottom - total
	if expectedBottom%32 != 0 {
		s.Bottom -= expectedBottom % 32
	}

	// Push our auxvec.
	// NOTE: We need an extra zero here per spec.
	// The Push function will automatically terminate
	// strings and arrays with a single null value.
	auxv := make([]hostarch.Addr, 0, len(aux))
	for _, a := range aux {
		auxv = append(auxv, hostarch.Addr(a.Key), a.Value)
	}
	auxv = append(auxv, hostarch.Addr(0))
	_, err := s.pushAddrSliceAndTerminator(auxv)
	if err != nil {
		return StackLayout{}, err
	}

	// Push environment.
	_, err = s.pushAddrSliceAndTerminator(envAddrs)
	if err != nil {
		return StackLayout{}, err
	}

	// Push args.
	_, err = s.pushAddrSliceAndTerminator(argAddrs)
	if err != nil {
		return StackLayout{}, err
	}

	// Push arg count.
	lenP := s.Arch.Native(uintptr(len(args)))
	if _, err = lenP.CopyOut(s, StackBottomMagic); err != nil {
		return StackLayout{}, err
	}

	return l, nil
}
