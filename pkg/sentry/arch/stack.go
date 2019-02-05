// Copyright 2018 Google LLC
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
	"encoding/binary"
	"fmt"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// Stack is a simple wrapper around a usermem.IO and an address.
type Stack struct {
	// Our arch info.
	// We use this for automatic Native conversion of usermem.Addrs during
	// Push() and Pop().
	Arch Context

	// The interface used to actually copy user memory.
	IO usermem.IO

	// Our current stack bottom.
	Bottom usermem.Addr
}

// Push pushes the given values on to the stack.
//
// (This method supports Addrs and treats them as native types.)
func (s *Stack) Push(vals ...interface{}) (usermem.Addr, error) {
	for _, v := range vals {

		// We convert some types to well-known serializable quanities.
		var norm interface{}

		// For array types, we will automatically add an appropriate
		// terminal value. This is done simply to make the interface
		// easier to use.
		var term interface{}

		switch v.(type) {
		case string:
			norm = []byte(v.(string))
			term = byte(0)
		case []int8, []uint8:
			norm = v
			term = byte(0)
		case []int16, []uint16:
			norm = v
			term = uint16(0)
		case []int32, []uint32:
			norm = v
			term = uint32(0)
		case []int64, []uint64:
			norm = v
			term = uint64(0)
		case []usermem.Addr:
			// Special case: simply push recursively.
			_, err := s.Push(s.Arch.Native(uintptr(0)))
			if err != nil {
				return 0, err
			}
			varr := v.([]usermem.Addr)
			for i := len(varr) - 1; i >= 0; i-- {
				_, err := s.Push(varr[i])
				if err != nil {
					return 0, err
				}
			}
			continue
		case usermem.Addr:
			norm = s.Arch.Native(uintptr(v.(usermem.Addr)))
		default:
			norm = v
		}

		if term != nil {
			_, err := s.Push(term)
			if err != nil {
				return 0, err
			}
		}

		c := binary.Size(norm)
		if c < 0 {
			return 0, fmt.Errorf("bad binary.Size for %T", v)
		}
		// TODO: Use a real context.Context.
		n, err := usermem.CopyObjectOut(context.Background(), s.IO, s.Bottom-usermem.Addr(c), norm, usermem.IOOpts{})
		if err != nil || c != n {
			return 0, err
		}

		s.Bottom -= usermem.Addr(n)
	}

	return s.Bottom, nil
}

// Pop pops the given values off the stack.
//
// (This method supports Addrs and treats them as native types.)
func (s *Stack) Pop(vals ...interface{}) (usermem.Addr, error) {
	for _, v := range vals {

		vaddr, isVaddr := v.(*usermem.Addr)

		var n int
		var err error
		if isVaddr {
			value := s.Arch.Native(uintptr(0))
			// TODO: Use a real context.Context.
			n, err = usermem.CopyObjectIn(context.Background(), s.IO, s.Bottom, value, usermem.IOOpts{})
			*vaddr = usermem.Addr(s.Arch.Value(value))
		} else {
			// TODO: Use a real context.Context.
			n, err = usermem.CopyObjectIn(context.Background(), s.IO, s.Bottom, v, usermem.IOOpts{})
		}
		if err != nil {
			return 0, err
		}

		s.Bottom += usermem.Addr(n)
	}

	return s.Bottom, nil
}

// Align aligns the stack to the given offset.
func (s *Stack) Align(offset int) {
	if s.Bottom%usermem.Addr(offset) != 0 {
		s.Bottom -= (s.Bottom % usermem.Addr(offset))
	}
}

// StackLayout describes the location of the arguments and environment on the
// stack.
type StackLayout struct {
	// ArgvStart is the beginning of the argument vector.
	ArgvStart usermem.Addr

	// ArgvEnd is the end of the argument vector.
	ArgvEnd usermem.Addr

	// EnvvStart is the beginning of the environment vector.
	EnvvStart usermem.Addr

	// EnvvEnd is the end of the environment vector.
	EnvvEnd usermem.Addr
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
	envAddrs := make([]usermem.Addr, len(env))
	for i := len(env) - 1; i >= 0; i-- {
		addr, err := s.Push(env[i])
		if err != nil {
			return StackLayout{}, err
		}
		envAddrs[i] = addr
	}
	l.EnvvStart = s.Bottom

	// Push our strings.
	l.ArgvEnd = s.Bottom
	argAddrs := make([]usermem.Addr, len(args))
	for i := len(args) - 1; i >= 0; i-- {
		addr, err := s.Push(args[i])
		if err != nil {
			return StackLayout{}, err
		}
		argAddrs[i] = addr
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
	total := usermem.Addr(argvSize) + usermem.Addr(envvSize) + usermem.Addr(auxvSize) + usermem.Addr(s.Arch.Width())
	expectedBottom := s.Bottom - total
	if expectedBottom%32 != 0 {
		s.Bottom -= expectedBottom % 32
	}

	// Push our auxvec.
	// NOTE: We need an extra zero here per spec.
	// The Push function will automatically terminate
	// strings and arrays with a single null value.
	auxv := make([]usermem.Addr, 0, len(aux))
	for _, a := range aux {
		auxv = append(auxv, usermem.Addr(a.Key), a.Value)
	}
	auxv = append(auxv, usermem.Addr(0))
	_, err := s.Push(auxv)
	if err != nil {
		return StackLayout{}, err
	}

	// Push environment.
	_, err = s.Push(envAddrs)
	if err != nil {
		return StackLayout{}, err
	}

	// Push args.
	_, err = s.Push(argAddrs)
	if err != nil {
		return StackLayout{}, err
	}

	// Push arg count.
	_, err = s.Push(usermem.Addr(len(args)))
	if err != nil {
		return StackLayout{}, err
	}

	return l, nil
}
