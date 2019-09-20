// Copyright 2019 The gVisor Authors.
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
	"unsafe"

	"gvisor.dev/gvisor/pkg/sentry/context"
)

// stringFromImmutableBytes is equivalent to string(bs), except that it never
// copies even if escape analysis can't prove that bs does not escape. This is
// only valid if bs is never mutated after stringFromImmutableBytes returns.
func stringFromImmutableBytes(bs []byte) string {
	// Compare strings.Builder.String().
	return *(*string)(unsafe.Pointer(&bs))
}

//go:linkname rawbyteslice runtime.rawbyteslice
func rawbyteslice(size int) []byte

// CopyInVecNew copies bytes from the memory mapped at ars in uio to a new
// slice. The capacity of the slice is ars.NumBytes() or num, whichever is
// less and the length is the number of bytes copied. CopyInVecNew returns the
// new slice; if the length is less than the capacity, it returns a non-nil
// error explaining why.
//
// Preconditions: As for IO.CopyIn.
func CopyInVecNew(ctx context.Context, uio IO, ars AddrRangeSeq, num int, opts IOOpts) ([]byte, error) {
	toCopy := num
	if nb := int(ars.NumBytes()); toCopy > nb {
		toCopy = nb
	}
	dst := rawbyteslice(toCopy)
	var done int
	for done < toCopy {
		ar := ars.Head()
		cplen := len(dst) - done
		if Addr(cplen) >= ar.Length() {
			cplen = int(ar.Length())
		}
		n, err := uio.CopyIn(ctx, ar.Start, dst[done:done+cplen], opts)
		done += n
		if err != nil {
			dst = dst[:done]

			// Zero out uninitialized portion of slice.
			dst = append(dst, make([]byte, toCopy-done)...)
			dst = dst[:done]

			return dst, err
		}
		ars = ars.DropFirst(n)
	}
	return dst, nil
}
