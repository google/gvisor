// Copyright 2022 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd.

package hostarch

// Masks often used when working with alignment in constant expressions.
//
// PageMask and HugePageMask are defined alongside PageSize and HugePageSize,
// since they are not constants on all architectures.
const (
	CacheLineMask = CacheLineSize - 1
	JumboPageMask = ^uintptr(JumboPageSize - 1)
)

type bytecount interface {
	~uint | ~uint32 | ~uint64 | ~uintptr
}

type hugebytecount interface {
	~uint | ~uint32 | ~uint64 | ~uintptr
}

// PageRoundDown returns x rounded down to the nearest multiple of PageSize.
func PageRoundDown[T bytecount](x T) T {
	return x &^ T(PageMask)
}

// PageRoundUp returns x rounded up to the nearest multiple of PageSize. ok is
// true iff rounding up does not overflow the range of T.
func PageRoundUp[T bytecount](x T) (val T, ok bool) {
	val = PageRoundDown(x + T(PageMask))
	ok = val >= x
	return
}

// MustPageRoundUp is equivalent to PageRoundUp, but panics if rounding up
// overflows.
func MustPageRoundUp[T bytecount](x T) T {
	val, ok := PageRoundUp(x)
	if !ok {
		panic("PageRoundUp overflows")
	}
	return val
}

// PageOffset returns the offset of x into its containing page.
func PageOffset[T bytecount](x T) T {
	return x & T(PageMask)
}

// IsPageAligned returns true if x is a multiple of PageSize.
func IsPageAligned[T bytecount](x T) bool {
	return PageOffset(x) == 0
}

// ToPagesRoundUp returns (the number of pages equal to x bytes rounded up,
// true). If rounding x up to a multiple of PageSize overflows the range of T,
// ToPagesRoundUp returns (unspecified, false).
func ToPagesRoundUp[T bytecount](x T) (T, bool) {
	y := x + T(PageMask)
	if y < x {
		return x, false
	}
	return y >> PageShift, true
}

// HugePageRoundDown returns x rounded down to the nearest multiple of
// HugePageSize.
func HugePageRoundDown[T hugebytecount](x T) T {
	return x &^ T(HugePageMask)
}

// HugePageRoundUp returns x rounded up to the nearest multiple of
// HugePageSize. ok is true iff rounding up does not overflow the range of T.
func HugePageRoundUp[T hugebytecount](x T) (val T, ok bool) {
	val = HugePageRoundDown(x + T(HugePageMask))
	ok = val >= x
	return
}

// MustHugePageRoundUp is equivalent to HugePageRoundUp, but panics if rounding
// up overflows.
func MustHugePageRoundUp[T hugebytecount](x T) T {
	val, ok := HugePageRoundUp(x)
	if !ok {
		panic("HugePageRoundUp overflows")
	}
	return val
}

// HugePageOffset returns the offset of x into its containing page.
func HugePageOffset[T hugebytecount](x T) T {
	return x & T(HugePageMask)
}

// IsHugePageAligned returns true if x is a multiple of HugePageSize.
func IsHugePageAligned[T hugebytecount](x T) bool {
	return HugePageOffset(x) == 0
}

// CacheLineRoundDown returns the offset rounded down to the nearest multiple
// of CacheLineSize.
func CacheLineRoundDown[T bytecount](x T) T {
	return x &^ CacheLineMask
}

// CacheLineRoundUp returns the offset rounded up to the nearest multiple of
// CacheLineSize. ok is true iff rounding up does not overflow the range of T.
func CacheLineRoundUp[T bytecount](x T) (val T, ok bool) {
	val = CacheLineRoundDown(x + CacheLineMask)
	ok = val >= x
	return
}

// MustCacheLineRoundUp is equivalent to CacheLineRoundUp, but panics if
// rounding up overflows.
func MustCacheLineRoundUp[T bytecount](x T) T {
	val, ok := CacheLineRoundUp(x)
	if !ok {
		panic("CacheLineRoundUp overflows")
	}
	return val
}
