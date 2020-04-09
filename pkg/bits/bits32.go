package bits

// IsOn returns true if *all* bits set in 'bits' are set in 'mask'.
func IsOn32(mask, bits uint32) bool {
	return mask&bits == bits
}

// IsAnyOn returns true if *any* bit set in 'bits' is set in 'mask'.
func IsAnyOn32(mask, bits uint32) bool {
	return mask&bits != 0
}

// Mask returns a T with all of the given bits set.
func Mask32(is ...int) uint32 {
	ret := uint32(0)
	for _, i := range is {
		ret |= MaskOf32(i)
	}
	return ret
}

// MaskOf is like Mask, but sets only a single bit (more efficiently).
func MaskOf32(i int) uint32 {
	return uint32(1) << uint32(i)
}

// IsPowerOfTwo returns true if v is power of 2.
func IsPowerOfTwo32(v uint32) bool {
	if v == 0 {
		return false
	}
	return v&(v-1) == 0
}
