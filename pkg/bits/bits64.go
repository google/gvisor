package bits

// IsOn returns true if *all* bits set in 'bits' are set in 'mask'.
func IsOn64(mask, bits uint64) bool {
	return mask&bits == bits
}

// IsAnyOn returns true if *any* bit set in 'bits' is set in 'mask'.
func IsAnyOn64(mask, bits uint64) bool {
	return mask&bits != 0
}

// Mask returns a T with all of the given bits set.
func Mask64(is ...int) uint64 {
	ret := uint64(0)
	for _, i := range is {
		ret |= MaskOf64(i)
	}
	return ret
}

// MaskOf is like Mask, but sets only a single bit (more efficiently).
func MaskOf64(i int) uint64 {
	return uint64(1) << uint64(i)
}
