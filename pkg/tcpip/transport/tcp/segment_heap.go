// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tcp

type segmentHeap []*segment

// Len returns the length of h.
func (h segmentHeap) Len() int {
	return len(h)
}

// Less determines whether the i-th element of h is less than the j-th element.
func (h segmentHeap) Less(i, j int) bool {
	return h[i].sequenceNumber.LessThan(h[j].sequenceNumber)
}

// Swap swaps the i-th and j-th elements of h.
func (h segmentHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

// Push adds x as the last element of h.
func (h *segmentHeap) Push(x interface{}) {
	*h = append(*h, x.(*segment))
}

// Pop removes the last element of h and returns it.
func (h *segmentHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}
