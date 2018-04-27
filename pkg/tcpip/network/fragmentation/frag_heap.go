// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fragmentation

import (
	"container/heap"
	"fmt"

	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
)

type fragment struct {
	offset uint16
	vv     *buffer.VectorisedView
}

type fragHeap []fragment

func (h *fragHeap) Len() int {
	return len(*h)
}

func (h *fragHeap) Less(i, j int) bool {
	return (*h)[i].offset < (*h)[j].offset
}

func (h *fragHeap) Swap(i, j int) {
	(*h)[i], (*h)[j] = (*h)[j], (*h)[i]
}

func (h *fragHeap) Push(x interface{}) {
	*h = append(*h, x.(fragment))
}

func (h *fragHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

// reassamble empties the heap and returns a VectorisedView
// containing a reassambled version of the fragments inside the heap.
func (h *fragHeap) reassemble() (buffer.VectorisedView, error) {
	curr := heap.Pop(h).(fragment)
	views := curr.vv.Views()
	size := curr.vv.Size()

	if curr.offset != 0 {
		return buffer.NewVectorisedView(0, nil), fmt.Errorf("offset of the first packet is != 0 (%d)", curr.offset)
	}

	for h.Len() > 0 {
		curr := heap.Pop(h).(fragment)
		if int(curr.offset) < size {
			curr.vv.TrimFront(size - int(curr.offset))
		} else if int(curr.offset) > size {
			return buffer.NewVectorisedView(0, nil), fmt.Errorf("packet has a hole, expected offset %d, got %d", size, curr.offset)
		}
		size += curr.vv.Size()
		views = append(views, curr.vv.Views()...)
	}
	return buffer.NewVectorisedView(size, views), nil
}
