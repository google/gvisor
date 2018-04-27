// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buffer

// Prependable is a buffer that grows backwards, that is, more data can be
// prepended to it. It is useful when building networking packets, where each
// protocol adds its own headers to the front of the higher-level protocol
// header and payload; for example, TCP would prepend its header to the payload,
// then IP would prepend its own, then ethernet.
type Prependable struct {
	// Buf is the buffer backing the prependable buffer.
	buf View

	// usedIdx is the index where the used part of the buffer begins.
	usedIdx int
}

// NewPrependable allocates a new prependable buffer with the given size.
func NewPrependable(size int) Prependable {
	return Prependable{buf: NewView(size), usedIdx: size}
}

// Prepend reserves the requested space in front of the buffer, returning a
// slice that represents the reserved space.
func (p *Prependable) Prepend(size int) []byte {
	if size > p.usedIdx {
		return nil
	}

	p.usedIdx -= size
	return p.buf[p.usedIdx:][:size:size]
}

// View returns a View of the backing buffer that contains all prepended
// data so far.
func (p *Prependable) View() View {
	v := p.buf
	v.TrimFront(p.usedIdx)
	return v
}

// UsedBytes returns a slice of the backing buffer that contains all prepended
// data so far.
func (p *Prependable) UsedBytes() []byte {
	return p.buf[p.usedIdx:]
}

// UsedLength returns the number of bytes used so far.
func (p *Prependable) UsedLength() int {
	return len(p.buf) - p.usedIdx
}
