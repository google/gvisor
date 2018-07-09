// Copyright 2018 Google Inc.
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

// Package buffer provides the implementation of a buffer view.
package buffer

// View is a slice of a buffer, with convenience methods.
type View []byte

// NewView allocates a new buffer and returns an initialized view that covers
// the whole buffer.
func NewView(size int) View {
	return make(View, size)
}

// NewViewFromBytes allocates a new buffer and copies in the given bytes.
func NewViewFromBytes(b []byte) View {
	return append(View(nil), b...)
}

// TrimFront removes the first "count" bytes from the visible section of the
// buffer.
func (v *View) TrimFront(count int) {
	*v = (*v)[count:]
}

// CapLength irreversibly reduces the length of the visible section of the
// buffer to the value specified.
func (v *View) CapLength(length int) {
	// We also set the slice cap because if we don't, one would be able to
	// expand the view back to include the region just excluded. We want to
	// prevent that to avoid potential data leak if we have uninitialized
	// data in excluded region.
	*v = (*v)[:length:length]
}

// ToVectorisedView transforms a View in a VectorisedView from an
// already-allocated slice of View.
func (v *View) ToVectorisedView(views [1]View) VectorisedView {
	views[0] = *v
	return NewVectorisedView(len(*v), views[:])
}

// VectorisedView is a vectorised version of View using non contigous memory.
// It supports all the convenience methods supported by View.
type VectorisedView struct {
	views []View
	size  int
}

// NewVectorisedView creates a new vectorised view from an already-allocated slice
// of View and sets its size.
func NewVectorisedView(size int, views []View) VectorisedView {
	return VectorisedView{views: views, size: size}
}

// TrimFront removes the first "count" bytes of the vectorised view.
func (vv *VectorisedView) TrimFront(count int) {
	for count > 0 && len(vv.views) > 0 {
		if count < len(vv.views[0]) {
			vv.size -= count
			vv.views[0].TrimFront(count)
			return
		}
		count -= len(vv.views[0])
		vv.RemoveFirst()
	}
}

// CapLength irreversibly reduces the length of the vectorised view.
func (vv *VectorisedView) CapLength(length int) {
	if length < 0 {
		length = 0
	}
	if vv.size < length {
		return
	}
	vv.size = length
	for i := range vv.views {
		v := &vv.views[i]
		if len(*v) >= length {
			if length == 0 {
				vv.views = vv.views[:i]
			} else {
				v.CapLength(length)
				vv.views = vv.views[:i+1]
			}
			return
		}
		length -= len(*v)
	}
}

// Clone returns a clone of this VectorisedView.
// If the buffer argument is large enough to contain all the Views of this VectorisedView,
// the method will avoid allocations and use the buffer to store the Views of the clone.
func (vv *VectorisedView) Clone(buffer []View) VectorisedView {
	var views []View
	if len(buffer) >= len(vv.views) {
		views = buffer[:len(vv.views)]
	} else {
		views = make([]View, len(vv.views))
	}
	for i, v := range vv.views {
		views[i] = v
	}
	return VectorisedView{views: views, size: vv.size}
}

// First returns the first view of the vectorised view.
// It panics if the vectorised view is empty.
func (vv *VectorisedView) First() View {
	if len(vv.views) == 0 {
		return nil
	}
	return vv.views[0]
}

// RemoveFirst removes the first view of the vectorised view.
func (vv *VectorisedView) RemoveFirst() {
	if len(vv.views) == 0 {
		return
	}
	vv.size -= len(vv.views[0])
	vv.views = vv.views[1:]
}

// SetSize unsafely sets the size of the VectorisedView.
func (vv *VectorisedView) SetSize(size int) {
	vv.size = size
}

// SetViews unsafely sets the views of the VectorisedView.
func (vv *VectorisedView) SetViews(views []View) {
	vv.views = views
}

// Size returns the size in bytes of the entire content stored in the vectorised view.
func (vv *VectorisedView) Size() int {
	return vv.size
}

// ToView returns the a single view containing the content of the vectorised view.
func (vv *VectorisedView) ToView() View {
	v := make([]byte, vv.size)
	u := v
	for i := range vv.views {
		n := copy(u, vv.views[i])
		u = u[n:]
	}
	return v
}

// Views returns the slice containing the all views.
func (vv *VectorisedView) Views() []View {
	return vv.views
}

// ByteSlice returns a slice containing the all views as a []byte.
func (vv *VectorisedView) ByteSlice() [][]byte {
	s := make([][]byte, len(vv.views))
	for i := range vv.views {
		s[i] = []byte(vv.views[i])
	}
	return s
}

// copy returns a deep-copy of the vectorised view.
// It is an expensive method that should be used only in tests.
func (vv *VectorisedView) copy() *VectorisedView {
	uu := &VectorisedView{
		views: make([]View, len(vv.views)),
		size:  vv.size,
	}
	for i, v := range vv.views {
		uu.views[i] = make(View, len(v))
		copy(uu.views[i], v)
	}
	return uu
}
