// Copyright 2022 The gVisor Authors.
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

package buffer

import (
	"context"
)

// savedView keeps heap data compact while preserving external chunk ownership
// and sharing. It stores either live heap bytes in data or an externally backed
// View in external, never both.
//
// +stateify savable
type savedView struct {
	data     []byte
	external *View
}

// saveData is invoked by stateify.
func (b *Buffer) saveData() []savedView {
	var views []savedView
	for v := b.data.Front(); v != nil; v = v.Next() {
		if v.chunk.external != nil {
			// Save the owned View itself, without adding a chunk reference.
			// Its storage implementation owns saving the external bytes.
			views = append(views, savedView{external: v})
		} else {
			// A subslice would retain unused capacity and heap chunk aliases.
			// Keep only the live bytes, as the flattened representation did.
			views = append(views, savedView{data: v.ToSlice()})
		}
	}
	return views
}

// loadData is invoked by stateify.
func (b *Buffer) loadData(_ context.Context, views []savedView) {
	*b = Buffer{}
	for _, saved := range views {
		v := saved.external
		if v == nil {
			v = NewViewWithData(saved.data)
		}
		// Restore list ownership without acquiring another chunk reference or
		// accessing external bytes that may not have been restored yet. Append
		// could copy data or release an empty View, so only rebuild the links.
		b.appendOwned(v)
	}
}
