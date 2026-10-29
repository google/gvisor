// Copyright 2018 The gVisor Authors.
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

package tests

import (
	"context"

	"gvisor.dev/gvisor/pkg/state"
)

// +stateify savable
type arrayContainer struct {
	v [1]any
}

// +stateify savable
type arrayPtrContainer struct {
	v *[1]any
}

// +stateify savable
type sliceContainer struct {
	v []any
}

// +stateify savable
type slicePtrContainer struct {
	v *[]any
}

// +stateify type
type arraySigned int16

// +stateify type
type arrayUnsigned uint32

// +stateify type
type arrayString string

// +stateify savable
type arraySnapshotSource struct {
	values [2]uint64
}

// +stateify savable
type arraySnapshotMutator struct {
	target *arraySnapshotSource
}

func (m *arraySnapshotMutator) beforeSave() {
	m.target.values[0] = 99
}

// +stateify savable
type arrayTailDiscovery struct {
	values [][2]uint64
}

// +stateify savable
type countedArrayContainer struct {
	first    any
	values   []countedArrayWord
	pointers []*countedArrayWord
	zeros    []registeredMapStruct
}

// +stateify type
type arraySliceLoadWord struct{ value uint64 }

func (v *arraySliceLoadWord) StateSave(s state.Sink) { s.Save(0, &v.value) }

func (v *arraySliceLoadWord) StateLoad(ctx context.Context, s state.Source) {
	s.Load(0, &v.value)
	load := ctx.Value(arraySliceLoadKey{}).(*arraySliceLoadState)
	load.receivers = append(load.receivers, v)
	if len(load.receivers) == 1 {
		*load.target = load.replacement
	}
}

type arraySliceLoadKey struct{}

type arraySliceLoadState struct {
	target      *[]arraySliceLoadWord
	replacement []arraySliceLoadWord
	receivers   []*arraySliceLoadWord
}

// arraySliceLoad saves a slice field as an array value via SaveValue.
// +stateify type
type arraySliceLoad struct {
	ignored uint64 `state:"nosave"`
	values  []arraySliceLoadWord
}

func (v *arraySliceLoad) StateSave(s state.Sink) {
	var values [2]arraySliceLoadWord
	copy(values[:], v.values)
	s.SaveValue(0, values)
}

func (v *arraySliceLoad) StateLoad(_ context.Context, s state.Source) {
	s.Load(0, &v.values)
}

// +stateify type
type countedArrayWord struct{ value uint64 }

func (v *countedArrayWord) StateSave(s state.Sink) { s.Save(0, &v.value) }

func (v *countedArrayWord) StateLoad(ctx context.Context, s state.Source) {
	receivers := ctx.Value(arrayReceiverKey{}).(*arrayReceiverCensus)
	receivers.loaded = append(receivers.loaded, v)
	s.Load(0, &v.value)
}

type arrayReceiverKey struct{}

type arrayReceiverCensus struct {
	loaded []*countedArrayWord
}
