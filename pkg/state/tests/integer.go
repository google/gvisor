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
	"gvisor.dev/gvisor/pkg/state"
)

// +stateify type
type truncatingUint8 struct {
	save uint64
	load uint8 `state:"nosave"`
}

func (t *truncatingUint8) StateSave(m state.Sink) {
	m.Save(0, &t.save)
}

func (t *truncatingUint8) StateLoad(m state.Source) {
	m.Load(0, &t.load)
	t.save = uint64(t.load)
	t.load = 0
}

var _ state.SaverLoader = (*truncatingUint8)(nil)

// +stateify type
type truncatingUint16 struct {
	save uint64
	load uint16 `state:"nosave"`
}

func (t *truncatingUint16) StateSave(m state.Sink) {
	m.Save(0, &t.save)
}

func (t *truncatingUint16) StateLoad(m state.Source) {
	m.Load(0, &t.load)
	t.save = uint64(t.load)
	t.load = 0
}

var _ state.SaverLoader = (*truncatingUint16)(nil)

// +stateify type
type truncatingUint32 struct {
	save uint64
	load uint32 `state:"nosave"`
}

func (t *truncatingUint32) StateSave(m state.Sink) {
	m.Save(0, &t.save)
}

func (t *truncatingUint32) StateLoad(m state.Source) {
	m.Load(0, &t.load)
	t.save = uint64(t.load)
	t.load = 0
}

var _ state.SaverLoader = (*truncatingUint32)(nil)

// +stateify type
type truncatingInt8 struct {
	save int64
	load int8 `state:"nosave"`
}

func (t *truncatingInt8) StateSave(m state.Sink) {
	m.Save(0, &t.save)
}

func (t *truncatingInt8) StateLoad(m state.Source) {
	m.Load(0, &t.load)
	t.save = int64(t.load)
	t.load = 0
}

var _ state.SaverLoader = (*truncatingInt8)(nil)

// +stateify type
type truncatingInt16 struct {
	save int64
	load int16 `state:"nosave"`
}

func (t *truncatingInt16) StateSave(m state.Sink) {
	m.Save(0, &t.save)
}

func (t *truncatingInt16) StateLoad(m state.Source) {
	m.Load(0, &t.load)
	t.save = int64(t.load)
	t.load = 0
}

var _ state.SaverLoader = (*truncatingInt16)(nil)

// +stateify type
type truncatingInt32 struct {
	save int64
	load int32 `state:"nosave"`
}

func (t *truncatingInt32) StateSave(m state.Sink) {
	m.Save(0, &t.save)
}

func (t *truncatingInt32) StateLoad(m state.Source) {
	m.Load(0, &t.load)
	t.save = int64(t.load)
	t.load = 0
}

var _ state.SaverLoader = (*truncatingInt32)(nil)

// +stateify type
type truncatingFloat32 struct {
	save float64
	load float32 `state:"nosave"`
}

func (t *truncatingFloat32) StateSave(m state.Sink) {
	m.Save(0, &t.save)
}

func (t *truncatingFloat32) StateLoad(m state.Source) {
	m.Load(0, &t.load)
	t.save = float64(t.load)
	t.load = 0
}

var _ state.SaverLoader = (*truncatingFloat32)(nil)

// +stateify type
type truncatingComplex64 struct {
	save complex128
	load complex64 `state:"nosave"`
}

func (t *truncatingComplex64) StateSave(m state.Sink) {
	m.Save(0, &t.save)
}

func (t *truncatingComplex64) StateLoad(m state.Source) {
	m.Load(0, &t.load)
	t.save = complex128(t.load)
	t.load = 0
}

var _ state.SaverLoader = (*truncatingComplex64)(nil)
