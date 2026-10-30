// Copyright 2026 The gVisor Authors.
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

package state

import "math"

// The methods below save and load fields of predeclared types, which
// go_stateify can identify. Under the graph engine, each Load* method must be
// paired with the matching Save* method in slot order. Values of these types
// are never reused from encodings of containing objects (see trySplice).

func b2u8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// SaveBool saves a bool field. See Save.
func (s Sink) SaveBool(slot int, v *bool) {
	if es := s.graph.es; es != nil {
		es.out.byte(b2u8(*v))
		return
	}
	s.Save(slot, v)
}

// LoadBool loads a bool field. See Load.
func (s Source) LoadBool(slot int, v *bool) {
	if ds := s.graph.ds; ds != nil {
		x := ds.in.byte()
		if x > 1 {
			Failf("invalid bool %d", x)
		}
		if x != 0 || !ds.keepZero {
			*v = x != 0
		}
		return
	}
	s.Load(slot, v)
}

// SaveInt saves a int field. See Save.
func (s Sink) SaveInt(slot int, v *int) {
	if es := s.graph.es; es != nil {
		es.out.varint(int64(*v))
		return
	}
	s.Save(slot, v)
}

// LoadInt loads a int field. See Load.
func (s Source) LoadInt(slot int, v *int) {
	if ds := s.graph.ds; ds != nil {
		x := ds.in.varint()
		if int64(int(x)) != x {
			Failf("signed integer %d overflows int", x)
		}
		if x != 0 || !ds.keepZero {
			*v = int(x)
		}
		return
	}
	s.Load(slot, v)
}

// SaveInt8 saves a int8 field. See Save.
func (s Sink) SaveInt8(slot int, v *int8) {
	if es := s.graph.es; es != nil {
		es.out.byte(uint8(*v))
		return
	}
	s.Save(slot, v)
}

// LoadInt8 loads a int8 field. See Load.
func (s Source) LoadInt8(slot int, v *int8) {
	if ds := s.graph.ds; ds != nil {
		d := &ds.in
		if x := d.byte(); x != 0 || !ds.keepZero {
			*v = int8(x)
		}
		return
	}
	s.Load(slot, v)
}

// SaveInt16 saves a int16 field. See Save.
func (s Sink) SaveInt16(slot int, v *int16) {
	if es := s.graph.es; es != nil {
		es.out.varint(int64(*v))
		return
	}
	s.Save(slot, v)
}

// LoadInt16 loads a int16 field. See Load.
func (s Source) LoadInt16(slot int, v *int16) {
	if ds := s.graph.ds; ds != nil {
		x := ds.in.varint()
		if int64(int16(x)) != x {
			Failf("signed integer %d overflows int16", x)
		}
		if x != 0 || !ds.keepZero {
			*v = int16(x)
		}
		return
	}
	s.Load(slot, v)
}

// SaveInt32 saves a int32 field. See Save.
func (s Sink) SaveInt32(slot int, v *int32) {
	if es := s.graph.es; es != nil {
		es.out.varint(int64(*v))
		return
	}
	s.Save(slot, v)
}

// LoadInt32 loads a int32 field. See Load.
func (s Source) LoadInt32(slot int, v *int32) {
	if ds := s.graph.ds; ds != nil {
		x := ds.in.varint()
		if int64(int32(x)) != x {
			Failf("signed integer %d overflows int32", x)
		}
		if x != 0 || !ds.keepZero {
			*v = int32(x)
		}
		return
	}
	s.Load(slot, v)
}

// SaveInt64 saves a int64 field. See Save.
func (s Sink) SaveInt64(slot int, v *int64) {
	if es := s.graph.es; es != nil {
		es.out.varint(*v)
		return
	}
	s.Save(slot, v)
}

// LoadInt64 loads a int64 field. See Load.
func (s Source) LoadInt64(slot int, v *int64) {
	if ds := s.graph.ds; ds != nil {
		d := &ds.in
		if x := d.varint(); x != 0 || !ds.keepZero {
			*v = x
		}
		return
	}
	s.Load(slot, v)
}

// SaveUint saves a uint field. See Save.
func (s Sink) SaveUint(slot int, v *uint) {
	if es := s.graph.es; es != nil {
		es.out.uvarint(uint64(*v))
		return
	}
	s.Save(slot, v)
}

// LoadUint loads a uint field. See Load.
func (s Source) LoadUint(slot int, v *uint) {
	if ds := s.graph.ds; ds != nil {
		x := ds.in.uvarint()
		if uint64(uint(x)) != x {
			Failf("unsigned integer %d overflows uint", x)
		}
		if x != 0 || !ds.keepZero {
			*v = uint(x)
		}
		return
	}
	s.Load(slot, v)
}

// SaveUint8 saves a uint8 field. See Save.
func (s Sink) SaveUint8(slot int, v *uint8) {
	if es := s.graph.es; es != nil {
		es.out.byte(*v)
		return
	}
	s.Save(slot, v)
}

// LoadUint8 loads a uint8 field. See Load.
func (s Source) LoadUint8(slot int, v *uint8) {
	if ds := s.graph.ds; ds != nil {
		d := &ds.in
		if x := d.byte(); x != 0 || !ds.keepZero {
			*v = x
		}
		return
	}
	s.Load(slot, v)
}

// SaveUint16 saves a uint16 field. See Save.
func (s Sink) SaveUint16(slot int, v *uint16) {
	if es := s.graph.es; es != nil {
		es.out.uvarint(uint64(*v))
		return
	}
	s.Save(slot, v)
}

// LoadUint16 loads a uint16 field. See Load.
func (s Source) LoadUint16(slot int, v *uint16) {
	if ds := s.graph.ds; ds != nil {
		x := ds.in.uvarint()
		if uint64(uint16(x)) != x {
			Failf("unsigned integer %d overflows uint16", x)
		}
		if x != 0 || !ds.keepZero {
			*v = uint16(x)
		}
		return
	}
	s.Load(slot, v)
}

// SaveUint32 saves a uint32 field. See Save.
func (s Sink) SaveUint32(slot int, v *uint32) {
	if es := s.graph.es; es != nil {
		es.out.uvarint(uint64(*v))
		return
	}
	s.Save(slot, v)
}

// LoadUint32 loads a uint32 field. See Load.
func (s Source) LoadUint32(slot int, v *uint32) {
	if ds := s.graph.ds; ds != nil {
		x := ds.in.uvarint()
		if uint64(uint32(x)) != x {
			Failf("unsigned integer %d overflows uint32", x)
		}
		if x != 0 || !ds.keepZero {
			*v = uint32(x)
		}
		return
	}
	s.Load(slot, v)
}

// SaveUint64 saves a uint64 field. See Save.
func (s Sink) SaveUint64(slot int, v *uint64) {
	if es := s.graph.es; es != nil {
		es.out.uvarint(*v)
		return
	}
	s.Save(slot, v)
}

// LoadUint64 loads a uint64 field. See Load.
func (s Source) LoadUint64(slot int, v *uint64) {
	if ds := s.graph.ds; ds != nil {
		d := &ds.in
		if x := d.uvarint(); x != 0 || !ds.keepZero {
			*v = x
		}
		return
	}
	s.Load(slot, v)
}

// SaveUintptr saves a uintptr field. See Save.
func (s Sink) SaveUintptr(slot int, v *uintptr) {
	if es := s.graph.es; es != nil {
		es.out.uvarint(uint64(*v))
		return
	}
	s.Save(slot, v)
}

// LoadUintptr loads a uintptr field. See Load.
func (s Source) LoadUintptr(slot int, v *uintptr) {
	if ds := s.graph.ds; ds != nil {
		x := ds.in.uvarint()
		if uint64(uintptr(x)) != x {
			Failf("unsigned integer %d overflows uintptr", x)
		}
		if x != 0 || !ds.keepZero {
			*v = uintptr(x)
		}
		return
	}
	s.Load(slot, v)
}

// SaveFloat32 saves a float32 field. See Save.
func (s Sink) SaveFloat32(slot int, v *float32) {
	if es := s.graph.es; es != nil {
		es.out.uint32(math.Float32bits(*v))
		return
	}
	s.Save(slot, v)
}

// LoadFloat32 loads a float32 field. See Load.
func (s Source) LoadFloat32(slot int, v *float32) {
	if ds := s.graph.ds; ds != nil {
		d := &ds.in
		if x := d.uint32(); x != 0 || !ds.keepZero {
			*v = math.Float32frombits(x)
		}
		return
	}
	s.Load(slot, v)
}

// SaveFloat64 saves a float64 field. See Save.
func (s Sink) SaveFloat64(slot int, v *float64) {
	if es := s.graph.es; es != nil {
		es.out.uint64(math.Float64bits(*v))
		return
	}
	s.Save(slot, v)
}

// LoadFloat64 loads a float64 field. See Load.
func (s Source) LoadFloat64(slot int, v *float64) {
	if ds := s.graph.ds; ds != nil {
		d := &ds.in
		if x := d.uint64(); x != 0 || !ds.keepZero {
			*v = math.Float64frombits(x)
		}
		return
	}
	s.Load(slot, v)
}

// SaveString saves a string field. See Save.
func (s Sink) SaveString(slot int, v *string) {
	if es := s.graph.es; es != nil {
		es.out.string(*v)
		return
	}
	s.Save(slot, v)
}

// LoadString loads a string field. See Load.
func (s Source) LoadString(slot int, v *string) {
	if ds := s.graph.ds; ds != nil {
		d := &ds.in
		if n := d.byteLength(); n != 0 {
			*v = ds.makeString(d.next(n))
		} else if !ds.keepZero {
			*v = ""
		}
		return
	}
	s.Load(slot, v)
}
