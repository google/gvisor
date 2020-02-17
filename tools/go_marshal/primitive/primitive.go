// Copyright 2020 The gVisor Authors.
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

// Package primitive defines marshal.Marshallable implementations for primitive
// types.
package primitive

// Int32 is a marshal.Marshallable implementation for int32.
//
// +marshal vector
type Int32 int32

// Uint32 is a marshal.Marshallable implementation for uint32.
//
// +marshal
type Uint32 uint32

// Int64 is a marshal.Marshallable implementation for int64.
//
// +marshal
type Int64 int64

// Uint64 is a marshal.Marshallable implementation for uint64.
//
// +marshal
type Uint64 uint64
