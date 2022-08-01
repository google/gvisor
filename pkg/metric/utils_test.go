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

package metric

import (
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/eventchannel"
)

// sliceEmitter implements eventchannel.Emitter by appending all messages to a
// slice.
type sliceEmitter []proto.Message

// Emit implements eventchannel.Emitter.Emit.
func (s *sliceEmitter) Emit(msg proto.Message) (bool, error) {
	*s = append(*s, msg)
	return false, nil
}

// Emit implements eventchannel.Emitter.Close.
func (s *sliceEmitter) Close() error {
	return nil
}

// Reset clears all events in s.
func (s *sliceEmitter) Reset() {
	*s = nil
}

// emitter is the eventchannel.Emitter used for all tests. Package eventchannel
// doesn't allow removing Emitters, so we must use one global emitter for all
// test cases.
var emitter sliceEmitter

func init() {
	resetTest()

	eventchannel.AddEmitter(&emitter)
}

func resetTest() {
	initialized = false
	allMetrics = makeMetricSet()
	emitter.Reset()
}
