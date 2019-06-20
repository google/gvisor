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

package tcp

import (
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/buffer"
)

// saveData is invoked by stateify.
func (s *segment) saveData() buffer.VectorisedView {
	// We cannot save s.data directly as s.data.views may alias to s.views,
	// which is not allowed by state framework (in-struct pointer).
	v := make([]buffer.View, len(s.data.Views()))
	// For views already delivered, we cannot save them directly as they may
	// have already been sliced and saved elsewhere (e.g., readViews).
	for i := 0; i < s.viewToDeliver; i++ {
		v[i] = append([]byte(nil), s.data.Views()[i]...)
	}
	for i := s.viewToDeliver; i < len(v); i++ {
		v[i] = s.data.Views()[i]
	}
	return buffer.NewVectorisedView(s.data.Size(), v)
}

// loadData is invoked by stateify.
func (s *segment) loadData(data buffer.VectorisedView) {
	// NOTE: We cannot do the s.data = data.Clone(s.views[:]) optimization
	// here because data.views is not guaranteed to be loaded by now. Plus,
	// data.views will be allocated anyway so there really is little point
	// of utilizing s.views for data.views.
	s.data = data
}

// saveOptions is invoked by stateify.
func (s *segment) saveOptions() []byte {
	// We cannot save s.options directly as it may point to s.data's trimmed
	// tail, which is not allowed by state framework (in-struct pointer).
	b := make([]byte, 0, cap(s.options))
	return append(b, s.options...)
}

// loadOptions is invoked by stateify.
func (s *segment) loadOptions(options []byte) {
	// NOTE: We cannot point s.options back into s.data's trimmed tail. But
	// it is OK as they do not need to aliased. Plus, options is already
	// allocated so there is no cost here.
	s.options = options
}

// saveRcvdTime is invoked by stateify.
func (s *segment) saveRcvdTime() unixTime {
	return unixTime{s.rcvdTime.Unix(), s.rcvdTime.UnixNano()}
}

// loadRcvdTime is invoked by stateify.
func (s *segment) loadRcvdTime(unix unixTime) {
	s.rcvdTime = time.Unix(unix.second, unix.nano)
}

// saveXmitTime is invoked by stateify.
func (s *segment) saveXmitTime() unixTime {
	return unixTime{s.rcvdTime.Unix(), s.rcvdTime.UnixNano()}
}

// loadXmitTime is invoked by stateify.
func (s *segment) loadXmitTime(unix unixTime) {
	s.rcvdTime = time.Unix(unix.second, unix.nano)
}
