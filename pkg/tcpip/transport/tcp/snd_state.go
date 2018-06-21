// Copyright 2018 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tcp

import (
	"time"
)

type unixTime struct {
	second int64
	nano   int64
}

// saveLastSendTime is invoked by stateify.
func (s *sender) saveLastSendTime() unixTime {
	return unixTime{s.lastSendTime.Unix(), s.lastSendTime.UnixNano()}
}

// loadLastSendTime is invoked by stateify.
func (s *sender) loadLastSendTime(unix unixTime) {
	s.lastSendTime = time.Unix(unix.second, unix.nano)
}

// saveRttMeasureTime is invoked by stateify.
func (s *sender) saveRttMeasureTime() unixTime {
	return unixTime{s.rttMeasureTime.Unix(), s.rttMeasureTime.UnixNano()}
}

// loadRttMeasureTime is invoked by stateify.
func (s *sender) loadRttMeasureTime(unix unixTime) {
	s.rttMeasureTime = time.Unix(unix.second, unix.nano)
}

// afterLoad is invoked by stateify.
func (s *sender) afterLoad() {
	s.resendTimer.init(&s.resendWaker)
}
