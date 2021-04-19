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

package stack

import "time"

// StackFromEnv is the global stack created in restore run.
// FIXME(b/36201077)
var StackFromEnv *Stack

// saveT is invoked by stateify.
func (t *TCPCubicState) saveT() unixTime {
	return unixTime{t.T.Unix(), t.T.UnixNano()}
}

// loadT is invoked by stateify.
func (t *TCPCubicState) loadT(unix unixTime) {
	t.T = time.Unix(unix.second, unix.nano)
}

// saveXmitTime is invoked by stateify.
func (t *TCPRACKState) saveXmitTime() unixTime {
	return unixTime{t.XmitTime.Unix(), t.XmitTime.UnixNano()}
}

// loadXmitTime is invoked by stateify.
func (t *TCPRACKState) loadXmitTime(unix unixTime) {
	t.XmitTime = time.Unix(unix.second, unix.nano)
}

// saveLastSendTime is invoked by stateify.
func (t *TCPSenderState) saveLastSendTime() unixTime {
	return unixTime{t.LastSendTime.Unix(), t.LastSendTime.UnixNano()}
}

// loadLastSendTime is invoked by stateify.
func (t *TCPSenderState) loadLastSendTime(unix unixTime) {
	t.LastSendTime = time.Unix(unix.second, unix.nano)
}

// saveRTTMeasureTime is invoked by stateify.
func (t *TCPSenderState) saveRTTMeasureTime() unixTime {
	return unixTime{t.RTTMeasureTime.Unix(), t.RTTMeasureTime.UnixNano()}
}

// loadRTTMeasureTime is invoked by stateify.
func (t *TCPSenderState) loadRTTMeasureTime(unix unixTime) {
	t.RTTMeasureTime = time.Unix(unix.second, unix.nano)
}

// saveMeasureTime is invoked by stateify.
func (r *RcvBufAutoTuneParams) saveMeasureTime() unixTime {
	return unixTime{r.MeasureTime.Unix(), r.MeasureTime.UnixNano()}
}

// loadMeasureTime is invoked by stateify.
func (r *RcvBufAutoTuneParams) loadMeasureTime(unix unixTime) {
	r.MeasureTime = time.Unix(unix.second, unix.nano)
}

// saveRTTMeasureTime is invoked by stateify.
func (r *RcvBufAutoTuneParams) saveRTTMeasureTime() unixTime {
	return unixTime{r.RTTMeasureTime.Unix(), r.RTTMeasureTime.UnixNano()}
}

// loadRTTMeasureTime is invoked by stateify.
func (r *RcvBufAutoTuneParams) loadRTTMeasureTime(unix unixTime) {
	r.RTTMeasureTime = time.Unix(unix.second, unix.nano)
}

// saveSegTime is invoked by stateify.
func (t *TCPEndpointState) saveSegTime() unixTime {
	return unixTime{t.SegTime.Unix(), t.SegTime.UnixNano()}
}

// loadSegTime is invoked by stateify.
func (t *TCPEndpointState) loadSegTime(unix unixTime) {
	t.SegTime = time.Unix(unix.second, unix.nano)
}
