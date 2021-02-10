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

package transport

// saveAcceptedChan is invoked by stateify.
func (e *connectionedEndpoint) saveAcceptedChan() []*connectionedEndpoint {
	// If acceptedChan is nil (i.e. we are not listening) then we will save nil.
	// Otherwise we create a (possibly empty) slice of the values in acceptedChan and
	// save that.
	var acceptedSlice []*connectionedEndpoint
	if e.acceptedChan != nil {
		// Swap out acceptedChan with a new empty channel of the same capacity.
		saveChan := e.acceptedChan
		e.acceptedChan = make(chan *connectionedEndpoint, cap(saveChan))

		// Create a new slice with the same len and capacity as the channel.
		acceptedSlice = make([]*connectionedEndpoint, len(saveChan), cap(saveChan))
		// Drain acceptedChan into saveSlice, and fill up the new acceptChan at the
		// same time.
		for i := range acceptedSlice {
			ep := <-saveChan
			acceptedSlice[i] = ep
			e.acceptedChan <- ep
		}
		close(saveChan)
	}
	return acceptedSlice
}

// loadAcceptedChan is invoked by stateify.
func (e *connectionedEndpoint) loadAcceptedChan(acceptedSlice []*connectionedEndpoint) {
	// If acceptedSlice is nil, then acceptedChan should also be nil.
	if acceptedSlice != nil {
		// Otherwise, create a new channel with the same capacity as acceptedSlice.
		e.acceptedChan = make(chan *connectionedEndpoint, cap(acceptedSlice))
		// Seed the channel with values from acceptedSlice.
		for _, ep := range acceptedSlice {
			e.acceptedChan <- ep
		}
	}
}

// afterLoad is invoked by stateify.
func (e *connectionedEndpoint) afterLoad() {
	e.ops.InitHandler(e, &stackHandler{}, getSendBufferLimits)
}
