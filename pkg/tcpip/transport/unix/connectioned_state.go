// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package unix

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
