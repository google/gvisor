// Copyright 2019 The gVisor Authors.
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

package flipcall

import (
	"fmt"
)

type endpointControlState struct{}

func (ep *Endpoint) initControlState(ctrlMode ControlMode) error {
	if ctrlMode != ControlModeFutex {
		return fmt.Errorf("unsupported control mode: %v", ctrlMode)
	}
	return nil
}

func (ep *Endpoint) doRoundTrip() error {
	return ep.doFutexRoundTrip()
}

func (ep *Endpoint) doWaitFirst() error {
	return ep.doFutexWaitFirst()
}

func (ep *Endpoint) doNotifyLast() error {
	return ep.doFutexNotifyLast()
}

// Preconditions: ep.isShutdown() == true.
func (ep *Endpoint) interruptForShutdown() {
	ep.doFutexInterruptForShutdown()
}
