// Copyright 2021 The gVisor Authors.
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

import (
	"context"
	"fmt"
	"runtime"
	"strings"
)

// beforeSave is invoked by stateify.
func (e *connectionlessEndpoint) beforeSave() {
	if e.closerStackLen == 0 {
		return
	}

	frames := runtime.CallersFrames(e.closerStack[:e.closerStackLen])
	var b strings.Builder
	for {
		frame, more := frames.Next()
		fmt.Fprintf(&b, "%s\n\t%s:%d pc=%#x\n", frame.Function, frame.File, frame.Line, frame.PC)
		if !more {
			break
		}
	}
	e.closerStackStr = b.String()
}

// afterLoad is invoked by stateify.
func (e *connectionlessEndpoint) afterLoad(context.Context) {
	e.ops.InitHandler(e, &stackHandler{}, getSendBufferLimits, getReceiveBufferLimits)
}
