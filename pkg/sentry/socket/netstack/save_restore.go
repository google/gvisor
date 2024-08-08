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

package netstack

import (
	"context"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// afterLoad is invoked by stateify.
func (s *Stack) afterLoad(ctx context.Context) {
	log.Infof("Check if s.Stack is nil %v", s.Stack)
	if st := stack.RestoreStackFromContext(ctx); st != nil {
		log.Infof("Netstack is not restored, assign the new netstack.")
		/* instead check if the stack should be restored or use new-old stack. */
		s.Stack = st
	}
	if s.Stack == nil {
		panic("can't restore without netstack/tcpip/stack.Stack")
	}
}
