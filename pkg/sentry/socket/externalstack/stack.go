// Copyright 2023 The gVisor Authors.
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

package externalstack

import (
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/stack"
)

type ExternalStack struct {
	inet.Stack
	interfaces     map[int32]inet.Interface
	interfaceAddrs map[int32][]inet.InterfaceAddr
	routes         []inet.Route
	notifier       *ExternalNotifier `state:"nosave"`
	tcpRecovery    inet.TCPLossRecovery
}

func (s *ExternalStack) InitExternalStack(args *stack.InitExternalStackArgs) error {
	//TODO: implement glue layer
	return nil
}

func (s *ExternalStack) PreInitExternalStack(args *stack.PreInitExternalStackArgs) error {
	//TODO: implement glue layer
	return nil
}

func (s *ExternalStack) PostInitExternalStack(args *stack.PostInitExternalStackArgs) error {
	//TODO: implement glue layer
	return nil
}

func init() {
	stack.RegisterExternalStack(&ExternalStack{})
}
