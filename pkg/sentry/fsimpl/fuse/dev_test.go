// Copyright 2020 The gVisor Authors.
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

package fuse

import (
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// TestFUSECommunication tests that the communication layer between the Sentry and the
// FUSE server daemon works as expected.
func TestFUSECommunication(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	k := kernel.KernelFromContext(s.Ctx)
	creds := auth.CredentialsFromContext(s.Ctx)

	// Create test cases with different number of concurrent clients and servers.
	testCases := []struct {
		Name              string
		NumClients        int
		NumServers        int
		MaxActiveRequests uint64
	}{
		{
			Name:              "SingleClientSingleServer",
			NumClients:        1,
			NumServers:        1,
			MaxActiveRequests: MaxActiveRequestsDefault,
		},
		{
			Name:              "SingleClientMultipleServers",
			NumClients:        1,
			NumServers:        10,
			MaxActiveRequests: MaxActiveRequestsDefault,
		},
		{
			Name:              "MultipleClientsSingleServer",
			NumClients:        10,
			NumServers:        1,
			MaxActiveRequests: MaxActiveRequestsDefault,
		},
		{
			Name:              "MultipleClientsMultipleServers",
			NumClients:        10,
			NumServers:        10,
			MaxActiveRequests: MaxActiveRequestsDefault,
		},
		{
			Name:              "RequestCapacityFull",
			NumClients:        10,
			NumServers:        1,
			MaxActiveRequests: 1,
		},
		{
			Name:              "RequestCapacityContinuouslyFull",
			NumClients:        100,
			NumServers:        2,
			MaxActiveRequests: 2,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			conn, fd, err := newTestConnection(s, k, testCase.MaxActiveRequests)
			if err != nil {
				t.Fatalf("newTestConnection: %v", err)
			}

			clientsDone := make([]chan struct{}, testCase.NumClients)
			serversDone := make([]chan struct{}, testCase.NumServers)
			serversKill := make([]chan struct{}, testCase.NumServers)

			// FUSE clients.
			for i := 0; i < testCase.NumClients; i++ {
				clientsDone[i] = make(chan struct{})
				go func(i int) {
					fuseClientRun(t, s, k, conn, creds, uint32(i), uint64(i), clientsDone[i])
				}(i)
			}

			// FUSE servers.
			for j := 0; j < testCase.NumServers; j++ {
				serversDone[j] = make(chan struct{})
				serversKill[j] = make(chan struct{}, 1) // The kill command shouldn't block.
				go func(j int) {
					fuseServerRun(t, s, k, fd, serversDone[j], serversKill[j])
				}(j)
			}

			// Tear down.
			//
			// Make sure all the clients are done.
			for i := 0; i < testCase.NumClients; i++ {
				<-clientsDone[i]
			}

			// Kill any server that is potentially waiting.
			for j := 0; j < testCase.NumServers; j++ {
				serversKill[j] <- struct{}{}
			}

			// Make sure all the servers are done.
			for j := 0; j < testCase.NumServers; j++ {
				<-serversDone[j]
			}
		})
	}
}
