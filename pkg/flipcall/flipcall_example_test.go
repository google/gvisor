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
	"bytes"
	"fmt"
	"sync"
)

func Example() {
	const (
		reqPrefix     = "request "
		respPrefix    = "response "
		count         = 3
		maxMessageLen = len(respPrefix) + 1 // 1 digit
	)

	pwa, err := NewPacketWindowAllocator()
	if err != nil {
		panic(err)
	}
	defer pwa.Destroy()
	pwd, err := pwa.Allocate(PacketWindowLengthForDataCap(uint32(maxMessageLen)))
	if err != nil {
		panic(err)
	}
	var clientEP Endpoint
	if err := clientEP.Init(pwd); err != nil {
		panic(err)
	}
	defer clientEP.Destroy()
	var serverEP Endpoint
	if err := serverEP.Init(pwd); err != nil {
		panic(err)
	}
	defer serverEP.Destroy()

	var serverRun sync.WaitGroup
	serverRun.Add(1)
	go func() {
		defer serverRun.Done()
		i := 0
		var buf bytes.Buffer
		// wait for first request
		n, err := serverEP.RecvFirst()
		if err != nil {
			return
		}
		for {
			// read request
			buf.Reset()
			buf.Write(serverEP.Data()[:n])
			fmt.Println(buf.String())
			// write response
			buf.Reset()
			fmt.Fprintf(&buf, "%s%d", respPrefix, i)
			copy(serverEP.Data(), buf.Bytes())
			// send response and wait for next request
			n, err = serverEP.SendRecv(uint32(buf.Len()))
			if err != nil {
				return
			}
			i++
		}
	}()
	defer func() {
		serverEP.Shutdown()
		serverRun.Wait()
	}()

	// establish connection as client
	if err := clientEP.Connect(); err != nil {
		panic(err)
	}
	var buf bytes.Buffer
	for i := 0; i < count; i++ {
		// write request
		buf.Reset()
		fmt.Fprintf(&buf, "%s%d", reqPrefix, i)
		copy(clientEP.Data(), buf.Bytes())
		// send request and wait for response
		n, err := clientEP.SendRecv(uint32(buf.Len()))
		if err != nil {
			panic(err)
		}
		// read response
		buf.Reset()
		buf.Write(clientEP.Data()[:n])
		fmt.Println(buf.String())
	}

	// Output:
	// request 0
	// response 0
	// request 1
	// response 1
	// request 2
	// response 2
}
