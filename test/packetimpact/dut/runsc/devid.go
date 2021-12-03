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

//go:build linux
// +build linux

// The devid binary is used to get the device ID in the runsc container.
package main

import (
	"fmt"
	"log"
	"net"
	"os"
)

func main() {
	iface, err := net.InterfaceByName(os.Args[1])
	if err != nil {
		log.Fatalf("could not find link %s: %s", os.Args[1], err)
	}
	fmt.Printf("%d", iface.Index)
}
