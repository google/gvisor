// Copyright 2025 The gVisor Authors.
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

package eventfd

import (
	"context"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
)

func (efd *EventFileDescription) beforeSave() {
	if efd.hostfd < 0 {
		return
	}
	if !efd.sentryOwnedHostfd {
		panic("EventFileDescription.beforeSave: hostfd is not owned by the sentry")
	}
	var buf [8]byte
	if _, err := unix.Read(efd.hostfd, buf[:]); err != nil {
		log.Warningf("Failed to read host fd for eventfd: %v", err)
		return
	}
	copy(efd.hostfdState[:], buf[:])
}

func (efd *EventFileDescription) afterLoad(ctx context.Context) {
	if efd.hostfd < 0 {
		return
	}
	efd.hostfd = -1
	if _, err := efd.HostFD(); err != nil {
		log.Warningf("Failed to create host fd for eventfd: %v", err)
		return
	}
	if _, err := unix.Write(efd.hostfd, efd.hostfdState[:]); err != nil {
		log.Warningf("Failed to write host fd for eventfd: %v", err)
	}
}
