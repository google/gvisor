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

package filter

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/platform/kvm"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap"
)

func TestIoctlFirstArgumentIsNonNegativeFD(t *testing.T) {
	for name, options := range map[string]Options{
		"default systrap": Options{
			Platform: &systrap.Systrap{},
		},
		"default kvm": Options{
			Platform: &kvm.KVM{},
		},
		"nvproxy": Options{
			Platform: &systrap.Systrap{},
			NVProxy:  true,
		},
		"tpuproxy": Options{
			Platform: &systrap.Systrap{},
			TPUProxy: true,
		},
		"host network": Options{
			Platform:    &systrap.Systrap{},
			HostNetwork: true,
		},
		"host network with raw sockets": Options{
			Platform:              &systrap.Systrap{},
			HostNetwork:           true,
			HostNetworkRawSockets: true,
		},
		"profiling": Options{
			Platform:      &systrap.Systrap{},
			ProfileEnable: true,
		},
		"host filesystem": Options{
			Platform:       &systrap.Systrap{},
			HostFilesystem: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			rules, _ := Rules(options)
			if err := rules.ForSingleArgument(unix.SYS_IOCTL, 0, func(v seccomp.ValueMatcher) error {
				if v == nil {
					return fmt.Errorf("nil first argument")
				}
				if _, isNonNegativeFD := v.(seccomp.NonNegativeFD); !isNonNegativeFD {
					return fmt.Errorf("first argument should be NonNegativeFD")
				}
				return nil
			}); err != nil {
				t.Fatalf("cannot look up PerArg rules for ioctl system call: %v", err)
			}
		})
	}
}
