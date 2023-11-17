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

package config

import (
	"fmt"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/platform/kvm"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap"
)

func TestIoctlFirstArgumentIsNonNegativeFD(t *testing.T) {
	for name, options := range map[string]Options{
		"default systrap": Options{
			Platform: (&systrap.Systrap{}).SeccompInfo(),
		},
		"default kvm": Options{
			Platform: (&kvm.KVM{}).SeccompInfo(),
		},
		"nvproxy": Options{
			Platform: (&systrap.Systrap{}).SeccompInfo(),
			NVProxy:  true,
		},
		"tpuproxy": Options{
			Platform: (&systrap.Systrap{}).SeccompInfo(),
			TPUProxy: true,
		},
		"host network": Options{
			Platform:    (&systrap.Systrap{}).SeccompInfo(),
			HostNetwork: true,
		},
		"host network with raw sockets": Options{
			Platform:              (&systrap.Systrap{}).SeccompInfo(),
			HostNetwork:           true,
			HostNetworkRawSockets: true,
		},
		"profiling": Options{
			Platform:      (&systrap.Systrap{}).SeccompInfo(),
			ProfileEnable: true,
		},
		"host filesystem": Options{
			Platform:       (&systrap.Systrap{}).SeccompInfo(),
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

// TestOptionsConfigKey verifies the behavior of `Options.ConfigKey`.
func TestOptionsConfigKey(t *testing.T) {
	// mutateFn mutates the value of a specific Options field.
	type mutateFn func(opt *Options)

	defaultOpt := Options{
		Platform: (&systrap.Systrap{}).SeccompInfo(),
	}

	// Map of `Options` struct field names mapped to a function to mutate them.
	// This should only contain fields which influence the configuration;
	// calling the mutation function of these should change the value of
	// `Options.Key`.
	var configFields = map[string]mutateFn{
		"Platform": func(opt *Options) {
			if defaultOpt.Platform.ConfigKey() == opt.Platform.ConfigKey() {
				opt.Platform = (&kvm.KVM{}).SeccompInfo()
			} else {
				opt.Platform = (&systrap.Systrap{}).SeccompInfo()
			}
		},
		"HostNetwork":           func(opt *Options) { opt.HostNetwork = !opt.HostNetwork },
		"HostNetworkRawSockets": func(opt *Options) { opt.HostNetworkRawSockets = !opt.HostNetworkRawSockets },
		"HostFilesystem":        func(opt *Options) { opt.HostFilesystem = !opt.HostFilesystem },
		"ProfileEnable":         func(opt *Options) { opt.ProfileEnable = !opt.ProfileEnable },
		"NVProxy":               func(opt *Options) { opt.NVProxy = !opt.NVProxy },
		"TPUProxy":              func(opt *Options) { opt.TPUProxy = !opt.TPUProxy },
	}

	// Map of `Options` struct field names mapped to a function to mutate them.
	// This should only contain fields which are used as variables during
	// filter generation; calling the mutation function of these should *not*
	// change the value of `Options.Key`.
	var varsFields = map[string]mutateFn{
		"ControllerFD": func(opt *Options) { opt.ControllerFD++ },
	}

	t.Run("fields are exhaustive", func(t *testing.T) {
		for i := 0; i < reflect.ValueOf(defaultOpt).NumField(); i++ {
			f := reflect.TypeOf(defaultOpt).Field(i)
			found := false
			for name := range configFields {
				if f.Name == name {
					found = true
					break
				}
			}
			for name := range varsFields {
				if f.Name == name {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("field `Options.%s` is not known to TestOptionsKey; please add it", f.Name)
			}
		}
	})

	t.Run("mutating config fields causes ConfigKey to change", func(t *testing.T) {
		opt := defaultOpt // Make a copy, as we're about to mutate it.
		key := opt.ConfigKey()
		for name, mutateFn := range configFields {
			mutateFn(&opt)
			newKey := opt.ConfigKey()
			if key == newKey {
				t.Fatalf("mutating config field %q did not cause the ConfigKey to change: %q", name, key)
			}
			key = newKey
		}
	})

	t.Run("mutating vars fields does not cause ConfigKey to change", func(t *testing.T) {
		opt := defaultOpt // Make a copy, as we're about to mutate it.
		key := opt.ConfigKey()
		for name, mutateFn := range varsFields {
			mutateFn(&opt)
			if newKey := opt.ConfigKey(); key != newKey {
				t.Fatalf("mutating var field %q caused the ConfigKey to change: %q -> %q", name, key, newKey)
			}
		}
	})
}
