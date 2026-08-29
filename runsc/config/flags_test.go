// Copyright 2026 The gVisor Authors.
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
	"testing"

	"gvisor.dev/gvisor/runsc/flag"
)

// boolFlagAllowlist contains all boolean flags that existed before the policy
// of only adding enum-typed flags. It must never grow.
var boolFlagAllowlist = map[string]struct{}{
	"TESTONLY-afs-syscall-panic":       {},
	"TESTONLY-autosave-resume":         {},
	"TESTONLY-nftables":                {},
	"TESTONLY-unsafe-nonroot":          {},
	"EXPERIMENTAL-xdp-need-wakeup":     {},
	"allow-connected-on-save":          {},
	"allow-flag-override":              {},
	"allow-live-tcp-migration":         {},
	"allow-packet-socket-write":        {},
	"allow-rootfs-tar-annotation":      {},
	"allow-suid":                       {},
	"alsologtostderr":                  {},
	"app-huge-pages":                   {},
	"buffer-pooling":                   {},
	"cgroupfs":                         {},
	"cpu-num-from-quota":               {},
	"debug":                            {},
	"debug-to-user-log":                {},
	"directfs":                         {},
	"enable-core-tags":                 {},
	"fsgofer-host-uds":                 {},
	"fuse":                             {},
	"gso":                              {},
	"gvisor-gro":                       {},
	"gvisor-marker-file":               {},
	"ignore-cgroups":                   {},
	"iouring":                          {},
	"kvm-use-cpu-nums":                 {},
	"lisafs":                           {},
	"log-packets":                      {},
	"mount-cgroup-v2":                  {},
	"net-disconnect-ok":                {},
	"net-raw":                          {},
	"nvproxy":                          {},
	"nvproxy-allow-unsupported-driver": {},
	"nvproxy-docker":                   {},
	"oci-seccomp":                      {},
	"overlay":                          {},
	"pause-external-networking":        {},
	"profile":                          {},
	"rdmaproxy":                        {},
	"reproduce-nat":                    {},
	"reproduce-nftables":               {},
	"rootless":                         {},
	"rx-checksum-offload":              {},
	"save-restore-netstack":            {},
	"software-gso":                     {},
	"strace":                           {},
	"strace-event":                     {},
	"systemd-cgroup":                   {},
	"systrap-disable-fast-path":        {},
	"systrap-disable-syscall-patching": {},
	"tpuproxy":                         {},
	"tx-checksum-offload":              {},
	"vfs2":                             {},
}

// TestNoNewBoolFlagsPlease enforces the policy that no new boolean-typed
// flags may be added. New flags must be enum-typed instead.
func TestNoNewBoolFlagsPlease(t *testing.T) {
	flagSet := flag.NewFlagSet("test", flag.ContinueOnError)
	RegisterFlags(flagSet)
	registered := make(map[string]struct{})
	flagSet.VisitAll(func(fl *flag.Flag) {
		if _, isBool := flag.Get(fl.Value).(bool); !isBool {
			return
		}
		registered[fl.Name] = struct{}{}
		if _, ok := boolFlagAllowlist[fl.Name]; !ok {
			t.Errorf(
				"Cannot add new boolean flags (found new flag --%s).", fl.Name)
			t.Errorf("The policy is to only ever use enum-typed flags. Boolean cannot grow new states, and cannot distinguish the 'unset' from 'explicitly set' state, preventing the addition of automatic selection logic down the line.")
			t.Errorf("Instead, define an enum flag with at least two named values instead. See e.g. --host-settings or `--sidecar-release-enforcement-policy`.")
		}
	})
	for name := range boolFlagAllowlist {
		if _, ok := registered[name]; !ok {
			t.Errorf("Flag --%s is in boolFlagAllowlist but is not a registered boolean flag. Thank you for removing boolean flags! Now please remove it from the allowlist.", name)
		}
	}
}

func TestDoNotAddNewFlagsToAllowlist(t *testing.T) {
	const expectedNumAllowlistFlagsPleaseDoNotModifyThis = 55 // Never modify this, unless you are decreasing it.
	if len(boolFlagAllowlist) != expectedNumAllowlistFlagsPleaseDoNotModifyThis {
		t.Errorf("Cannot add new boolean flags to allowlist")
	}
}
