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

package sandbox

import (
	"slices"
	"testing"

	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
)

func warmTestConfig(t *testing.T) *config.Config {
	t.Helper()
	testFlags := flag.NewFlagSet("test", flag.ContinueOnError)
	config.RegisterFlags(testFlags)
	conf, err := config.NewFromFlags(testFlags)
	if err != nil {
		t.Fatalf("NewFromFlags() failed: %v", err)
	}
	conf.WarmSentry = true
	conf.Network = config.NetworkNone
	return conf
}

func TestWarmConfigFlagsIgnoreLogging(t *testing.T) {
	conf1 := warmTestConfig(t)
	conf1.LogFilename = "/tmp/one.log"
	conf1.DebugLog = "/tmp/one.debug"

	conf2 := warmTestConfig(t)
	conf2.LogFilename = "/tmp/two.log"
	conf2.DebugLog = "/tmp/two.debug"

	flags1 := warmConfigFlags(conf1)
	flags2 := warmConfigFlags(conf2)
	if !slices.Equal(flags1, flags2) {
		t.Fatalf("warmConfigFlags() mismatch for logging-only changes: %v vs %v", flags1, flags2)
	}
}

func TestValidateWarmConfig(t *testing.T) {
	conf := warmTestConfig(t)
	s := &Sandbox{
		ID:              "sandbox-test",
		WarmSentry:      true,
		WarmConfigFlags: warmConfigFlags(conf),
	}
	if err := s.validateWarmConfig(conf); err != nil {
		t.Fatalf("validateWarmConfig() failed: %v", err)
	}

	changed := warmTestConfig(t)
	changed.NumNetworkChannels = 2
	if err := s.validateWarmConfig(changed); err == nil {
		t.Fatal("validateWarmConfig() unexpectedly accepted a changed config")
	}
}
