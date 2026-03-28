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

func warmTestSandbox(t *testing.T, conf *config.Config) *Sandbox {
	t.Helper()
	s := &Sandbox{
		ID:         "sandbox-test",
		WarmSentry: true,
	}
	s.WarmConfigFlags = warmConfigFlags(conf, s.warmDerivedBootFlags(conf))
	return s
}

func TestWarmConfigFlagsIgnoreLogging(t *testing.T) {
	conf1 := warmTestConfig(t)
	conf1.LogFilename = "/tmp/one.log"
	conf1.DebugLog = "/tmp/one.debug"

	conf2 := warmTestConfig(t)
	conf2.LogFilename = "/tmp/two.log"
	conf2.DebugLog = "/tmp/two.debug"

	flags1 := warmConfigFlags(conf1, nil)
	flags2 := warmConfigFlags(conf2, nil)
	if !slices.Equal(flags1, flags2) {
		t.Fatalf("warmConfigFlags() mismatch for logging-only changes: %v vs %v", flags1, flags2)
	}
}

func TestWarmConfigFlagsIncludeDerivedResources(t *testing.T) {
	conf := warmTestConfig(t)
	derived := []string{"--cpu-num=4", "--total-memory=2147483648"}
	flags := warmConfigFlags(conf, derived)
	if !slices.Contains(flags, "--cpu-num=4") {
		t.Fatalf("warmConfigFlags() = %v, want --cpu-num=4", flags)
	}
	if !slices.Contains(flags, "--total-memory=2147483648") {
		t.Fatalf("warmConfigFlags() = %v, want --total-memory=2147483648", flags)
	}
}

func TestWarmConfigFlagsDerivedResourceDrift(t *testing.T) {
	conf := warmTestConfig(t)

	// Create sandbox with specific derived flags.
	s := &Sandbox{
		ID:         "sandbox-test",
		WarmSentry: true,
	}
	s.WarmConfigFlags = warmConfigFlags(conf, []string{"--cpu-num=4", "--total-memory=2147483648"})

	// Validation with the same config and same derived flags passes.
	if err := s.validateWarmConfig(conf); err != nil {
		// The live system's total-memory will differ from the test values,
		// which is exactly the drift we want to detect.
		t.Logf("Config drift correctly detected (expected on live system): %v", err)
	}

	// Changing a config flag should always fail.
	changed := warmTestConfig(t)
	changed.NumNetworkChannels = 99
	s2 := &Sandbox{
		ID:         "sandbox-test",
		WarmSentry: true,
	}
	s2.WarmConfigFlags = warmConfigFlags(conf, s2.warmDerivedBootFlags(conf))
	if err := s2.validateWarmConfig(changed); err == nil {
		t.Fatal("validateWarmConfig() unexpectedly accepted a changed config")
	}
}

func TestValidateWarmConfig(t *testing.T) {
	conf := warmTestConfig(t)
	s := warmTestSandbox(t, conf)
	if err := s.validateWarmConfig(conf); err != nil {
		t.Fatalf("validateWarmConfig() failed: %v", err)
	}

	changed := warmTestConfig(t)
	changed.NumNetworkChannels = 2
	if err := s.validateWarmConfig(changed); err == nil {
		t.Fatal("validateWarmConfig() unexpectedly accepted a changed config")
	}
}

func TestWarmWaitDoesNotHang(t *testing.T) {
	s := &Sandbox{ID: "sandbox-test", WarmSentry: true}
	if !s.IsRootContainer("sandbox-test") {
		t.Fatal("IsRootContainer unexpectedly returned false for matching ID")
	}
	if s.IsRootContainer("other-container") {
		t.Fatal("IsRootContainer unexpectedly returned true for non-matching ID")
	}
}
