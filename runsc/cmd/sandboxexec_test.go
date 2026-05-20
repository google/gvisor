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

package cmd

import (
	"os"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/config"
	sandboxexecpb "gvisor.dev/gvisor/sandboxexec/proto/sandbox_options_go_proto"
)

func TestCreateSpecDefault(t *testing.T) {
	opts := &sandboxexecpb.SandboxOptions{}
	conf := &config.Config{}
	args := []string{"echo", "hello"}

	spec, err := createSpec(opts, args, conf)
	if err != nil {
		t.Fatalf("createSpec failed: %v", err)
	}

	if len(spec.Process.Args) != 2 || spec.Process.Args[0] != "echo" || spec.Process.Args[1] != "hello" {
		t.Errorf("expected args ['echo', 'hello'], got %v", spec.Process.Args)
	}

	// Check default mounts are present
	expectedMounts := []string{"/proc", "/sys", "/dev", "/dev/pts", "/sys/fs/cgroup", "/tmp"}
	for _, want := range expectedMounts {
		found := false
		for _, m := range spec.Mounts {
			if m.Destination == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("default mount %s not found", want)
		}
	}
}

func TestCreateSpecEnvVars(t *testing.T) {
	opts := &sandboxexecpb.SandboxOptions{
		EnvVars: []*sandboxexecpb.EnvVar{
			{
				Name: "VAR1",
				PolicyOrValue: &sandboxexecpb.EnvVar_Value{
					Value: "val1",
				},
			},
			{
				Name: "VAR2",
				PolicyOrValue: &sandboxexecpb.EnvVar_Policy{
					Policy: sandboxexecpb.EnvVar_ENV_VAR_POLICY_FORWARD,
				},
			},
		},
	}
	os.Setenv("VAR2", "val2_forwarded")
	defer os.Unsetenv("VAR2")

	conf := &config.Config{}
	args := []string{"true"}

	spec, err := createSpec(opts, args, conf)
	if err != nil {
		t.Fatalf("createSpec failed: %v", err)
	}

	foundVar1 := false
	foundVar2 := false
	for _, env := range spec.Process.Env {
		if env == "VAR1=val1" {
			foundVar1 = true
		}
		if env == "VAR2=val2_forwarded" {
			foundVar2 = true
		}
	}
	if !foundVar1 {
		t.Error("VAR1=val1 not found in spec.Process.Env")
	}
	if !foundVar2 {
		t.Error("VAR2=val2_forwarded not found in spec.Process.Env")
	}
}

func TestCreateSpecMounts(t *testing.T) {
	opts := &sandboxexecpb.SandboxOptions{
		Mounts: []*sandboxexecpb.Mount{
			{
				Target: "/mnt/host",
				Mount: &sandboxexecpb.Mount_HostMount{
					HostMount: &sandboxexecpb.HostMount{
						HostPath: "/var/lib/data",
					},
				},
			},
			{
				Target: "/mnt/tmp",
				Mount: &sandboxexecpb.Mount_SandboxTmpfsMount{
					SandboxTmpfsMount: &sandboxexecpb.SandboxTmpfsMount{},
				},
			},
		},
	}

	conf := &config.Config{}
	args := []string{"true"}

	spec, err := createSpec(opts, args, conf)
	if err != nil {
		t.Fatalf("createSpec failed: %v", err)
	}

	foundHostMount := false
	foundTmpfsMount := false
	for _, m := range spec.Mounts {
		if m.Destination == "/mnt/host" && m.Type == "bind" && m.Source == "/var/lib/data" {
			foundHostMount = true
		}
		if m.Destination == "/mnt/tmp" && m.Type == "tmpfs" {
			foundTmpfsMount = true
		}
	}
	if !foundHostMount {
		t.Error("host mount not found or incorrect")
	}
	if !foundTmpfsMount {
		t.Error("tmpfs mount not found or incorrect")
	}
}

func TestCreateSpecNetworking(t *testing.T) {
	opts := &sandboxexecpb.SandboxOptions{
		NetworkingOptions: &sandboxexecpb.NetworkingOptions{
			EnableExternalNetworking: true,
		},
	}

	conf := &config.Config{}
	args := []string{"true"}

	_, err := createSpec(opts, args, conf)
	if err != nil {
		t.Fatalf("createSpec failed: %v", err)
	}

	if conf.Network != config.NetworkSandbox {
		t.Errorf("expected network to be %v, got %v", config.NetworkSandbox, conf.Network)
	}
}

func TestCreateSpecRootless(t *testing.T) {
	opts := &sandboxexecpb.SandboxOptions{}
	conf := &config.Config{Rootless: true}
	args := []string{"true"}

	spec, err := createSpec(opts, args, conf)
	if err != nil {
		t.Fatalf("createSpec failed: %v", err)
	}

	if spec.Linux == nil {
		t.Fatal("spec.Linux is nil, expected UserNamespace config")
	}

	foundUserNS := false
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == specs.UserNamespace {
			foundUserNS = true
			break
		}
	}
	if !foundUserNS {
		t.Error("UserNamespace not found in spec.Linux.Namespaces")
	}

	if len(spec.Linux.UIDMappings) == 0 {
		t.Error("UIDMappings empty")
	}
	if len(spec.Linux.GIDMappings) == 0 {
		t.Error("GIDMappings empty")
	}
}
