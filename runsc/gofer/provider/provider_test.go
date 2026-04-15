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

package provider

import (
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/runsc/specutils"
)

type fakeProvider struct {
	name   string
	prefix string
}

func (f *fakeProvider) Name() string { return f.name }

func (f *fakeProvider) NewServer(_ *specs.Spec, mountPath string, _ specutils.GoferMountConf, _ bool) (*lisafs.Server, error) {
	if !strings.HasPrefix(mountPath, f.prefix) {
		return nil, nil
	}
	s := &lisafs.Server{}
	return s, nil
}

func (f *fakeProvider) SeccompRules() seccomp.SyscallRules {
	return seccomp.SyscallRules{}
}

func TestRegisterAndRegistered(t *testing.T) {
	registered = nil

	p1 := &fakeProvider{name: "p1", prefix: "/storage"}
	p2 := &fakeProvider{name: "p2", prefix: "/data"}
	Register(p1)
	Register(p2)

	all := Registered()
	if len(all) != 2 {
		t.Fatalf("got %d providers, want 2", len(all))
	}
	if all[0] != p1 || all[1] != p2 {
		t.Fatalf("providers not in registration order")
	}
}

func TestFirstNonNilServerWins(t *testing.T) {
	registered = nil

	p1 := &fakeProvider{name: "first", prefix: "/storage"}
	p2 := &fakeProvider{name: "second", prefix: "/storage"}
	Register(p1)
	Register(p2)

	spec := &specs.Spec{}
	conf := specutils.GoferMountConf{}
	for _, p := range Registered() {
		srv, err := p.NewServer(spec, "/storage/vol", conf, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if srv != nil {
			if p.Name() != "first" {
				t.Fatalf("expected first provider to win, got %s", p.Name())
			}
			return
		}
	}
	t.Fatalf("no provider returned a server for /storage/vol")
}

func TestNoProviderFallsThrough(t *testing.T) {
	registered = nil

	Register(&fakeProvider{name: "storage", prefix: "/storage"})

	spec := &specs.Spec{}
	conf := specutils.GoferMountConf{}
	for _, p := range Registered() {
		srv, err := p.NewServer(spec, "/tmp", conf, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if srv != nil {
			t.Fatalf("expected no provider to claim /tmp")
		}
	}
}

func TestEmptyRegistered(t *testing.T) {
	registered = nil

	if len(Registered()) != 0 {
		t.Fatalf("expected empty provider list")
	}
}

// annotationReaderProvider is a fakeProvider that captures the annotation
// value for a fixed key on each NewServer call, so tests can assert the
// spec was forwarded intact.
type annotationReaderProvider struct {
	name       string
	annotation string
	// seen is written on every NewServer call and tracks the last value
	// the provider read from spec.Annotations[annotation].
	seen string
}

func (a *annotationReaderProvider) Name() string { return a.name }

func (a *annotationReaderProvider) NewServer(spec *specs.Spec, _ string, _ specutils.GoferMountConf, _ bool) (*lisafs.Server, error) {
	if spec == nil {
		return nil, nil
	}
	a.seen = spec.Annotations[a.annotation]
	s := &lisafs.Server{}
	return s, nil
}

func (a *annotationReaderProvider) SeccompRules() seccomp.SyscallRules {
	return seccomp.SyscallRules{}
}

func TestProviderReadsAnnotationsFromSpec(t *testing.T) {
	registered = nil

	p := &annotationReaderProvider{name: "annotated", annotation: "dev.example.endpoint"}
	Register(p)

	spec := &specs.Spec{
		Annotations: map[string]string{
			"dev.example.endpoint": "http://file-service:8080",
			"dev.example.other":    "ignored",
		},
	}
	conf := specutils.GoferMountConf{}
	srv, err := Registered()[0].NewServer(spec, "/storage/vol", conf, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if srv == nil {
		t.Fatalf("expected non-nil server")
	}
	if got, want := p.seen, "http://file-service:8080"; got != want {
		t.Fatalf("provider read annotation %q, want %q", got, want)
	}
}
