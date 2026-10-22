// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runsc

import (
	"os"
	"path/filepath"
	"testing"

	runctypes "github.com/containerd/containerd/api/types/runc/options"
	typeurl "github.com/containerd/typeurl/v2"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/types/known/anypb"

	"gvisor.dev/gvisor/pkg/shim/v1/runtimeoptions"
)

func marshalAny(t *testing.T, v any) *anypb.Any {
	t.Helper()
	a, err := typeurl.MarshalAnyToProto(v)
	if err != nil {
		t.Fatalf("MarshalAnyToProto(%T): %v", v, err)
	}
	return a
}

func TestResolveOptions(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "runsc.toml")
	if err := os.WriteFile(configPath, []byte(`binary_name = "/custom/runsc"`), 0644); err != nil {
		t.Fatal(err)
	}
	shimConfig := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(shimConfig, []byte(`root = "/shim/root"`), 0644); err != nil {
		t.Fatal(err)
	}
	oldPaths := shimConfigPaths
	shimConfigPaths = []string{shimConfig}
	t.Cleanup(func() { shimConfigPaths = oldPaths })
	fallback := &Options{Root: "/shim/root"}

	for _, tc := range []struct {
		name    string
		options *anypb.Any
		sandbox bool
		want    *Options
	}{
		{
			name: "container without options gets defaults",
			want: &Options{},
		},
		{
			name:    "sandbox without options reads the config file",
			sandbox: true,
			want:    fallback,
		},
		{
			name:    "runsc options without a config path give defaults",
			options: marshalAny(t, &runtimeoptions.Options{}),
			want:    &Options{},
		},
		{
			name:    "runsc options read their config path",
			options: marshalAny(t, &runtimeoptions.Options{ConfigPath: configPath}),
			sandbox: true,
			want:    &Options{BinaryName: "/custom/runsc"},
		},
		{
			name:    "runc options read the config file",
			options: marshalAny(t, &runctypes.Options{}),
			want:    fallback,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveOptions(tc.options, tc.sandbox)
			if err != nil {
				t.Fatalf("resolveOptions: %v", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("resolveOptions mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestResolveOptionsErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options *anypb.Any
	}{
		{
			name:    "foreign type",
			options: marshalAny(t, &runctypes.CheckpointOptions{}),
		},
		{
			name:    "missing config path",
			options: marshalAny(t, &runtimeoptions.Options{ConfigPath: filepath.Join(t.TempDir(), "missing.toml")}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := resolveOptions(tc.options, true); err == nil {
				t.Errorf("resolveOptions = %+v, want error", got)
			}
		})
	}
}
