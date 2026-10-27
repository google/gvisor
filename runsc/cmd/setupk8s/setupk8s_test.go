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

package setupk8s

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/flag"
)

func TestReleaseChartVersion(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    string
	}{
		{"release-20261005.0", "20261005.0.0"},
		{"release-20261005.12", "20261005.12.0"},
		{"release-20261005", "20261005.0.0"},
		{"release-20261005.0-dirty", ""},
		{"release-20261005.0-3-gabcdef", ""},
		{"release-20261005.0-staging", ""},
		{"release-20260230.0", ""},
		{"release-20261005.01", ""},
		{"release-20261005.+1", ""},
		{"0.0.0", ""},
	} {
		t.Run(tc.version, func(t *testing.T) {
			got, err := releaseChartVersion(tc.version)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("releaseChartVersion(%q) = %q, want error", tc.version, got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("releaseChartVersion(%q) = %q, %v, want %q", tc.version, got, err, tc.want)
			}
		})
	}
}

func TestArguments(t *testing.T) {
	var c Command
	var fs flag.FlagSet
	c.SetFlags(&fs)
	c.chart = "oci://registry.example/gvisor"
	c.values = "/tmp/values with spaces.yaml"
	c.kubeContext = "test-context"
	got, err := c.arguments("release-20261005.0")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"upgrade", "--install", "gvisor", c.chart,
		"--namespace", "kube-system", "--create-namespace", "--wait", "--timeout", "10m0s",
		"--version", "20261005.0.0", "--values", c.values, "--kube-context", c.kubeContext}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("arguments = %q, want %q", got, want)
	}
	if _, err := c.arguments("dev"); err == nil {
		t.Fatal("development version selected a remote chart without an explicit version")
	}
	c.chartVersion = "1.2.3"
	if _, err := c.arguments("dev"); err != nil {
		t.Fatalf("explicit chart version: %v", err)
	}
	c.chartVersion = ""
	c.chart = t.TempDir()
	if _, err := c.arguments("dev"); err != nil {
		t.Fatalf("local chart: %v", err)
	}
}

func TestHelmExitStatus(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "helm"), []byte("#!/bin/sh\nexit 42\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "kubectl"), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	var c Command
	var fs flag.FlagSet
	c.SetFlags(&fs)
	c.chart = t.TempDir()
	if got := c.Execute(context.Background(), &fs); got != subcommands.ExitStatus(42) {
		t.Fatalf("Execute returned %v, want Helm's exit status 42", got)
	}
}

func TestRolloutArguments(t *testing.T) {
	c := Command{releaseName: "sandbox", namespace: "sandbox-system", kubeContext: "lab", timeout: time.Minute}
	want := []string{"rollout", "status", "daemonset/sandbox-gvisor", "--namespace", "sandbox-system", "--timeout", "1m0s", "--context", "lab"}
	if got := c.rolloutArguments(); !reflect.DeepEqual(got, want) {
		t.Fatalf("rollout arguments = %q, want %q", got, want)
	}
}

func TestRolloutExitStatus(t *testing.T) {
	bin := t.TempDir()
	for name, body := range map[string]string{"helm": "#!/bin/sh\nexit 0\n", "kubectl": "#!/bin/sh\nexit 43\n"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
	var c Command
	var fs flag.FlagSet
	c.SetFlags(&fs)
	c.chart = t.TempDir()
	if got := c.Execute(context.Background(), &fs); got != subcommands.ExitStatus(43) {
		t.Fatalf("Execute returned %v, want kubectl's exit status 43", got)
	}
}

func TestMissingKubectlDoesNotRunHelm(t *testing.T) {
	bin := t.TempDir()
	marker := filepath.Join(bin, "helm-ran")
	t.Setenv("HELM_MARKER", marker)
	if err := os.WriteFile(filepath.Join(bin, "helm"), []byte("#!/bin/sh\n: > \"$HELM_MARKER\"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	var c Command
	var fs flag.FlagSet
	c.SetFlags(&fs)
	c.chart = t.TempDir()
	if got := c.Execute(context.Background(), &fs); got == subcommands.ExitSuccess {
		t.Fatal("Execute succeeded without kubectl")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("Helm ran before checking kubectl: %v", err)
	}
}

func TestSharedContext(t *testing.T) {
	t.Setenv("HELM_KUBECONTEXT", "helm-context")
	var c Command
	var fs flag.FlagSet
	c.SetFlags(&fs)
	if c.kubeContext != "helm-context" {
		t.Fatalf("context = %q", c.kubeContext)
	}
	if err := fs.Parse([]string{"--kube-context=explicit"}); err != nil {
		t.Fatal(err)
	}
	if c.kubeContext != "explicit" {
		t.Fatalf("context override = %q", c.kubeContext)
	}
	c.chart = t.TempDir()
	t.Setenv("HELM_KUBEAPISERVER", "https://other-server.invalid")
	if _, err := c.arguments("dev"); err == nil {
		t.Fatal("accepted divergent Helm connection override")
	}
}

var benchmarkBinary = flag.String("runsc-benchmark-binary", "", "runsc binary for the process startup benchmark")

func BenchmarkProcessStartup(b *testing.B) {
	binary := *benchmarkBinary
	if binary == "" {
		var err error
		binary, err = testutil.FindFile("release/runsc")
		if err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if err := exec.Command(binary, "--version").Run(); err != nil {
			b.Fatal(err)
		}
	}
}
