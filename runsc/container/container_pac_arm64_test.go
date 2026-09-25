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

//go:build arm64
// +build arm64

package container

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/sandbox"
)

// pacSRStatus reads the output of test_app pac-sr: whether pointer
// authentication was in use when it signed its pointer, and the last "OK"
// iteration.
func pacSRStatus(path string) (active string, last int, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", -1, err
	}
	last = -1
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(line, "SIGNED active="):
			active = strings.TrimPrefix(line, "SIGNED active=")
		case strings.HasPrefix(line, "FAIL"):
			return active, last, fmt.Errorf("pac-sr: %s", line)
		case strings.HasPrefix(line, "OK "):
			n, err := strconv.Atoi(strings.TrimPrefix(line, "OK "))
			if err != nil {
				return active, last, fmt.Errorf("bad line %q: %v", line, err)
			}
			last = n
		}
	}
	return active, last, nil
}

// waitPACSR waits until pac-sr reports more than three iterations after
// after.
func waitPACSR(path string, after int) (int, error) {
	var last int
	err := testutil.Poll(func() error {
		var err error
		_, last, err = pacSRStatus(path)
		if err != nil {
			return backoff.Permanent(err)
		}
		if last < after+3 {
			return fmt.Errorf("pac-sr at iteration %d, waiting for %d", last, after+3)
		}
		return nil
	}, 30*time.Second)
	return last, err
}

// pacSRTest is a pac-sr container set up for checkpoint/restore tests.
type pacSRTest struct {
	dir        string
	outputPath string
	spec       *specs.Spec
	bundleDir  string
	// conf uses pointer authentication; noPACConf behaves as on a host without
	// it. Both share the root directory set by SetupContainer.
	conf      *config.Config
	noPACConf *config.Config
}

// setupPACSR skips the test if the host does not support pointer
// authentication, and prepares a pac-sr container.
func setupPACSR(t *testing.T) *pacSRTest {
	cpuid.Initialize()
	if !cpuid.HostFeatureSet().HasFeature(cpuid.ARM64FeaturePACA) {
		t.Skip("host does not support pointer authentication")
	}
	app, err := testutil.FindFile("test/cmd/test_app/test_app")
	if err != nil {
		t.Fatal("error finding test_app:", err)
	}

	dir, err := os.MkdirTemp(testutil.TmpDir(), "checkpoint-test")
	if err != nil {
		t.Fatalf("os.MkdirTemp failed: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatalf("error chmoding file: %q, %v", dir, err)
	}
	outputPath := filepath.Join(dir, "output")
	outputFile, err := createWriteableOutputFile(outputPath)
	if err != nil {
		t.Fatalf("error creating output file: %v", err)
	}
	t.Cleanup(func() { outputFile.Close() })

	conf := testutil.TestConfig(t)
	conf.Platform = "systrap"
	spec := testutil.NewSpecWithArgs(app, "pac-sr", "--file", outputPath)
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	t.Cleanup(cleanup)
	noPACConf := *conf
	noPACConf.TestOnlyDisablePAC = true
	return &pacSRTest{
		dir:        dir,
		outputPath: outputPath,
		spec:       spec,
		bundleDir:  bundleDir,
		conf:       conf,
		noPACConf:  &noPACConf,
	}
}

// start starts pac-sr with conf and waits until it runs.
func (p *pacSRTest) start(t *testing.T, conf *config.Config) (*Container, int) {
	cont, err := New(conf, Args{ID: testutil.RandomContainerID(), Spec: p.spec, BundleDir: p.bundleDir})
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	t.Cleanup(func() { cont.Destroy() })
	if err := cont.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}
	last, err := waitPACSR(p.outputPath, -1)
	if err != nil {
		t.Fatalf("pac-sr before checkpoint: %v", err)
	}
	return cont, last
}

// checkpoint checkpoints cont with conf into a new image directory and
// destroys it.
func (p *pacSRTest) checkpoint(t *testing.T, cont *Container, conf *config.Config, name string) string {
	imageDir := filepath.Join(p.dir, name)
	if err := os.Mkdir(imageDir, 0777); err != nil {
		t.Fatalf("os.Mkdir(%q): %v", imageDir, err)
	}
	if err := cont.Checkpoint(conf, imageDir, sandbox.CheckpointOpts{}); err != nil {
		t.Fatalf("checkpoint %s: %v", name, err)
	}
	cont.Destroy()
	return imageDir
}

// restore restores imageDir into a new container with conf.
func (p *pacSRTest) restore(t *testing.T, conf *config.Config, imageDir string) (*Container, error) {
	cont, err := New(conf, Args{ID: testutil.RandomContainerID(), Spec: p.spec, BundleDir: p.bundleDir})
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	t.Cleanup(func() { cont.Destroy() })
	return cont, cont.Restore(conf, imageDir, false /* direct */, false /* background */, nil /* networkArgs */)
}

// TestCheckpointRestorePACNotInUse checks that a checkpoint taken where the
// application did not use ARM64 pointer authentication restores on a host
// that supports it. Return addresses that the application saved without
// signing must still authenticate after restore, including after another
// checkpoint and restore on that host.
func TestCheckpointRestorePACNotInUse(t *testing.T) {
	p := setupPACSR(t)
	cont, last := p.start(t, p.noPACConf)
	if active, _, _ := pacSRStatus(p.outputPath); active != "false" {
		t.Fatalf("pac-sr signed with active=%q, want false", active)
	}

	// Restore on this host, then checkpoint and restore again.
	for i, checkpointConf := range []*config.Config{p.noPACConf, p.conf} {
		imageDir := p.checkpoint(t, cont, checkpointConf, fmt.Sprintf("image%d", i))
		var err error
		if cont, err = p.restore(t, p.conf, imageDir); err != nil {
			t.Fatalf("restore %d: %v", i, err)
		}
		if last, err = waitPACSR(p.outputPath, last); err != nil {
			t.Fatalf("pac-sr after restore %d: %v", i, err)
		}
	}
}

// TestCheckpointRestorePACRejected checks that a checkpoint taken where the
// application used ARM64 pointer authentication does not restore on a host
// without it, where pointers signed before the checkpoint cannot be
// authenticated.
func TestCheckpointRestorePACRejected(t *testing.T) {
	p := setupPACSR(t)
	cont, _ := p.start(t, p.conf)
	if active, _, _ := pacSRStatus(p.outputPath); active != "true" {
		t.Fatalf("pac-sr signed with active=%q, want true", active)
	}

	imageDir := p.checkpoint(t, cont, p.conf, "image")
	_, err := p.restore(t, p.noPACConf, imageDir)
	if err == nil {
		t.Fatalf("restore on a host without pointer authentication succeeded, want error")
	}
	if want := "does not support address authentication"; !strings.Contains(err.Error(), want) {
		t.Errorf("restore error = %v, want it to contain %q", err, want)
	}
}
