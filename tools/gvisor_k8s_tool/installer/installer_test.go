// Copyright The Isola Authors
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

package installer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// MainPID matches the fake /proc entry newTestEnv writes.
const healthyUnitShow = "LoadState=loaded\nActiveState=active\nMainPID=1234\nKillMode=process\nExecStart={ path=/usr/bin/containerd ; argv[]=/usr/bin/containerd ; ignore_errors=no }\n"

// fakeHost scripts host-command behavior.
type fakeHost struct {
	mu sync.Mutex
	// distroPaths marks paths that `test -e` reports as existing.
	distroPaths map[string]bool
	// unitShow is returned for `systemctl show containerd ...`.
	unitShow string
	showErr  error
	// dumpFunc returns the dump output.
	dumpFunc func() ([]byte, error)
	// restartErr fails `systemctl restart containerd` when set.
	restartErr error
	restarts   int
	onRestart  func()
}

func (f *fakeHost) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch name {
	case "test":
		if len(args) == 2 && f.distroPaths[args[1]] {
			return nil, nil
		}
		return nil, errors.New("exit status 1")
	case "/usr/bin/containerd":
		return f.dumpFunc()
	case "systemctl":
		if len(args) > 0 && args[0] == "show" {
			return []byte(f.unitShow), f.showErr
		}
		f.restarts++
		if f.onRestart != nil {
			f.onRestart()
		}
		return nil, f.restartErr
	default:
		return nil, fmt.Errorf("unexpected host command %q", name)
	}
}

// hostFunc makes every host command behave the same way.
type hostFunc func(context.Context, string, ...string) ([]byte, error)

func (f hostFunc) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f(ctx, name, args...)
}

type fakeCRI struct {
	mu          sync.Mutex
	st          criStatus
	err         error
	identityErr error
}

func (f *fakeCRI) Status(_ context.Context, withHandlers bool) (criStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !withHandlers {
		return criStatus{RuntimeReady: f.st.RuntimeReady}, f.err
	}
	return f.st, f.err
}

func (f *fakeCRI) set(st criStatus, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.st, f.err = st, err
}

// criStatusFromConfig mirrors containerd: the handler is served with exactly
// the shim and ConfigPath the loaded config named.
func criStatusFromConfig(raw []byte, handler string) criStatus {
	st := criStatus{
		RuntimeReady: true,
		Handlers:     []string{"runc"},
		Runtimes:     map[string]criRuntime{"runc": {Type: "io.containerd.runc.v2"}},
	}
	rt, found := runtimeFromDump(raw, handler)
	if !found {
		return st
	}
	opts, _ := rt["options"].(map[string]any)
	shimPath, _ := rt["runtime_path"].(string)
	configPath, _ := opts["ConfigPath"].(string)
	rtType, _ := rt["runtime_type"].(string)
	st.Handlers = append(st.Handlers, handler)
	st.Runtimes[handler] = criRuntime{Type: rtType, Path: shimPath, ConfigPath: configPath, OptionsTypeURL: runscOptionsTypeURL}
	return st
}

type fakeNode struct {
	mu     sync.Mutex
	labels map[string]string
	events []string
}

func (f *fakeNode) SetNodeLabels(_ context.Context, labels map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.labels == nil {
		f.labels = map[string]string{}
	}
	for k, v := range labels {
		if v == "" {
			delete(f.labels, k)
		} else {
			f.labels[k] = v
		}
	}
	return nil
}

func (f *fakeNode) Event(eventType, reason, message string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, eventType+"/"+reason+": "+message)
}

func (f *fakeNode) label(k string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.labels[k]
}

func (f *fakeNode) hasEvent(reason string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.events {
		if strings.Contains(e, reason) {
			return true
		}
	}
	return false
}

func (f *fakeCRI) VerifyIdentity(_ context.Context, pid int, uid string) error {
	if pid != 1234 || uid != "installer-uid" {
		return fmt.Errorf("unexpected target identity")
	}
	return f.identityErr
}

type discardLogger struct{}

func (discardLogger) Info(string, ...any)  {}
func (discardLogger) Warn(string, ...any)  {}
func (discardLogger) Error(string, ...any) {}

type testEnv struct {
	i    *Installer
	host *fakeHost
	cri  *fakeCRI
	node *fakeNode
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	hostRoot := t.TempDir()
	payload := t.TempDir()
	runscSource := filepath.Join(t.TempDir(), "runsc.toml")
	for name, data := range map[string]string{"runsc": "#!/bin/sh\necho 'runsc version release-20261027.0'\n", shimBinary: "shim", "gvisor-bin/checkpointgofer": "gofer", "arbitrary/deep/future-helper": "helper"} {
		dest := filepath.Join(payload, name)
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, []byte(data), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(runscSource, []byte("[runsc_config]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		NodeName:          "worker",
		Namespace:         "system",
		PodName:           "installer-pod",
		PodUID:            "installer-uid",
		Handler:           "runsc",
		HostRoot:          hostRoot,
		InstallDir:        "/opt/gvisor",
		StateDir:          "/var/lib/gvisor-installer",
		PayloadDir:        payload,
		ContainerdConfig:  containerdConfigPath,
		ContainerdSocket:  "/run/containerd/containerd.sock",
		ContainerdService: "containerd",
		RunscConfigSrc:    runscSource,
		ReconcileInterval: time.Minute,
		RetryInterval:     time.Second,
	}
	for _, dir := range []string{"/run", "/etc/containerd"} {
		if err := os.MkdirAll(cfg.hostPath(dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	cfgPath := cfg.hostPath(cfg.ContainerdConfig)
	if err := os.WriteFile(cfgPath, []byte(kindStyleConfig), 0600); err != nil {
		t.Fatal(err)
	}
	env := &testEnv{host: &fakeHost{unitShow: healthyUnitShow}, cri: &fakeCRI{}, node: &fakeNode{}}
	env.host.dumpFunc = func() ([]byte, error) { return os.ReadFile(cfgPath) }
	env.cri.st = criStatus{RuntimeReady: true, Handlers: []string{"runc"}, Runtimes: map[string]criRuntime{"runc": {Type: "io.containerd.runc.v2"}}}
	env.i = New(cfg, discardLogger{}, env.host, env.cri, env.node)
	env.i.healthWait = 20 * time.Millisecond
	env.i.healthPoll = time.Millisecond
	env.i.restartCooldown = 50 * time.Millisecond
	t.Cleanup(func() { _ = env.i.Close() })
	proc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(proc, "1234"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "1234", "cmdline"), []byte("/usr/bin/containerd\x00"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/containerd", filepath.Join(proc, "1234", "exe")); err != nil {
		t.Fatal(err)
	}
	env.i.procRoot = proc
	env.host.onRestart = func() { raw, _ := os.ReadFile(cfgPath); env.cri.set(criStatusFromConfig(raw, cfg.Handler), nil) }
	return env
}
func (e *testEnv) configOnDisk(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(e.i.cfg.hostPath(e.i.cfg.ContainerdConfig))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
func (e *testEnv) state(t *testing.T) installerState {
	t.Helper()
	st, err := e.i.readState()
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestReconcileInstallAndRetainedState(t *testing.T) {
	env := newTestEnv(t)
	if err := env.i.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !env.i.Ready() || env.node.label(LabelGVisorReady) != "true" || env.node.label(LabelGVisorVersion) != "20261027.0" {
		t.Fatal("installation did not publish verified availability")
	}
	st := env.state(t)
	if st.Active == nil || st.Pending != nil {
		t.Fatalf("unsettled state %+v", st)
	}
	if !strings.HasPrefix(env.configOnDisk(t), kindStyleConfig) {
		t.Fatal("admin bytes changed")
	}
	if err := env.i.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if env.host.restarts != 1 {
		t.Fatalf("idempotent reconciliation restarted %d times", env.host.restarts)
	}
	if err := env.i.Close(); err != nil {
		t.Fatal(err)
	}
	replacement := New(env.i.cfg, discardLogger{}, env.host, env.cri, env.node)
	replacement.procRoot = env.i.procRoot
	t.Cleanup(func() { _ = replacement.Close() })
	if err := replacement.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if env.host.restarts != 1 {
		t.Fatal("retained state caused a reinstall restart")
	}
}

func TestForeignHandlerNeverMutated(t *testing.T) {
	for _, rtType := range []string{runscRuntimeType, "io.containerd.runc.v2"} {
		t.Run(rtType, func(t *testing.T) {
			env := newTestEnv(t)
			raw := kindStyleConfig + fmt.Sprintf("\n[plugins.%q.containerd.runtimes.runsc]\nruntime_type=%q\n", criPluginIDV2, rtType)
			if err := os.WriteFile(env.i.cfg.hostPath(env.i.cfg.ContainerdConfig), []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			if err := env.i.Reconcile(t.Context()); err == nil {
				t.Fatal("accepted foreign handler")
			}
			if env.configOnDisk(t) != raw || env.host.restarts != 0 {
				t.Fatal("foreign handler changed")
			}
			if _, err := os.Stat(env.i.statePath()); !os.IsNotExist(err) {
				t.Fatal("foreign conflict wrote state")
			}
		})
	}
}

func TestStateFailsClosed(t *testing.T) {
	for _, raw := range []string{"{", `{"schemaVersion":999}`, `{"schemaVersion":1,"active":{}}`} {
		t.Run(raw, func(t *testing.T) {
			env := newTestEnv(t)
			if err := os.MkdirAll(filepath.Dir(env.i.statePath()), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(env.i.statePath(), []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			before := env.configOnDisk(t)
			if err := env.i.Reconcile(t.Context()); err == nil {
				t.Fatal("invalid state accepted")
			}
			if env.host.restarts != 0 || env.configOnDisk(t) != before {
				t.Fatal("invalid journal mutated host")
			}
		})
	}
}

func TestPersistentTargetCannotBeRetargeted(t *testing.T) {
	for _, field := range []string{"config", "socket", "service", "handler", "install"} {
		t.Run(field, func(t *testing.T) {
			env := newTestEnv(t)
			if err := env.i.Reconcile(t.Context()); err != nil {
				t.Fatal(err)
			}
			st := env.state(t)
			st.Pending = &pendingActivation{Target: *st.Active, PreviousManagedBlock: st.Active.ManagedBlock, PreviousHandler: st.Active.Handler}
			if err := env.i.writeState(st); err != nil {
				t.Fatal(err)
			}
			before := env.configOnDisk(t)
			restarts := env.host.restarts
			switch field {
			case "config":
				env.i.cfg.ContainerdConfig = "/other/config.toml"
			case "socket":
				env.i.cfg.ContainerdSocket = "/other/socket"
			case "service":
				env.i.cfg.ContainerdService = "other"
			case "handler":
				env.i.cfg.Handler = "other"
			case "install":
				env.i.cfg.InstallDir = "/other/install"
			}
			if err := env.i.Reconcile(t.Context()); err == nil {
				t.Fatal("pending target retargeted")
			}
			raw, err := os.ReadFile(env.i.cfg.hostPath(containerdConfigPath))
			if err != nil {
				t.Fatal(err)
			}
			if env.host.restarts != restarts || string(raw) != before {
				t.Fatal("retargeted journal mutated original service")
			}
		})
	}
}

func TestLifetimeLockRejectsSecondInstallerBeforeStatus(t *testing.T) {
	env := newTestEnv(t)
	if err := env.i.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	secondNode := &fakeNode{}
	second := New(env.i.cfg, discardLogger{}, env.host, env.cri, secondNode)
	t.Cleanup(func() { _ = second.Close() })
	if err := second.Reconcile(t.Context()); err == nil {
		t.Fatal("concurrent installer acquired host")
	}
	if len(secondNode.labels) != 0 || env.host.restarts != 1 {
		t.Fatal("lock contender published status or restarted host")
	}
}

func TestPreflightIdentityFailureDoesNotMutate(t *testing.T) {
	env := newTestEnv(t)
	env.cri.identityErr = errors.New("socket belongs to other process")
	before := env.configOnDisk(t)
	if err := env.i.Reconcile(t.Context()); err == nil {
		t.Fatal("wrong CRI target accepted")
	}
	if env.configOnDisk(t) != before || env.host.restarts != 0 {
		t.Fatal("identity failure changed host")
	}
	if _, err := os.Stat(env.i.statePath()); !os.IsNotExist(err) {
		t.Fatal("identity failure wrote state")
	}
}

func TestImmutablePayloadAndConfig(t *testing.T) {
	env := newTestEnv(t)
	if err := env.i.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	old := env.state(t).Active
	// A new payload version produces a sibling generation and config.
	if err := os.WriteFile(filepath.Join(env.i.cfg.PayloadDir, "runsc"), []byte("#!/bin/sh\necho 'runsc version release-20261028.0'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := env.i.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	current := env.state(t).Active
	if old.GenerationPath == current.GenerationPath || old.ConfigPath == current.ConfigPath {
		t.Fatal("upgrade reused immutable paths")
	}
	if _, err := os.Stat(env.i.cfg.hostPath(old.GenerationPath)); err != nil {
		t.Fatal("old release removed")
	}
	if !env.i.runscConfigIntact(old.ConfigPath) {
		t.Fatal("old shim config changed")
	}
	// Corruption is never overwritten with a different payload at the same path.
	if err := os.WriteFile(env.i.cfg.hostPath(filepath.Join(current.GenerationPath, "runsc")), []byte("corrupt"), 0755); err != nil {
		t.Fatal(err)
	}
	restarts := env.host.restarts
	if err := env.i.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if env.state(t).Active.GenerationPath != current.GenerationPath || env.host.restarts != restarts || !env.i.Ready() {
		t.Fatal("exact payload repair changed identity, restarted containerd, or stayed unready")
	}
}

func TestFailedUpgradePreservesVerifiedAvailability(t *testing.T) {
	env := newTestEnv(t)
	if err := env.i.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	env.i.cfg.PayloadDir = filepath.Join(t.TempDir(), "missing")
	if err := env.i.Reconcile(t.Context()); err == nil {
		t.Fatal("missing desired payload succeeded")
	}
	if env.i.Ready() {
		t.Fatal("desired convergence probe ready after failed update")
	}
	if env.node.label(LabelGVisorReady) != "true" {
		t.Fatal("failed update removed old verified availability")
	}
}

func TestActivationRollbackPreservesConcurrentAdminChanges(t *testing.T) {
	env := newTestEnv(t)
	cfgPath := env.i.cfg.hostPath(env.i.cfg.ContainerdConfig)
	env.host.onRestart = func() {
		raw, _ := os.ReadFile(cfgPath)
		if env.host.restarts == 1 {
			raw = append(raw, []byte("\n# admin edit during restart\n")...)
			os.WriteFile(cfgPath, raw, 0600)
			env.cri.set(criStatus{RuntimeReady: false, Handlers: []string{"runc"}}, nil)
			return
		}
		env.cri.set(criStatusFromConfig(raw, env.i.cfg.Handler), nil)
	}
	if err := env.i.Reconcile(t.Context()); err == nil {
		t.Fatal("activation failure reported success")
	}
	if !strings.Contains(env.configOnDisk(t), "# admin edit during restart") {
		t.Fatal("rollback reverted admin edit")
	}
	if strings.Contains(env.configOnDisk(t), beginMarker) {
		t.Fatal("rollback retained new handler")
	}
	if env.host.restarts != 2 {
		t.Fatalf("restart count %d, want activation and rollback", env.host.restarts)
	}
	if err := env.i.Reconcile(t.Context()); err == nil {
		t.Fatal("failed activation retried immediately")
	}
	if env.host.restarts != 2 {
		t.Fatal("restart cooldown failed")
	}
}

func TestPendingRecoveryWithCRIUnavailable(t *testing.T) {
	env := newTestEnv(t)
	env.host.restartErr = errors.New("service failed")
	if err := env.i.Reconcile(t.Context()); err == nil {
		t.Fatal("restart failure reported success")
	}
	if env.state(t).Pending == nil {
		t.Fatal("failed rollback lost recovery journal")
	}
	env.host.restartErr = nil
	env.cri.identityErr = errCRIUnavailable
	env.cri.set(criStatus{}, errors.New("CRI down"))
	env.host.onRestart = func() {
		env.cri.identityErr = nil
		raw, _ := os.ReadFile(env.i.cfg.hostPath(env.i.cfg.ContainerdConfig))
		env.cri.set(criStatusFromConfig(raw, env.i.cfg.Handler), nil)
	}
	time.Sleep(60 * time.Millisecond)
	_ = env.i.Reconcile(t.Context())
	if env.state(t).Pending != nil || !env.cri.st.RuntimeReady {
		t.Fatal("journal did not recover the predecessor")
	}
	time.Sleep(60 * time.Millisecond)
	if err := env.i.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !env.i.Ready() {
		t.Fatal("desired installation did not converge after failure cooldown")
	}

}

func TestConfigSchemaOnlyTwoAndThree(t *testing.T) {
	for _, schema := range []int{1, 4} {
		env := newTestEnv(t)
		raw := fmt.Sprintf("version = %d\n", schema)
		os.WriteFile(env.i.cfg.hostPath(env.i.cfg.ContainerdConfig), []byte(raw), 0600)
		if err := env.i.Reconcile(t.Context()); err == nil {
			t.Fatalf("unsupported schema %d accepted", schema)
		}
		if env.host.restarts != 0 || env.configOnDisk(t) != raw {
			t.Fatal("unsupported schema changed config")
		}
	}
}

func TestImportedRuntimeConflictsBeforeAndAfterWrite(t *testing.T) {
	for _, afterWrite := range []bool{false, true} {
		t.Run(fmt.Sprint(afterWrite), func(t *testing.T) {
			env := newTestEnv(t)
			cfgPath := env.i.cfg.hostPath(env.i.cfg.ContainerdConfig)
			env.host.dumpFunc = func() ([]byte, error) {
				raw, err := os.ReadFile(cfgPath)
				if err != nil {
					return nil, err
				}
				if !afterWrite || strings.Contains(string(raw), beginMarker) {
					if !strings.Contains(string(raw), beginMarker) {
						return []byte(string(raw) + "\n" + renderManagedBlock(criPluginIDV2, env.i.cfg.Handler, "/foreign/shim", "/foreign/config")), nil
					}
					block, _, _ := managedBlock(raw)
					return []byte(strings.Replace(string(raw), block, renderManagedBlock(criPluginIDV2, env.i.cfg.Handler, "/foreign/shim", "/foreign/config"), 1)), nil
				}
				return raw, nil
			}
			before := env.configOnDisk(t)
			if err := env.i.Reconcile(t.Context()); err == nil {
				t.Fatal("effective imported handler override accepted")
			}
			if env.host.restarts != 0 {
				t.Fatal("invalid effective config restarted service")
			}
			if strings.Contains(env.configOnDisk(t), beginMarker) {
				t.Fatal("invalid managed stanza remained on host")
			}
			if !strings.HasPrefix(env.configOnDisk(t), before) {
				t.Fatal("rollback changed administrator config")
			}
		})
	}
}

func TestSchemaThreeActivation(t *testing.T) {
	env := newTestEnv(t)
	raw := strings.ReplaceAll(strings.Replace(kindStyleConfig, "version = 2", "version = 3", 1), criPluginIDV2, criPluginIDV3)
	if err := os.WriteFile(env.i.cfg.hostPath(env.i.cfg.ContainerdConfig), []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	if err := env.i.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !env.i.Ready() || !strings.Contains(env.configOnDisk(t), criPluginIDV3) {
		t.Fatal("schema 3 runtime did not converge")
	}
}

func TestJournaledRestartCooldownSurvivesInstallerReplacement(t *testing.T) {
	env := newTestEnv(t)
	env.host.restartErr = errors.New("failed restart")
	if err := env.i.Reconcile(t.Context()); err == nil {
		t.Fatal("restart failure accepted")
	}
	restarts := env.host.restarts
	if err := env.i.Close(); err != nil {
		t.Fatal(err)
	}
	replacement := New(env.i.cfg, discardLogger{}, env.host, env.cri, env.node)
	replacement.procRoot = env.i.procRoot
	replacement.restartCooldown = env.i.restartCooldown
	t.Cleanup(func() { _ = replacement.Close() })
	if err := replacement.Reconcile(t.Context()); err == nil {
		t.Fatal("pending recovery should be cooldown blocked")
	}
	if env.host.restarts != restarts {
		t.Fatal("new installer process bypassed restart cooldown")
	}
}

func TestPendingRecoveryRevalidatesCRIIdentityAfterRepair(t *testing.T) {
	env := newTestEnv(t)
	env.host.restartErr = errors.New("failed restart")
	if err := env.i.Reconcile(t.Context()); err == nil {
		t.Fatal("restart failure accepted")
	}
	env.host.restartErr = nil
	env.cri.identityErr = errors.New("wrong endpoint")
	time.Sleep(60 * time.Millisecond)
	env.host.onRestart = func() { env.cri.set(criStatus{RuntimeReady: true, Handlers: []string{"runc"}}, nil) }
	if err := env.i.Reconcile(t.Context()); err == nil {
		t.Fatal("recovery accepted wrong CRI endpoint")
	}
	if env.state(t).Pending == nil || env.node.label(LabelGVisorReady) != "false" {
		t.Fatal("unproven recovery cleared journal or availability gate")
	}
}

func TestLiveForeignHandlerCannotBeAdoptedFromAbsentDiskEntry(t *testing.T) {
	env := newTestEnv(t)
	env.cri.set(criStatus{RuntimeReady: true, Handlers: []string{"runc", "runsc"}, Runtimes: map[string]criRuntime{"runsc": {Type: runscRuntimeType, Path: "/foreign/shim", ConfigPath: "/foreign/config", OptionsTypeURL: runscOptionsTypeURL}}}, nil)
	before := env.configOnDisk(t)
	if err := env.i.Reconcile(t.Context()); err == nil {
		t.Fatal("adopted foreign live handler")
	}
	if env.configOnDisk(t) != before || env.host.restarts != 0 {
		t.Fatal("foreign live handler changed host")
	}
	if _, err := os.Stat(env.i.statePath()); !os.IsNotExist(err) {
		t.Fatal("foreign live handler wrote journal")
	}
}

func TestContainerdKillModeMustPreserveShims(t *testing.T) {
	for _, mode := range []string{"control-group", "mixed", "none", ""} {
		t.Run(mode, func(t *testing.T) {
			env := newTestEnv(t)
			env.host.unitShow = strings.Replace(healthyUnitShow, "KillMode=process", "KillMode="+mode, 1)
			if err := env.i.Reconcile(t.Context()); err == nil {
				t.Fatal("unsafe service KillMode accepted")
			}
			if env.host.restarts != 0 {
				t.Fatal("unsafe service restarted")
			}
		})
	}
}

func TestSuccessfulConfigUpgradesHaveNoFailureCooldown(t *testing.T) {
	env := newTestEnv(t)
	env.i.restartCooldown = time.Hour
	for n := 0; n < 3; n++ {
		if err := os.WriteFile(env.i.cfg.RunscConfigSrc, []byte(fmt.Sprintf("[runsc_config]\n debug = %q\n", fmt.Sprint(n%2 == 0))), 0644); err != nil {
			t.Fatal(err)
		}
		if err := env.i.Reconcile(t.Context()); err != nil {
			t.Fatalf("upgrade %d blocked: %v", n, err)
		}
		if !env.state(t).RestartNotBefore.IsZero() {
			t.Fatal("successful settlement retained failure cooldown")
		}
	}
	if env.host.restarts != 3 {
		t.Fatalf("got %d restarts for three successful configs", env.host.restarts)
	}
}

func TestHostWriteTargetsRejectSymlinks(t *testing.T) {
	for _, target := range []string{"containerd file", "containerd parent", "shim config parent"} {
		t.Run(target, func(t *testing.T) {
			env := newTestEnv(t)
			outside := t.TempDir()
			switch target {
			case "containerd file":
				config := env.i.cfg.hostPath(env.i.cfg.ContainerdConfig)
				if err := os.WriteFile(filepath.Join(outside, "config.toml"), []byte(kindStyleConfig), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(config); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(outside, "config.toml"), config); err != nil {
					t.Fatal(err)
				}
			case "containerd parent":
				parent := filepath.Dir(env.i.cfg.hostPath(env.i.cfg.ContainerdConfig))
				if err := os.Rename(parent, filepath.Join(outside, "containerd")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(outside, "containerd"), parent); err != nil {
					t.Fatal(err)
				}
			case "shim config parent":
				parent := env.i.cfg.hostPath(env.i.cfg.configsDir())
				if err := os.MkdirAll(filepath.Dir(parent), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, parent); err != nil {
					t.Fatal(err)
				}
			}
			if err := env.i.Reconcile(t.Context()); err == nil {
				t.Fatal("symlink write target accepted")
			}
			if env.host.restarts != 0 {
				t.Fatal("symlink write target restarted service")
			}
			if target == "shim config parent" {
				entries, err := os.ReadDir(outside)
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 0 {
					t.Fatal("shim config escaped through symlink")
				}
			}
		})
	}
}

func TestPendingIdentityMismatchNeverMutatesOrRestarts(t *testing.T) {
	for _, identityErr := range []error{errIdentityMismatch, errors.New("endpoint missing installer UID")} {
		t.Run(identityErr.Error(), func(t *testing.T) {
			env := newTestEnv(t)
			env.host.restartErr = errors.New("activation interrupted")
			if err := env.i.Reconcile(t.Context()); err == nil {
				t.Fatal("activation unexpectedly succeeded")
			}
			before := env.configOnDisk(t)
			restarts := env.host.restarts
			env.cri.identityErr = identityErr
			if err := env.i.Reconcile(t.Context()); err == nil {
				t.Fatal("pending recovery accepted positive identity mismatch")
			}
			if env.configOnDisk(t) != before || env.host.restarts != restarts {
				t.Fatal("positive identity mismatch mutated pending target")
			}
		})
	}
}

func TestGenerationRepairDoesNotTruncateOpenFiles(t *testing.T) {
	env := newTestEnv(t)
	if err := env.i.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	active := env.state(t).Active
	dest := env.i.cfg.hostPath(filepath.Join(active.GenerationPath, shimBinary))
	corrupt := filepath.Join(filepath.Dir(dest), "replacement")
	if err := os.WriteFile(corrupt, []byte("corrupt executable"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(corrupt, dest); err != nil {
		t.Fatal(err)
	}
	open, err := os.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = open.Close() }()
	before, err := open.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := env.i.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("repair reused and truncated old executable inode")
	}
	oldBytes, err := io.ReadAll(open)
	if err != nil {
		t.Fatal(err)
	}
	if string(oldBytes) != "corrupt executable" {
		t.Fatal("repair mutated content behind an open descriptor")
	}
}

func TestGenerationRepairRestoresNestedDirectoryPermissions(t *testing.T) {
	env := newTestEnv(t)
	if err := env.i.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	active := env.state(t).Active
	dir := env.i.cfg.hostPath(filepath.Join(active.GenerationPath, "arbitrary", "deep"))
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := env.i.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0755 || !env.i.Ready() {
		t.Fatal("nested payload directory permissions were not repaired")
	}
}

func TestRepairIgnoresPreexistingTemporarySymlink(t *testing.T) {
	env := newTestEnv(t)
	if err := env.i.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	active := env.state(t).Active
	dir := env.i.cfg.hostPath(active.GenerationPath)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, tempPrefix+shimBinary)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, shimBinary), []byte("damaged"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := env.i.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "preserve" {
		t.Fatal("repair followed a temporary-file symlink")
	}
}

func TestMalformedManagedMarkersFailClosed(t *testing.T) {
	for _, raw := range []string{endMarker + "\n", beginMarker + "\n" + beginMarker + "\n" + endMarker + "\n", "#prefix " + beginMarker + "\n" + endMarker + "\n", beginMarker + " suffix\n" + endMarker + "\n"} {
		if _, _, err := managedBlock([]byte(raw)); err == nil {
			t.Fatalf("accepted malformed markers %q", raw)
		}
		if _, err := spliceManagedBlock([]byte(raw), "new"); err == nil {
			t.Fatalf("rewrote malformed markers %q", raw)
		}
		if _, err := removeManagedBlock([]byte(raw)); err == nil {
			t.Fatalf("removed malformed markers %q", raw)
		}
	}
}

func TestPendingRecoveryRejectsSymlinkBeforeSettlement(t *testing.T) {
	env := newTestEnv(t)
	if err := env.i.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	st := env.state(t)
	st.Pending = &pendingActivation{Target: *st.Active, PreviousManagedBlock: st.Active.ManagedBlock, PreviousHandler: st.Active.Handler}
	if err := env.i.writeState(st); err != nil {
		t.Fatal(err)
	}
	config := env.i.cfg.hostPath(env.i.cfg.ContainerdConfig)
	moved := filepath.Join(t.TempDir(), "config.toml")
	if err := os.Rename(config, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, config); err != nil {
		t.Fatal(err)
	}
	if err := env.i.Reconcile(t.Context()); err == nil {
		t.Fatal("pending activation accepted symlink target")
	}
	if env.state(t).Pending == nil || env.host.restarts != 1 {
		t.Fatal("symlink target settled journal or restarted containerd")
	}
}

func stagePendingConfigUpgrade(t *testing.T, env *testEnv) installerState {
	t.Helper()
	if err := env.i.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	env.i.restartCooldown = time.Hour
	if err := os.WriteFile(env.i.cfg.RunscConfigSrc, []byte("[runsc_config]\n debug = \"true\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	raw := []byte(env.configOnDisk(t))
	gen, _, err := env.i.ensureGeneration(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	dump, err := env.i.configDump(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	config, err := env.i.ensureRunscConfig(gen, dump)
	if err != nil {
		t.Fatal(err)
	}
	block, err := env.i.desiredManagedBlock(raw, runtimeTarget{ShimPath: gen.shimPath(), ConfigPath: config})
	if err != nil {
		t.Fatal(err)
	}
	st := env.state(t)
	st.Pending = &pendingActivation{Target: generationRecord{GenerationPath: gen.Path, ConfigPath: config, Version: gen.Version, PayloadSHA512: gen.PayloadSHA512, Handler: env.i.cfg.Handler, ManagedBlock: block}, PreviousManagedBlock: st.Active.ManagedBlock, PreviousHandler: st.Active.Handler}
	if err := env.i.writeState(st); err != nil {
		t.Fatal(err)
	}
	next, err := spliceManagedBlock(raw, block)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(env.i.cfg.hostPath(env.i.cfg.ContainerdConfig), next); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestForwardRecoveryFailureGetsImmediateBoundedRollback(t *testing.T) {
	env := newTestEnv(t)
	st := stagePendingConfigUpgrade(t, env)
	env.host.onRestart = func() {
		if env.host.restarts == 2 {
			env.host.restartErr = errors.New("forward recovery failed")
			env.cri.identityErr = errCRIUnavailable
			env.cri.set(criStatus{}, errCRIUnavailable)
			return
		}
		env.host.restartErr = nil
		env.cri.identityErr = nil
		raw, _ := os.ReadFile(env.i.cfg.hostPath(env.i.cfg.ContainerdConfig))
		env.cri.set(criStatusFromConfig(raw, env.i.cfg.Handler), nil)
	}
	_ = env.i.Reconcile(t.Context())
	settled := env.state(t)
	if env.host.restarts != 3 || settled.Pending != nil || settled.Active.ConfigPath != st.Active.ConfigPath {
		t.Fatalf("forward recovery did not immediately settle predecessor, restarts=%d state=%+v", env.host.restarts, settled)
	}
	if settled.RestartNotBefore.IsZero() {
		t.Fatal("failed target lost cooldown")
	}
	if err := env.i.Reconcile(t.Context()); err == nil {
		t.Fatal("failed target immediately retried")
	}
	if env.host.restarts != 3 {
		t.Fatal("failed target bypassed cooldown after rollback")
	}
}

func TestRollbackAllowanceSurvivesCrashAndCannotBeReused(t *testing.T) {
	env := newTestEnv(t)
	st := stagePendingConfigUpgrade(t, env)
	env.host.restartErr = errors.New("restart failed")
	env.host.onRestart = func() { env.cri.identityErr = errCRIUnavailable; env.cri.set(criStatus{}, errCRIUnavailable) }
	if err := env.i.commitTarget(t.Context(), &st); err == nil {
		t.Fatal("forward recovery unexpectedly succeeded")
	}
	if !env.state(t).Pending.RollbackAvailable {
		t.Fatal("forward recovery did not persist rollback allowance")
	}
	raw := []byte(env.configOnDisk(t))
	previous, err := previousConfig(raw, st.Pending)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(env.i.cfg.hostPath(env.i.cfg.ContainerdConfig), previous); err != nil {
		t.Fatal(err)
	}
	// Model a crash after restoring the predecessor but before its restart.
	if err := env.i.Close(); err != nil {
		t.Fatal(err)
	}
	replacement := New(env.i.cfg, discardLogger{}, env.host, env.cri, env.node)
	replacement.procRoot = env.i.procRoot
	replacement.restartCooldown = time.Hour
	t.Cleanup(func() { _ = replacement.Close() })
	if err := replacement.Reconcile(t.Context()); err == nil {
		t.Fatal("failed rollback unexpectedly settled")
	}
	if env.host.restarts != 3 {
		t.Fatalf("persisted allowance did not permit exactly one rollback, restarts=%d", env.host.restarts)
	}
	saved, err := replacement.readState()
	if err != nil {
		t.Fatal(err)
	}
	if saved.Pending == nil || saved.Pending.RollbackAvailable {
		t.Fatal("failed rollback did not durably consume allowance")
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
	again := New(env.i.cfg, discardLogger{}, env.host, env.cri, env.node)
	again.procRoot = env.i.procRoot
	t.Cleanup(func() { _ = again.Close() })
	if err := again.Reconcile(t.Context()); err == nil {
		t.Fatal("repeated failed rollback ignored cooldown")
	}
	if env.host.restarts != 3 {
		t.Fatal("replacement installer reused consumed rollback allowance")
	}
}

func TestContainerdInvocationIdentity(t *testing.T) {
	for _, scenario := range []string{"unit differs from live", "live and unit drift", "stopped unit drift"} {
		t.Run(scenario, func(t *testing.T) {
			env := newTestEnv(t)
			if scenario != "unit differs from live" {
				if err := env.i.Reconcile(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			before := env.configOnDisk(t)
			restarts := env.host.restarts
			env.host.unitShow = strings.Replace(healthyUnitShow, "argv[]=/usr/bin/containerd ;", "argv[]=/usr/bin/containerd --state /different-state ;", 1)
			if scenario == "live and unit drift" {
				if err := os.WriteFile(filepath.Join(env.i.procRoot, "1234", "cmdline"), []byte("/usr/bin/containerd\x00--state\x00/different-state\x00"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "stopped unit drift" {
				st := env.state(t)
				st.Pending = &pendingActivation{Target: *st.Active, PreviousManagedBlock: st.Active.ManagedBlock, PreviousHandler: st.Active.Handler}
				if err := env.i.writeState(st); err != nil {
					t.Fatal(err)
				}
				env.host.unitShow = strings.Replace(strings.Replace(env.host.unitShow, "MainPID=1234", "MainPID=0", 1), "ActiveState=active", "ActiveState=inactive", 1)
			}
			if err := env.i.Reconcile(t.Context()); err == nil {
				t.Fatal("changed containerd invocation accepted")
			}
			if env.host.restarts != restarts || env.configOnDisk(t) != before {
				t.Fatal("invocation mismatch mutated or restarted containerd")
			}
		})
	}
}

func TestInitialActivationCrashRetainsImmediateRollbackAllowance(t *testing.T) {
	env := newTestEnv(t)
	if err := env.i.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	active := *env.state(t).Active
	env.i.restartCooldown = time.Hour
	if err := os.WriteFile(env.i.cfg.RunscConfigSrc, []byte("[runsc_config]\n debug = \"true\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	env.host.onRestart = func() { panic("simulated process exit during restart") }
	func() { defer func() { _ = recover() }(); _ = env.i.Reconcile(t.Context()) }()
	saved := env.state(t)
	if saved.Pending == nil || !saved.Pending.RollbackAvailable {
		t.Fatal("initial activation did not journal rollback allowance")
	}
	if err := env.i.Close(); err != nil {
		t.Fatal(err)
	}
	env.host.onRestart = func() {
		raw, _ := os.ReadFile(env.i.cfg.hostPath(env.i.cfg.ContainerdConfig))
		env.cri.set(criStatusFromConfig(raw, env.i.cfg.Handler), nil)
	}
	replacement := New(env.i.cfg, discardLogger{}, env.host, env.cri, env.node)
	replacement.procRoot = env.i.procRoot
	t.Cleanup(func() { _ = replacement.Close() })
	_ = replacement.Reconcile(t.Context())
	settled, err := replacement.readState()
	if err != nil {
		t.Fatal(err)
	}
	if env.host.restarts != 3 || settled.Pending != nil || settled.Active.ConfigPath != active.ConfigPath {
		t.Fatal("replacement did not immediately recover predecessor after activation crash")
	}
}

func TestRollbackAllowanceCannotBypassRecoveryValidation(t *testing.T) {
	for _, scenario := range []string{"identity mismatch", "unknown block", "invalid predecessor config"} {
		t.Run(scenario, func(t *testing.T) {
			env := newTestEnv(t)
			st := stagePendingConfigUpgrade(t, env)
			st.Pending.RollbackAvailable = true
			st.RestartNotBefore = time.Now().Add(time.Hour)
			if err := env.i.writeState(st); err != nil {
				t.Fatal(err)
			}
			before := env.configOnDisk(t)
			switch scenario {
			case "identity mismatch":
				env.cri.identityErr = errIdentityMismatch
			case "unknown block":
				changed, err := spliceManagedBlock([]byte(before), "unrecognized = true")
				if err != nil {
					t.Fatal(err)
				}
				if err := writeFileAtomic(env.i.cfg.hostPath(env.i.cfg.ContainerdConfig), changed); err != nil {
					t.Fatal(err)
				}
				before = string(changed)
			case "invalid predecessor config":
				env.host.dumpFunc = func() ([]byte, error) {
					raw, err := os.ReadFile(env.i.cfg.hostPath(env.i.cfg.ContainerdConfig))
					if err != nil {
						return nil, err
					}
					block, _, _ := managedBlock(raw)
					if block == st.Active.ManagedBlock {
						return nil, errors.New("restored config invalid")
					}
					return raw, nil
				}
			}
			if err := env.i.Reconcile(t.Context()); err == nil {
				t.Fatal("invalid recovery accepted")
			}
			if env.host.restarts != 1 {
				t.Fatal("rollback allowance bypassed identity, ownership, or configuration validation")
			}
			saved := env.state(t)
			if saved.Pending == nil || !saved.Pending.RollbackAvailable {
				t.Fatal("invalid recovery consumed rollback allowance")
			}
			if scenario != "invalid predecessor config" && env.configOnDisk(t) != before {
				t.Fatal("invalid recovery changed untrusted target")
			}
		})
	}
}
