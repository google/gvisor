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
	"fmt"
	"os"
	"path"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// defaultReconcileTimeout bounds host commands and activation health checks.
const defaultReconcileTimeout = 10 * time.Minute

// stallFactor keeps the watchdog well past both ReconcileInterval and
// reconcileTimeout, so it cannot flap during a long install.
const stallFactor = 2

// Installer reconciles one node towards the desired gVisor installation.
type Installer struct {
	reconcileMu          sync.Mutex
	lock                 lifetimeLock
	containerdExecutable string
	containerdInvocation string
	cfg                  Config
	log                  Logger
	host                 HostExec
	cri                  CRIClient
	node                 NodeClient

	ready atomic.Bool
	// Emit node events on transitions only, not every reconcile.
	lastReadyLabel string

	// Host procfs, readable because the pod runs with hostPID.
	procRoot string

	// Bounds convergence restarts to one per regression, so a node that cannot
	// converge is not restarted on every retry.
	convergeRestartedFor string
	// Rate-limit rather than latch: a node whose containerd is unhealthy for
	// unrelated reasons must not be restarted every interval, but must still
	// recover on its own once the cause clears.
	recoveryGate    restartGate
	activationGate  restartGate
	restartCooldown time.Duration

	// Post-restart health check pacing (shortened in tests).
	healthWait time.Duration
	healthPoll time.Duration

	// Verifying a generation hashes its full ~265MB payload. The early drift
	// check and publishStatus both need the verdict, so one reconcile pass
	// memoizes it rather than doubling the installer's steady-state IO.
	verifyCache map[string]error

	// Fields so tests can shorten them.
	reconcileTimeout time.Duration
	stallThreshold   time.Duration
	// Unix nanos, feeding the /healthz watchdog.
	lastReconcileDone atomic.Int64
}

func New(cfg Config, log Logger, host HostExec, cri CRIClient, node NodeClient) *Installer {
	reconcileTimeout := cfg.ReconcileTimeout
	// Configs built directly (tests, callers that do not go through
	// ConfigFromEnv) leave it zero, which would abort every iteration at once.
	if reconcileTimeout <= 0 {
		reconcileTimeout = defaultReconcileTimeout
	}
	i := &Installer{
		cfg:              cfg,
		log:              log,
		host:             host,
		cri:              cri,
		node:             node,
		procRoot:         "/proc",
		healthWait:       90 * time.Second,
		healthPoll:       2 * time.Second,
		restartCooldown:  30 * time.Minute,
		reconcileTimeout: reconcileTimeout,
	}
	i.stallThreshold = stallFactor * (i.reconcileTimeout + cfg.ReconcileInterval)
	// The pod has not stalled before it has had a chance to run.
	i.lastReconcileDone.Store(time.Now().UnixNano())
	return i
}

func (i *Installer) Ready() bool { return i.ready.Load() }

// Stalled reports whether the loop stopped completing iterations, and for how
// long (liveness probe). Only an unkillable host command reaches this, since
// the per-iteration timeout ends every other hang, so restarting the pod is
// the only recovery.
func (i *Installer) Stalled() (bool, time.Duration) {
	silent := time.Since(time.Unix(0, i.lastReconcileDone.Load()))
	return silent > i.stallThreshold, silent
}

// Run backs off exponentially because each retry can re-copy the payload
// and restart containerd. It deliberately does not clean up on shutdown: a
// DaemonSet pod cannot tell "helm uninstall" from a rolling update, and
// removing the handler under running sandboxes breaks them.
func (i *Installer) Run(ctx context.Context) {
	defer func() { _ = i.Close() }()
	failures := 0
	for {
		if err := i.reconcileOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			failures++
			i.log.Error("reconcile failed", "error", err)
		} else {
			failures = 0
		}
		interval := i.cfg.ReconcileInterval
		if failures > 0 {
			interval = backoffInterval(i.cfg.RetryInterval, failures, i.cfg.ReconcileInterval)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// reconcileOnce runs one iteration under its own deadline. ctx stays the
// parent so Run can still tell shutdown apart from a timeout.
func (i *Installer) reconcileOnce(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, i.reconcileTimeout)
	defer cancel()
	return i.Reconcile(ctx)
}

func backoffInterval(base time.Duration, failures int, maxWait time.Duration) time.Duration {
	d := base
	for n := 1; n < failures; n++ {
		d *= 2
		if d >= maxWait {
			return maxWait
		}
	}
	if d > maxWait {
		return maxWait
	}
	return d
}

type restartGate struct {
	sig       string
	notBefore time.Time
}

func (g *restartGate) blocked(now time.Time, sig string) bool {
	return g.sig == sig && now.Before(g.notBefore)
}

func (g *restartGate) block(now time.Time, sig string, cooldown time.Duration) {
	g.sig, g.notBefore = sig, now.Add(cooldown)
}

func (g *restartGate) clear() { *g = restartGate{} }

type reconcileOutcome struct {
	// The handler name is backed by something else. Never ready.
	conflict bool
}

// Reconcile always publishes labels reflecting observed state, so a failed
// upgrade on a working node keeps it schedulable.
func (i *Installer) Reconcile(ctx context.Context) error {
	i.reconcileMu.Lock()
	defer i.reconcileMu.Unlock()
	defer func() { i.lastReconcileDone.Store(time.Now().UnixNano()) }()
	if err := i.cfg.Validate(); err != nil {
		return err
	}
	if err := i.acquireLock(); err != nil {
		i.ready.Store(false)
		return err
	}
	i.verifyCache = map[string]error{}
	out, err := i.reconcile(ctx)
	i.publishStatus(ctx, out, err)
	return err
}

func (i *Installer) reconcile(ctx context.Context) (out reconcileOutcome, err error) {
	st, err := i.readState()
	if err != nil {
		return out, err
	}
	if err := checkRegularFile(i.cfg.hostPath(i.cfg.ContainerdConfig)); err != nil {
		return out, err
	}
	if err := i.preflight(ctx, st.Pending != nil); err != nil {
		return out, err
	}

	// While pending exists, neither the on-disk block nor the served handler
	// can be attributed to a generation, so settle it before classifying.
	if st.Pending != nil {
		if err := i.recoverPending(ctx, &st); err != nil {
			return out, fmt.Errorf("recovering interrupted activation: %w", err)
		}
	}

	cfgPath := i.cfg.hostPath(i.cfg.ContainerdConfig)
	if err := checkRegularFile(cfgPath); err != nil {
		return out, err
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return out, fmt.Errorf("reading containerd config %s: %w", i.cfg.ContainerdConfig, err)
	}

	// `config dump` is both the merged view (file + imports + defaults) and the
	// only validation containerd offers. It parses the on-disk config and says
	// nothing about the running daemon, hence the separate CRI check.
	dump, err := i.configDump(ctx)
	if err != nil {
		return out, fmt.Errorf("containerd's current configuration failed to load, refusing to modify anything: %w", err)
	}

	if _, err := criPluginID(configSchemaVersion(raw)); err != nil {
		return out, err
	}
	current, managed, err := managedBlock(raw)
	if err != nil {
		return out, err
	}
	activeCurrent := managed && st.Active != nil && current == st.Active.ManagedBlock
	// A drop-in import can override our entry even on a managed node.
	rt, handlerInDump := runtimeFromDump(dump, i.cfg.Handler)
	if handlerInDump {
		if err := i.mergedEntryConflict(rt, i.pinnedTarget(st, activeCurrent)); err != nil {
			out.conflict = true
			return out, err
		}
	}
	live, liveErr := i.cri.Status(ctx, true)
	if liveErr != nil {
		return out, liveErr
	}
	if slices.Contains(live.Handlers, i.cfg.Handler) {
		runtime, ok := live.Runtimes[i.cfg.Handler]
		if st.Active == nil || !ok || runtime.Type != runscRuntimeType || runtime.Path != path.Join(st.Active.GenerationPath, shimBinary) || runtime.ConfigPath != st.Active.ConfigPath || runtime.OptionsTypeURL != runscOptionsTypeURL {
			out.conflict = true
			return out, fmt.Errorf("live CRI runtime handler is not owned by the active installer record")
		}
	}
	if (!managed && handlerInDump) || (managed && (st.Active == nil || current != st.Active.ManagedBlock)) {
		out.conflict = true
		return out, fmt.Errorf("runtime handler or managed block is not owned by this installer")
	}

	if st.Target.Executable == "" {
		st.Target = i.targetIdentity()
		if err := i.writeState(st); err != nil {
			return out, err
		}
	}
	i.maintainActive(ctx, st)

	gen, _, err := i.ensureGeneration(ctx)
	if err != nil {
		return out, err
	}
	configPath, err := i.ensureRunscConfig(gen, dump)
	if err != nil {
		return out, err
	}
	target := runtimeTarget{ShimPath: gen.shimPath(), ConfigPath: configPath}
	changed, err := i.ensureContainerdConfig(ctx, &st, raw, gen, target)
	if err != nil {
		return out, err
	}
	if changed {
		// Path pinning was skipped above while the block was stale, so re-check
		// now rather than leaving a conflicting drop-in ready until next cycle.
		dump, err := i.configDump(ctx)
		if err != nil {
			return out, fmt.Errorf("containerd configuration failed to load after the managed block update: %w", err)
		}
		if rt, ok := runtimeFromDump(dump, i.cfg.Handler); ok {
			if err := i.mergedEntryConflict(rt, &target); err != nil {
				out.conflict = true
				return out, err
			}
		}
	}
	return out, nil
}

// nil when nothing is safely pinnable: foreign entries and stale blocks own
// their paths.
func (i *Installer) pinnedTarget(st installerState, activeCurrent bool) *runtimeTarget {
	if !activeCurrent {
		return nil
	}
	g, err := i.loadGeneration(st.Active.GenerationPath)
	if err != nil {
		return nil
	}
	return &runtimeTarget{ShimPath: g.shimPath(), ConfigPath: st.Active.ConfigPath}
}

// A corrupted active generation flips the node unready before the repair
// copy, not after: its sandboxes may be failing right now. A failed
// upgrade with an intact active generation keeps the node ready.
func (i *Installer) maintainActive(ctx context.Context, st installerState) {
	if st.Active == nil || st.Active.Handler != i.cfg.Handler {
		return
	}
	err := i.verifiedActiveGeneration(st)
	if err == nil && !i.runscConfigIntact(st.Active.ConfigPath) {
		err = fmt.Errorf("active shim config %s is missing or altered", st.Active.ConfigPath)
	}
	// Either failing means new sandboxes cannot work RIGHT NOW, the node must
	// not stay schedulable for the duration of whatever repair or upgrade
	// copy follows.
	if err != nil {
		i.log.Warn("active installation unhealthy, marking node unready before repairing", "generation", st.Active.GenerationPath, "error", err)
		_ = i.setNodeLabels(ctx, "false", "")
	}
}

func (i *Installer) verifiedActiveGeneration(st installerState) error {
	if st.Active == nil {
		return fmt.Errorf("no active generation")
	}
	g, err := i.loadGeneration(st.Active.GenerationPath)
	if err != nil {
		return err
	}
	if g.Version != st.Active.Version || g.PayloadSHA512 != st.Active.PayloadSHA512 {
		return fmt.Errorf("generation %s does not match the active record", st.Active.GenerationPath)
	}
	return i.verifyGenerationCached(g)
}

func (i *Installer) mergedEntryConflict(rt map[string]any, pin *runtimeTarget) error {
	if rtType, _ := rt["runtime_type"].(string); rtType != runscRuntimeType {
		return fmt.Errorf("containerd has a runtime handler %q with runtime_type %q (expected %s). "+
			"resolve the conflict by removing it or by configuring a different gvisor.installer.handler",
			i.cfg.Handler, rt["runtime_type"], runscRuntimeType)
	}
	if pin == nil {
		return nil
	}
	if field, got := mergedEntryOverride(rt, *pin); field != "" {
		return fmt.Errorf("a containerd import overrides the managed runtime handler %q (%s is %q). "+
			"sandboxes would not run the gvisor-managed gVisor: remove the conflicting drop-in",
			i.cfg.Handler, field, got)
	}
	return nil
}

func (i *Installer) desiredManagedBlock(raw []byte, want runtimeTarget) (string, error) {
	pluginID, err := criPluginID(configSchemaVersion(raw))
	if err != nil {
		return "", err
	}
	return renderManagedBlock(pluginID, i.cfg.Handler, want.ShimPath, want.ConfigPath), nil
}

// changed reports whether the on-disk config was rewritten, which tells the
// caller to re-check the merged view.
func (i *Installer) ensureContainerdConfig(ctx context.Context, st *installerState, raw []byte, gen Generation, want runtimeTarget) (changed bool, err error) {
	// Every success path below ends with the handler verified served, which
	// is the condition the convergence-restart budget is scoped to.
	defer func() {
		if err == nil {
			i.convergeRestartedFor = ""
		}
	}()

	desired, err := i.desiredManagedBlock(raw, want)
	if err != nil {
		return false, err
	}
	current, found, err := managedBlock(raw)
	if err != nil {
		return false, err
	}
	settled := found && current == desired &&
		st.Active != nil && st.Active.ManagedBlock == desired
	if !settled {
		err := i.activate(ctx, st, raw, desired, gen, want)
		return err == nil, err
	}

	servingErr := i.verifyServing(ctx, i.cfg.Handler, &want)
	if servingErr == nil {
		return false, nil
	}
	// The configuration is on disk, but containerd is not using it. Try one
	// restart. If it starts healthy but still lacks the handler, do not repeat it.
	if i.convergeRestartedFor == desired {
		return false, fmt.Errorf("runtime handler still not served after a convergence restart: %w", servingErr)
	}
	i.log.Warn("containerd config is up to date but the running daemon does not serve the handler; restarting containerd to converge", "error", servingErr)
	// systemctl restart can stop containerd and then fail to start it.
	// Save Pending first so the next reconcile can recover the stopped runtime,
	// even if the installer process has also restarted.
	st.Pending = &pendingActivation{
		Target:               *st.Active,
		PreviousManagedBlock: st.Active.ManagedBlock,
		PreviousHandler:      st.Active.Handler,
	}
	if err := i.writeState(*st); err != nil {
		return false, err
	}
	i.convergeRestartedFor = desired
	if err := i.recoveryRestart(ctx, st.Pending, "commit"); err != nil {
		return false, err
	}
	st.Pending = nil
	if err := i.writeSettledState(*st); err != nil {
		return false, err
	}
	i.recoveryGate.clear()
	return false, i.verifyServing(ctx, i.cfg.Handler, &want)
}

// Labels reflect observed state, not reconcile success, so a failed upgrade
// copy does not clear an already-working node's label.
func (i *Installer) publishStatus(ctx context.Context, out reconcileOutcome, reconcileErr error) {
	// The reconcile ctx may already be cancelled on shutdown.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()

	identity := false
	versionLabel := ""
	var want *runtimeTarget
	if !out.conflict {
		if record, ok := i.verifiedActiveState(); ok {
			identity = true
			versionLabel = record.Version
			want = &runtimeTarget{
				ShimPath:   (Generation{Path: record.GenerationPath}).shimPath(),
				ConfigPath: record.ConfigPath,
			}
		}
	}

	readyLabel := "false"
	if identity && i.preflight(ctx, false) == nil && i.verifyServing(ctx, i.cfg.Handler, want) == nil {
		readyLabel = "true"
	} else {
		versionLabel = ""
	}

	patchErr := i.setNodeLabels(ctx, readyLabel, versionLabel)

	if reconcileErr != nil {
		i.node.Event(corev1.EventTypeWarning, "GVisorInstallFailed", truncateOutput([]byte(reconcileErr.Error())))
	}
	if readyLabel != i.lastReadyLabel {
		if readyLabel == "true" {
			i.node.Event(corev1.EventTypeNormal, "GVisorReady",
				fmt.Sprintf("gVisor runtime handler %q is available on this node (version: %s)", i.cfg.Handler, versionLabel))
		} else if i.lastReadyLabel == "true" {
			i.node.Event(corev1.EventTypeWarning, "GVisorUnready",
				fmt.Sprintf("gVisor runtime handler %q is no longer verified healthy on this node", i.cfg.Handler))
		}
		i.lastReadyLabel = readyLabel
	}

	i.ready.Store(reconcileErr == nil && readyLabel == "true" && patchErr == nil)
}

// CRI registration alone cannot be identity: containerd lists handlers
// without stat'ing the shim, and a broken ConfigPath fails every new sandbox
// while the handler stays listed. Hence block, payload and shim config are
// all checked against the settled journal.
func (i *Installer) verifiedActiveState() (generationRecord, bool) {
	st, err := i.readState()
	if err != nil {
		return generationRecord{}, false
	}
	if st.Pending != nil || st.Active == nil || st.Active.Handler != i.cfg.Handler {
		return generationRecord{}, false
	}
	raw, err := os.ReadFile(i.cfg.hostPath(i.cfg.ContainerdConfig))
	if err != nil {
		return generationRecord{}, false
	}
	current, found, err := managedBlock(raw)
	if err != nil || !found || current != st.Active.ManagedBlock {
		return generationRecord{}, false
	}
	if err := i.verifiedActiveGeneration(st); err != nil {
		return generationRecord{}, false
	}
	if !i.runscConfigIntact(st.Active.ConfigPath) {
		return generationRecord{}, false
	}
	return *st.Active, true
}

// Unconditional, so externally deleted labels are healed, a no-op
// strategic-merge patch does not bump the node's resourceVersion.
func (i *Installer) setNodeLabels(ctx context.Context, ready, version string) error {
	err := i.node.SetNodeLabels(ctx, map[string]string{
		LabelGVisorReady:   ready,
		LabelGVisorVersion: version,
	})
	if err != nil {
		i.log.Error("updating node labels failed", "error", err)
	}
	return err
}
