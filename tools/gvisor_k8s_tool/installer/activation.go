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
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// activate switches containerd to the generation under a durable journal:
// pending is written before the block is touched and cleared only once a
// restart has settled the daemon on a known block, so a crash at any point
// leaves enough to finish or roll back coherently.
func (i *Installer) activate(ctx context.Context, st *installerState, raw []byte, desired string, gen Generation, want runtimeTarget) error {
	if time.Now().Before(st.RestartNotBefore) {
		return fmt.Errorf("containerd restart cooldown is active")
	}
	if i.activationGate.blocked(time.Now(), desired) {
		return fmt.Errorf("this managed block failed to activate recently and containerd was rolled back, waiting before restarting it again")
	}
	if err := i.preflight(ctx, false); err != nil {
		return err
	}
	pending := &pendingActivation{
		Target: generationRecord{
			GenerationPath: gen.Path,
			ConfigPath:     want.ConfigPath,
			Version:        gen.Version,
			PayloadSHA512:  gen.PayloadSHA512,
			Handler:        i.cfg.Handler,
			ManagedBlock:   desired,
		},
	}
	// The predecessor must be a previously committed generation.

	if st.Active != nil {
		pending.PreviousManagedBlock = st.Active.ManagedBlock
		pending.PreviousHandler = st.Active.Handler
	}
	st.Pending = pending
	if err := i.writeState(*st); err != nil {
		return err
	}

	if err := i.applyConfigChange(ctx, st, raw, desired, want); err != nil {
		return err
	}

	if latest, err := i.readState(); err == nil {
		st.RestartNotBefore = latest.RestartNotBefore
	}
	st.Active = &pending.Target
	st.Pending = nil
	// On failure the stale pending record makes the next reconcile redo the
	// commit via recovery.
	return i.writeSettledState(*st)
}

// applyConfigChange runs the safety chain: backup, atomic write, validate,
// restart, health check, rollback on failure. In-place rollback is possible
// because the installer pod survives containerd restarts.
func (i *Installer) applyConfigChange(ctx context.Context, st *installerState, raw []byte, desired string, want runtimeTarget) error {
	// raw predates a copy that can take minutes. Splicing a stale snapshot
	// would silently revert anything edited in that window, so bail out rather
	// than merge and let the next reconcile recompute.
	cfgPath := i.cfg.hostPath(i.cfg.ContainerdConfig)
	fresh, err := os.ReadFile(cfgPath)
	if err != nil {
		return i.abandonPending(st, fmt.Errorf("re-reading containerd config before writing it: %w", err))
	}
	if !bytes.Equal(fresh, raw) {
		return i.abandonPending(st, fmt.Errorf("%s changed while this reconcile was running. Nothing was written and containerd was not restarted, retrying from the current file", i.cfg.ContainerdConfig))
	}

	if err := i.preflight(ctx, false); err != nil {
		return i.abandonPending(st, err)
	}
	next, err := spliceManagedBlock(raw, desired)
	if err != nil {
		return i.abandonPending(st, err)
	}

	if err := writePristineBackup(i.cfg.hostPath(path.Join(i.cfg.StateDir, "containerd-original.toml")), cfgPath, raw); err != nil {
		return i.abandonPending(st, fmt.Errorf("writing pristine config backup: %w", err))
	}

	i.log.Info("updating containerd config", "path", i.cfg.ContainerdConfig, "schemaVersion", configSchemaVersion(raw))
	if err := compareAndWrite(cfgPath, raw, next); err != nil {
		return i.abandonPending(st, fmt.Errorf("writing containerd config: %w", err))
	}

	dump, dumpErr := i.configDump(ctx)
	if dumpErr == nil {
		rt, ok := runtimeFromDump(dump, i.cfg.Handler)
		if !ok {
			dumpErr = fmt.Errorf("new handler missing from effective config")
		} else {
			dumpErr = i.mergedEntryConflict(rt, &want)
		}
	}
	if dumpErr != nil {
		if restoreErr := i.restorePreviousBlock(cfgPath, st.Pending); restoreErr != nil {
			return fmt.Errorf("new config failed validation (%w), restoring block failed: %w", dumpErr, restoreErr)
		}
		return i.abandonPending(st, fmt.Errorf("new config failed validation, managed block restored: %w", dumpErr))
	}

	st.Pending.RollbackAvailable = st.Pending.PreviousManagedBlock != st.Pending.Target.ManagedBlock
	if err := i.writeState(*st); err != nil {
		return err
	}
	i.log.Warn("restarting containerd to register the gVisor runtime handler")
	if err := i.restartAndAwaitHealthy(ctx); err != nil {
		i.log.Error("containerd unhealthy after config change; rolling back", "error", err)
		// Rollback splices the recognized predecessor into the surrounding
		// config rather than restoring raw verbatim: raw may carry a drifted
		// block that must never be blessed with a restart.
		rbErr := i.rollback(ctx, cfgPath, st.Pending)
		if rbErr != nil {
			return fmt.Errorf("containerd unhealthy after config change (%w) AND rollback failed: %w", err, rbErr)
		}
		// The rollback restart settled the daemon on the previous config, so
		// the transaction is closed.
		i.activationGate.block(time.Now(), desired, i.restartCooldown)
		return i.abandonPending(st, fmt.Errorf("containerd unhealthy after config change, previous config rolled back and containerd recovered: %w", err))
	}

	// containerd came back healthy but does not serve the new runtime, so the
	// block is bad. Leaving it live would keep re-activating and restarting
	// every interval, so restore the predecessor and spend the budget.
	if err := i.verifyServing(ctx, i.cfg.Handler, &want); err != nil {
		rbErr := i.rollback(ctx, cfgPath, st.Pending)
		if rbErr != nil {
			return fmt.Errorf("the new config does not serve runtime handler %q (%w) AND rollback failed: %w", i.cfg.Handler, err, rbErr)
		}
		i.activationGate.block(time.Now(), desired, i.restartCooldown)
		return i.abandonPending(st, fmt.Errorf("the new config does not serve runtime handler %q, previous config rolled back: %w", i.cfg.Handler, err))
	}
	i.activationGate.clear()
	i.log.Info("gVisor runtime handler registered with containerd", "handler", i.cfg.Handler)
	i.node.Event(corev1.EventTypeNormal, "GVisorRuntimeConfigured",
		fmt.Sprintf("Registered containerd runtime handler %q (gVisor %s)", i.cfg.Handler, i.cfg.Version))
	return nil
}

func previousConfig(raw []byte, p *pendingActivation) ([]byte, error) {
	if p == nil || p.PreviousManagedBlock == "" {
		return removeManagedBlock(raw)
	}
	return spliceManagedBlock(raw, p.PreviousManagedBlock)
}

// abandonPending closes a transaction that verifiably never reached the
// daemon, where leaving the journal pending would only force a needless
// recovery restart.
func (i *Installer) abandonPending(st *installerState, cause error) error {
	st.Pending = nil
	if err := i.writeState(*st); err != nil {
		i.log.Warn("clearing pending activation failed; next reconcile recovers it", "error", err)
	}
	return cause
}

// The on-disk block decides the direction: the target block finishes forward
// when the target still checks out. Other recognized states roll back to
// the predecessor. Both paths verify what the daemon serves.
func (i *Installer) recoverPending(ctx context.Context, st *installerState) error {
	p := st.Pending
	i.log.Warn("recovering interrupted activation", "targetGeneration", p.Target.GenerationPath)

	raw, err := os.ReadFile(i.cfg.hostPath(i.cfg.ContainerdConfig))
	if err != nil {
		return err
	}
	block, found, err := managedBlock(raw)
	if err != nil {
		return err
	}

	if found && block == p.Target.ManagedBlock {
		err := i.commitTarget(ctx, st)
		if err == nil {
			return nil
		}
		// Once the daemon settled on the target, rollback is no longer an
		// improvement: retry the commit forward on the next reconcile.
		if errors.Is(err, errCommitSettled) {
			return err
		}
		// Both configurations are the same. Rolling back would just restart
		// containerd again, bypassing the delay between recovery attempts.
		if p.PreviousManagedBlock == p.Target.ManagedBlock {
			return err
		}
		i.log.Warn("interrupted activation cannot be committed, rolling back", "error", err)
	} else if !found && p.PreviousManagedBlock != "" || found && block != p.PreviousManagedBlock {
		// An unrecognized block must never be blessed with a restart just
		// because it happens to be on disk.
		i.log.Warn("on-disk managed block matches neither the pending target nor its predecessor, restoring the predecessor")
	}
	return i.rollbackPending(ctx, st, raw)
}

// commitTarget verifies the journaled payload before settling the activation.
func (i *Installer) commitTarget(ctx context.Context, st *installerState) error {
	p := st.Pending
	g, err := i.loadGeneration(p.Target.GenerationPath)
	if err != nil {
		return err
	}
	if g.Version != p.Target.Version || g.PayloadSHA512 != p.Target.PayloadSHA512 {
		return fmt.Errorf("generation %s does not match the pending record", p.Target.GenerationPath)
	}
	if err := i.verifyGeneration(g); err != nil {
		return err
	}
	dump, err := i.configDump(ctx)
	if err != nil {
		return fmt.Errorf("target config failed validation: %w", err)
	}
	// Re-rendering restores the recorded config only while it still hashes to
	// the same name. A different hash means the values changed under the
	// crash, leaving this activation unreconstructible.
	if !i.runscConfigIntact(p.Target.ConfigPath) {
		configPath, err := i.ensureRunscConfig(g, dump)
		if err != nil {
			return err
		}
		if configPath != p.Target.ConfigPath {
			return fmt.Errorf("shim config %s recorded by the pending activation can no longer be reproduced", p.Target.ConfigPath)
		}
	}
	want := runtimeTarget{ShimPath: g.shimPath(), ConfigPath: p.Target.ConfigPath}
	if rt, ok := runtimeFromDump(dump, p.Target.Handler); ok {
		if err := i.mergedEntryConflict(rt, &want); err != nil {
			return err
		}
	}
	// A crash after the activation restart leaves the daemon already on the
	// target. Only the pinned paths can tell, as both generations register
	// the same handler name.
	if err := i.verifyServing(ctx, p.Target.Handler, &want); err != nil {
		if err := i.recoveryRestart(ctx, p, "commit"); err != nil {
			return err
		}
		if err := i.verifyServing(ctx, p.Target.Handler, &want); err != nil {
			return err
		}
	}
	// st stays untouched until the journal write lands: on failure the caller
	// still needs the pending record. Past this point the daemon serves the
	// target, so failures are settled rather than rollback-worthy.
	if err := i.writeSettledState(installerState{Active: &p.Target}); err != nil {
		return fmt.Errorf("%w: %w", errCommitSettled, err)
	}
	st.Active = &p.Target
	st.Pending = nil
	i.recoveryGate.clear()
	return nil
}

// errCommitSettled marks commit failures that happened after the daemon
// settled on the target.
var errCommitSettled = errors.New("target is serving but the activation is not fully committed")

func recoverySig(p *pendingActivation, direction string) string {
	return p.Target.GenerationPath + "\x00" + p.Target.ConfigPath + "\x00" + p.Target.ManagedBlock + "\x00" + direction
}

// Rate-limited so an unrelated containerd outage cannot turn into two
// restarts per interval forever.
func (i *Installer) recoveryRestart(ctx context.Context, p *pendingActivation, direction string) error {
	stored, err := i.readState()
	if err != nil {
		return err
	}
	if stored.Pending == nil || stored.Pending.Target != p.Target || stored.Pending.PreviousManagedBlock != p.PreviousManagedBlock || stored.Pending.PreviousHandler != p.PreviousHandler {
		return fmt.Errorf("pending activation changed before recovery restart")
	}
	rollback := direction == "roll back"
	allowance := rollback && stored.Pending.RollbackAvailable
	if time.Now().Before(stored.RestartNotBefore) && !allowance {
		return fmt.Errorf("containerd recovery restart cooldown is active")
	}
	sig := recoverySig(p, direction)
	if i.recoveryGate.blocked(time.Now(), sig) && !allowance {
		return fmt.Errorf("containerd was restarted recently to %s this interrupted activation and still does not serve the expected runtime", direction)
	}
	if err := i.preflight(ctx, true); err != nil {
		return err
	}
	if rollback {
		stored.Pending.RollbackAvailable = false
	} else if stored.Pending.PreviousManagedBlock != stored.Pending.Target.ManagedBlock {
		stored.Pending.RollbackAvailable = true
	}
	if err := i.writeState(stored); err != nil {
		return err
	}
	i.recoveryGate.block(time.Now(), sig, i.restartCooldown)
	return i.restartAndAwaitHealthy(ctx)
}

// Pending is cleared only after the restart succeeded: a crash beforehand
// leaves the journal for the next process, which still knows a restart is
// mandatory.
func (i *Installer) rollbackPending(ctx context.Context, st *installerState, raw []byte) error {
	if err := i.preflight(ctx, true); err != nil {
		return err
	}
	p := st.Pending
	current, found, blockErr := managedBlock(raw)
	if blockErr != nil {
		return blockErr
	}
	if found && current != p.Target.ManagedBlock && current != p.PreviousManagedBlock {
		return fmt.Errorf("managed block changed during pending activation, refusing recovery mutation")
	}
	var next []byte
	var err error
	if p.PreviousManagedBlock == "" {
		next, err = removeManagedBlock(raw)
	} else {
		next, err = spliceManagedBlock(raw, p.PreviousManagedBlock)
	}
	if err != nil {
		return err
	}
	cfgPath := i.cfg.hostPath(i.cfg.ContainerdConfig)
	if !bytes.Equal(next, raw) {
		if err := compareAndWrite(cfgPath, raw, next); err != nil {
			return fmt.Errorf("restoring previous managed block: %w", err)
		}
	}
	// Recovery preserves surrounding config, which may have been edited
	// while this activation was interrupted. Do not stop a healthy daemon
	// until the complete restored config parses successfully.
	if _, err := i.configDump(ctx); err != nil {
		return fmt.Errorf("restored containerd config failed validation, leaving recovery pending: %w", err)
	}
	// A cooldown records an attempt, not a successful restart. Keep the
	// journal until a restart has actually settled the predecessor.
	if err := i.recoveryRestart(ctx, p, "roll back"); err != nil {
		return fmt.Errorf("restarting containerd onto the previous config: %w", err)
	}
	if p.PreviousHandler != "" {
		// Settled but unhealthy is still settled, the normal flow takes over.
		if err := i.verifyServing(ctx, p.PreviousHandler, nil); err != nil {
			i.log.Warn("previous handler not served after rollback", "handler", p.PreviousHandler, "error", err)
		}
	}
	st.Pending = nil
	if err := i.writeState(*st); err != nil {
		return err
	}
	settled, err := i.readState()
	if err != nil {
		return err
	}
	*st = settled
	i.log.Info("interrupted activation rolled back", "targetGeneration", p.Target.GenerationPath)
	return nil
}

// writePristineBackup keeps a write-once copy for manual recovery, at the
// source's mode: config.toml may be 0600 and hold inline registry credentials,
// which writeFileAtomic's 0644 default for new files would leak.
func writePristineBackup(backupPath, srcPath string, raw []byte) error {
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(srcPath); err == nil {
		mode = fi.Mode().Perm()
	}
	// Write-once. A zero-length backup is a crash remnant, not the pristine
	// config. An existing one is never re-permissioned: it can hold credentials
	// the current config no longer does, so tracking config.toml's mode could
	// only expose it.
	if fi, err := os.Stat(backupPath); err == nil && fi.Size() > 0 {
		return nil
	}
	if err := os.Remove(backupPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	// writeFileAtomic preserves an existing file's mode, so pre-create at the
	// target mode. The chmod defeats the umask.
	f, err := os.OpenFile(backupPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(backupPath, mode); err != nil {
		return err
	}
	return writeFileAtomic(backupPath, raw)
}

// rollback detaches from ctx: an expired deadline or SIGTERM must not skip
// the restart that recovers the node onto the previous config.
func (i *Installer) restorePreviousBlock(cfgPath string, p *pendingActivation) error {
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	current, found, err := managedBlock(raw)
	if err != nil {
		return err
	}
	if found && current != p.Target.ManagedBlock && current != p.PreviousManagedBlock {
		return fmt.Errorf("managed block changed concurrently, refusing rollback")
	}
	previous, err := previousConfig(raw, p)
	if err != nil {
		return err
	}
	return compareAndWrite(cfgPath, raw, previous)
}

func checkRegularFile(p string) error {
	if err := checkDirectoryAncestors(path.Dir(p)); err != nil {
		return err
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file", p)
	}
	return nil
}

func compareAndWrite(cfgPath string, before, after []byte) error {
	if err := checkRegularFile(cfgPath); err != nil {
		return err
	}
	fresh, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	if !bytes.Equal(fresh, before) {
		return fmt.Errorf("configuration changed concurrently")
	}
	return writeFileAtomic(cfgPath, after)
}

func (i *Installer) rollback(ctx context.Context, cfgPath string, p *pendingActivation) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), i.healthWait+time.Minute)
	defer cancel()
	if err := i.preflight(ctx, true); err != nil {
		return err
	}
	if err := i.restorePreviousBlock(cfgPath, p); err != nil {
		return err
	}
	if _, err := i.configDump(ctx); err != nil {
		return fmt.Errorf("rollback config does not validate: %w", err)
	}
	return i.recoveryRestart(ctx, p, "roll back")
}

func (i *Installer) restartAndAwaitHealthy(ctx context.Context) error {
	st, err := i.readState()
	if err != nil {
		return err
	}

	if err := i.preflight(ctx, true); err != nil {
		return err
	}
	st.RestartNotBefore = time.Now().Add(i.restartCooldown)
	if err := i.writeState(st); err != nil {
		return err
	}
	if _, err := i.host.Run(ctx, "systemctl", "restart", i.cfg.ContainerdService); err != nil {
		return err
	}
	return i.awaitRuntimeReady(ctx)
}

// awaitRuntimeReady verifies endpoint identity and polls CRI RuntimeReady.
func (i *Installer) awaitRuntimeReady(ctx context.Context) error {
	deadline := time.Now().Add(i.healthWait)
	var lastErr error
	for time.Now().Before(deadline) {
		// Asking for handlers would marshal containerd 1.x's config every poll.
		identityErr := i.preflight(ctx, true)
		st, err := i.cri.Status(ctx, false)
		if identityErr != nil {
			err = identityErr
		}
		if err == nil && st.RuntimeReady {
			return i.preflight(ctx, false)
		}
		if err == nil {
			err = fmt.Errorf("RuntimeReady condition is false")
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(i.healthPoll):
		}
	}
	return fmt.Errorf("containerd not ready within %s: %w", i.healthWait, lastErr)
}

// Asks the live daemon, never the on-disk config: a config written but never
// loaded must not count as installed. want additionally pins the loaded
// paths, the only way to tell two generations apart.
func (i *Installer) verifyServing(ctx context.Context, handler string, want *runtimeTarget) error {
	st, err := i.cri.Status(ctx, true)
	if err != nil {
		return err
	}
	if !st.RuntimeReady {
		return fmt.Errorf("containerd RuntimeReady condition is false")
	}
	if len(st.Handlers) == 0 {
		return errNoRuntimeHandlers
	}
	if !slices.Contains(st.Handlers, handler) {
		return fmt.Errorf("runtime handler %q not served by containerd (handlers: %v)", handler, st.Handlers)
	}
	loaded, ok := st.Runtimes[handler]
	if !ok {
		return fmt.Errorf("containerd did not report a loaded config for runtime handler %q", handler)
	}
	if loaded.Type != runscRuntimeType {
		return fmt.Errorf("containerd serves handler %q with runtime_type %q, expected %s", handler, loaded.Type, runscRuntimeType)
	}
	if loaded.OptionsTypeURL != runscOptionsTypeURL {
		return fmt.Errorf("containerd runtime options type differs from gVisor shim options")
	}
	if want != nil {
		if loaded.Path != want.ShimPath {
			return fmt.Errorf("containerd serves handler %q from shim %q, expected %q", handler, loaded.Path, want.ShimPath)
		}
		if loaded.ConfigPath != want.ConfigPath {
			return fmt.Errorf("containerd serves handler %q with ConfigPath %q, expected %q", handler, loaded.ConfigPath, want.ConfigPath)
		}
	}
	return nil
}
