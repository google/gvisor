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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

const stateSchemaVersion = 1

// generationRecord binds a complete payload and shim config to its exact
// containerd runtime stanza.
type generationRecord struct {
	// Host-view absolute path.
	GenerationPath string `json:"generationPath"`
	// Sandboxes created under this activation keep reading this exact path.
	ConfigPath    string `json:"configPath"`
	Version       string `json:"version"`
	PayloadSHA512 string `json:"payloadSHA512"`
	Handler       string `json:"handler"`
	ManagedBlock  string `json:"managedBlock"`
}

// Saved before changing the managed block or restarting containerd. If the
// installer stops before confirming the result, this record tells the next
// process which configuration to finish applying or restore.
type pendingActivation struct {
	Target generationRecord `json:"target"`
	// Empty when no block existed, rollback then removes the block.
	PreviousManagedBlock string `json:"previousManagedBlock"`
	// Empty means no gvisor-managed handler to expect after rolling back.
	PreviousHandler string `json:"previousHandler"`
	// RollbackAvailable permits one immediate predecessor restart after a
	// forward recovery attempt. Consumption is durable before restarting.
	RollbackAvailable bool `json:"rollbackAvailable,omitempty"`
}

type installerState struct {
	SchemaVersion    int                `json:"schemaVersion"`
	Target           targetIdentity     `json:"target"`
	RestartNotBefore time.Time          `json:"restartNotBefore,omitempty"`
	Active           *generationRecord  `json:"active,omitempty"`
	Pending          *pendingActivation `json:"pending,omitempty"`
}

// targetIdentity persists the exact host target before activation.
type targetIdentity struct {
	Node       string `json:"node"`
	Config     string `json:"config"`
	Socket     string `json:"socket"`
	Service    string `json:"service"`
	Executable string `json:"executable"`
	Invocation string `json:"invocation"`
	InstallDir string `json:"installDir"`
	StateDir   string `json:"stateDir"`
	Handler    string `json:"handler"`
}

func (i *Installer) targetIdentity() targetIdentity {
	return targetIdentity{
		Node:       i.cfg.NodeName,
		Config:     i.cfg.ContainerdConfig,
		Socket:     i.cfg.ContainerdSocket,
		Service:    i.cfg.ContainerdService,
		Executable: i.containerdExecutable,
		Invocation: i.containerdInvocation,
		InstallDir: i.cfg.InstallDir,
		StateDir:   i.cfg.StateDir,
		Handler:    i.cfg.Handler,
	}
}
func (i *Installer) statePath() string {
	return i.cfg.hostPath(path.Join(i.cfg.StateDir, "state.json"))
}

func (i *Installer) readState() (installerState, error) {
	var st installerState
	if err := checkDirectoryAncestors(i.cfg.hostPath(i.cfg.StateDir)); err != nil {
		return st, err
	}
	data, err := os.ReadFile(i.statePath())
	if os.IsNotExist(err) {
		return installerState{SchemaVersion: stateSchemaVersion}, nil
	}
	if err != nil {
		return st, fmt.Errorf("reading installer state: %w", err)
	}
	if fi, err := os.Lstat(i.statePath()); err != nil || !fi.Mode().IsRegular() {
		return st, fmt.Errorf("installer state must be a regular file")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&st); err != nil {
		return st, fmt.Errorf("malformed installer state: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return st, fmt.Errorf("installer state has trailing data")
	}
	if st.SchemaVersion != stateSchemaVersion || !st.valid() {
		return st, fmt.Errorf("unsupported or invalid installer state schema %d", st.SchemaVersion)
	}
	desired := i.targetIdentity()
	desired.Executable = st.Target.Executable
	desired.Invocation = st.Target.Invocation
	if desired != st.Target {
		return st, fmt.Errorf("configured host target differs from persistent installer identity")
	}
	i.containerdExecutable = st.Target.Executable
	i.containerdInvocation = st.Target.Invocation
	return st, nil
}

func (i *Installer) writeState(st installerState) error { return i.writeStateWithCooldown(st, false) }
func (i *Installer) writeSettledState(st installerState) error {
	return i.writeStateWithCooldown(st, true)
}
func (i *Installer) writeStateWithCooldown(st installerState, settled bool) error {
	st.SchemaVersion = stateSchemaVersion
	st.Target = i.targetIdentity()
	var previous installerState
	if settled {
		st.RestartNotBefore = time.Time{}
	}
	if !settled && readJSONFile(i.statePath(), &previous) == nil && previous.RestartNotBefore.After(st.RestartNotBefore) {
		st.RestartNotBefore = previous.RestartNotBefore
	}
	if err := ensureDirectory(i.cfg.hostPath(i.cfg.StateDir), 0700); err != nil {
		return err
	}
	if err := writeJSONFile(i.statePath(), st); err != nil {
		return fmt.Errorf("writing installer state: %w", err)
	}
	return nil
}

func (st installerState) valid() bool {
	if st.Target.Invocation == "" || strings.Split(st.Target.Invocation, "\x00")[0] != st.Target.Executable {
		return false
	}
	if path.Base(st.Target.Executable) != "containerd" || strings.ContainsAny(st.Target.Executable, " \t\n") || !path.IsAbs(st.Target.Executable) || st.Target.Config == "" || st.Target.Socket == "" || st.Target.Service == "" {
		return false
	}

	for _, r := range []*generationRecord{st.Active, st.pendingTarget()} {
		if r == nil {
			continue
		}
		if path.Dir(r.GenerationPath) != path.Join(st.Target.InstallDir, "releases") || path.Dir(r.ConfigPath) != path.Join(st.Target.InstallDir, "runsc-configs") || r.Handler != st.Target.Handler ||
			r.Version == "" || r.Handler == "" || r.ManagedBlock == "" {
			return false
		}
		if path.Base(r.GenerationPath) != generationDirName(r.Version, r.PayloadSHA512) {
			return false
		}
		if !regexp.MustCompile(`^[a-f0-9]{32}\.toml$`).MatchString(path.Base(r.ConfigPath)) {
			return false
		}
		validBlock := false
		for _, plugin := range []string{criPluginIDV2, criPluginIDV3} {
			if r.ManagedBlock == renderManagedBlock(plugin, r.Handler, path.Join(r.GenerationPath, shimBinary), r.ConfigPath) {
				validBlock = true
			}
		}
		if !validBlock {
			return false
		}
		if len(r.PayloadSHA512) != sha512HexLen || !isHex(r.PayloadSHA512) {
			return false
		}
	}
	if st.Pending != nil {
		if st.Pending.RollbackAvailable && st.Pending.PreviousManagedBlock == st.Pending.Target.ManagedBlock {
			return false
		}
		if st.Active == nil {
			if st.Pending.PreviousManagedBlock != "" || st.Pending.PreviousHandler != "" {
				return false
			}
		} else if st.Pending.PreviousManagedBlock != st.Active.ManagedBlock || st.Pending.PreviousHandler != st.Active.Handler {
			return false
		}
	}
	return true
}

func (st installerState) pendingTarget() *generationRecord {
	if st.Pending == nil {
		return nil
	}
	return &st.Pending.Target
}
