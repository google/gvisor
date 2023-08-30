// Copyright 2019 The gVisor Authors.
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

package container

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gofrs/flock"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
)

const stateFileExtension = "state"

// ErrStateFileLocked is returned by Load() when the state file is locked
// and TryLock is enabled.
var ErrStateFileLocked = errors.New("state file locked")

// TryLock represents whether we should block waiting for the lock to be acquired or not.
type TryLock bool

const (
	// BlockAcquire means we will block until the lock can be acquired.
	BlockAcquire TryLock = false

	// TryAcquire means we will fail fast if the lock cannot be acquired.
	TryAcquire TryLock = true
)

// LoadOpts provides options for Load()ing a container.
type LoadOpts struct {
	// Exact tells whether the search should be exact. See Load() for more.
	Exact bool

	// SkipCheck tells Load() to skip checking if container is runnning.
	SkipCheck bool

	// TryLock tells Load() to fail if the container state file cannot be locked,
	// as opposed to blocking until it is available.
	// When the state file cannot be locked, it will error with ErrStateFileLocked.
	TryLock TryLock

	// RootContainer when true matches the search only with the root container of
	// a sandbox. This is used when looking for a sandbox given that root
	// container and sandbox share the same ID.
	RootContainer bool
}

// Load loads a container with the given id from a metadata file. "id" may
// be an abbreviation of the full container id in case LoadOpts.Exact if not
// set. It also checks if the container is still running, in order to return
// an error to the caller earlier. This check is skipped if LoadOpts.SkipCheck
// is set.
//
// Returns ErrNotExist if no container is found. Returns error in case more than
// one containers matching the ID prefix is found.
func Load(rootDir string, id FullID, opts LoadOpts) (*Container, error) {
	log.Debugf("Load container, rootDir: %q, id: %+v, opts: %+v", rootDir, id, opts)
	if !opts.Exact {
		var err error
		id, err = findContainerID(rootDir, id.ContainerID)
		if err != nil {
			// Preserve error so that callers can distinguish 'not found' errors.
			return nil, err
		}
	}

	if err := id.validate(); err != nil {
		return nil, fmt.Errorf("invalid container id: %v", err)
	}
	state := StateFile{
		RootDir: rootDir,
		ID:      id,
	}
	defer state.close()

	c := &Container{}
	if err := state.load(c, opts); err != nil {
		if os.IsNotExist(err) {
			// Preserve error so that callers can distinguish 'not found' errors.
			return nil, err
		}
		return nil, fmt.Errorf("reading container metadata file %q: %v", state.statePath(), err)
	}

	if opts.RootContainer && c.ID != c.Sandbox.ID {
		return nil, fmt.Errorf("ID %q doesn't belong to a sandbox", id)
	}

	if !opts.SkipCheck {
		// If the status is "Running" or "Created", check that the sandbox/container
		// is still running, setting it to Stopped if not.
		//
		// This is inherently racy.
		switch c.Status {
		case Created:
			if !c.IsSandboxRunning() {
				// Sandbox no longer exists, so this container definitely does not exist.
				c.changeStatus(Stopped)
			}
		case Running:
			if err := c.SignalContainer(unix.Signal(0), false); err != nil {
				c.changeStatus(Stopped)
			}
		}
	}

	return c, nil
}

// List returns all container ids in the given root directory.
func List(rootDir string) ([]FullID, error) {
	log.Debugf("List containers %q", rootDir)
	return listMatch(rootDir, FullID{})
}

// ListSandboxes returns all sandbox ids in the given root directory.
func ListSandboxes(rootDir string) ([]FullID, error) {
	log.Debugf("List containers %q", rootDir)
	ids, err := List(rootDir)
	if err != nil {
		return nil, err
	}

	sandboxes := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		sandboxes[id.SandboxID] = struct{}{}
	}
	// Reset ids to list only sandboxes.
	ids = nil
	for id := range sandboxes {
		ids = append(ids, FullID{SandboxID: id, ContainerID: id})
	}
	return ids, nil
}

// listMatch returns all container ids that match the provided id.
func listMatch(rootDir string, id FullID) ([]FullID, error) {
	id.SandboxID += "*"
	id.ContainerID += "*"
	pattern := buildPath(rootDir, id, stateFileExtension)
	list, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	var out []FullID
	for _, path := range list {
		id, err := parseFileName(filepath.Base(path))
		if err == nil {
			out = append(out, id)
		}
	}
	return out, nil
}

// LoadSandbox loads all containers that belong to the sandbox with the given
// ID.
func LoadSandbox(rootDir, id string, opts LoadOpts) ([]*Container, error) {
	cids, err := listMatch(rootDir, FullID{SandboxID: id})
	if err != nil {
		return nil, err
	}

	// Override load options that don't make sense in the context of this function.
	opts.SkipCheck = true      // We're loading all containers irrespective of status.
	opts.RootContainer = false // We're loading all containers, not just the root one.
	opts.Exact = true          // We'll iterate over exact container IDs below.

	// Load the container metadata.
	var containers []*Container
	for _, cid := range cids {
		container, err := Load(rootDir, cid, opts)
		if err != nil {
			// Container file may not exist if it raced with creation/deletion or
			// directory was left behind. Load provides a snapshot in time, so it's
			// fine to skip it.
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("loading sandbox %q, failed to load container %q: %v", id, cid, err)
		}
		containers = append(containers, container)
	}
	return containers, nil
}

func findContainerID(rootDir, partialID string) (FullID, error) {
	// Check whether the id fully specifies an existing container.
	pattern := buildPath(rootDir, FullID{SandboxID: "*", ContainerID: partialID + "*"}, stateFileExtension)
	list, err := filepath.Glob(pattern)
	if err != nil {
		return FullID{}, err
	}
	switch len(list) {
	case 0:
		return FullID{}, os.ErrNotExist
	case 1:
		return parseFileName(filepath.Base(list[0]))
	}

	// Now see whether id could be an abbreviation of exactly 1 of the
	// container ids. If id is ambiguous (it could match more than 1
	// container), it is an error.
	ids, err := List(rootDir)
	if err != nil {
		return FullID{}, err
	}
	var rv *FullID
	for _, id := range ids {
		if strings.HasPrefix(id.ContainerID, partialID) {
			if rv != nil {
				return FullID{}, fmt.Errorf("id %q is ambiguous and could refer to multiple containers: %q, %q", partialID, rv, id)
			}
			rv = &id
		}
	}
	if rv == nil {
		return FullID{}, os.ErrNotExist
	}
	log.Debugf("abbreviated id %q resolves to full id %v", partialID, *rv)
	return *rv, nil
}

func parseFileName(name string) (FullID, error) {
	re := regexp.MustCompile(`([\w+-\.]+)_sandbox:([\w+-\.]+)\.` + stateFileExtension)
	groups := re.FindStringSubmatch(name)
	if len(groups) != 3 {
		return FullID{}, fmt.Errorf("invalid state file name format: %q", name)
	}
	id := FullID{
		SandboxID:   groups[2],
		ContainerID: groups[1],
	}
	if err := id.validate(); err != nil {
		return FullID{}, fmt.Errorf("invalid state file name %q: %w", name, err)
	}
	return id, nil
}

// FullID combines sandbox and container ID to identify a container. Sandbox ID
// is used to allow all containers for a given sandbox to be loaded by matching
// sandbox ID in the file name.
type FullID struct {
	SandboxID   string `json:"sandboxId"`
	ContainerID string `json:"containerId"`
}

func (f *FullID) String() string {
	return f.SandboxID + "/" + f.ContainerID
}

func (f *FullID) validate() error {
	if err := validateID(f.SandboxID); err != nil {
		return err
	}
	return validateID(f.ContainerID)
}

// StateFile handles load from/save to container state safely from multiple
// processes. It uses a lock file to provide synchronization between operations.
//
// The lock file is located at: "${s.RootDir}/${containerd-id}_sand:{sandbox-id}.lock".
// The state file is located at: "${s.RootDir}/${containerd-id}_sand:{sandbox-id}.state".
type StateFile struct {
	// RootDir is the directory containing the container metadata file.
	RootDir string `json:"rootDir"`

	// ID is the sandbox+container ID.
	ID FullID `json:"id"`

	//
	// Fields below this line are not saved in the state file and will not
	// be preserved across commands.
	//

	once  sync.Once    `nojson:"true"`
	flock *flock.Flock `nojson:"true"`
}

// lock globally locks all locking operations for the container.
func (s *StateFile) lock(tryLock TryLock) error {
	s.once.Do(func() {
		s.flock = flock.New(s.lockPath())
	})

	if tryLock {
		gotLock, err := s.flock.TryLock()
		if err != nil {
			return fmt.Errorf("acquiring lock on %q: %v", s.flock, err)
		}
		if !gotLock {
			return ErrStateFileLocked
		}
	} else {
		if err := s.flock.Lock(); err != nil {
			return fmt.Errorf("acquiring lock on %q: %v", s.flock, err)
		}
	}
	return nil
}

// LockForNew acquires the lock and checks if the state file doesn't exist. This
// is done to ensure that more than one creation didn't race to create
// containers with the same ID.
func (s *StateFile) LockForNew() error {
	if err := s.lock(BlockAcquire); err != nil {
		return err
	}

	// Checks if the container already exists by looking for the metadata file.
	if _, err := os.Stat(s.statePath()); err == nil {
		s.UnlockOrDie()
		return fmt.Errorf("container already exists")
	} else if !os.IsNotExist(err) {
		s.UnlockOrDie()
		return fmt.Errorf("looking for existing container: %v", err)
	}
	return nil
}

// unlock globally unlocks all locking operations for the container.
func (s *StateFile) unlock() error {
	if !s.flock.Locked() {
		panic("unlock called without lock held")
	}

	if err := s.flock.Unlock(); err != nil {
		log.Warningf("Error to release lock on %q: %v", s.flock, err)
		return fmt.Errorf("releasing lock on %q: %v", s.flock, err)
	}
	return nil
}

// UnlockOrDie is the same as unlock() but panics in case of failure.
func (s *StateFile) UnlockOrDie() {
	if !s.flock.Locked() {
		panic("unlock called without lock held")
	}
	if err := s.flock.Unlock(); err != nil {
		panic(fmt.Sprintf("Error releasing lock on %q: %v", s.flock, err))
	}
}

// SaveLocked saves 'v' to the state file.
//
// Preconditions: lock(*) must been called before.
func (s *StateFile) SaveLocked(v any) error {
	if !s.flock.Locked() {
		panic("saveLocked called without lock held")
	}

	meta, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(s.statePath(), meta, 0640); err != nil {
		return fmt.Errorf("writing json file: %v", err)
	}
	return nil
}

// Stat returns the result of calling stat() on the state file.
// Doing so does not require locking.
func (s *StateFile) Stat() (os.FileInfo, error) {
	return os.Stat(s.statePath())
}

func (s *StateFile) load(v any, opts LoadOpts) error {
	if err := s.lock(opts.TryLock); err != nil {
		return err
	}
	defer s.UnlockOrDie()

	metaBytes, err := ioutil.ReadFile(s.statePath())
	if err != nil {
		return err
	}
	return json.Unmarshal(metaBytes, &v)
}

func (s *StateFile) close() error {
	if s.flock == nil {
		return nil
	}
	if s.flock.Locked() {
		panic("Closing locked file")
	}
	return s.flock.Close()
}

func buildPath(rootDir string, id FullID, extension string) string {
	// Note: "_" and ":" are not valid in IDs.
	name := fmt.Sprintf("%s_sandbox:%s.%s", id.ContainerID, id.SandboxID, extension)
	return filepath.Join(rootDir, name)
}

// statePath is the full path to the state file.
func (s *StateFile) statePath() string {
	return buildPath(s.RootDir, s.ID, stateFileExtension)
}

// lockPath is the full path to the lock file.
func (s *StateFile) lockPath() string {
	return buildPath(s.RootDir, s.ID, "lock")
}

// Destroy deletes all state created by the stateFile. It may be called with the
// lock file held. In that case, the lock file must still be unlocked and
// properly closed after destroy returns.
func (s *StateFile) Destroy() error {
	if err := os.Remove(s.statePath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(s.lockPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
