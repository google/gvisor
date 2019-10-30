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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"github.com/gofrs/flock"
	"gvisor.dev/gvisor/pkg/log"
)

const stateFileExtension = ".state"

// StateFile handles load from/save to container state safely from multiple
// processes. It uses a lock file to provide synchronization between operations.
//
// The lock file is located at: "${s.RootDir}/${s.ID}.lock".
// The state file is located at: "${s.RootDir}/${s.ID}.state".
type StateFile struct {
	// RootDir is the directory containing the container metadata file.
	RootDir string `json:"rootDir"`

	// ID is the container ID.
	ID string `json:"id"`

	//
	// Fields below this line are not saved in the state file and will not
	// be preserved across commands.
	//

	once  sync.Once
	flock *flock.Flock
}

// List returns all container ids in the given root directory.
func List(rootDir string) ([]string, error) {
	log.Debugf("List containers %q", rootDir)
	list, err := filepath.Glob(filepath.Join(rootDir, "*"+stateFileExtension))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, path := range list {
		// Filter out files that do no belong to a container.
		fileName := filepath.Base(path)
		if len(fileName) < len(stateFileExtension) {
			panic(fmt.Sprintf("invalid file match %q", path))
		}
		// Remove the extension.
		cid := fileName[:len(fileName)-len(stateFileExtension)]
		if validateID(cid) == nil {
			out = append(out, cid)
		}
	}
	return out, nil
}

// lock globally locks all locking operations for the container.
func (s *StateFile) lock() error {
	s.once.Do(func() {
		s.flock = flock.NewFlock(s.lockPath())
	})

	if err := s.flock.Lock(); err != nil {
		return fmt.Errorf("acquiring lock on %q: %v", s.flock, err)
	}
	return nil
}

// lockForNew acquires the lock and checks if the state file doesn't exist. This
// is done to ensure that more than one creation didn't race to create
// containers with the same ID.
func (s *StateFile) lockForNew() error {
	if err := s.lock(); err != nil {
		return err
	}

	// Checks if the container already exists by looking for the metadata file.
	if _, err := os.Stat(s.statePath()); err == nil {
		s.unlock()
		return fmt.Errorf("container already exists")
	} else if !os.IsNotExist(err) {
		s.unlock()
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

// saveLocked saves 'v' to the state file.
//
// Preconditions: lock() must been called before.
func (s *StateFile) saveLocked(v interface{}) error {
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

func (s *StateFile) load(v interface{}) error {
	if err := s.lock(); err != nil {
		return err
	}
	defer s.unlock()

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

func buildStatePath(rootDir, id string) string {
	return filepath.Join(rootDir, id+stateFileExtension)
}

// statePath is the full path to the state file.
func (s *StateFile) statePath() string {
	return buildStatePath(s.RootDir, s.ID)
}

// lockPath is the full path to the lock file.
func (s *StateFile) lockPath() string {
	return filepath.Join(s.RootDir, s.ID+".lock")
}

// destroy deletes all state created by the stateFile. It may be called with the
// lock file held. In that case, the lock file must still be unlocked and
// properly closed after destroy returns.
func (s *StateFile) destroy() error {
	if err := os.Remove(s.statePath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(s.lockPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
