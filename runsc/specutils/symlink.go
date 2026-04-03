// Copyright 2025 The gVisor Authors.
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

package specutils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveSymlinks walks 'rel' having 'root' as the root directory. If there are
// symlinks, they are evaluated relative to 'root' to ensure the end result is
// the same as if the process was running inside the container.
func ResolveSymlinks(root, rel string) (string, error) {
	return resolveSymlinksImpl(root, root, rel, 255)
}

func resolveSymlinksImpl(root, base, rel string, followCount uint) (string, error) {
	if followCount == 0 {
		return "", fmt.Errorf("too many symlinks to follow, path: %q", filepath.Join(base, rel))
	}

	rel = filepath.Clean(rel)
	for _, name := range strings.Split(rel, string(filepath.Separator)) {
		if name == "" {
			continue
		}
		// Note that Join() resolves things like ".." and returns a clean path.
		path := filepath.Join(base, name)
		if !strings.HasPrefix(path, root) {
			// One cannot '..' their way out of root.
			base = root
			continue
		}
		fi, err := os.Lstat(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return "", err
			}
			// Not found means there is no symlink to check. Just keep walking dirs.
			base = path
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return "", err
			}
			if filepath.IsAbs(link) {
				base = root
			}
			base, err = resolveSymlinksImpl(root, base, link, followCount-1)
			if err != nil {
				return "", err
			}
			continue
		}
		base = path
	}
	return base, nil
}
