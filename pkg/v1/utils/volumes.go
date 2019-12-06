/*
Copyright 2019 Google LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/containerd/cri/pkg/annotations"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const volumeKeyPrefix = "dev.gvisor.spec.mount."

var kubeletPodsDir = "/var/lib/kubelet/pods"

// volumeName gets volume name from volume annotation key, example:
// dev.gvisor.spec.mount.NAME.share
func volumeName(k string) string {
	return strings.SplitN(strings.TrimPrefix(k, volumeKeyPrefix), ".", 2)[0]
}

// volumeFieldName gets volume field name from volume annotation key, example:
// `type` is the field of dev.gvisor.spec.mount.NAME.type
func volumeFieldName(k string) string {
	parts := strings.Split(strings.TrimPrefix(k, volumeKeyPrefix), ".")
	return parts[len(parts)-1]
}

// podUID gets pod UID from the pod log path.
func podUID(s *specs.Spec) (string, error) {
	sandboxLogDir := s.Annotations[annotations.SandboxLogDir]
	if sandboxLogDir == "" {
		return "", errors.New("no sandbox log path annotation")
	}
	fields := strings.Split(filepath.Base(sandboxLogDir), "_")
	switch len(fields) {
	case 1: // This is the old CRI logging path
		return fields[0], nil
	case 3: // This is the new CRI logging path
		return fields[2], nil
	}
	return "", errors.Errorf("unexpected sandbox log path %q", sandboxLogDir)
}

// isVolumeKey checks whether an annotation key is for volume.
func isVolumeKey(k string) bool {
	return strings.HasPrefix(k, volumeKeyPrefix)
}

// volumeSourceKey constructs the annotation key for volume source.
func volumeSourceKey(volume string) string {
	return volumeKeyPrefix + volume + ".source"
}

// volumePath searches the volume path in the kubelet pod directory.
func volumePath(volume, uid string) (string, error) {
	// TODO: Support subpath when gvisor supports pod volume bind mount.
	volumeSearchPath := fmt.Sprintf("%s/%s/volumes/*/%s", kubeletPodsDir, uid, volume)
	dirs, err := filepath.Glob(volumeSearchPath)
	if err != nil {
		return "", err
	}
	if len(dirs) != 1 {
		return "", errors.Errorf("unexpected matched volume list %v", dirs)
	}
	return dirs[0], nil
}

// isVolumePath checks whether a string is the volume path.
func isVolumePath(volume, path string) (bool, error) {
	// TODO: Support subpath when gvisor supports pod volume bind mount.
	volumeSearchPath := fmt.Sprintf("%s/*/volumes/*/%s", kubeletPodsDir, volume)
	return filepath.Match(volumeSearchPath, path)
}

// UpdateVolumeAnnotations add necessary OCI annotations for gvisor
// volume optimization.
func UpdateVolumeAnnotations(bundle string, s *specs.Spec) error {
	var (
		uid string
		err error
	)
	if IsSandbox(s) {
		uid, err = podUID(s)
		if err != nil {
			// Skip if we can't get pod UID, because this doesn't work
			// for containerd 1.1.
			logrus.WithError(err).Error("Can't get pod uid")
			return nil
		}
	}
	var updated bool
	for k, v := range s.Annotations {
		if !isVolumeKey(k) {
			continue
		}
		if volumeFieldName(k) != "type" {
			continue
		}
		volume := volumeName(k)
		if uid != "" {
			// This is a sandbox
			path, err := volumePath(volume, uid)
			if err != nil {
				return errors.Wrapf(err, "get volume path for %q", volume)
			}
			s.Annotations[volumeSourceKey(volume)] = path
			updated = true
		} else {
			// This is a container
			for i := range s.Mounts {
				// An error is returned for sandbox if source annotation
				// is not successfully applied, so it is guaranteed that
				// the source annotation for sandbox has already been
				// successfully applied at this point.
				// The volume name is unique inside a pod, so matching without
				// podUID is fine here.
				// TODO: Pass podUID down to shim for containers to do
				// more accurate matching.
				if yes, _ := isVolumePath(volume, s.Mounts[i].Source); yes {
					// gVisor requires the container mount type to match
					// sandbox mount type.
					s.Mounts[i].Type = v
					updated = true
				}
			}
		}
	}
	if !updated {
		return nil
	}
	// Update bundle
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filepath.Join(bundle, "config.json"), b, 0666)
}
