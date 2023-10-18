// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"fmt"
	"path/filepath"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/specutils"
)

const (
	volumeKeyPrefix = "dev.gvisor.spec.mount."

	// devshmName is the volume name used for /dev/shm. Pick a name that is
	// unlikely to be used.
	devshmName = "gvisorinternaldevshm"

	// emptyDirVolumesDir is the directory inside kubeletPodsDir/{uid}/volumes/
	// that hosts all the EmptyDir volumes used by the pod.
	emptyDirVolumesDir = "kubernetes.io~empty-dir"
)

// The directory structure for volumes is as follows:
// /var/lib/kubelet/pods/{uid}/volumes/{type} where `uid` is the pod UID and
// `type` is the volume type.
var kubeletPodsDir = "/var/lib/kubelet/pods"

// volumeName gets volume name from volume annotation key, example:
//
//	dev.gvisor.spec.mount.NAME.share
func volumeName(k string) string {
	return strings.SplitN(strings.TrimPrefix(k, volumeKeyPrefix), ".", 2)[0]
}

// volumeFieldName gets volume field name from volume annotation key, example:
//
//	`type` is the field of dev.gvisor.spec.mount.NAME.type
func volumeFieldName(k string) string {
	parts := strings.Split(strings.TrimPrefix(k, volumeKeyPrefix), ".")
	return parts[len(parts)-1]
}

// podUID gets pod UID from the pod log path.
func podUID(s *specs.Spec) (string, error) {
	sandboxLogDir := s.Annotations[sandboxLogDirAnnotation]
	if sandboxLogDir == "" {
		return "", fmt.Errorf("no sandbox log path annotation")
	}
	fields := strings.Split(filepath.Base(sandboxLogDir), "_")
	switch len(fields) {
	case 1: // This is the old CRI logging path.
		return fields[0], nil
	case 3: // This is the new CRI logging path.
		return fields[2], nil
	}
	return "", fmt.Errorf("unexpected sandbox log path %q", sandboxLogDir)
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
		return "", fmt.Errorf("unexpected matched volume list %v", dirs)
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
// volume optimization. Returns true if the spec was modified.
//
// Note about EmptyDir handling:
// The admission controller sets mount annotations for EmptyDir as follows:
// - For EmptyDir volumes with medium=Memory, the "type" field is set to tmpfs.
// - For EmptyDir volumes with medium="", the "type" field is set to bind.
//
// The container spec has EmptyDir mount points as bind mounts. This method
// modifies the spec as follows:
// - The "type" mount annotation for all EmptyDirs is changed to tmpfs.
// - The mount type in spec.Mounts[i].Type is changed as follows:
//   - For EmptyDir volumes with medium=Memory, we change it to tmpfs.
//   - For EmptyDir volumes with medium="", we leave it as a bind mount.
//   - (Essentially we set it to what the admission controller said.)
//
// runsc should use these two setting to infer EmptyDir medium:
//   - tmpfs annotation type + tmpfs mount type = memory-backed EmptyDir
//   - tmpfs annotation type + bind mount type = disk-backed EmptyDir
func UpdateVolumeAnnotations(s *specs.Spec) (bool, error) {
	var uid string
	if IsSandbox(s) {
		var err error
		uid, err = podUID(s)
		if err != nil {
			// Skip if we can't get pod UID, because this doesn't work
			// for containerd 1.1.
			return false, nil
		}
	}
	updated := false
	for k, v := range s.Annotations {
		if !isVolumeKey(k) {
			continue
		}
		if volumeFieldName(k) != "type" {
			continue
		}
		volume := volumeName(k)
		if uid != "" {
			// This is the root (first) container. Mount annotations are only
			// consumed from this container's spec. So fix mount annotations by:
			// 1. Adding source annotation.
			// 2. Fixing type annotation.
			path, err := volumePath(volume, uid)
			if err != nil {
				return false, fmt.Errorf("get volume path for %q: %w", volume, err)
			}
			s.Annotations[volumeSourceKey(volume)] = path
			if strings.Contains(path, emptyDirVolumesDir) {
				s.Annotations[k] = "tmpfs" // See note about EmptyDir.
			}
			updated = true
		} else {
			// This is a sub-container. Mount annotations are ignored. So no need to
			// bother fixing those.
			for i := range s.Mounts {
				// An error is returned for sandbox if source annotation is not
				// successfully applied, so it is guaranteed that the source annotation
				// for sandbox has already been successfully applied at this point.
				//
				// The volume name is unique inside a pod, so matching without podUID
				// is fine here.
				//
				// TODO: Pass podUID down to shim for containers to do more accurate
				// matching.
				if yes, _ := isVolumePath(volume, s.Mounts[i].Source); yes {
					// Container mount type must match the mount type specified by
					// admission controller. See note about EmptyDir.
					specutils.ChangeMountType(&s.Mounts[i], v)
					updated = true
				}
			}
		}
	}

	if ok, err := configureShm(s); err != nil {
		return false, err
	} else if ok {
		updated = true
	}

	return updated, nil
}

// configureShm sets up annotations to mount /dev/shm as a pod shared tmpfs
// mount inside containers.
//
// Pods are configured to mount /dev/shm to a common path in the host, so it's
// shared among containers in the same pod. In gVisor, /dev/shm must be
// converted to a tmpfs mount inside the sandbox, otherwise shm_open(3) doesn't
// use it (see where_is_shmfs() in glibc). Mount annotation hints are used to
// instruct runsc to mount the same tmpfs volume in all containers inside the
// pod.
func configureShm(s *specs.Spec) (bool, error) {
	const (
		shmPath    = "/dev/shm"
		devshmType = "tmpfs"
	)

	// Some containers contain a duplicate mount entry for /dev/shm using tmpfs.
	// If this is detected, remove the extraneous entry to ensure the correct one
	// is used.
	duplicate := -1
	for i, m := range s.Mounts {
		if m.Destination == shmPath && m.Type == devshmType {
			duplicate = i
			break
		}
	}

	updated := false
	for i := range s.Mounts {
		m := &s.Mounts[i]
		if m.Destination == shmPath && m.Type == "bind" {
			if IsSandbox(s) {
				s.Annotations[volumeKeyPrefix+devshmName+".source"] = m.Source
				s.Annotations[volumeKeyPrefix+devshmName+".type"] = devshmType
				s.Annotations[volumeKeyPrefix+devshmName+".share"] = "pod"
				// Given that we don't have visibility into mount options for all
				// containers, assume broad access for the master mount (it's tmpfs
				// inside the sandbox anyways) and apply options to subcontainers as
				// they bind mount individually.
				s.Annotations[volumeKeyPrefix+devshmName+".options"] = "rw"
			}

			specutils.ChangeMountType(m, devshmType)
			updated = true

			// Remove the duplicate entry now that we found the shared /dev/shm mount.
			if duplicate >= 0 {
				s.Mounts = append(s.Mounts[:duplicate], s.Mounts[duplicate+1:]...)
			}
			break
		}
	}
	return updated, nil
}
