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
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/log"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/specutils"
)

const (
	volumeKeyPrefix = "dev.gvisor.spec.mount."

	udsFlagAnnotation = "dev.gvisor.flag.host-uds"

	// devshmName is the volume name used for /dev/shm. Pick a name that is
	// unlikely to be used.
	devshmName = "gvisorinternaldevshm"

	// emptyDirVolumesDir is the directory inside kubeletPodsDir/{uid}/volumes/
	// that hosts all the EmptyDir volumes used by the pod.
	emptyDirVolumesDir = "kubernetes.io~empty-dir"

	// selfFilestorePrefix is the prefix for the filestore files used for
	// self-backed mounts.
	selfFilestorePrefix = ".gvisor.filestore."

	// gcsFuseSidecarTmpVolumeName is the name of the GCS FUSE sidecar's volume
	// that contains the socket for communicating with the driver. Same as
	// GoogleCloudPlatform/gcs-fuse-csi-driver/pkg/webhook/sidecar_spec.go:SidecarContainerTmpVolumeName.
	gcsFuseSidecarTmpVolumeName = "gke-gcsfuse-tmp"
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

// volumeShareKey constructs the annotation key for volume share type.
func volumeShareKey(volume string) string {
	return volumeKeyPrefix + volume + ".share"
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
//
// NOTE(b/416567832): Some CSI drivers (like GCS FUSE driver) use EmptyDirs to
// communicate with the Pod over a UDS. While not foolproof, we detect such
// EmptyDirs by checking if the host directory is not empty and turn off the
// EmptyDir optimization for them by configuring them as normal bind mounts.
func UpdateVolumeAnnotations(s *specs.Spec) (bool, error) {
	updated := false
	for k, v := range s.Annotations {
		if !isVolumeKey(k) {
			continue
		}
		if volumeFieldName(k) != "type" {
			continue
		}
		volume := volumeName(k)
		if IsSandbox(s) {
			// This is the root (first) container. Mount annotations are only
			// consumed from this container's spec. So fix mount annotations by:
			// 1. Adding source annotation.
			// 2. Fixing type annotation.
			uid, err := podUID(s)
			if err != nil {
				// Skip if we can't get pod UID, because this doesn't work
				// for containerd 1.1.
				return false, nil
			}
			path, err := volumePath(volume, uid)
			if err != nil {
				return false, fmt.Errorf("get volume path for %q: %w", volume, err)
			}
			s.Annotations[volumeSourceKey(volume)] = path
			if strings.Contains(path, emptyDirVolumesDir) {
				if isEmptyDirEmpty(path) {
					s.Annotations[k] = "tmpfs" // See note about EmptyDir.
				} else {
					// This is a non-empty EmptyDir volume. Configure it as a bind mount.
					log.L.Infof("Non-empty EmptyDir volume %q, configuring bind mount annotations", volume)
					s.Annotations[k] = "bind"
					s.Annotations[volumeShareKey(volume)] = "shared"
					if volume == gcsFuseSidecarTmpVolumeName && s.Annotations[udsFlagAnnotation] == "" {
						// Enable host UDS flag to allow communication with the gcsfuse driver.
						log.L.Infof("GCS Fuse sidecar detected in Pod, setting --host-uds=open")
						s.Annotations[udsFlagAnnotation] = "open"
					}
				}
			}
			updated = true
		} else {
			// This is a sub-container. Mount annotations are ignored. So no need to
			// bother fixing those. An error is returned for sandbox if source
			// annotation is not successfully applied, so it is guaranteed that the
			// source annotation for sandbox has already been successfully applied at
			// this point. Update mount type in spec.Mounts if required.
			for i := range s.Mounts {
				// The volume name is unique inside a pod, so matching without podUID
				// is fine here.
				//
				// TODO: Pass podUID down to shim for containers to do more accurate
				// matching.
				if yes, _ := isVolumePath(volume, s.Mounts[i].Source); yes {
					if strings.Contains(s.Mounts[i].Source, emptyDirVolumesDir) && !isEmptyDirEmpty(s.Mounts[i].Source) {
						// This is a non-empty EmptyDir volume. Don't change the mount type.
						log.L.Infof("Non-empty EmptyDir volume %q, not changing its mount type", volume)
						if volume == gcsFuseSidecarTmpVolumeName && s.Annotations[udsFlagAnnotation] == "" {
							// Enable host UDS flag to allow communication with the gcsfuse
							// driver. Do this for subcontainers too to update fsgofer's UDS
							// configuration because each subcontainer has its own fsgofer.
							log.L.Infof("This is a GCS Fuse sidecar container, setting --host-uds=open")
							s.Annotations[udsFlagAnnotation] = "open"
						}
						continue
					}
					// Container mount type must match the mount type specified by
					// admission controller. See note about EmptyDir.
					if specutils.ChangeMountType(&s.Mounts[i], v) {
						updated = true
					}
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

func isEmptyDirEmpty(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		log.L.Warningf("failed to open %q to check if it is empty: %v", path, err)
		return true
	}
	defer f.Close()

	names, err := f.Readdirnames(2)
	if len(names) == 0 && err == io.EOF {
		return true
	}
	if err != io.EOF && err != nil {
		log.L.Warningf("failed to readdirnames %q to check if it is empty: %v", path, err)
		return true
	}
	if len(names) == 1 && strings.HasPrefix(names[0], selfFilestorePrefix) {
		// The gVisor filestore file is the only file in the directory. This means
		// that a previous container already created a shared mount for this
		// EmptyDir. This is expected and should be considered empty.
		return true
	}
	return false
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
				updated = true
			}

			if specutils.ChangeMountType(m, devshmType) {
				updated = true
			}

			// Remove the duplicate entry now that we found the shared /dev/shm mount.
			if duplicate >= 0 {
				s.Mounts = append(s.Mounts[:duplicate], s.Mounts[duplicate+1:]...)
				updated = true
			}
			break
		}
	}
	return updated, nil
}
