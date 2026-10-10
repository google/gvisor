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
	"strconv"
	"strings"

	"github.com/containerd/log"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/specutils"
)

const (
	volumeKeyPrefix = "dev.gvisor.spec.mount."

	udsFlagAnnotation = "dev.gvisor.flag.host-uds"

	// emptyDirAnnotationPrefix is the prefix for EmptyDir-specific gVisor
	// annotations. Users can set it in their PodSpec.
	emptyDirAnnotationPrefix = "dev.gvisor.empty-dir."

	// emptyDirForceSharedField is the EmptyDir annotation field name that, when
	// set to a true, forces that specific EmptyDir volume to be configured as a
	// normal shared bind mount instead of being optimized into a gVisor-internal
	// tmpfs mount. This is useful for EmptyDirs that are shared with host-side
	// processes.
	emptyDirForceSharedField = "force-shared"

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

// statfs is unix.Statfs. It is a variable so tests can override it.
var statfs = unix.Statfs

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

// PodUID gets the Kubernetes pod UID from the pod annotations. If not found in
// the container spec and bundle is non-empty, it falls back to looking up the
// pod sandbox spec for child containers.
func PodUID(s *specs.Spec, bundle string) (string, error) {
	if s != nil && s.Annotations != nil {
		if uid := s.Annotations[sandboxUIDAnnotation]; uid != "" {
			return uid, nil
		}
		if sandboxLogDir := s.Annotations[sandboxLogDirAnnotation]; sandboxLogDir != "" {
			fields := strings.Split(filepath.Base(sandboxLogDir), "_")
			switch len(fields) {
			case 1: // This is the old CRI logging path.
				return fields[0], nil
			case 3: // This is the new CRI logging path.
				return fields[2], nil
			}
		}
		if bundle != "" {
			sandboxID := s.Annotations[specutils.ContainerdSandboxIDAnnotation]
			if sandboxID != "" {
				sandboxBundle := filepath.Join(filepath.Dir(bundle), sandboxID)
				if sandboxSpec, err := ReadSpec(sandboxBundle); err == nil {
					return PodUID(sandboxSpec, "")
				}
			}
		}
	}
	return "", fmt.Errorf("could not determine pod UID from spec")
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

// volumeOptionsKey constructs the annotation key for volume mount options.
func volumeOptionsKey(volume string) string {
	return volumeKeyPrefix + volume + ".options"
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
// Note about EmptyDir sizes:
// For memory-backed EmptyDirs, the kubelet mounts a tmpfs on the host volume
// directory, sized to the smallest of the EmptyDir's sizeLimit, the pod's
// memory limit and the node's allocatable memory. runsc doesn't use that
// mount. It mounts a sandbox-internal tmpfs instead, which would otherwise
// default to half of the total memory. So the host tmpfs size is added as a
// "size" option to the "options" mount annotation, unless one is already set.
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
			// 3. Adding size option for memory-backed EmptyDirs.
			uid, err := PodUID(s, "")
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
				forceShared := emptyDirForceShared(s.Annotations, volume)
				empty := isEmptyDirEmpty(path)
				if !forceShared && empty {
					s.Annotations[k] = "tmpfs" // See note about EmptyDir.
					if v == "tmpfs" {
						// Memory-backed EmptyDir. See note about EmptyDir sizes.
						setSizeFromHostTmpfs(s.Annotations, volume, path)
					}
				} else {
					// The EmptyDir was either forced to be shared by annotation
					// or it is non-empty. Configure it as a bind mount.
					if forceShared {
						log.L.Infof("EmptyDir volume %q forced to be shared, configuring bind mount annotations", volume)
					} else {
						log.L.Infof("Non-empty EmptyDir volume %q, configuring bind mount annotations", volume)
					}
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
					if strings.Contains(s.Mounts[i].Source, emptyDirVolumesDir) {
						forceShared := emptyDirForceShared(s.Annotations, volume)
						empty := isEmptyDirEmpty(s.Mounts[i].Source)
						if forceShared || !empty {
							// The EmptyDir was either forced to be shared by
							// annotation or it is non-empty. Keep it as a bind
							// mount by not changing its mount type.
							if forceShared {
								log.L.Infof("EmptyDir volume %q forced to be shared, not changing its mount type", volume)
							} else {
								log.L.Infof("Non-empty EmptyDir volume %q, not changing its mount type", volume)
							}
							if volume == gcsFuseSidecarTmpVolumeName && s.Annotations[udsFlagAnnotation] == "" {
								// Enable host UDS flag to allow communication with the gcsfuse
								// driver. Do this for subcontainers too to update fsgofer's UDS
								// configuration because each subcontainer has its own fsgofer.
								log.L.Infof("This is a GCS Fuse sidecar container, setting --host-uds=open")
								s.Annotations[udsFlagAnnotation] = "open"
							}
							continue
						}
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

func emptyDirForceShared(annotations map[string]string, volume string) bool {
	key := emptyDirAnnotationPrefix + volume + "." + emptyDirForceSharedField
	v, ok := annotations[key]
	if !ok {
		return false
	}
	forceShared, err := strconv.ParseBool(v)
	if err != nil {
		log.L.Warningf("Ignoring invalid value %q for annotation %q: %v", v, key, err)
		return false
	}
	return forceShared
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

// hostTmpfsSize returns the size limit in bytes of the host tmpfs containing
// path. It returns false if path is not on a tmpfs, or if the tmpfs has no size
// limit.
func hostTmpfsSize(path string) (uint64, bool) {
	var st unix.Statfs_t
	if err := statfs(path, &st); err != nil {
		log.L.Warningf("Failed to statfs %q to get its tmpfs size: %v", path, err)
		return 0, false
	}
	if st.Type != unix.TMPFS_MAGIC {
		return 0, false
	}
	// f_blocks is in units of f_frsize, which equals f_bsize for tmpfs. Fall
	// back to f_bsize in case f_frsize isn't set.
	blockSize := uint64(st.Frsize)
	if blockSize == 0 {
		blockSize = uint64(st.Bsize)
	}
	// A tmpfs mounted with size=0 has no size limit and reports f_blocks=0.
	if st.Blocks == 0 || blockSize == 0 {
		return 0, false
	}
	return st.Blocks * blockSize, true
}

// withSizeOption returns the comma-separated mount options in opts with a
// "size" option for size bytes appended. opts is returned unchanged if it
// already has a "size" option.
func withSizeOption(opts string, size uint64) string {
	if opts == "" {
		return fmt.Sprintf("size=%d", size)
	}
	for _, o := range strings.Split(opts, ",") {
		if strings.HasPrefix(o, "size=") {
			return opts
		}
	}
	return fmt.Sprintf("%s,size=%d", opts, size)
}

// setSizeFromHostTmpfs adds the size of the host tmpfs containing hostPath, if
// any, as a "size" option to the mount options annotation of volume. This
// makes the sandbox-internal tmpfs that replaces the host mount enforce the
// same size limit. A "size" option already in the annotation takes precedence.
//
// This calls statfs(2) on hostPath, so hostPath must not be on a FUSE
// filesystem whose server may be unresponsive.
func setSizeFromHostTmpfs(annotations map[string]string, volume, hostPath string) {
	size, ok := hostTmpfsSize(hostPath)
	if !ok {
		return
	}
	key := volumeOptionsKey(volume)
	opts := annotations[key]
	newOpts := withSizeOption(opts, size)
	if newOpts == opts {
		log.L.Infof("Volume %q already has a size option in %q, ignoring host tmpfs size %d of %q", volume, opts, size, hostPath)
		return
	}
	log.L.Infof("Setting size of volume %q to %d bytes, matching host tmpfs %q", volume, size, hostPath)
	annotations[key] = newOpts
}

// configureShm sets up annotations to mount /dev/shm as a pod shared tmpfs
// mount inside containers.
//
// Pods are configured to mount /dev/shm to a common path in the host, so it's
// shared among containers in the same pod. In gVisor, /dev/shm must be
// converted to a tmpfs mount inside the sandbox, otherwise shm_open(3) doesn't
// use it (see where_is_shmfs() in glibc). Mount annotation hints are used to
// instruct runsc to mount the same tmpfs volume in all containers inside the
// pod. If the host path is a size-limited tmpfs, the sandbox tmpfs gets the
// same size limit.
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
				// IsSandbox is true for a spec without annotations.
				if s.Annotations == nil {
					s.Annotations = make(map[string]string)
				}
				s.Annotations[volumeKeyPrefix+devshmName+".source"] = m.Source
				s.Annotations[volumeKeyPrefix+devshmName+".type"] = devshmType
				s.Annotations[volumeKeyPrefix+devshmName+".share"] = "pod"
				// Given that we don't have visibility into mount options for all
				// containers, assume broad access for the master mount (it's tmpfs
				// inside the sandbox anyways) and apply options to subcontainers as
				// they bind mount individually.
				s.Annotations[volumeKeyPrefix+devshmName+".options"] = "rw"
				// The host /dev/shm is usually a size-limited tmpfs, e.g. containerd
				// mounts a 64MiB tmpfs for each pod. Apply the same limit inside the
				// sandbox.
				setSizeFromHostTmpfs(s.Annotations, devshmName, m.Source)
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
