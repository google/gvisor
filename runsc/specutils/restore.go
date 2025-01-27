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
	"reflect"
	"slices"
	"sort"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/config"
)

func validateErrorWithMsg(field, cName string, oldV, newV any, msg string) error {
	return fmt.Errorf("%v does not match across checkpoint restore for container: %v, checkpoint %v restore %v, got error %v", field, cName, oldV, newV, msg)
}

func validateError(field, cName string, oldV, newV any) error {
	return fmt.Errorf("%v does not match across checkpoint restore for container: %v, checkpoint %v restore %v", field, cName, oldV, newV)
}

func cloneMount(mnt specs.Mount) specs.Mount {
	cloneMnt := specs.Mount{
		Source:      mnt.Source,
		Destination: mnt.Destination,
		Type:        mnt.Type,
	}
	cloneMnt.Options = make([]string, len(mnt.Options))
	copy(cloneMnt.Options, mnt.Options)
	sort.Strings(cloneMnt.Options)
	cloneMnt.UIDMappings = make([]specs.LinuxIDMapping, len(mnt.UIDMappings))
	copy(cloneMnt.UIDMappings, mnt.UIDMappings)
	cloneMnt.GIDMappings = make([]specs.LinuxIDMapping, len(mnt.GIDMappings))
	copy(cloneMnt.GIDMappings, mnt.GIDMappings)
	return cloneMnt
}

// validateMounts validates the mounts in the checkpoint and restore spec.
// Duplicate mounts are allowed iff all the fields in the mount are same.
func validateMounts(field, cName string, o, n []specs.Mount) error {
	// Create a new mount map without source as source path can vary
	// across checkpoint restore.
	oldMnts := make(map[string]specs.Mount)
	for _, m := range o {
		oldMnts[m.Destination] = cloneMount(m)
	}
	newMnts := make(map[string]specs.Mount)
	for _, m := range n {
		mnt := cloneMount(m)
		oldMnt, ok := oldMnts[mnt.Destination]
		if !ok {
			return validateError(field, cName, o, n)
		}

		// Duplicate mounts are allowed iff all fields in specs.Mount are same.
		if val, ok := newMnts[mnt.Destination]; ok {
			if !reflect.DeepEqual(val, mnt) {
				return validateErrorWithMsg(field, cName, o, n, "invalid mount in the restore spec")
			}
			continue
		}
		newMnts[mnt.Destination] = mnt

		if err := validateArray(field, cName, oldMnt.UIDMappings, mnt.UIDMappings); err != nil {
			return validateError(field, cName, o, n)
		}
		oldMnt.UIDMappings, mnt.UIDMappings = []specs.LinuxIDMapping{}, []specs.LinuxIDMapping{}
		if err := validateArray(field, cName, oldMnt.GIDMappings, mnt.GIDMappings); err != nil {
			return validateError(field, cName, o, n)
		}
		oldMnt.GIDMappings, mnt.GIDMappings = []specs.LinuxIDMapping{}, []specs.LinuxIDMapping{}

		oldMnt.Source, mnt.Source = "", ""
		if !reflect.DeepEqual(oldMnt, mnt) {
			return validateError(field, cName, o, n)
		}
	}
	if len(oldMnts) != len(newMnts) {
		return validateError(field, cName, o, n)
	}
	return nil
}

func validateDevices(field, cName string, o, n []specs.LinuxDevice) error {
	if len(o) != len(n) {
		return validateErrorWithMsg(field, cName, o, n, "length mismatch")
	}
	if len(o) == 0 {
		return nil
	}

	// Create with only Path and Type fields as other fields can vary during restore.
	devs := make(map[specs.LinuxDevice]struct{})
	for _, d := range o {
		dev := specs.LinuxDevice{
			Path: d.Path,
			Type: d.Type,
		}
		if _, ok := devs[dev]; ok {
			return fmt.Errorf("duplicate device found in the spec %v before checkpoint for container %v", o, cName)
		}
		devs[dev] = struct{}{}
	}
	for _, d := range n {
		dev := specs.LinuxDevice{
			Path: d.Path,
			Type: d.Type,
		}
		if _, ok := devs[dev]; !ok {
			return validateError(field, cName, o, n)
		}
		delete(devs, dev)
	}
	if len(devs) != 0 {
		return validateError(field, cName, o, n)
	}
	return nil
}

func extractAnnotationsToValidate(o map[string]string) map[string]string {
	const (
		gvisorPrefix   = "dev.gvisor."
		internalPrefix = "dev.gvisor.internal."
		mntPrefix      = "dev.gvisor.spec.mount."
	)

	n := make(map[string]string)
	for key, val := range o {
		if strings.HasPrefix(key, internalPrefix) || (strings.HasPrefix(key, mntPrefix) && strings.HasSuffix(key, ".source")) {
			continue
		}

		if strings.HasPrefix(key, gvisorPrefix) {
			n[key] = val
		}
	}
	return n
}

func validateAnnotations(cName string, before, after map[string]string) error {
	oldM := extractAnnotationsToValidate(before)
	newM := extractAnnotationsToValidate(after)
	if !reflect.DeepEqual(oldM, newM) {
		return validateError("Annotations", cName, oldM, newM)
	}
	return nil
}

// validateArray performs a deep comparison of two arrays, checking for equality
// at every level of nesting. Note that this method:
// * does not allow duplicates in the arrays.
// * does not depend on the order of the elements in the arrays.
func validateArray[T any](field, cName string, oldArr, newArr []T) error {
	if len(oldArr) != len(newArr) {
		return validateErrorWithMsg(field, cName, oldArr, newArr, "length mismatch")
	}
	if len(oldArr) == 0 {
		return nil
	}
	oldMap := make(map[any]struct{})
	newMap := make(map[any]struct{})
	for i := 0; i < len(oldArr); i++ {
		key := oldArr[i]
		if _, ok := oldMap[key]; ok {
			return validateErrorWithMsg(field, cName, oldArr, newArr, "duplicate value")
		}
		oldMap[key] = struct{}{}

		key = newArr[i]
		if _, ok := newMap[key]; ok {
			return validateErrorWithMsg(field, cName, oldArr, newArr, "duplicate value")
		}
		newMap[key] = struct{}{}
	}
	if !reflect.DeepEqual(oldMap, newMap) {
		return validateError(field, cName, oldArr, newArr)
	}

	return nil
}

func validateMap[K comparable, V comparable](field, cName string, oldM map[K]V, newM map[K]V) error {
	if len(oldM) != len(newM) {
		return validateError(field, cName, oldM, newM)
	}
	for k, v1 := range oldM {
		v2, ok := newM[k]
		if !ok || v1 != v2 {
			return validateError(field, cName, oldM, newM)
		}
	}
	return nil
}

func sortCapabilities(o *specs.LinuxCapabilities) {
	sort.Strings(o.Bounding)
	sort.Strings(o.Effective)
	sort.Strings(o.Inheritable)
	sort.Strings(o.Permitted)
	sort.Strings(o.Ambient)
}

func validateCapabilities(field, cName string, oldCaps, newCaps *specs.LinuxCapabilities) error {
	if oldCaps == nil && newCaps == nil {
		return nil
	}
	if oldCaps == nil || newCaps == nil {
		return validateError(field, cName, oldCaps, newCaps)
	}
	sortCapabilities(oldCaps)
	sortCapabilities(newCaps)
	if !reflect.DeepEqual(oldCaps, newCaps) {
		return validateError(field, cName, oldCaps, newCaps)
	}
	return nil
}

func validateResources(field, cName string, oldR, newR *specs.LinuxResources) error {
	if oldR == nil && newR == nil {
		return nil
	}
	if oldR == nil || newR == nil {
		return validateError(field, cName, oldR, newR)
	}
	before := *oldR
	after := *newR
	if err := validateArray(field+".HugepageLimits", cName, before.HugepageLimits, after.HugepageLimits); err != nil {
		return validateError(field+".HugepageLimits", cName, oldR, newR)
	}
	before.HugepageLimits, after.HugepageLimits = nil, nil

	// LinuxResources.Devices is not used in gVisor, also the major and minor
	// versions of the devices can change across checkpoint restore. Mark them
	// to nil as there is no need to validate each device.
	before.Devices, after.Devices = nil, nil

	if err := validateMap(field+".Rdma", cName, before.Rdma, after.Rdma); err != nil {
		return err
	}
	before.Rdma, after.Rdma = nil, nil
	if err := validateMap(field+".Unified", cName, before.Unified, after.Unified); err != nil {
		return err
	}
	before.Unified, after.Unified = nil, nil

	if !reflect.DeepEqual(before, after) {
		return validateError(field, cName, oldR, newR)
	}
	return nil
}

func copyNamespaceArr(namespaceArr []specs.LinuxNamespace) []specs.LinuxNamespace {
	arr := make([]specs.LinuxNamespace, 0, len(namespaceArr))
	for _, n := range namespaceArr {
		// Namespace path can change during restore.
		arr = append(arr, specs.LinuxNamespace{Type: n.Type})
	}
	return arr
}

func validateNamespaces(field, cName string, oldN, newN []specs.LinuxNamespace) error {
	oldArr := copyNamespaceArr(oldN)
	newArr := copyNamespaceArr(newN)
	return validateArray(field, cName, oldArr, newArr)
}

func validateStruct(field, cName string, oldS, newS any) error {
	if !reflect.DeepEqual(oldS, newS) {
		return validateError(field, cName, oldS, newS)
	}
	return nil
}

func ifNil[T any](v *T) *T {
	if v != nil {
		return v
	}
	var t T
	return &t
}

func validateSpecForContainer(oSpec, nSpec *specs.Spec, cName string) error {
	oldSpec := *oSpec
	newSpec := *nSpec

	// Validate OCI version.
	if oldSpec.Version != newSpec.Version {
		return validateError("OCI Version", cName, oldSpec.Version, newSpec.Version)
	}
	oldSpec.Version, newSpec.Version = "", ""

	// Validate specs.Spec.Root. Note that Root.Path can change during restore.
	oldSpec.Root, newSpec.Root = ifNil(oldSpec.Root), ifNil(newSpec.Root)
	oldRoot, newRoot := *oldSpec.Root, *newSpec.Root
	if oldRoot.Readonly != newRoot.Readonly {
		return validateError("Root.Readonly", cName, oldRoot.Readonly, newRoot.Readonly)
	}
	oldSpec.Root.Path, newSpec.Root.Path = "", ""

	// Validate specs.Spec.Mounts.
	if err := validateMounts("Mounts", cName, oldSpec.Mounts, newSpec.Mounts); err != nil {
		return err
	}
	oldSpec.Mounts, newSpec.Mounts = nil, nil

	// Validate specs.Annotations.
	if err := validateAnnotations(cName, oldSpec.Annotations, newSpec.Annotations); err != nil {
		return err
	}
	oldSpec.Annotations, newSpec.Annotations = nil, nil

	// Validate specs.Process.
	oldSpec.Process, newSpec.Process = ifNil(oldSpec.Process), ifNil(newSpec.Process)
	oldProcess, newProcess := *oldSpec.Process, *newSpec.Process
	if oldProcess.Terminal != newProcess.Terminal {
		return validateError("Terminal", cName, oldProcess.Terminal, newProcess.Terminal)
	}
	if oldProcess.Cwd != newProcess.Cwd {
		return validateError("Cwd", cName, oldProcess.Cwd, newProcess.Cwd)
	}
	if err := validateStruct("User", cName, oldProcess.User, newProcess.User); err != nil {
		return err
	}
	oldProcess.User, newProcess.User = specs.User{}, specs.User{}
	if err := validateArray("Rlimits", cName, oldProcess.Rlimits, newProcess.Rlimits); err != nil {
		return err
	}
	oldProcess.Rlimits, newProcess.Rlimits = nil, nil
	if ok := slices.Equal(oldProcess.Args, newProcess.Args); !ok {
		return validateError("Args", cName, oldProcess.Args, newProcess.Args)
	}
	if err := validateCapabilities("Capabilities", cName, oldProcess.Capabilities, newProcess.Capabilities); err != nil {
		return err
	}
	oldProcess.Capabilities, newProcess.Capabilities = nil, nil

	// Validate specs.Linux.
	oldSpec.Linux, newSpec.Linux = ifNil(oldSpec.Linux), ifNil(newSpec.Linux)
	oldLinux, newLinux := *oldSpec.Linux, *newSpec.Linux
	if err := validateMap("Sysctl", cName, oldLinux.Sysctl, newLinux.Sysctl); err != nil {
		return err
	}
	oldLinux.Sysctl, newLinux.Sysctl = nil, nil
	if err := validateStruct("Seccomp", cName, oldLinux.Seccomp, newLinux.Seccomp); err != nil {
		return err
	}
	oldLinux.Seccomp, newLinux.Seccomp = nil, nil
	if err := validateDevices("Devices", cName, oldLinux.Devices, newLinux.Devices); err != nil {
		return err
	}
	oldLinux.Devices, newLinux.Devices = nil, nil
	if err := validateResources("Resources", cName, oldLinux.Resources, newLinux.Resources); err != nil {
		// Resource limits can be changed during restore, log a warning and do not
		// return error.
		log.Warningf("specs.Linux.Resources has been changed during restore, err %v", err)
	}
	oldLinux.Resources, newLinux.Resources = nil, nil
	if err := validateArray("UIDMappings", cName, oldLinux.UIDMappings, newLinux.UIDMappings); err != nil {
		return err
	}
	oldLinux.UIDMappings, newLinux.UIDMappings = nil, nil
	if err := validateArray("GIDMappings", cName, oldLinux.GIDMappings, newLinux.GIDMappings); err != nil {
		return err
	}
	oldLinux.GIDMappings, newLinux.GIDMappings = nil, nil
	if err := validateNamespaces("Namespace", cName, oldLinux.Namespaces, newLinux.Namespaces); err != nil {
		return err
	}
	oldLinux.Namespaces, newLinux.Namespaces = nil, nil

	// Hostname, Domainname, Environment variables and CgroupsPath are
	// allowed to change during restore. Hooks contain callbacks for
	// lifecycle of the container such as prestart and teardown, and can
	// change. Do not validate these fields.
	oldSpec.Hostname, newSpec.Hostname = "", ""
	oldSpec.Domainname, newSpec.Domainname = "", ""
	oldProcess.Env, newProcess.Env = nil, nil
	oldLinux.CgroupsPath, newLinux.CgroupsPath = "", ""
	oldSpec.Hooks, newSpec.Hooks = nil, nil

	// Validate remaining fields of specs.Process.
	if ok := reflect.DeepEqual(oldProcess, newProcess); !ok {
		return validateError("Process", cName, oSpec, nSpec)
	}
	oldSpec.Process, newSpec.Process = nil, nil

	// Validate remaining fields of specs.Linux.
	if ok := reflect.DeepEqual(oldLinux, newLinux); !ok {
		return validateError("Linux", cName, oSpec, nSpec)
	}
	oldSpec.Linux, newSpec.Linux = nil, nil

	if ok := reflect.DeepEqual(oldSpec, newSpec); !ok {
		return validateError("Spec", cName, oSpec, nSpec)
	}
	return nil
}

// Validate OCI specs before restoring the containers.
func validateSpecs(oldSpecs, newSpecs map[string]*specs.Spec) error {
	for cName, newSpec := range newSpecs {
		oldSpec, ok := oldSpecs[cName]
		if !ok {
			return fmt.Errorf("checkpoint image does not contain spec for container: %q", cName)
		}
		return validateSpecForContainer(oldSpec, newSpec, cName)
	}

	return nil
}

// RestoreValidateSpec deals with spec validation according to the given policy during restore.
func RestoreValidateSpec(oldSpecs, newSpecs map[string]*specs.Spec, conf *config.Config) error {
	switch conf.RestoreSpecValidation {
	case config.RestoreSpecValidationIgnore:
		return nil
	case config.RestoreSpecValidationWarning:
		// Log a warning if the spec validation fails.
		if err := validateSpecs(oldSpecs, newSpecs); err != nil {
			log.Warningf("Failed to validate restore spec (ignoring error as per configuration): %v", err)
		}
	case config.RestoreSpecValidationEnforce:
		// Restoring containers will be aborted if spec validation fails.
		if err := validateSpecs(oldSpecs, newSpecs); err != nil {
			return fmt.Errorf("failed to validate restore spec: %w", err)
		}
	default:
		return fmt.Errorf("invalid option for restore spec validation %d", conf.RestoreSpecValidation)
	}
	return nil
}
