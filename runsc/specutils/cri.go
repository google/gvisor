package specutils

import (
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const (
	// ContainerdContainerTypeAnnotation is the OCI annotation set by
	// containerd to indicate whether the container to create should have
	// its own sandbox or a container within an existing sandbox.
	ContainerdContainerTypeAnnotation = "io.kubernetes.cri.container-type"
	// ContainerdContainerTypeContainer is the container type value
	// indicating the container should be created in an existing sandbox.
	ContainerdContainerTypeContainer = "container"
	// ContainerdContainerTypeSandbox is the container type value
	// indicating the container should be created in a new sandbox.
	ContainerdContainerTypeSandbox = "sandbox"

	// ContainerdSandboxIDAnnotation is the OCI annotation set to indicate
	// which sandbox the container should be created in when the container
	// is not the first container in the sandbox.
	ContainerdSandboxIDAnnotation = "io.kubernetes.cri.sandbox-id"


	// CRIOContainerTypeAnnotation is the OCI annotation set by
	// CRI-O to indicate whether the container to create should have
	// its own sandbox or a container within an existing sandbox.
	CRIOContainerTypeAnnotation = "io.kubernetes.cri-o.ContainerType"

	// CRIOContainerTypeContainer is the container type value
	// indicating the container should be created in an existing sandbox.
	CRIOContainerTypeContainer = "container"
	// CRIOContainerTypeSandbox is the container type value
	// indicating the container should be created in a new sandbox.
	CRIOContainerTypeSandbox = "sandbox"

	// CRIOSandboxIDAnnotation is the OCI annotation set to indicate
	// which sandbox the container should be created in when the container
	// is not the first container in the sandbox.
	CRIOSandboxIDAnnotation = "io.kubernetes.cri-o.SandboxID"
)

// ContainerType represents the type of container requested by the calling container manager.
type ContainerType int

const (
	// ContainerTypeUnspecified indicates that no known container type
	// annotation was found in the spec.
	ContainerTypeUnspecified ContainerType = iota
	// ContainerTypeUnknown indicates that a container type was specified
	// but is unknown to us.
	ContainerTypeUnknown
	// ContainerTypeSandbox indicates that the container should be run in a
	// new sandbox.
	ContainerTypeSandbox
	// ContainerTypeContainer indicates that the container should be run in
	// an existing sandbox.
	ContainerTypeContainer
)

// SpecContainerType tries to determine the type of container specified by the
// container manager using well-known container annotations.
func SpecContainerType(spec *specs.Spec) ContainerType {
	if t, ok := spec.Annotations[ContainerdContainerTypeAnnotation]; ok {
		switch t {
		case ContainerdContainerTypeSandbox:
			return ContainerTypeSandbox
		case ContainerdContainerTypeContainer:
			return ContainerTypeContainer
		default:
			return ContainerTypeUnknown
		}
	}
	if t, ok := spec.Annotations[CRIOContainerTypeAnnotation]; ok {
		switch t {
		case CRIOContainerTypeSandbox:
			return ContainerTypeSandbox
		case CRIOContainerTypeContainer:
			return ContainerTypeContainer
		default:
			return ContainerTypeUnknown
		}
	}
	return ContainerTypeUnspecified
}

// SandboxID returns the ID of the sandbox to join and whether an ID was found
// in the spec.
func SandboxID(spec *specs.Spec) (string, bool) {
	if id, ok := spec.Annotations[ContainerdSandboxIDAnnotation]; ok {
		return id, true
	}
	if id, ok := spec.Annotations[CRIOSandboxIDAnnotation]; ok {
		return id, true
	}
	return "", false
}
