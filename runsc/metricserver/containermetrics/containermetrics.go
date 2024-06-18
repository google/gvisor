// Copyright 2023 The gVisor Authors.
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

// Package containermetrics returns metrics and labels interesting to export
// about a container or sandbox.
package containermetrics

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
	"strconv"

	"gvisor.dev/gvisor/pkg/prometheus"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/specutils"
)

// SandboxPrometheusLabels returns a set of Prometheus labels that identifies the sandbox running
// the given root container.
func SandboxPrometheusLabels(rootContainer *container.Container) (map[string]string, error) {
	s := rootContainer.Sandbox
	labels := make(map[string]string, 4)
	labels[prometheus.SandboxIDLabel] = s.ID

	// Compute iteration ID label in a stable manner.
	// This uses sha256(ID + ":" + creation time).
	h := sha256.New()
	if _, err := io.WriteString(h, s.ID); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(h, ":"); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(h, rootContainer.CreatedAt.UTC().String()); err != nil {
		return nil, err
	}
	labels[prometheus.IterationIDLabel] = strconv.FormatUint(binary.BigEndian.Uint64(h.Sum(nil)[:8]), 36)

	if s.PodName != "" {
		labels[prometheus.PodNameLabel] = s.PodName
	}
	if s.Namespace != "" {
		labels[prometheus.NamespaceLabel] = s.Namespace
	}
	return labels, nil
}

// ComputeSpecMetadata returns the labels for the `spec_metadata` metric.
// It merges data from the Specs of multiple containers running within the
// same sandbox.
// This function must support being called with `allContainers` being nil.
// It must return the same set of label keys regardless of how many containers
// are in `allContainers`.
func ComputeSpecMetadata(allContainers []*container.Container) map[string]string {
	const (
		unknownOCIVersion      = "UNKNOWN"
		inconsistentOCIVersion = "INCONSISTENT"
	)

	hasUID0Container := false
	ociVersion := unknownOCIVersion
	hasNVProxy := false
	hasTPUProxy := false
	for _, cont := range allContainers {
		if cont.RunsAsUID0() {
			hasUID0Container = true
		}
		if ociVersion == unknownOCIVersion {
			ociVersion = cont.Spec.Version
		} else if ociVersion != cont.Spec.Version {
			ociVersion = inconsistentOCIVersion
		}
		hasNVProxy = hasNVProxy || cont.Spec.Annotations[specutils.AnnotationNVProxy] == "true"
		hasTPUProxy = hasTPUProxy || cont.Spec.Annotations[specutils.AnnotationTPU] == "true"
	}
	return map[string]string{
		"hasuid0":    strconv.FormatBool(hasUID0Container),
		"ociversion": ociVersion,
		"nvproxy":    strconv.FormatBool(hasNVProxy),
		"tpuproxy":   strconv.FormatBool(hasTPUProxy),
	}
}
