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

// Package driver implements tests for driver version compatibility.
package driver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/prototext"
	cospb "gvisor.dev/gvisor/test/gpu/gpu_driver_versions_go_proto"
	"gvisor.dev/gvisor/test/kubernetes/k8sctx"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
	v13 "k8s.io/api/core/v1"
)

var unsupportedGPUs = map[string]any{
	"NVIDIA_TESLA_V100": true,
	"NVIDIA_TESLA_P100": true,
	"NVIDIA_TESLA_P4":   true,
	"OTHERS":            true,
	"NO_GPU":            true,
}

// RunDriverVersion tests that all driver versions the cluster version are compatible with
// the runsc version.
func RunDriverVersion(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster) {
	ns := cluster.Namespace(testcluster.NamespaceDefault)
	image, err := k8sCtx.ResolveImage(ctx, "alpine")
	if err != nil {
		t.Fatalf("Failed to resolve image: %v", err)
	}

	runscSupportedDrivers, err := getRunscDriverInfo(ctx, ns, cluster, image)
	if err != nil {
		t.Fatalf("Failed to get runsc supported drivers: %v", err)
	}

	cosDriverVersions, err := getCOSDrivers(ctx, ns, cluster, image)
	if err != nil {
		t.Fatalf("Failed to get COS driver versions: %v", err)
	}

	for _, info := range cosDriverVersions.GetGpuDriverVersionInfo() {
		if _, ok := unsupportedGPUs[info.GetGpuDevice().GetGpuType()]; ok {
			continue
		}
		t.Run(info.GetGpuDevice().GetGpuType(), func(t *testing.T) {
			for _, driver := range info.GetSupportedDriverVersions() {
				switch driver.GetLabel() {
				case "LATEST":
				case "DEFAULT":
				default:
					continue
				}

				if _, ok := runscSupportedDrivers[driver.GetVersion()]; !ok {
					t.Errorf("Driver version %v is not supported by runsc", driver)
				}
			}
		})
	}
}

func getRunscDriverInfo(ctx context.Context, ns *testcluster.Namespace, cluster *testcluster.TestCluster, image string) (map[string]any, error) {
	const runtimePath = "/home/containerd/usr/local/sbin/runsc"
	pod := ns.NewAlpinePod(fmt.Sprintf("hello-%d", time.Now().UnixNano()), image, []string{})
	pod, err := cluster.ConfigurePodForRuntimeTestNodepool(ctx, pod)
	if err != nil {
		return nil, fmt.Errorf("failed to set pod on cluster %q: %v", cluster.GetName(), err)
	}

	pod.Spec.RuntimeClassName = nil
	pod.Spec.Tolerations = append(pod.Spec.Tolerations, cluster.GetGVisorRuntimeToleration())

	pod.Spec.Volumes = append(pod.Spec.Volumes, v13.Volume{
		Name: "runsc",
		VolumeSource: v13.VolumeSource{
			HostPath: &v13.HostPathVolumeSource{
				Path: runtimePath,
				Type: new(v13.HostPathType),
			},
		},
	})

	container := v13.Container{
		Name:    "runsc",
		Image:   image,
		Command: []string{"./runsc", "nvproxy", "list-supported-drivers"},
		VolumeMounts: []v13.VolumeMount{
			{
				Name:      "runsc",
				MountPath: "runsc",
				ReadOnly:  false,
			},
		},
	}

	pod.Spec.Containers = []v13.Container{container}
	pod, err = cluster.CreatePod(ctx, pod)
	if err != nil {
		return nil, fmt.Errorf("failed to create pod on cluster %q: %v", cluster.GetName(), err)
	}
	defer cluster.DeletePod(ctx, pod)
	if err := cluster.WaitForPodCompleted(ctx, pod); err != nil {
		return nil, fmt.Errorf("failed to wait for pod on cluster %q: %v", cluster.GetName(), err)
	}
	reader, err := cluster.GetLogReader(ctx, pod, v13.PodLogOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get log reader on cluster %q: %v", cluster.GetName(), err)
	}
	defer reader.Close()

	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, reader); err != nil {
		return nil, fmt.Errorf("failed to read log on cluster %q: %v", cluster.GetName(), err)
	}
	versions := make(map[string]any)
	for _, v := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		versions[v] = true
	}
	if len(versions) == 0 {
		return nil, fmt.Errorf("no driver versions found in log: %s", buf.String())
	}
	return versions, nil
}

func getCOSDrivers(ctx context.Context, ns *testcluster.Namespace, cluster *testcluster.TestCluster, image string) (*cospb.GPUDriverVersionInfoList, error) {
	const cosExtensionsPath = "/etc/cos-package-info.json"
	const cosExtensions = "cos-extensions"
	pod := ns.NewAlpinePod(fmt.Sprintf("cos-%d", time.Now().UnixNano()), image, []string{})
	pod, err := cluster.ConfigurePodForRuntimeTestNodepool(ctx, pod)
	if err != nil {
		return nil, fmt.Errorf("failed to set pod on cluster %q: %v", cluster.GetName(), err)
	}
	pod.Spec.RuntimeClassName = nil
	pod.Spec.Tolerations = append(pod.Spec.Tolerations, cluster.GetGVisorRuntimeToleration())

	file := v13.HostPathType(v13.HostPathFile)
	pod.Spec.Volumes = append(pod.Spec.Volumes, v13.Volume{
		Name: "host",
		VolumeSource: v13.VolumeSource{
			HostPath: &v13.HostPathVolumeSource{
				Path: cosExtensionsPath,
				Type: &file,
			},
		},
	})

	container := v13.Container{
		Name:    cosExtensions,
		Image:   image,
		Command: []string{"cat", cosExtensionsPath},
		VolumeMounts: []v13.VolumeMount{
			{
				Name:      "host",
				MountPath: cosExtensionsPath,
				ReadOnly:  true,
			},
		},
	}
	pod.Spec.Containers = []v13.Container{container}
	pod, err = cluster.CreatePod(ctx, pod)
	if err != nil {
		return nil, fmt.Errorf("failed to create pod on cluster %q: %v", cluster.GetName(), err)
	}
	defer cluster.DeletePod(ctx, pod)
	if err := cluster.WaitForPodCompleted(ctx, pod); err != nil {
		return nil, fmt.Errorf("failed to wait for pod on cluster %q: %v", cluster.GetName(), err)
	}
	reader, err := cluster.GetLogReader(ctx, pod, v13.PodLogOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get log reader on cluster %q: %v", cluster.GetName(), err)
	}
	defer reader.Close()
	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, reader); err != nil {
		return nil, fmt.Errorf("failed to read log on cluster %q: %v", cluster.GetName(), err)
	}

	cosVersion, err := extractCosVersion(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to extract COS version: %v", err)
	}
	return getCOSDriverFromReleaseVersion(cosVersion)

}

func extractCosVersion(content *bytes.Buffer) (string, error) {
	cosMap := make(map[string]any)
	if err := json.Unmarshal(content.Bytes(), &cosMap); err != nil {
		return "", fmt.Errorf("failed to unmarshal cos-extensions: %v", err)
	}

	packages := cosMap["installedPackages"]
	pkgs, ok := packages.([]any)
	if !ok {
		return "", fmt.Errorf("cos-extensions not found in cos-extensions: %v", packages)
	}

	pkg, ok := pkgs[0].(map[string]any)
	if !ok {
		return "", fmt.Errorf("cos-extensions not found in cos-extensions: %v", pkgs)
	}

	version, ok := pkg["version"].(string)
	if !ok {
		return "", fmt.Errorf("version not found in cos-extensions: %v", pkg)
	}

	return version, nil
}

func getCOSDriverFromReleaseVersion(cosVersion string) (*cospb.GPUDriverVersionInfoList, error) {
	// Each entry on the COS release list has a corresponding textproto file with the list of GPU
	// driver versions supported in that release.
	// See: https://cloud.google.com/container-optimized-os/docs/release-notes
	url := fmt.Sprintf("https://storage.googleapis.com/cos-tools/%s/lakitu/gpu_driver_versions.textproto", cosVersion)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get driver versions for release %q: %w", cosVersion, err)
	}
	defer resp.Body.Close()

	var content []byte

	switch {
	case resp.StatusCode == 404:
		// When COS versions are newly released, they will often show up in projects but not the release
		// page. In this case, we return an empty list of driver versions.
		content = []byte("gpu_driver_version_info: []")
	default:
		content, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read driver versions for release %q: %w", cosVersion, err)
		}
	}

	list := cospb.GPUDriverVersionInfoList{}
	if err := prototext.Unmarshal(content, &list); err != nil {
		return nil, fmt.Errorf("failed to unmarshal driver versions: %v", err)
	}

	return &list, nil
}
