// Copyright 2024 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package cos_gpu_compatibility_test checks the latest COS images' GPU drivers for
// gVisor compatibility.
package cos_gpu_compatibility_test

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/prototext"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
	cospb "gvisor.dev/gvisor/test/gpu/gpu_driver_versions_go_proto"
)

var (
	imageJSON          = flag.String("image_json", "", "Path to file containing the list of COS images")
	unsupportedDevices = map[string]any{
		"NVIDIA_TESLA_V100": true,
		"NVIDIA_TESLA_P100": true,
		"NVIDIA_TESLA_P4":   true,
		"NO_GPU":            true,
	}
)

func TestGPUDriversCompatibility(t *testing.T) {
	content, err := os.ReadFile(*imageJSON)
	if err != nil {
		t.Fatalf("Failed to read image JSON file: %v", err)
	}
	images := []map[string]any{}
	if err := json.Unmarshal(content, &images); err != nil {
		t.Fatalf("Failed to unmarshal image JSON file: %v", err)
	}

	executedTests := 0

	for _, image := range images {
		name := image["name"].(string)
		family := image["family"].(string)

		t.Run(fmt.Sprintf("%s", name), func(t *testing.T) {
			cosBranch, version, err := imageNameToCosPatchVersion(name, family)
			if err != nil {
				t.Fatalf("Failed to convert image name to COS version: %v", err)
			}

			if cosBranch < 109 {
				// As of writing, GKE is only on cos-109 and above.
				t.Skipf("Skipping COS branch %d image: %q family: %q", cosBranch, name, family)
			}

			driverVersions, err := listedDriverVersions(version)
			if err != nil {
				t.Fatalf("Failed to get listed driver versions: %v", err)
			}

			list := cospb.GPUDriverVersionInfoList{}
			if err := prototext.Unmarshal(driverVersions, &list); err != nil {
				t.Fatalf("Failed to unmarshal driver versions: %v", err)
			}

			supportedDrivers := map[string]bool{}
			for _, driver := range nvproxy.SupportedDrivers() {
				supportedDrivers[driver.String()] = true
			}

			for _, info := range list.GetGpuDriverVersionInfo() {
				if _, ok := unsupportedDevices[info.GetGpuDevice().GetGpuType()]; ok {
					continue
				}

				for _, driver := range info.GetSupportedDriverVersions() {
					switch strings.ToLower(driver.GetLabel()) {
					case "default":
					case "latest":
					default:
						continue
					}
					executedTests++
					if !supportedDrivers[driver.GetVersion()] {
						t.Errorf("Unsupported driver patch: %q gpu: %q version: %q", driver.GetVersion(), info.GetGpuDevice().GetGpuType(), driver.GetLabel())
						continue
					}
					t.Logf("Supported driver patch: %q gpu: %q version: %q", driver.GetVersion(), info.GetGpuDevice().GetGpuType(), driver.GetLabel())

				}
			}
		})
	}
	if !t.Failed() && executedTests <= 0 {
		t.Fatalf("No successful tests: check logs for details")
	}
}

func imageNameToCosPatchVersion(imageName string, family string) (int, string, error) {
	cosVersionRegex := regexp.MustCompile(`^cos-(?:arm64-)?(?:lm-)?(?:beta-|dev-|stable-)?(\d+)-(\d+)-(\d+)-(\d+)$`)
	matches := cosVersionRegex.FindStringSubmatch(imageName)
	if len(matches) != 5 {
		return 0, "", fmt.Errorf("image name %q does not match regex %q", imageName, cosVersionRegex.String())
	}
	cosBranch, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, "", fmt.Errorf("failed to convert COS branch to int: %w", err)
	}
	return cosBranch, fmt.Sprintf("%s.%s.%s", matches[2], matches[3], matches[4]), nil
}

// listedDriverVersions returns the list of GPU driver versions listed for the given COS version.
func listedDriverVersions(cosVersion string) ([]byte, error) {
	// Each entry on the COS release list has a corresponding textproto file with the list of GPU
	// driver versions supported in that release.
	// See: https://cloud.google.com/container-optimized-os/docs/release-notes
	url := fmt.Sprintf("https://storage.googleapis.com/cos-tools/%s/lakitu/gpu_driver_versions.textproto", cosVersion)
	resp, err := http.Get(url)
	// When COS versions are newly released, they will often show up in projects but not the release
	// page. In this case, we return an empty list of driver versions.
	if resp.StatusCode == 404 {
		resp.Body.Close()
		return []byte("gpu_driver_version_info: []"), nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get driver versions for release %q: %w", cosVersion, err)
	}
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}

func TestMain(m *testing.M) {
	flag.Parse()
	nvproxy.Init()
	os.Exit(m.Run())
}
