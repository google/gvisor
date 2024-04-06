// Copyright 2024 The gVisor Authors.
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

// Package vllm_test runs vLLM and generates some text with it.
package vllm_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/mount"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
)

const (
	// vertexModelGardenBucket is the public GCS bucket for Vertex Model Garden.
	vertexModelGardenBucket = "gs://vertex-model-garden-public-us-central1"
)

// requestVLLM sends an HTTP request to the vLLM model server.
func requestVLLM(ctx context.Context, t *testing.T, vllmCont *dockerutil.Container, method, endpoint, postData string) (string, error) {
	const (
		vllmHost = "vllm"
		vllmPort = 7080
	)
	cmd := []string{
		"httpclient",
		fmt.Sprintf("--method=%s", method),
		fmt.Sprintf("--url=http://%s:%d%s", vllmHost, vllmPort, endpoint),
	}
	if method == "POST" {
		cmd = append(cmd, fmt.Sprintf("--post_base64=%s", base64.StdEncoding.EncodeToString([]byte(postData))))
	}
	if ctxDeadline, hasDeadline := ctx.Deadline(); hasDeadline {
		cmd = append(cmd, fmt.Sprintf("--timeout=%v", time.Until(ctxDeadline)))
	}
	out, err := dockerutil.MakeContainer(ctx, t).Run(ctx, dockerutil.RunOpts{
		Image: "gpu/ollama/client",
		Links: []string{vllmCont.MakeLink(vllmHost)},
	}, cmd...)
	if err != nil {
		if out != "" {
			return out, fmt.Errorf("command %q failed (%w): %v", strings.Join(cmd, " "), err, out)
		}
		return "", fmt.Errorf("could not run command %q: %w", strings.Join(cmd, " "), err)
	}
	return out, nil
}

// TestVLLM tests the vLLM model server. Requires gcsfuse to be installed.
func TestVLLM(t *testing.T) {
	ctx := context.Background()
	gcloudPath, err := exec.LookPath("gcloud")
	if err != nil {
		t.Fatalf("This test requires gcloud to be installed: %v", err)
	}
	tmpDir, err := os.MkdirTemp(os.TempDir(), fmt.Sprintf("%s-models-*", t.Name()))
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	modelDir := filepath.Join(tmpDir, "model")
	for _, modelPath := range []string{"llama2/llama2-7b-hf"} {
		modelName := filepath.Base(modelPath)
		t.Run(modelName, func(t *testing.T) {
			if err := os.MkdirAll(modelDir, 0755); err != nil {
				t.Fatalf("Failed to create model dir: %v", err)
			}
			defer os.RemoveAll(modelDir)
			copyCtx, copyCancel := context.WithTimeout(ctx, 5*time.Minute)
			defer copyCancel()
			bucketSource := fmt.Sprintf("%s/%s/*", vertexModelGardenBucket, modelPath)
			if err := exec.CommandContext(copyCtx, gcloudPath, "storage", "cp", bucketSource, modelDir).Run(); err != nil {
				t.Fatalf("Failed to copy model from GCS %s: %v", bucketSource, err)
			}
			vllmCont := dockerutil.MakeContainer(ctx, t)
			defer vllmCont.CleanUp(ctx)
			defer func() {
				if vllmLogs, err := vllmCont.Logs(ctx); err == nil {
					t.Logf("vLLM logs:\n%s", vllmLogs)
				}
			}()
			opts := dockerutil.GPURunOpts()
			opts.Image = "gpu/vllm"
			opts.Mounts = append(opts.Mounts, mount.Mount{
				Type:     mount.TypeBind,
				Source:   modelDir,
				Target:   "/model",
				ReadOnly: true,
			})
			if err := vllmCont.Spawn(ctx, opts); err != nil {
				t.Fatalf("could not start vLLM: %v", err)
			}
			t.Log("Starting vLLM...")
			startupCtx, startupCancel := context.WithTimeout(ctx, 5*time.Minute)
			defer startupCancel()
			var lastStartupErr error
			for startupCtx.Err() == nil {
				if _, err := requestVLLM(startupCtx, t, vllmCont, "GET", "/", ""); lastStartupErr == nil || ctx.Err() == nil {
					lastStartupErr = err
				}
				if vllmStatus, err := vllmCont.Status(ctx); err != nil {
					t.Fatalf("Failed to get vLLM container status: %v", err)
				} else if !vllmStatus.Running {
					t.Fatalf("vLLM container is no longer running: %v", vllmStatus)
				}
				if lastStartupErr == nil {
					break
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(10 * time.Millisecond):
				}
			}
			if lastStartupErr != nil {
				t.Fatalf("Failed to start vLLM: %v", lastStartupErr)
			}
			t.Log("vLLM started, issuing query...")
			promptCtx, promptCancel := context.WithTimeout(ctx, 5*time.Minute)
			defer promptCancel()
			response, err := requestVLLM(promptCtx, t, vllmCont, "POST", "/generate", `{
				"n": 1,
				"prompt": "What is the meaning of life?",
				"stream": true,
				"temperature": 0.0,
				"top_p": 1.0
			}`)
			if err != nil {
				t.Fatalf("Failed to get prompt response from vLLM: %v", err)
			}
			t.Logf("vLLM response: %v", response)
		})
	}
}
