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

// Package triton_test runs triton and generates some text with it.
package triton_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/gpu/triton"
)

// TestLLM tests an LLM running in a sandboxed container.
// It first asks the capital of Turkey.
// Then it asks it to write a unit test that verifies that
// given text contains the "Hello World" in Chinese.
func TestLLM(t *testing.T) {
	ctx := context.Background()
	// Run the LLM.
	llmContainer := dockerutil.MakeContainer(ctx, t)
	defer llmContainer.CleanUp(ctx)
	startCtx, startCancel := context.WithTimeout(ctx, 5*time.Minute)
	llm, err := triton.NewDocker(startCtx, llmContainer, t)
	startCancel()
	if err != nil {
		t.Fatalf("Failed to start triton: %v", err)
	}

	// Query it.
	t.Run("knowledge test", func(t *testing.T) {
		prompt := triton.ZeroTemperaturePrompt("How many legs do cats have?", 500)
		promptCtx, promptCancel := context.WithTimeout(ctx, 5*time.Minute)
		response, err := llm.PromptUntil(promptCtx, prompt, func(prompt *triton.Prompt, response *triton.Response) (*triton.Prompt, error) {
			defer prompt.RaiseTemperature()
			text := strings.TrimSpace(response.Text())
			t.Logf("The response is: %q", text)
			for _, acceptableWord := range []string{
				"4",
			} {
				if strings.Contains(text, acceptableWord) {
					return prompt, nil
				}
			}
			return prompt, errors.New("text does not contain any of the expected words")
		})
		promptCancel()
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		answer := strings.TrimSpace(response.Text())
		t.Logf("The response to %q is: %q", prompt.TextInput, answer)
	})
	if t.Failed() {
		return
	}
	t.Run("math test", func(t *testing.T) {
		prompt := triton.ZeroTemperaturePrompt("What is 9 times 10?", 500)
		promptCtx, promptCancel := context.WithTimeout(ctx, 5*time.Minute)
		response, err := llm.PromptUntil(promptCtx, prompt, func(prompt *triton.Prompt, response *triton.Response) (*triton.Prompt, error) {
			defer prompt.RaiseTemperature()
			text := strings.TrimSpace(response.Text())
			t.Logf("The response is: %q", text)
			for _, acceptableWord := range []string{
				"90",
			} {
				if strings.Contains(text, acceptableWord) {
					return prompt, nil
				}
			}
			return prompt, errors.New("text does not contain any of the expected words")
		})
		promptCancel()
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		answer := strings.TrimSpace(response.Text())
		t.Logf("The response to %q is: %q", prompt.TextInput, answer)
	})
	if t.Failed() {
		return
	}
}
