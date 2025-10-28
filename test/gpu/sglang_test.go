// Copyright 2023 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not- use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package sglang_test runs sglang and generates some text with it.
package sglang_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/gpu/sglang"
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
	llm, err := sglang.NewDocker(startCtx, llmContainer, t)
	startCancel()
	if err != nil {
		t.Fatalf("Failed to start sglang: %v", err)
	}

	t.Run("math test", func(t *testing.T) {
		prompt := sglang.Prompt{
			Text: `
				What is 1+17? Give me the answer without any wrapping text.
			`,
		}
		prompt.SetTemperature(0.0)
		promptCtx, promptCancel := context.WithTimeout(ctx, 5*time.Minute)
		response, err := llm.PromptUntil(promptCtx, &prompt, func(prompt *sglang.Prompt, response *sglang.Response) (*sglang.Prompt, error) {
			defer prompt.RaiseTemperature()
			text := strings.TrimSpace(response.Text())
			for _, acceptableWord := range []string{
				"18",
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
		t.Logf("The response to %q is: %q", prompt.Text, answer)
	})
	if t.Failed() {
		return
	}
	// Query it.
	t.Run("knowledge test", func(t *testing.T) {
		prompt := sglang.Prompt{
			Text: `
				What is the capital of Turkey? Give me one word answer.
				Do not include the country name in the answer.
			`,
		}
		prompt.SetTemperature(0.0)
		promptCtx, promptCancel := context.WithTimeout(ctx, 5*time.Minute)
		response, err := llm.PromptUntil(promptCtx, &prompt, func(prompt *sglang.Prompt, response *sglang.Response) (*sglang.Prompt, error) {
			defer prompt.RaiseTemperature()
			text := strings.TrimSpace(response.Text())
			for _, acceptableWord := range []string{
				"Ankara",
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
		t.Logf("The response to %q is: %q", prompt.Text, answer)
	})
	if t.Failed() {
		return
	}
}
