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
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/test/gpu/sglang"
)

//go:embed gvisor.png
var gVisorPNG []byte

// extractCode extracts code between two code block markers.
func extractCode(response, codeBlockDelim string) (string, error) {
	if !strings.Contains(response, codeBlockDelim) {
		return "", fmt.Errorf("no marker string %q", codeBlockDelim)
	}
	var codeLines []string
	isCodeBlock := false
	for _, line := range strings.Split(response, "\n") {
		if strings.HasPrefix(line, codeBlockDelim) {
			isCodeBlock = !isCodeBlock
		} else if isCodeBlock {
			codeLines = append(codeLines, line)
		}
	}
	if isCodeBlock {
		return "", errors.New("non-terminated code block")
	}
	if len(codeLines) == 0 {
		return "", errors.New("no or empty code block")
	}
	return strings.Join(codeLines, "\n") + "\n", nil
}

// runSandboxedPython runs the given Python code in a sandboxed container.
func runSandboxedPython(ctx context.Context, logger testutil.Logger, code string) (string, error) {
	return dockerutil.MakeContainer(ctx, logger).Run(ctx, dockerutil.RunOpts{
		Image:       "basic/python",
		NetworkMode: "none",
		Entrypoint:  []string{"python3"},
		Env:         []string{"PYTHONUTF8=1"},
	}, "-c", code)
}

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

	// Query it.
	t.Run("translate text", func(t *testing.T) {
		prompt := sglang.Prompt{
			Text: `
				What is the capital of Turkey?
			`,
		}
		prompt.SetTemperature(0.0)
		var answer string
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
		answer = strings.TrimSpace(response.Text())
		t.Logf("The response to %q is: %q", prompt.Text, answer)
	})
	if t.Failed() {
		return
	}
	t.Run("generate test case", func(t *testing.T) {
		const (
			markerString   = "FOOBARBAZQUUX"
			hello          = "你好"
			world          = "世界"
			codeBlockDelim = "```"
			translation    = "Hello World in Chinese is 你好世界"
		)
		promptCtx, promptCancel := context.WithTimeout(ctx, 5*time.Minute)
		prompt := sglang.Prompt{
			Text: fmt.Sprintf(`
				Generate a Python function that takes a string and verifies that it
				is a valid Chinese translation of the English phrase "Hello World".
				The function should first turn its input into lowercase in order to
				match case-insensitively, and remove all spaces.
				Then, the function should verify that the phrase contains at least
				"你好" ("hello") or "世界" ("world").
				If the verification succeeds, the function should return True.
				After this function is defined, you should call this function with
				the input string %q.
				Then, the code should verify that the function call returned True.
				If it did, the code should print "Verification succeeded";
				otherwise, it should print "Verification failed".
				You may use Python code comments, but do not otherwise explain how
				the code works and do not provide usage examples.
				Output a single block of Python code wrapped between %q marks.
			`, markerString, codeBlockDelim),
		}
		prompt.SetTemperature(0.0)
		response, err := llm.PromptUntil(promptCtx, &prompt, func(prompt *sglang.Prompt, response *sglang.Response) (*sglang.Prompt, error) {
			defer prompt.RaiseTemperature()
			pythonCode, err := extractCode(response.Text(), codeBlockDelim)
			if err != nil {
				return prompt, fmt.Errorf("code extraction failed: %w", err)
			}
			if !strings.Contains(pythonCode, markerString) {
				return prompt, fmt.Errorf("marker string %q is not in a code block", markerString)
			}
			out, err := runSandboxedPython(ctx, t, pythonCode)
			if err != nil {
				return prompt, fmt.Errorf("execution with marker string failed: %w", err)
			}
			out = strings.TrimSpace(out)
			if out == "" {
				return prompt, fmt.Errorf("execution with marker string %q had no output", markerString)
			}
			if out == "Verification succeeded" {
				return prompt, fmt.Errorf("verification did not fail for marker string %q (we expected it to fail for this string): got output %q", markerString, out)
			}
			if out != "Verification failed" {
				return prompt, fmt.Errorf("verification program returned unexpected output %q for marker string %q", out, markerString)
			}
			for _, word := range []string{hello, world} {
				codeWithRealText := strings.ReplaceAll(pythonCode, markerString, fmt.Sprintf("asdf %s fdsa", word))
				out, err = runSandboxedPython(ctx, t, codeWithRealText)
				if err != nil {
					return prompt, fmt.Errorf("execution with word %q failed: %w", word, err)
				}
				out = strings.TrimSpace(out)
				if out == "" {
					return prompt, fmt.Errorf("execution with word %q had no output", word)
				}
				if out != "Verification succeeded" {
					return prompt, fmt.Errorf("verification with word %q failed: got output %q", word, out)
				}
			}
			return nil, nil
		})
		promptCancel()
		if err != nil {
			t.Fatalf("Code generation prompt failed: %v", err)
		}
		pythonCode, err := extractCode(response.Text(), codeBlockDelim)
		if err != nil {
			t.Fatalf("Code extraction failed: %v", err)
		}
		testCode := strings.ReplaceAll(pythonCode, markerString, translation)
		out, err := runSandboxedPython(ctx, t, testCode)
		if err != nil {
			t.Fatalf("Translation verification with string %q failed: %v\nCode used:\n\n%s\n\n", translation, err, testCode)
		}
		out = strings.TrimSpace(out)
		if out != "Verification succeeded" {
			t.Fatalf("Translation verification with string %q failed: %q\nCode used:\n\n%s\n\n", translation, out, testCode)
		}
		t.Logf("Translation verification succeeded with code:\n\n%s\n\n", pythonCode)
	})
}
