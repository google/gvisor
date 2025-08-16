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

// Package cuda holds libraries for testing CUDA workloads.
package cuda

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

const (
	// defaultTestTimeout is the default timeout for a single CUDA sample test.
	defaultTestTimeout = 20 * time.Minute

	// hangingTestTimeout is the test timeout for tests that are fast when they
	// succeed, but hang forever otherwise.
	hangingTestTimeout = 1 * time.Minute

	// defaultContainersPerCPU is the default number of pooled containers to
	// spawn for each CPU. This can be a floating-point value.
	// This value was arrived at experimentally and has no particular meaning.
	// Setting it too low will cause the test to take longer than necessary
	// because of insufficient parallelism.
	// However, setting it too high will *also* cause the test to take longer
	// than necessary, because the added resource contention will cause more
	// tests to fail when run in parallel with each other, forcing them to be
	// re-run serialized.
	defaultContainersPerCPU = 1.75

	// exitCodeWaived is the EXIT_WAIVED constant used in CUDA tests.
	// This exit code is typically used by CUDA tests to indicate that the
	// test requires a capability or condition that is not met in the current
	// test environment.
	exitCodeWaived = 2
)

// Flags.
var (
	logSuccessfulTests = flag.Bool("cuda_log_successful_tests", false, "log console output of successful tests")
	debug              = flag.Bool("cuda_test_debug", false, "log more data as the test is running")
	containersPerCPU   = flag.Float64("cuda_containers_per_cpu", defaultContainersPerCPU, "number of parallel execution containers to spawn per CPU (floating point values allowed)")
)

// InitFlags parses the flags and sets the test.parallel flag to the desired
// parallelism.
func InitFlags() {
	flag.Parse()
	// The Go testing library won't run more than GOMAXPROCS parallel tests by
	// default, and the value of GOMAXPROCS is taken at program initialization
	// time, so by the time we get here, it is already stuck at GOMAXPROCS.
	// In order to run more parallel tests than there are cores, we therefore
	// need to override the `test.parallel` flag here before `m.Run`.
	testParallelFlag := flag.Lookup("test.parallel")
	if testParallelFlag == nil {
		panic("cannot find -test.parallel flag")
	}
	if err := testParallelFlag.Value.Set(strconv.Itoa(getDesiredTestParallelism())); err != nil {
		panic(fmt.Sprintf("cannot set -test.parallel flag: %v", err))
	}
}

// All CUDA features listed by /list_features.sh.
const (
	FeaturePersistentL2Caching Feature = "PERSISTENT_L2_CACHING"
	FeatureDynamicParallelism  Feature = "DYNAMIC_PARALLELISM"
	FeatureGL                  Feature = "GL"
	FeatureTensorCores         Feature = "TENSOR_CORES"
	FeatureCompressibleMemory  Feature = "COMPRESSIBLE_MEMORY"
	FeatureP2P                 Feature = "P2P"
)

// allFeatures is a list of all CUDA features above.
var allFeatures = []Feature{
	FeaturePersistentL2Caching,
	FeatureDynamicParallelism,
	FeatureGL,
	FeatureTensorCores,
	FeatureCompressibleMemory,
	FeatureP2P,
}

// Feature is a feature as listed by /list_features.sh.
type Feature string

// TestEnvironment represents the environment in which a sample test runs.
type TestEnvironment struct {
	NumGPUs         int
	RuntimeIsGVisor bool
	Features        map[Feature]bool
}

// GetEnvironment returns the environment in which a sample test runs.
func GetEnvironment(ctx context.Context, t *testing.T, image string) (*TestEnvironment, error) {
	numGPU := dockerutil.NumGPU()
	if numGPU == 0 {
		return nil, errors.New("no GPUs detected")
	}
	if numGPU == 1 {
		testLog(t, "1 GPU detected")
	} else {
		testLog(t, "%d GPUs detected", numGPU)
	}
	runtimeIsGVisor, err := dockerutil.IsGVisorRuntime(ctx, t)
	if err != nil {
		return nil, fmt.Errorf("cannot determine if runtime is gVisor or not: %w", err)
	}
	if runtimeIsGVisor {
		testLog(t, "Runtime is detected as gVisor")
		runtimeArgs, err := dockerutil.RuntimeArgs()
		if err != nil {
			t.Fatalf("Failed to get runtime arguments: %v", err)
		}
		foundNVCaps := ""
		const nvCapsPrefixFlag = "--nvproxy-allowed-driver-capabilities"
		for i, arg := range runtimeArgs {
			if strings.HasPrefix(arg, nvCapsPrefixFlag+"=") {
				foundNVCaps = strings.TrimPrefix(arg, nvCapsPrefixFlag+"=")
			} else if arg == "--nvproxy-allowed-driver-capabilities" && i < len(runtimeArgs)-1 {
				foundNVCaps = runtimeArgs[i+1]
			}
		}
		if foundNVCaps == "" {
			return nil, fmt.Errorf("did not find --nvproxy-allowed-driver-capabilities=all flag in gVisor runtime arguments, please specify it for this test")
		}
		if foundNVCaps != "all" {
			return nil, fmt.Errorf("found --nvproxy-allowed-driver-capabilities=%q flag in gVisor runtime arguments, please specify --nvproxy-allowed-driver-capabilities=all for this test", foundNVCaps)
		}
	} else {
		testLog(t, "Runtime is detected as non-gVisor")
	}
	featuresContainer := dockerutil.MakeContainer(ctx, t)
	defer featuresContainer.CleanUp(ctx)
	runOpts, err := getContainerOpts(image)
	if err != nil {
		return nil, fmt.Errorf("failed to get container options: %w", err)
	}
	featuresList, err := featuresContainer.Run(ctx, runOpts, "/list_features.sh")
	if err != nil {
		return nil, fmt.Errorf("cannot get list of CUDA features: %v", err)
	}
	features := make(map[Feature]bool)
	for _, line := range strings.Split(featuresList, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "//") {
			testLog(t, "/list_features.sh: %s", line)
			continue
		}
		featureAvailable := false
		var feature Feature
		if strings.HasPrefix(line, "PRESENT: ") {
			featureAvailable = true
			feature = Feature(strings.TrimPrefix(line, "PRESENT: "))
		} else if strings.HasPrefix(line, "ABSENT: ") {
			featureAvailable = false
			feature = Feature(strings.TrimPrefix(line, "ABSENT: "))
		} else {
			return nil, fmt.Errorf("unexpected CUDA feature line: %q", line)
		}
		found := false
		for _, f := range allFeatures {
			if feature == f {
				features[f] = featureAvailable
				if featureAvailable {
					testLog(t, "CUDA feature is available: %s", string(f))
				} else {
					testLog(t, "CUDA feature is *not* available: %s", string(f))
				}
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown CUDA feature: %s", string(feature))
		}
	}
	for _, feature := range allFeatures {
		if _, ok := features[feature]; !ok {
			return nil, fmt.Errorf("CUDA feature not found in feature list: %s", string(feature))
		}
	}
	// Use CUDA dynamic parallelism as a litmus test to see if the features were
	// enumerated correctly.
	if _, hasDynamicParallelism := features[FeatureDynamicParallelism]; !hasDynamicParallelism {
		return nil, errors.New("CUDA feature Dynamic Parallelism is not available yet should be available in all environments gVisor supports; this indicates a failure in the feature listing script")
	}
	return &TestEnvironment{
		NumGPUs:         numGPU,
		RuntimeIsGVisor: runtimeIsGVisor,
		Features:        features,
	}, nil
}

// Compatibility encodes the compatibility of a test depending on the
// environment it runs in.
type Compatibility interface {
	// WillFail returns a string explaining why the test is expected to fail
	// in the given environment, or "" if it isn't expected to fail.
	WillFail(ctx context.Context, env *TestEnvironment) string

	// IsExpectedFailure checks whether the `logs` (from a failed run of the test
	// in the given environment) matches the failure that this test expects in
	// that environment. If they match, this function should return nil.
	// It is only called when `WillFail` returns a non-empty string for the same
	// environment, so it may assume that `env` is non-compatible.
	IsExpectedFailure(ctx context.Context, env *TestEnvironment, logs string, exitCode int) error
}

// BrokenEverywhere implements `Compatibility` for tests that are broken in
// all environments.
type BrokenEverywhere struct {
	Reason string
}

// WillFail implements `Compatibility.WillFail`.
func (be *BrokenEverywhere) WillFail(ctx context.Context, env *TestEnvironment) string {
	return fmt.Sprintf("Known-broken test: %v", be.Reason)
}

// IsExpectedFailure implements `Compatibility.IsExpectedFailure`.
func (*BrokenEverywhere) IsExpectedFailure(ctx context.Context, env *TestEnvironment, logs string, exitCode int) error {
	return nil
}

// BrokenInGVisor implements `Compatibility` for tests that are broken in
// gVisor only.
type BrokenInGVisor struct {
	// OnlyWhenMultipleGPU may be set to true for tests which only fail when
	// multiple GPUs are present. This should not be used for tests that
	// *require* multiple GPUs to run (use RequiresMultiGPU instead).
	// This is for tests that can run on a single or multiple GPUs alike,
	// but specifically fail in gVisor when run with multiple GPUs.
	OnlyWhenMultipleGPU bool
}

// WillFail implements `Compatibility.WillFail`.
func (big *BrokenInGVisor) WillFail(ctx context.Context, env *TestEnvironment) string {
	if !env.RuntimeIsGVisor {
		return ""
	}
	if big.OnlyWhenMultipleGPU && env.NumGPUs == 1 {
		return ""
	}
	if big.OnlyWhenMultipleGPU {
		return "Known to be broken in gVisor when multiple GPUs are present"
	}
	return "Known to be broken in gVisor"
}

// IsExpectedFailure implements `Compatibility.IsExpectedFailure`.
func (*BrokenInGVisor) IsExpectedFailure(ctx context.Context, env *TestEnvironment, logs string, exitCode int) error {
	return nil
}

// RequiresMultiGPU implements `Compatibility` for tests that require multiple
// GPUs.
type RequiresMultiGPU struct{}

// WillFail implements `Compatibility.WillFail`.
func (*RequiresMultiGPU) WillFail(ctx context.Context, env *TestEnvironment) string {
	if env.NumGPUs < 2 {
		return "Requires >= 2 GPUs"
	}
	return ""
}

// IsExpectedFailure implements `Compatibility.IsExpectedFailure`.
func (*RequiresMultiGPU) IsExpectedFailure(ctx context.Context, env *TestEnvironment, logs string, exitCode int) error {
	if exitCode != exitCodeWaived {
		return fmt.Errorf("exit code %d, expected EXIT_WAIVED (%d)", exitCode, exitCodeWaived)
	}
	return nil
}

// RequiresP2P implements `Compatibility` for tests that require
// peer-to-peer communication between GPUs.
// Implies RequiresMultiGPU, so tests do not need to specify both.
type RequiresP2P struct{}

// WillFail implements `Compatibility.WillFail`.
func (*RequiresP2P) WillFail(ctx context.Context, env *TestEnvironment) string {
	if notEnoughGPUs := (&RequiresMultiGPU{}).WillFail(ctx, env); notEnoughGPUs != "" {
		return notEnoughGPUs
	}
	if hasP2P := env.Features[FeatureP2P]; !hasP2P {
		return "Requires P2P support"
	}
	return ""
}

// IsExpectedFailure implements `Compatibility.IsExpectedFailure`.
func (*RequiresP2P) IsExpectedFailure(ctx context.Context, env *TestEnvironment, logs string, exitCode int) error {
	if err := (&RequiresMultiGPU{}).IsExpectedFailure(ctx, env, logs, exitCode); err == nil {
		return nil
	}
	const wantLog = "Peer to Peer access is not available amongst GPUs in the system, waiving test"
	if strings.Contains(logs, wantLog) {
		return nil
	}
	return fmt.Errorf("exit code %d and logs %q, expected EXIT_WAIVED (%d) or log message %q", exitCode, logs, exitCodeWaived, wantLog)
}

// requiresFeatures implements `Compatibility` for tests that require
// specific features.
type requiresFeatures struct {
	features []Feature
}

// RequiresFeatures implements `Compatibility` for tests that require
// specific features.
func RequiresFeatures(features ...Feature) Compatibility {
	return &requiresFeatures{features: features}
}

// WillFail implements `Compatibility.WillFail`.
func (r *requiresFeatures) WillFail(ctx context.Context, env *TestEnvironment) string {
	for _, feature := range r.features {
		if !env.Features[feature] {
			return fmt.Sprintf("Requires feature %s", feature)
		}
	}
	return ""
}

// IsExpectedFailure implements `Compatibility.IsExpectedFailure`.
func (r *requiresFeatures) IsExpectedFailure(ctx context.Context, env *TestEnvironment, logs string, exitCode int) error {
	if slices.Contains(r.features, FeatureGL) && !env.Features[FeatureGL] && strings.Contains(logs, `code=999(cudaErrorUnknown) "cudaGraphicsGLRegisterBuffer(&cuda_vbo_resource, vbo, cudaGraphicsMapFlagsNone)"`) {
		// Some GL-requiring tests such as `5_Domain_Specific/postProcessGL`
		// and `5_Domain_Specific/fluidsGL` will incorrectly detect that GL
		// is supported, and fail with this error message rather than waiving.
		return nil
	}
	if exitCode != exitCodeWaived {
		return fmt.Errorf("exit code %d, expected EXIT_WAIVED (%d)", exitCode, exitCodeWaived)
	}
	return nil
}

// OnlyOnWindows implements `Compatibility` for tests that are only expected
// to only pass on Windows.
type OnlyOnWindows struct{}

// WillFail implements `Compatibility.WillFail`.
func (*OnlyOnWindows) WillFail(ctx context.Context, env *TestEnvironment) string {
	if runtime.GOOS != "windows" {
		return "Only runs on Windows"
	}
	return ""
}

// IsExpectedFailure implements `Compatibility.IsExpectedFailure`.
func (*OnlyOnWindows) IsExpectedFailure(ctx context.Context, env *TestEnvironment, logs string, exitCode int) error {
	if strings.Contains(logs, "is not supported on Linux") {
		return nil
	}
	if exitCode != exitCodeWaived {
		return fmt.Errorf("exit code %d, expected EXIT_WAIVED (%d)", exitCode, exitCodeWaived)
	}
	return nil
}

// RequiresNvSci implements `Compatibility` for tests that require the NvSci
// library.
type RequiresNvSci struct{}

// WillFail implements `Compatibility.WillFail`.
func (*RequiresNvSci) WillFail(ctx context.Context, env *TestEnvironment) string {
	return "Requires NvSci library which is not open-source"
}

// IsExpectedFailure implements `Compatibility.IsExpectedFailure`.
func (*RequiresNvSci) IsExpectedFailure(ctx context.Context, env *TestEnvironment, logs string, exitCode int) error {
	return nil
}

// NoCrossCompile implements `Compatibility` for tests that cannot cross compile.
type NoCrossCompile struct{}

// WillFail implements `Compatibility.WillFail`.
func (*NoCrossCompile) WillFail(ctx context.Context, env *TestEnvironment) string {
	if strings.HasPrefix(runtime.GOARCH, "arm") {
		return "Test not supported on ARM. Cross compiled libraries not supported."
	}
	return ""
}

// IsExpectedFailure implements `Compatibility.IsExpectedFailure`.
func (*NoCrossCompile) IsExpectedFailure(ctx context.Context, env *TestEnvironment, logs string, _ int) error {
	crossCompileString := "cross compiling from sbsa to aarch64 is not supported!"
	if strings.Contains(logs, crossCompileString) {
		return nil
	}
	return fmt.Errorf("expected log message %q not found: logs: %q", crossCompileString, logs)
}

// multiCompatibility implements `Compatibility` with multiple possible
// Compatibility implementations.
type multiCompatibility struct {
	compats []Compatibility
}

// MultiCompatibility implements `Compatibility` with multiple possible
// Compatibility implementations.
func MultiCompatibility(compats ...Compatibility) Compatibility {
	return &multiCompatibility{compats: compats}
}

// WillFail implements `Compatibility.WillFail`.
func (mc *multiCompatibility) WillFail(ctx context.Context, env *TestEnvironment) string {
	for _, compat := range mc.compats {
		if reason := compat.WillFail(ctx, env); reason != "" {
			return reason
		}
	}
	return ""
}

// IsExpectedFailure implements `Compatibility.IsExpectedFailure`.
func (mc *multiCompatibility) IsExpectedFailure(ctx context.Context, env *TestEnvironment, logs string, exitCode int) error {
	var possibleCompats []Compatibility
	for _, compat := range mc.compats {
		if reason := compat.WillFail(ctx, env); reason != "" {
			possibleCompats = append(possibleCompats, compat)
		}
	}
	if len(possibleCompats) == 0 {
		return errors.New("no known explanation for this failure")
	}
	var errs []string
	for _, compat := range possibleCompats {
		err := compat.IsExpectedFailure(ctx, env, logs, exitCode)
		if err == nil {
			return nil
		}
		errs = append(errs, fmt.Sprintf("might have been broken because %s but %v", compat.WillFail(ctx, env), err))
	}
	return fmt.Errorf("no known explanation for this failure: %v", strings.Join(errs, "; "))
}

// FullyCompatible implements `Compatibility` for tests that are expected to
// pass in any environment.
type FullyCompatible struct{}

// WillFail implements `Compatibility.WillFail`.
func (*FullyCompatible) WillFail(ctx context.Context, env *TestEnvironment) string {
	return ""
}

// IsExpectedFailure implements `Compatibility.IsExpectedFailure`.
func (*FullyCompatible) IsExpectedFailure(ctx context.Context, env *TestEnvironment, logs string, exitCode int) error {
	return errors.New("test is expected to pass regardless of environment")
}

// testLog logs a line as a test log.
// If debug is enabled, it is also printed immediately to stderr.
// This is useful for debugging tests.
func testLog(t *testing.T, format string, values ...any) {
	t.Helper()
	if *debug {
		fmt.Fprintf(os.Stderr, "[%s] %s\n", t.Name(), fmt.Sprintf(format, values...))
	}
	t.Logf(format, values...)
}

// multiLineLog logs a multiline string as separate log messages to `t`.
// This is useful to log multi-line container logs without them looking weird
// with line breaks in the middle.
func multiLineLog(t *testing.T, output string) {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		// `line` may contain % characters here, so we need to format it through
		// `%s` so that `%` characters don't show up as "MISSING" in the logs.
		testLog(t, "%s", line)
	}
}

// runSampleTest runs a single CUDA sample test.
// It first tries to run in pooled container.
// If that fails, then it runs in an exclusive container.
// It returns a skip reason (or empty if the test was not skipped), and
// an error if the test fails.
func runSampleTest(ctx context.Context, t *testing.T, testName string, te *TestEnvironment, cp *dockerutil.ContainerPool, args *RunCudaTestArgs) (string, error) {
	var compatibilities []Compatibility
	if compat, found := args.TestCompatibility[testName]; found {
		compatibilities = append(compatibilities, compat)
	}
	for suite, comp := range args.TestSuiteCompatibility {
		if strings.HasPrefix(testName, suite) {
			compatibilities = append(compatibilities, comp)
		}
	}
	compat := MultiCompatibility(compatibilities...)
	if len(compatibilities) == 0 {
		compat = &FullyCompatible{}
	}
	willFailReason := compat.WillFail(ctx, te)
	if skipReason, isAlwaysSkipped := args.AlwaysSkippedTests[testName]; isAlwaysSkipped {
		return fmt.Sprintf("this test is always skipped (%v)", skipReason), nil
	}
	testTimeout := defaultTestTimeout
	execTestTimeout := testTimeout - 15*time.Second
	testAttempts := 1
	if _, isFlakyTest := args.FlakyTests[testName]; isFlakyTest {
		testAttempts = 3
	}
	parallelAttempts := testAttempts
	if _, isExclusiveTest := args.ExclusiveTests[testName]; isExclusiveTest {
		parallelAttempts = 0
	}
	for attempt := 0; attempt < parallelAttempts; attempt++ {
		c, release, err := cp.Get(ctx)
		if err != nil {
			release()
			return "", fmt.Errorf("failed to get container: %v", err)
		}
		cp.SetContainerLabel(c, fmt.Sprintf("Running %s in parallel (attempt %d/%d)", testName, attempt+1, parallelAttempts))
		testLog(t, "Running test in parallel mode in container %s (attempt %d/%d)...", c.Name, attempt+1, parallelAttempts)
		parallelCtx, parallelCancel := context.WithTimeoutCause(ctx, testTimeout, errors.New("parallel execution took too long"))
		testStartedAt := time.Now()
		output, err := c.Exec(parallelCtx, dockerutil.ExecOpts{}, "/run_sample", fmt.Sprintf("--timeout=%v", execTestTimeout), testName)
		testDuration := time.Since(testStartedAt)
		parallelCancel()
		release()
		if err == nil {
			if willFailReason != "" {
				multiLineLog(t, output)
				return "", fmt.Errorf("test unexpectedly succeeded, but we expected it to fail: %s; please update `testCompatibility`", willFailReason)
			}
			// Only log the output when the test succeeds here.
			// If it fails, we'll run exclusively below, and the output from *that*
			// run will be logged instead.
			if *logSuccessfulTests {
				multiLineLog(t, output)
			}
			testLog(t, "Test passed in parallel mode in %v.", testDuration)
			return "", nil
		}
		var exitCode int
		if execErr, ok := err.(*dockerutil.ExecError); ok {
			exitCode = execErr.ExitStatus
		}
		if willFailReason != "" {
			isExpectedErr := compat.IsExpectedFailure(ctx, te, output, exitCode)
			if isExpectedErr == nil {
				testLog(t, "Test failed as expected: %s (took %v)", willFailReason, testDuration)
				return "", nil
			}
		}
	}
	if parallelAttempts > 0 {
		testLog(t, "Will re-run the test in exclusive mode.")
	}
	c, release, err := cp.GetExclusive(ctx)
	defer release()
	if err != nil {
		return "", fmt.Errorf("failed to get excusive container: %v", err)
	}
	var testErr error
	for attempt := 0; attempt < testAttempts; attempt++ {
		cp.SetContainerLabel(c, fmt.Sprintf("Running %s exclusively (attempt %d/%d)", testName, attempt+1, testAttempts))
		testLog(t, "Running test in exclusive mode in container %s (attempt %d/%d)...", c.Name, attempt+1, testAttempts)
		exclusiveCtx, exclusiveCancel := context.WithTimeoutCause(ctx, testTimeout, errors.New("exclusive execution took too long"))
		testStartedAt := time.Now()
		var output string
		output, testErr = c.Exec(exclusiveCtx, dockerutil.ExecOpts{}, "/run_sample", fmt.Sprintf("--timeout=%v", execTestTimeout), testName)
		testDuration := time.Since(testStartedAt)
		exclusiveCancel()
		if testErr == nil {
			if willFailReason != "" {
				multiLineLog(t, output)
				return "", fmt.Errorf("test unexpectedly succeeded, but we expected it to fail: %s; please update `testCompatibility`", willFailReason)
			}
			if *logSuccessfulTests {
				multiLineLog(t, output)
			}
			testLog(t, "Test passed in exclusive mode in %v.", testDuration)
			return "", nil
		}
		multiLineLog(t, output)
		var exitCode int
		if execErr, ok := testErr.(*dockerutil.ExecError); ok {
			exitCode = execErr.ExitStatus
		}
		if willFailReason != "" {
			isExpectedErr := compat.IsExpectedFailure(ctx, te, output, exitCode)
			if isExpectedErr == nil {
				testLog(t, "Test failed as expected: %s (took %v)", willFailReason, testDuration)
				return "", nil
			}
			return "", fmt.Errorf("test was expected to fail (%s), but it failed with %v which is a different reason reason than expected: %v", willFailReason, testErr, isExpectedErr)
		}
	}
	return "", fmt.Errorf("test failed: %v", testErr)
}

// getDesiredTestParallelism returns the number of tests to run in parallel.
func getDesiredTestParallelism() int {
	numCPU := runtime.NumCPU()
	if numCPU <= 0 {
		panic("cannot detect number of cores")
	}
	return int(math.Ceil((*containersPerCPU) * float64(numCPU)))
}

// getContainerOpts returns the container run options to run CUDA tests.
func getContainerOpts(image string) (dockerutil.RunOpts, error) {
	opts, err := dockerutil.GPURunOpts(dockerutil.SniffGPUOpts{
		Capabilities: "all",
	})
	if err != nil {
		return dockerutil.RunOpts{}, fmt.Errorf("failed to get GPU run options: %w", err)
	}
	opts.Image = image
	return opts, nil
}

// RunCudaTestArgs contains arguments for RunCudaTests.
type RunCudaTestArgs struct {
	// TestSuiteCompatibility maps test suites to their compatibility data.
	// Unmapped test suites are assumed to be fully compatible.
	TestSuiteCompatibility map[string]Compatibility

	// SkippedTestSuites maps test suites to a skip reason.
	// If a test suite is mapped, then all tests in that suite will be skipped.
	SkippedTestSuites map[string]string

	// TestCompatibility maps test names to their compatibility data.
	// Unmapped test names are assumed to be fully compatible.
	TestCompatibility map[string]Compatibility

	// FlakyTests is a list of tests that are flaky.
	// These will be retried up to 3 times in parallel before running 3 times
	// serially.
	FlakyTests map[string]struct{}

	// ExclusiveTests is a list of tests that must run exclusively (i.e. with
	// no other test running on the machine at the same time), or they will
	// likely fail. These tests are not attempted to be run in parallel.
	// This is usually the case for performance tests or tests that use a lot
	// of resources in general.
	// This saves the trouble to run them in parallel, while also avoiding
	// causing spurious failures for the tests that happen to be running in
	// parallel with them.
	ExclusiveTests map[string]struct{}

	// AlwaysSkippedTests don't run at all.
	// Each test is mapped to a reason why it should be skipped.
	AlwaysSkippedTests map[string]string

	// Image is the image to use for the CUDA tests.
	Image string
}

// RunCudaTests runs CUDA tests.
func RunCudaTests(ctx context.Context, t *testing.T, args *RunCudaTestArgs) {
	const defaultMaxDuration = 59*time.Minute + 30*time.Second

	testStart := time.Now()
	maxDuration := defaultMaxDuration
	if timeoutFlag := flag.Lookup("timeout"); timeoutFlag != nil {
		if timeoutFlagStr := timeoutFlag.Value.String(); timeoutFlagStr != "" {
			timeoutFlagValue, err := time.ParseDuration(timeoutFlagStr)
			if err != nil {
				t.Fatalf("--timeout flag %q is not a valid duration: %v", timeoutFlagStr, err)
			}
			if timeoutFlagValue != 0 {
				maxDuration = timeoutFlagValue
			}
		}
	}
	ctx, cancel := context.WithTimeoutCause(context.Background(), maxDuration, errors.New("overall test timed out"))
	defer cancel()
	testDeadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("context had no deadline")
	}
	testLog(t, "Test timeout is %v; started at %v, deadline is %v", maxDuration, testStart, testDeadline)

	te, err := GetEnvironment(ctx, t, args.Image)
	if err != nil {
		t.Fatalf("Failed to get test environment: %v", err)
	}

	// Get a list of sample tests.
	listContainer := dockerutil.MakeNativeContainer(ctx, t)
	defer listContainer.CleanUp(ctx)
	runOpts := dockerutil.RunOpts{
		Image: args.Image,
	}
	testsList, err := listContainer.Run(ctx, runOpts, "/list_sample_tests.sh")
	if err != nil {
		t.Fatalf("Cannot list sample tests: %v", err)
	}
	testsSplit := strings.Split(testsList, "\n")
	allTests := make([]string, 0, len(testsSplit))
	allTestsMap := make(map[string]struct{}, len(testsSplit))
	for _, test := range testsSplit {
		testName := strings.TrimSpace(test)
		if testName == "" {
			continue
		}

		// Temporarily skip test suites that are not yet tested.
		matches := strings.SplitN(testName, "/", 2)
		if len(matches) != 2 {
			t.Errorf("Invalid test name: %q", testName)
			continue
		}
		if _, ok := args.SkippedTestSuites[matches[0]]; ok {
			testLog(t, "Skipping test %q in suite %q", testName, matches[0])
			continue
		}

		allTestsMap[testName] = struct{}{}
		allTests = append(allTests, testName)
	}
	numTests := len(allTests)
	testLog(t, "Number of CUDA sample tests detected: %d", numTests)

	// Check that all tests in test maps still exist.
	t.Run("CUDA test existence", func(t *testing.T) {
		for testName := range args.TestCompatibility {
			if _, ok := allTestsMap[testName]; !ok {
				t.Errorf("CUDA test %q referenced in `testCompatibility` but it no longer exists, please remove it.", testName)
			}
		}
	})

	// Filter tests if partitioning is enabled.
	testIndices, err := testutil.TestIndicesForShard(numTests)
	if err != nil {
		t.Fatalf("Failed to get test indices for shard: %v", err)
	}
	if len(testIndices) != numTests {
		filteredTests := make([]string, 0, len(testIndices))
		for _, testIndex := range testIndices {
			filteredTests = append(filteredTests, allTests[testIndex])
		}
		testLog(t, "Filtered tests from sharding; %d -> %d tests.", numTests, len(filteredTests))
		allTests = filteredTests
		numTests = len(allTests)
	}

	// In order to go through tests efficiently, we reuse containers.
	// However, running tests serially within the same container would also be
	// slow. So this test spawns a pool of containers, one per CPU.
	// This saves time because a lot of the time here is actually spent waiting
	// for compilation of the CUDA program on the CPU, and isn't actually
	// blocked on the GPU. However, it is possible that two CUDA tests do end
	// up running on the GPU at the same time, and that they don't work together
	// for some reason (e.g. out of GPU memory).
	// To address this, the test first runs every test in parallel. Then, if
	// any of them failed, it will run only the failed ones serially.
	numParallel := getDesiredTestParallelism()
	numContainers := min(numParallel, max(numTests, 1))
	if numContainers == numParallel {
		testLog(t, "Number of cores is %d, spawning %.1f CUDA containers for each (%d containers total)...", runtime.NumCPU(), *containersPerCPU, numContainers)
	} else {
		testLog(t, "%d tests to run, spawning %d CUDA containers...", numTests, numContainers)
	}
	spawnGroup, spawnCtx := errgroup.WithContext(ctx)
	containers := make([]*dockerutil.Container, numContainers)
	for i := 0; i < numContainers; i++ {
		spawnGroup.Go(func() error {
			c := dockerutil.MakeContainer(ctx, t)
			runOpts, err := getContainerOpts(args.Image)
			if err != nil {
				return fmt.Errorf("failed to get container options: %w", err)
			}
			if err := c.Spawn(spawnCtx, runOpts, "/bin/sleep", "6h"); err != nil {
				return fmt.Errorf("container %v failed to spawn: %w", c.Name, err)
			}
			containers[i] = c
			return nil
		})
	}
	if err := spawnGroup.Wait(); err != nil {
		for _, c := range containers {
			if c != nil {
				c.CleanUp(ctx)
			}
		}
		t.Fatalf("Failed to spawn containers: %v", err)
	}
	cp := dockerutil.NewContainerPool(containers)
	defer cp.CleanUp(ctx)
	var testMu sync.Mutex
	testsDone := 0
	var failedTests []string
	statusFn := func() {
		now := time.Now()
		testMu.Lock()
		defer testMu.Unlock()
		donePct := 100.0 * float64(testsDone) / float64(numTests)
		startedAgo := now.Sub(testStart)
		deadlineIn := testDeadline.Sub(now)
		durationPct := 100.0 * float64(startedAgo) / float64(testDeadline.Sub(testStart))
		testLog(t, "[Timing] %d/%d tests (%.1f%%) finished executing. Test started %v ago, deadline in %v (%.1f%%).", testsDone, numTests, donePct, startedAgo.Truncate(time.Second), deadlineIn.Truncate(time.Second), durationPct)
		if len(failedTests) > 0 {
			testLog(t, "[Failed] %d test(s) failed: %v", len(failedTests), strings.Join(failedTests, ", "))
		}
		testLog(t, "[Pool] %v", cp.String())
	}
	if *debug {
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					statusFn()
				}
			}
		}()
	}
	var samplesTestName string
	t.Run("Samples", func(t *testing.T) {
		samplesTestName = t.Name()
		// Now spawn all subtests in parallel.
		// All sub-tests will first try to run in parallel using one of the pooled
		// containers.
		// Those that failed will try to grab `serialMu` in order to run serially.
		// Therefore, the main goroutine here holds `serialMu` and only releases
		// when all parallel test attempts have completed.
		testutil.NewTree(allTests, "/").RunParallel(t, func(t *testing.T, testName string) {
			t.Helper()
			skippedReason, err := runSampleTest(ctx, t, testName, te, cp, args)
			if err != nil {
				t.Errorf("%s: %v", testName, err)
			}
			testMu.Lock()
			defer testMu.Unlock()
			testsDone++
			if t.Failed() && ctx.Err() == nil {
				failedTests = append(failedTests, testName)
			}
			if skippedReason != "" {
				t.Skip(skippedReason)
			}
		})
	})
	statusFn()
	testMu.Lock()
	defer testMu.Unlock()
	if len(failedTests) > 0 {
		if ctx.Err() != nil {
			t.Errorf("%d tests failed prior to timeout:", len(failedTests))
			for _, testName := range failedTests {
				t.Errorf("  %s", testName)
			}
		}
		if len(failedTests) > 0 {
			t.Errorf("To re-run a specific test locally, either re-run this test with filtering enabled (example: --test.run=%s/%s), or:", samplesTestName, failedTests[0])
			t.Errorf(
				"  $ docker run --runtime=%s --gpus=all -e %s --rm %s /run_sample %s",
				dockerutil.Runtime(),
				dockerutil.AllGPUCapabilitiesEnv,
				runOpts.Image,
				failedTests[0],
			)
		}
	} else if poolUtilization := cp.Utilization(); poolUtilization < 0.6 {
		testLog(t, "WARNING: Container pool utilization was only %.1f%% during the test.", poolUtilization*100.0)
		testLog(t, "This test can be made faster and more efficient with proper test categorization,")
		testLog(t, "by identifying flaky tests and exclusive-requiring tests.")
		testLog(t, "Consider going over the logs to identify such tests and categorize them accordingly.")
	}

}
