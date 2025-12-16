package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/cgroup"
)

// MockCgroup implements cgroup.Cgroup for testing
type MockCgroup struct {
	Quota float64
	Path  string
}

func (m *MockCgroup) CPUQuota() (float64, error) {
	return m.Quota, nil
}

func (m *MockCgroup) MakePath(controller string) string {
	return m.Path
}

// Stubs for interface satisfaction
func (m *MockCgroup) Install(res *specs.LinuxResources) error { return nil }
func (m *MockCgroup) Uninstall() error                        { return nil }
func (m *MockCgroup) Join() (func(), error)                   { return func() {}, nil }
func (m *MockCgroup) CPUUsage() (uint64, error)               { return 0, nil }
func (m *MockCgroup) NumCPU() (int, error)                    { return 0, nil }
func (m *MockCgroup) MemoryLimit() (uint64, error)            { return 0, nil }

func TestGetEffectiveCPUQuota(t *testing.T) {
	// Create temporary cgroup hierarchy
	rootDir := t.TempDir()
	parentDir := filepath.Join(rootDir, "parent")
	childDir := filepath.Join(parentDir, "child")

	if err := os.MkdirAll(childDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Case 1: Child has explicit limit
	// Create cpu.max in child
	if err := os.WriteFile(filepath.Join(childDir, "cpu.max"), []byte("50000 100000"), 0644); err != nil {
		t.Fatal(err)
	}
	cg1 := &MockCgroup{Quota: 0.5, Path: childDir}
	if q, _ := getEffectiveCPUQuota(cg1); q != 0.5 {
		t.Errorf("Expected 0.5, got %v", q)
	}

	// Case 2: Child unlimited (-1), Parent has limit
	cg2 := &MockCgroup{Quota: -1, Path: childDir} // Simulate CPUQuota returning -1
	// Write "max" to child
	if err := os.WriteFile(filepath.Join(childDir, "cpu.max"), []byte("max 100000"), 0644); err != nil {
		t.Fatal(err)
	}
	// Write limit to parent
	if err := os.WriteFile(filepath.Join(parentDir, "cpu.max"), []byte("25000 100000"), 0644); err != nil {
		t.Fatal(err)
	}
	
	if q, _ := getEffectiveCPUQuota(cg2); q != 0.25 {
		t.Errorf("Expected 0.25 (inherited), got %v", q)
	}

	// Case 3: Both unlimited
	if err := os.WriteFile(filepath.Join(parentDir, "cpu.max"), []byte("max 100000"), 0644); err != nil {
		t.Fatal(err)
	}
	if q, _ := getEffectiveCPUQuota(cg2); q != -1 {
		t.Errorf("Expected -1, got %v", q)
	}
}
