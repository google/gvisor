package experiment

import (
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
)

func TestFoo(t *testing.T) {
	ctx := contexttest.Context(t)
	f := makeFoo(ctx)
	if f.ts != ktime.ZeroTime {
		t.Fatalf("Initial time wasn't zero time: %v", f.ts)
	}
}
