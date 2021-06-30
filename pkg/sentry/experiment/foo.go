package experiment

import (
	"gvisor.dev/gvisor/pkg/context"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
)

type Foo struct {
	ts ktime.Time
}

func makeFoo(ctx context.Context) *Foo {
	return &Foo{
		ts: ktime.ZeroTime,
	}
}
