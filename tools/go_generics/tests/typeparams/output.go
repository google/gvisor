package tests

type Number interface {
	~int | ~int64
}

type Box[T any] struct {
	v T
}

func (b Box[T]) Get() T {
	return b.v
}

func Use[T Number](v T) Box[T] {
	return Box[T]{v: v}
}

func UseGlobal(x MyT) MyT {
	return x
}

type Pair[A, B any] struct {
	first  A
	second B
}

var _ = Pair[int, string]{}
var _ = Box[int]{}
var _ = Use[int](1)
