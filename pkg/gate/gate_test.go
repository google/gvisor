package gate_test

import (
	"sync"
	"testing"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/gate"
)

func TestBasicEnter(t *testing.T) {
	var g gate.Gate

	if !g.Enter() {
		t.Fatalf("Failed to enter when it should be allowed")
	}

	g.Leave()

	g.Close()

	if g.Enter() {
		t.Fatalf("Allowed to enter when it should fail")
	}
}

func enterFunc(t *testing.T, g *gate.Gate, enter, leave, reenter chan struct{}, done1, done2, done3 *sync.WaitGroup) {
	// Wait until instructed to enter.
	<-enter
	if !g.Enter() {
		t.Errorf("Failed to enter when it should be allowed")
	}

	done1.Done()

	// Wait until instructed to leave.
	<-leave
	g.Leave()

	done2.Done()

	// Wait until instructed to reenter.
	<-reenter
	if g.Enter() {
		t.Errorf("Allowed to enter when it should fail")
	}
	done3.Done()
}

func TestConcurrentEnter(t *testing.T) {
	var g gate.Gate
	var done1, done2, done3 sync.WaitGroup

	// Create 1000 worker goroutines.
	enter := make(chan struct{})
	leave := make(chan struct{})
	reenter := make(chan struct{})
	done1.Add(1000)
	done2.Add(1000)
	done3.Add(1000)
	for i := 0; i < 1000; i++ {
		go enterFunc(t, &g, enter, leave, reenter, &done1, &done2, &done3)
	}

	// Tell them all to enter, then leave.
	close(enter)
	done1.Wait()

	close(leave)
	done2.Wait()

	// Close the gate, then have the workers try to enter again.
	g.Close()
	close(reenter)
	done3.Wait()
}

func closeFunc(g *gate.Gate, done chan struct{}) {
	g.Close()
	close(done)
}

func TestCloseWaits(t *testing.T) {
	var g gate.Gate

	// Enter 10 times.
	for i := 0; i < 10; i++ {
		if !g.Enter() {
			t.Fatalf("Failed to enter when it should be allowed")
		}
	}

	// Launch closer. Check that it doesn't complete.
	done := make(chan struct{})
	go closeFunc(&g, done)

	for i := 0; i < 10; i++ {
		select {
		case <-done:
			t.Fatalf("Close function completed too soon")
		case <-time.After(100 * time.Millisecond):
		}

		g.Leave()
	}

	// Now the closer must complete.
	<-done
}

func TestMultipleSerialCloses(t *testing.T) {
	var g gate.Gate

	// Enter 10 times.
	for i := 0; i < 10; i++ {
		if !g.Enter() {
			t.Fatalf("Failed to enter when it should be allowed")
		}
	}

	// Launch closer. Check that it doesn't complete.
	done := make(chan struct{})
	go closeFunc(&g, done)

	for i := 0; i < 10; i++ {
		select {
		case <-done:
			t.Fatalf("Close function completed too soon")
		case <-time.After(100 * time.Millisecond):
		}

		g.Leave()
	}

	// Now the closer must complete.
	<-done

	// Close again should not block.
	done = make(chan struct{})
	go closeFunc(&g, done)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("Second Close is blocking")
	}
}

func worker(g *gate.Gate, done *sync.WaitGroup) {
	for {
		if !g.Enter() {
			break
		}
		g.Leave()
	}
	done.Done()
}

func TestConcurrentAll(t *testing.T) {
	var g gate.Gate
	var done sync.WaitGroup

	// Launch 1000 goroutines to concurrently enter/leave.
	done.Add(1000)
	for i := 0; i < 1000; i++ {
		go worker(&g, &done)
	}

	// Wait for the goroutines to do some work, then close the gate.
	time.Sleep(2 * time.Second)
	g.Close()

	// Wait for all of them to complete.
	done.Wait()
}
