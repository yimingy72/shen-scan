package main

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestBrowserRequestDrainBound(t *testing.T) {
	var normal sync.WaitGroup
	normal.Add(1)
	go func() { time.Sleep(20 * time.Millisecond); normal.Done() }()
	finished, drained := drainBrowserRequests(context.Background(), &normal, 200*time.Millisecond)
	if !drained {
		t.Fatal("accepted work was canceled before bounded drain")
	}
	<-finished
	var pending sync.WaitGroup
	pending.Add(1)
	start := time.Now()
	finished, drained = drainBrowserRequests(context.Background(), &pending, 20*time.Millisecond)
	if drained || time.Since(start) > time.Second {
		t.Fatal("drain did not honor short bound")
	}
	pending.Done()
	<-finished
	var canceled sync.WaitGroup
	canceled.Add(1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start = time.Now()
	finished, drained = drainBrowserRequests(ctx, &canceled, time.Second)
	if drained || time.Since(start) > 200*time.Millisecond {
		t.Fatal("parent cancellation waited for drain window")
	}
	canceled.Done()
	<-finished
}
