package ratelimit

import (
	"sync"
	"testing"
	"time"
)

func TestLimiter_AllowWorkspace(t *testing.T) {
	l := New()
	userID := int64(42)

	if !l.AllowWorkspace(userID) {
		t.Error("expected first request to be allowed")
	}

	if l.AllowWorkspace(userID) {
		t.Error("expected second request within 1s to be blocked")
	}

	time.Sleep(1050 * time.Millisecond)

	if !l.AllowWorkspace(userID) {
		t.Error("expected request after 1s window to be allowed again")
	}
}

func TestLimiter_AllowWorkspace_MinuteLimit(t *testing.T) {
	l := New()
	userID := int64(4242)

	// Max 2 per minute:
	if !l.AllowWorkspace(userID) {
		t.Error("expected 1st workspace creation to be allowed")
	}

	time.Sleep(1050 * time.Millisecond)

	if !l.AllowWorkspace(userID) {
		t.Error("expected 2nd workspace creation to be allowed")
	}

	time.Sleep(1050 * time.Millisecond)

	if l.AllowWorkspace(userID) {
		t.Error("expected 3rd workspace creation within the same minute to be blocked")
	}
}

func TestLimiter_AllowTask(t *testing.T) {
	l := New()
	userID := int64(43)

	if !l.AllowTask(userID) {
		t.Error("expected first task to be allowed")
	}

	if l.AllowTask(userID) {
		t.Error("expected second task request within 1s to be blocked")
	}

	time.Sleep(1050 * time.Millisecond)

	if !l.AllowTask(userID) {
		t.Error("expected task request after 1s window to be allowed again")
	}
}

func TestLimiter_AllowTask_MinuteLimit(t *testing.T) {
	userID := int64(4343)

	lim := &limiter{
		workspaceRequests: make(map[int64]*rotatingBucket),
		taskRequests:      make(map[int64]*rotatingBucket),
		messageRequests:   make(map[int64]*rotatingBucket),
	}
	rb := &rotatingBucket{
		LastUpdate: time.Now().Unix(),
	}
	for i := 0; i < 10; i++ {
		rb.Buckets[i%60]++
	}
	lim.taskRequests[userID] = rb

	if lim.AllowTask(userID) {
		t.Error("expected 11th task within the same minute to be blocked")
	}
}

func TestLimiter_AllowMessage_SecondAndMinuteWindow(t *testing.T) {
	l := New()
	userID := int64(100)

	// 5 requests allowed per second
	for i := 0; i < 5; i++ {
		if !l.AllowMessage(userID) {
			t.Errorf("expected request %d to be allowed", i+1)
		}
	}

	if l.AllowMessage(userID) {
		t.Error("expected 6th request within 1s to be blocked")
	}

	// Wait 1 second to clear the second bucket
	time.Sleep(1050 * time.Millisecond)

	// Now we can send another 5 requests
	for i := 0; i < 5; i++ {
		if !l.AllowMessage(userID) {
			t.Errorf("expected request %d to be allowed in the next second", i+6)
		}
	}
}

func TestLimiter_AllowMessage_MinuteLimit(t *testing.T) {
	l := &limiter{
		workspaceRequests: make(map[int64]*rotatingBucket),
		taskRequests:      make(map[int64]*rotatingBucket),
		messageRequests:   make(map[int64]*rotatingBucket),
	}
	userID := int64(101)

	// Setup a simulated rotatingBucket with 60 requests sent in the last minute (across different buckets)
	mb := &rotatingBucket{
		LastUpdate: time.Now().Unix(),
	}
	for i := 0; i < 60; i++ {
		mb.Buckets[i%60]++
	}
	l.messageRequests[userID] = mb

	// A new message should be blocked because the sum is 60
	if l.AllowMessage(userID) {
		t.Error("expected request to be blocked due to minute-level rate limit")
	}
}

func TestLimiter_ThreadSafety(t *testing.T) {
	l := New()
	var wg sync.WaitGroup
	numWorkers := 50
	requestsPerWorker := 100

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			userID := int64(workerID % 5) // distribute workers across 5 distinct users

			for j := 0; j < requestsPerWorker; j++ {
				_ = l.AllowWorkspace(userID)
				_ = l.AllowTask(userID)
				_ = l.AllowMessage(userID)
			}
		}(i)
	}

	wg.Wait()
}



