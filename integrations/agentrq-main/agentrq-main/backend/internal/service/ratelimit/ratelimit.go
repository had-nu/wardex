package ratelimit

import (
	"sync"
	"time"
)

type Limiter interface {
	AllowWorkspace(userID int64) bool
	AllowTask(userID int64) bool
	AllowMessage(userID int64) bool
}

type rotatingBucket struct {
	LastUpdate int64
	Buckets    [60]uint8
}

type limiter struct {
	sync.Mutex
	workspaceRequests map[int64]*rotatingBucket
	taskRequests      map[int64]*rotatingBucket
	messageRequests   map[int64]*rotatingBucket
}

func New() Limiter {
	return &limiter{
		workspaceRequests: make(map[int64]*rotatingBucket),
		taskRequests:      make(map[int64]*rotatingBucket),
		messageRequests:   make(map[int64]*rotatingBucket),
	}
}

func (l *limiter) AllowWorkspace(userID int64) bool {
	l.Lock()
	defer l.Unlock()

	now := time.Now().Unix()
	rb, ok := l.workspaceRequests[userID]
	if !ok {
		rb = &rotatingBucket{}
		l.workspaceRequests[userID] = rb
	}

	return allow(rb, now, 1, 2)
}

func (l *limiter) AllowTask(userID int64) bool {
	l.Lock()
	defer l.Unlock()

	now := time.Now().Unix()
	rb, ok := l.taskRequests[userID]
	if !ok {
		rb = &rotatingBucket{}
		l.taskRequests[userID] = rb
	}

	return allow(rb, now, 1, 10)
}

func (l *limiter) AllowMessage(userID int64) bool {
	l.Lock()
	defer l.Unlock()

	now := time.Now().Unix()
	rb, ok := l.messageRequests[userID]
	if !ok {
		rb = &rotatingBucket{}
		l.messageRequests[userID] = rb
	}

	return allow(rb, now, 5, 60)
}

func allow(rb *rotatingBucket, now int64, maxSec int, maxMin int) bool {
	// Calculate difference and clear stale buckets
	diff := now - rb.LastUpdate
	if diff >= 60 {
		rb.Buckets = [60]uint8{}
	} else if diff > 0 {
		for t := rb.LastUpdate + 1; t <= now; t++ {
			rb.Buckets[t%60] = 0
		}
	}

	// Enforce second-level limit
	if rb.Buckets[now%60] >= uint8(maxSec) {
		return false
	}

	// Enforce minute-level limit
	var sum int
	for _, count := range rb.Buckets {
		sum += int(count)
	}
	if sum >= maxMin {
		return false
	}

	// Record request
	rb.Buckets[now%60]++
	rb.LastUpdate = now
	return true
}


