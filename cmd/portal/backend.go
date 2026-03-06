package portal

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

var (
	jobs = struct {
		sync.RWMutex
		m map[string]*ScanJob
	}{m: make(map[string]*ScanJob)}
)

type ScanJob struct {
	ID      string
	RepoURL string
	Profile string
	Clients []chan string
	Metrics *JobMetrics
	mu      sync.Mutex
	done    bool
}

type JobMetrics struct {
	RawVulns      int `json:"raw_vulns"`
	BlockedVulns  int `json:"blocked_vulns"`
	BypassedVulns int `json:"bypassed_vulns"`
}

type ScanRequest struct {
	RepoURL string `json:"repo_url"`
	Profile string `json:"profile"`
}

func handleScanAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.RepoURL == "" {
		http.Error(w, "repo_url cannot be empty", http.StatusBadRequest)
		return
	}

	// Basic anti-abuse validation
	if !strings.HasPrefix(req.RepoURL, "https://github.com/") {
		http.Error(w, "Only public github.com repositories are allowed", http.StatusBadRequest)
		return
	}

	jobID := generateID()
	job := &ScanJob{
		ID:      jobID,
		RepoURL: req.RepoURL,
		Profile: req.Profile,
	}

	jobs.Lock()
	jobs.m[jobID] = job
	jobs.Unlock()

	// Run job in background
	go runScanJob(job)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"job_id": jobID})
}

func handleStreamAPI(w http.ResponseWriter, r *http.Request) {
	jobID := strings.TrimPrefix(r.URL.Path, "/api/scan/")
	jobID = strings.TrimSuffix(jobID, "/stream")

	jobs.RLock()
	job, ok := jobs.m[jobID]
	jobs.RUnlock()

	if !ok {
		http.Error(w, "Job not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	ch := make(chan string, 10)

	job.mu.Lock()
	if job.done {
		job.mu.Unlock()
		// If it's already done before they connect, we just send completion
		b, _ := json.Marshal(map[string]interface{}{"type": "complete", "metrics": job.Metrics})
		fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
		return
	}
	job.Clients = append(job.Clients, ch)
	job.mu.Unlock()

	ctx := r.Context()

	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				// Job finished
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		}
	}
}

func broadcast(job *ScanJob, msgType string, level string, text string) {
	b, _ := json.Marshal(map[string]string{
		"type":  msgType,
		"level": level,
		"text":  text,
	})

	job.mu.Lock()
	defer job.mu.Unlock()
	for _, ch := range job.Clients {
		ch <- string(b)
	}
}

func broadcastCompletion(job *ScanJob, metrics JobMetrics) {
	b, _ := json.Marshal(map[string]interface{}{
		"type":    "complete",
		"metrics": metrics,
	})

	job.mu.Lock()
	defer job.mu.Unlock()
	job.Metrics = &metrics
	job.done = true

	for _, ch := range job.Clients {
		ch <- string(b)
		close(ch)
	}
	job.Clients = nil
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
