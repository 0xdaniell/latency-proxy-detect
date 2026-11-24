package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// logEntry is one line of visits.jsonl.
type logEntry struct {
	*Result
	UserAgent string `json:"userAgent,omitempty"`
}

// store appends every result to <dataDir>/visits.jsonl and keeps the most
// recent ones in memory for the result and admin endpoints.
type store struct {
	mu     sync.Mutex
	file   *os.File
	recent []logEntry // newest last
	max    int
}

func openStore(dataDir string, max int) (*store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, "visits.jsonl")
	s := &store{max: max}

	// Load the tail of the existing log.
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			var e logEntry
			if json.Unmarshal(sc.Bytes(), &e) == nil && e.Result != nil {
				s.push(e)
			}
		}
		f.Close()
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	s.file = f
	return s, nil
}

func (s *store) push(e logEntry) {
	s.recent = append(s.recent, e)
	if len(s.recent) > s.max {
		s.recent = s.recent[len(s.recent)-s.max:]
	}
}

func (s *store) add(r *Result, userAgent string) {
	e := logEntry{Result: r, UserAgent: userAgent}
	b, _ := json.Marshal(e)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.file.Write(append(b, '\n'))
	s.push(e)
}

// result returns a recent result by ID, for browsers whose WebSocket died
// during the 0trace step. Results older than an hour are not served.
func (s *store) result(id string) *Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.recent) - 1; i >= 0; i-- {
		r := s.recent[i].Result
		if r.ID == id {
			if time.Since(r.Time) > time.Hour {
				return nil
			}
			return r
		}
	}
	return nil
}

// latest returns up to n entries, newest first.
func (s *store) latest(n int) []logEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n > len(s.recent) {
		n = len(s.recent)
	}
	out := make([]logEntry, 0, n)
	for i := len(s.recent) - 1; i >= len(s.recent)-n; i-- {
		out = append(out, s.recent[i])
	}
	return out
}
