// server_select.go
package main

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"
)

type ServerSelector struct {
	HTTP         *http.Client
	HealthPath   string
	ProbeTimeout time.Duration

	AcceptStatus map[int]bool
	InsecureTLS  bool
	PreferLowest bool
}

type probeResult struct {
	addr    string
	latency time.Duration
}

// Select the lowest-latency Vault server from the list of provided addresses
// This is not meant to provide HA capabilities for this client
// It simply permits the use of a static client configuration that would use an
// alternative server upon restart if conditions have changed
func (s *ServerSelector) Select(ctx context.Context, addrs []string) (string, error) {
	results := make([]probeResult, 0, len(addrs))

	for _, a := range addrs {
		u, err := url.Parse(a)
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		pctx, cancel := context.WithTimeout(ctx, s.ProbeTimeout)
		lat, ok := s.probe(pctx, a)
		cancel()
		if ok {
			results = append(results, probeResult{addr: a, latency: lat})
		}
	}

	if len(results) == 0 {
		return "", errors.New("no responsive Vault servers")
	}

	best := results[0]
	for _, r := range results[1:] {
		if r.latency < best.latency {
			best = r
		}
	}
	return best.addr, nil
}

func (s *ServerSelector) probe(ctx context.Context, addr string) (time.Duration, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, addr+s.HealthPath, nil)
	if err != nil {
		return 0, false
	}
	start := time.Now()
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return 0, false
	}
	resp.Body.Close()

	if !s.AcceptStatus[resp.StatusCode] {
		return 0, false
	}
	return time.Since(start), true
}
