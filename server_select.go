// server_select.go
package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

type ServerSelector struct {
	HTTP         *http.Client
	HealthPath   string
	ProbeTimeout time.Duration
	Logger       *log.Logger

	AcceptStatus map[int]bool
	InsecureTLS  bool
	PreferLowest bool
}

type probeResult struct {
	addr    string
	latency time.Duration
}

// Select the lowest-latency Vault server from the list of provided addresses
func (s *ServerSelector) Select(ctx context.Context, addrs []string) (string, error) {
	results := make([]probeResult, 0, len(addrs))

	for _, a := range addrs {
		u, err := url.Parse(a)
		if err != nil || u.Scheme == "" || u.Host == "" {
			if s.Logger != nil {
				s.Logger.Printf("DEBUG: skipping invalid address %q: parse error", a)
			}
			continue
		}
		pctx, cancel := context.WithTimeout(ctx, s.ProbeTimeout)
		lat, ok := s.probe(pctx, a)
		cancel()
		if ok {
			results = append(results, probeResult{addr: a, latency: lat})
			if s.Logger != nil {
				s.Logger.Printf("DEBUG: server selection: %s is responsive (latency: %v)", a, lat)
			}
		} else if s.Logger != nil {
			s.Logger.Printf("DEBUG: server selection: %s is not responsive", a)
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

// SelectAlternative probes the given addresses and returns the first one that is responsive.
// This is used for failover when the primary server is no longer available.
func (s *ServerSelector) SelectAlternative(ctx context.Context, addrs []string) (string, error) {
	for _, addr := range addrs {
		u, err := url.Parse(addr)
		if err != nil || u.Scheme == "" || u.Host == "" {
			if s.Logger != nil {
				s.Logger.Printf("DEBUG: failover: skipping invalid address %q", addr)
			}
			continue
		}
		pctx, cancel := context.WithTimeout(ctx, s.ProbeTimeout)
		lat, ok := s.probe(pctx, addr)
		cancel()
		if ok {
			if s.Logger != nil {
				s.Logger.Printf("INFO: failover: found healthy alternative server: %s (latency: %v)", addr, lat)
			}
			return addr, nil
		}
	}
	return "", errors.New("no responsive alternative servers found")
}

func (s *ServerSelector) probe(ctx context.Context, addr string) (time.Duration, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, addr+s.HealthPath, nil)
	if err != nil {
		if s.Logger != nil {
			s.Logger.Printf("DEBUG: probe %s: failed to create request: %v", addr, err)
		}
		return 0, false
	}
	start := time.Now()
	resp, err := s.HTTP.Do(req)
	if err != nil {
		if s.Logger != nil {
			s.Logger.Printf("DEBUG: probe %s: HTTP request failed: %v", addr, err)
		}
		return 0, false
	}
	defer resp.Body.Close()

	// Consume and discard body to ensure proper connection reuse
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))

	lat := time.Since(start)
	if !s.AcceptStatus[resp.StatusCode] {
		if s.Logger != nil {
			acceptedCodes := make([]int, 0, len(s.AcceptStatus))
			for code := range s.AcceptStatus {
				acceptedCodes = append(acceptedCodes, code)
			}
			s.Logger.Printf("DEBUG: probe %s: status code %d not in accepted codes %v", addr, resp.StatusCode, acceptedCodes)
		}
		return 0, false
	}
	return lat, true
}
