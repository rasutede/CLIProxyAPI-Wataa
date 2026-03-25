// Package claude provides authentication functionality for Anthropic's Claude API.
// This file implements a custom HTTP transport using utls to bypass TLS fingerprinting.
package claude

import (
	"net/http"
	"strings"
	"sync"

	tls "github.com/refraction-networking/utls"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

// utlsRoundTripper implements http.RoundTripper using utls with Chrome fingerprint
// to bypass Cloudflare's TLS fingerprinting on Anthropic domains.
// Uses sync.Map for lock-free reads on the hot path (cached connection hit).
type utlsRoundTripper struct {
	// connections caches HTTP/2 client connections per host (lock-free reads)
	connections sync.Map // map[string]*http2.ClientConn
	// pending provides per-host mutual exclusion for connection creation
	pending sync.Map // map[string]*pendingEntry
	// dialer is used to create network connections, supporting proxies
	dialer proxy.Dialer
}

// pendingEntry synchronizes concurrent connection creation for a single host.
type pendingEntry struct {
	mu   sync.Mutex
	conn *http2.ClientConn
	err  error
	done bool
}

// newUtlsRoundTripper creates a new utls-based round tripper with optional proxy support
func newUtlsRoundTripper(cfg *config.SDKConfig) *utlsRoundTripper {
	var dialer proxy.Dialer = proxy.Direct
	if cfg != nil {
		proxyDialer, mode, errBuild := proxyutil.BuildDialer(cfg.ProxyURL)
		if errBuild != nil {
			log.Errorf("failed to configure proxy dialer for %q: %v", cfg.ProxyURL, errBuild)
		} else if mode != proxyutil.ModeInherit && proxyDialer != nil {
			dialer = proxyDialer
		}
	}

	return &utlsRoundTripper{
		dialer: dialer,
	}
}

// getOrCreateConnection gets an existing connection or creates a new one.
// Hot path (cache hit) is lock-free via sync.Map.Load.
// Cold path (cache miss) uses per-host locking to prevent duplicate connections.
func (t *utlsRoundTripper) getOrCreateConnection(host, addr string) (*http2.ClientConn, error) {
	// Fast path: check cached connection (lock-free)
	if val, ok := t.connections.Load(host); ok {
		if h2Conn := val.(*http2.ClientConn); h2Conn.CanTakeNewRequest() {
			return h2Conn, nil
		}
		// Stale connection — remove it
		t.connections.Delete(host)
	}

	// Slow path: create new connection with per-host mutual exclusion
	entry := &pendingEntry{}
	entry.mu.Lock()

	if actual, loaded := t.pending.LoadOrStore(host, entry); loaded {
		// Another goroutine is already creating a connection for this host
		entry.mu.Unlock() // unlock our unused entry
		existing := actual.(*pendingEntry)
		existing.mu.Lock() // wait for the creator to finish
		existing.mu.Unlock()

		// Check if connection is now available
		if val, ok := t.connections.Load(host); ok {
			if h2Conn := val.(*http2.ClientConn); h2Conn.CanTakeNewRequest() {
				return h2Conn, nil
			}
		}
		// Connection still not available — retry (recursive but bounded)
		return t.getOrCreateConnection(host, addr)
	}

	// We won the race — create the connection
	h2Conn, err := t.createConnection(host, addr)

	// Store result and wake up waiters
	if err == nil {
		t.connections.Store(host, h2Conn)
	}
	t.pending.Delete(host)
	entry.mu.Unlock()

	if err != nil {
		return nil, err
	}
	return h2Conn, nil
}

// createConnection creates a new HTTP/2 connection with Chrome TLS fingerprint.
// Chrome's TLS fingerprint is closer to Node.js/OpenSSL (which real Claude Code uses)
// than Firefox, reducing the mismatch between TLS layer and HTTP headers.
func (t *utlsRoundTripper) createConnection(host, addr string) (*http2.ClientConn, error) {
	conn, err := t.dialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{ServerName: host}
	tlsConn := tls.UClient(conn, tlsConfig, tls.HelloChrome_Auto)

	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	tr := &http2.Transport{}
	h2Conn, err := tr.NewClientConn(tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, err
	}

	return h2Conn, nil
}

// RoundTrip implements http.RoundTripper
func (t *utlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	addr := host
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}

	// Get hostname without port for TLS ServerName
	hostname := req.URL.Hostname()

	h2Conn, err := t.getOrCreateConnection(hostname, addr)
	if err != nil {
		return nil, err
	}

	resp, err := h2Conn.RoundTrip(req)
	if err != nil {
		// Connection failed, remove it from cache if it's still the same one
		if cached, ok := t.connections.Load(hostname); ok && cached.(*http2.ClientConn) == h2Conn {
			t.connections.Delete(hostname)
		}
		return nil, err
	}

	return resp, nil
}

// NewAnthropicHttpClient creates an HTTP client that bypasses TLS fingerprinting
// for Anthropic domains by using utls with Chrome fingerprint.
// It accepts optional SDK configuration for proxy settings.
func NewAnthropicHttpClient(cfg *config.SDKConfig) *http.Client {
	return &http.Client{
		Transport: newUtlsRoundTripper(cfg),
	}
}
