package executor

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
)

// optimizedTransport is a shared transport with connection pooling for non-proxy clients.
var optimizedTransport = &http.Transport{
	MaxIdleConns:        500,
	MaxIdleConnsPerHost: 100,
	IdleConnTimeout:     120 * time.Second,
	DisableCompression:  true,
}

// defaultClient is the shared HTTP client for requests without proxy or custom RoundTripper.
var (
	defaultClient     *http.Client
	defaultClientOnce sync.Once
)

// proxyClients caches HTTP clients keyed by proxy URL to reuse connections.
var proxyClients sync.Map // proxyURL -> *http.Client

func getDefaultClient() *http.Client {
	defaultClientOnce.Do(func() {
		defaultClient = &http.Client{
			Transport: optimizedTransport,
		}
	})
	return defaultClient
}

func getProxyClient(proxyURL string) *http.Client {
	if val, ok := proxyClients.Load(proxyURL); ok {
		return val.(*http.Client)
	}
	transport := buildProxyTransport(proxyURL)
	if transport == nil {
		return nil
	}
	// Apply the same pool settings to proxy transports
	transport.MaxIdleConns = 500
	transport.MaxIdleConnsPerHost = 100
	transport.IdleConnTimeout = 120 * time.Second
	transport.DisableCompression = true
	client := &http.Client{Transport: transport}
	actual, _ := proxyClients.LoadOrStore(proxyURL, client)
	return actual.(*http.Client)
}

// newProxyAwareHTTPClient creates an HTTP client with proper proxy configuration priority:
// 1. Use auth.ProxyURL if configured (highest priority)
// 2. Use cfg.ProxyURL if auth proxy is not configured
// 3. Use RoundTripper from context if neither are configured
// 4. Use shared default client with optimized connection pooling
//
// Clients are cached by proxy URL to enable TCP connection reuse across requests.
//
// Parameters:
//   - ctx: The context containing optional RoundTripper
//   - cfg: The application configuration
//   - auth: The authentication information
//   - timeout: The client timeout (0 means no timeout)
//
// Returns:
//   - *http.Client: An HTTP client with configured proxy or transport
func newProxyAwareHTTPClient(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth, timeout time.Duration) *http.Client {
	// Priority 1: Use auth.ProxyURL if configured
	var proxyURL string
	if auth != nil {
		proxyURL = strings.TrimSpace(auth.ProxyURL)
	}

	// Priority 2: Use cfg.ProxyURL if auth proxy is not configured
	if proxyURL == "" && cfg != nil {
		proxyURL = strings.TrimSpace(cfg.ProxyURL)
	}

	// If we have a proxy URL configured, use cached proxy client
	if proxyURL != "" {
		if client := getProxyClient(proxyURL); client != nil {
			if timeout > 0 {
				// Return a shallow copy with the desired timeout;
				// the underlying Transport is still shared.
				return &http.Client{Transport: client.Transport, Timeout: timeout}
			}
			return client
		}
		// If proxy setup failed, log and fall through to context RoundTripper
		log.Debugf("failed to setup proxy from URL: %s, falling back to context transport", proxyURL)
	}

	// Priority 3: Use RoundTripper from context (typically from RoundTripperFor)
	// Context-based transports cannot be cached as they are per-request.
	if rt, ok := ctx.Value("cliproxy.roundtripper").(http.RoundTripper); ok && rt != nil {
		httpClient := &http.Client{Transport: rt}
		if timeout > 0 {
			httpClient.Timeout = timeout
		}
		return httpClient
	}

	// Priority 4: Use shared default client with optimized transport
	if timeout > 0 {
		return &http.Client{Transport: optimizedTransport, Timeout: timeout}
	}
	return getDefaultClient()
}

// buildProxyTransport creates an HTTP transport configured for the given proxy URL.
// It supports SOCKS5, HTTP, and HTTPS proxy protocols.
//
// Parameters:
//   - proxyURL: The proxy URL string (e.g., "socks5://user:pass@host:port", "http://host:port")
//
// Returns:
//   - *http.Transport: A configured transport, or nil if the proxy URL is invalid
func buildProxyTransport(proxyURL string) *http.Transport {
	transport, _, errBuild := proxyutil.BuildHTTPTransport(proxyURL)
	if errBuild != nil {
		log.Errorf("%v", errBuild)
		return nil
	}
	return transport
}
