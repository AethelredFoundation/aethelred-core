package keeper

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"crypto/tls"

	"github.com/aethelred/aethelred/internal/httpclient"
)

const (
	// httpClientTimeout is the maximum duration for HTTP requests.
	httpClientTimeout = 30 * time.Second
	// maxResponseSize is the maximum size of HTTP responses (10 MB).
	maxResponseSize = 10 * 1024 * 1024
	// maxIdleConns is the maximum number of idle connections.
	maxIdleConns = 10
	// idleConnTimeout is the timeout for idle connections.
	idleConnTimeout = 90 * time.Second
)

// secureHTTPClient creates an HTTP client with proper security configuration.
// SECURITY: Prevents DoS attacks via hanging connections and large responses.
func secureHTTPClient() *http.Client {
	return httpclient.NewPooledClient(httpclient.PoolConfig{
		Timeout:             httpClientTimeout,
		MaxIdleConns:        maxIdleConns,
		MaxIdleConnsPerHost: maxIdleConns,
		IdleConnTimeout:     idleConnTimeout,
		TLSHandshakeTimeout: 10 * time.Second,
		MinTLSVersion:       tls.VersionTLS12,
	})
}

// secureHTTPClientProvider is a test seam for remote verifier HTTP calls.
// Production code should not override this.
var secureHTTPClientProvider = secureHTTPClient

// validateEndpointURL validates that an endpoint URL is safe to call.
// SECURITY: Prevents SSRF attacks by validating URL structure.
func validateEndpointURL(endpoint string) error {
	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint URL: %w", err)
	}

	// Only allow HTTPS in production (HTTP only for localhost in dev).
	if parsedURL.Scheme != "https" {
		if parsedURL.Scheme == "http" {
			host := parsedURL.Hostname()
			if host != "localhost" && host != "127.0.0.1" && host != "::1" {
				return fmt.Errorf("HTTP endpoints only allowed for localhost, use HTTPS for remote endpoints")
			}
		} else {
			return fmt.Errorf("unsupported URL scheme: %s (only https allowed)", parsedURL.Scheme)
		}
	}

	// Block internal/private IP ranges to prevent SSRF.
	host := parsedURL.Hostname()
	blockedPrefixes := []string{
		"10.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
		"172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
		"172.30.", "172.31.", "192.168.", "169.254.",
	}
	for _, prefix := range blockedPrefixes {
		if strings.HasPrefix(host, prefix) {
			return fmt.Errorf("internal IP addresses are not allowed: %s", host)
		}
	}

	// Block metadata endpoints.
	blockedHosts := []string{
		"metadata.google.internal",
		"169.254.169.254", // AWS/GCP metadata
		"metadata.azure.com",
	}
	for _, blocked := range blockedHosts {
		if host == blocked {
			return fmt.Errorf("access to cloud metadata endpoints is blocked: %s", host)
		}
	}

	return nil
}

// limitedReader wraps an io.Reader with a size limit.
// SECURITY: Prevents memory exhaustion from large responses.
func limitedReader(r io.Reader, maxBytes int64) io.Reader {
	return io.LimitReader(r, maxBytes)
}
