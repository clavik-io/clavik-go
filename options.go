package vault

import (
	"net/http"
	"strings"
	"time"
)

// Option configures a Client.
type Option func(*Client) error

// WithEndpoint sets the API base URL (default: https://api.clavik.io/api/v1).
func WithEndpoint(endpoint string) Option {
	return func(c *Client) error {
		c.baseURL = deriveBaseURL(endpoint)
		c.healthURL = deriveHealthURL(endpoint)
		return nil
	}
}

// WithHealthEndpoint sets the health check base URL explicitly.
func WithHealthEndpoint(url string) Option {
	return func(c *Client) error {
		c.healthURL = url
		return nil
	}
}

// WithAPIKey configures static API key authentication.
func WithAPIKey(apiKey string) Option {
	return func(c *Client) error {
		c.auth = &staticTokenAuth{token: apiKey}
		return nil
	}
}

// WithBearerToken configures authentication using a pre-existing bearer token
// (e.g., a Cidaas OAuth2 token already obtained externally).
func WithBearerToken(token string) Option {
	return func(c *Client) error {
		c.auth = &staticTokenAuth{token: token}
		return nil
	}
}

// WithOAuth2 configures OAuth2 client-credentials authentication via Cidaas.
func WithOAuth2(clientID, clientSecret, tokenURL string) Option {
	return func(c *Client) error {
		c.auth = &oauth2Auth{
			clientID:     clientID,
			clientSecret: clientSecret,
			tokenURL:     tokenURL,
			httpClient:   c.httpClient,
		}
		return nil
	}
}

// WithTenant sets the X-Tenant-Key header value (required).
func WithTenant(tenant string) Option {
	return func(c *Client) error {
		c.tenant = tenant
		return nil
	}
}

// WithHTTPClient sets a custom http.Client for API requests.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) error {
		c.httpClient = httpClient
		if oa, ok := c.auth.(*oauth2Auth); ok {
			oa.httpClient = httpClient
		}
		return nil
	}
}

// WithTimeout sets the HTTP client timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) error {
		c.httpClient.Timeout = timeout
		return nil
	}
}

// WithMaxRetries sets the maximum number of retries for transient failures.
func WithMaxRetries(maxRetries int) Option {
	return func(c *Client) error {
		c.maxRetries = maxRetries
		return nil
	}
}

// WithRetryBaseDelay sets the base delay for exponential backoff retries.
func WithRetryBaseDelay(delay time.Duration) Option {
	return func(c *Client) error {
		c.retryBase = delay
		return nil
	}
}

func deriveBaseURL(endpoint string) string {
	const suffix = "/api/v1"
	endpoint = strings.TrimRight(endpoint, "/")

	if strings.HasSuffix(endpoint, suffix) {
		return endpoint
	}

	return endpoint + suffix
}

func deriveHealthURL(endpoint string) string {
	const suffix = "/api/v1"
	endpoint = strings.TrimRight(endpoint, "/")

	if strings.HasSuffix(endpoint, suffix) {
		return strings.TrimSuffix(endpoint, suffix) + "/health"
	}

	return endpoint + "/health"
}
