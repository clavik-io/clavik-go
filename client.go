package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Client is the Clavik Vault REST API client.
type Client struct {
	baseURL    string
	healthURL  string
	tenant     string
	httpClient *http.Client
	auth       tokenProvider
	maxRetries int
	retryBase  time.Duration

	secrets    *SecretsService
	keys       *KeysService
	folders    *FoldersService
	access     *AccessService
	tools      *ToolsService
	algorithms *AlgorithmsService
	policies   *PoliciesService
	activity   *ActivityService
	compliance *ComplianceService
	health     *HealthService
}

type tokenProvider interface {
	Token(ctx context.Context) (string, error)
}

type staticTokenAuth struct {
	token string
}

func (a *staticTokenAuth) Token(_ context.Context) (string, error) {
	return a.token, nil
}

type oauth2Auth struct {
	clientID     string
	clientSecret string
	tokenURL     string
	httpClient   *http.Client

	mu          sync.Mutex
	accessToken string
	expiresAt   time.Time
}

type oauth2TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

const (
	defaultTimeout    = 30 * time.Second
	defaultMaxRetries = 3
	defaultRetryBase  = 500 * time.Millisecond
)

func (a *oauth2Auth) Token(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.accessToken != "" && time.Now().Before(a.expiresAt.Add(-30*time.Second)) {
		return a.accessToken, nil
	}

	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {a.clientID},
		"client_secret": {a.clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.tokenURL, strings.NewReader(body.Encode()))
	if err != nil {
		return "", fmt.Errorf("vault: create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := a.httpClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault: fetch oauth token: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("vault: read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vault: oauth token request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var tokenResp oauth2TokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return "", fmt.Errorf("vault: decode token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", errors.New("vault: oauth token response missing access_token")
	}

	a.accessToken = tokenResp.AccessToken
	if tokenResp.ExpiresIn > 0 {
		a.expiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	} else {
		a.expiresAt = time.Now().Add(time.Hour)
	}

	return a.accessToken, nil
}

// NewClient creates a new Clavik Vault API client.
func NewClient(opts ...Option) (*Client, error) {
	c := &Client{
		httpClient: &http.Client{Timeout: defaultTimeout},
		maxRetries: defaultMaxRetries,
		retryBase:  defaultRetryBase,
	}

	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}

	if c.tenant == "" {
		return nil, errors.New("vault: tenant is required; use WithTenant")
	}
	if c.auth == nil {
		return nil, errors.New("vault: authentication is required; use WithAPIKey, WithBearerToken, or WithOAuth2")
	}

	c.secrets = &SecretsService{client: c}
	c.keys = &KeysService{client: c}
	c.folders = &FoldersService{client: c}
	c.access = &AccessService{client: c}
	c.tools = &ToolsService{client: c}
	c.algorithms = &AlgorithmsService{client: c}
	c.policies = &PoliciesService{client: c}
	c.activity = &ActivityService{client: c}
	c.compliance = &ComplianceService{client: c}
	c.health = &HealthService{client: c}

	return c, nil
}

func (c *Client) Secrets() *SecretsService       { return c.secrets }
func (c *Client) Keys() *KeysService             { return c.keys }
func (c *Client) Folders() *FoldersService       { return c.folders }
func (c *Client) Access() *AccessService         { return c.access }
func (c *Client) Tools() *ToolsService           { return c.tools }
func (c *Client) Algorithms() *AlgorithmsService { return c.algorithms }
func (c *Client) Policies() *PoliciesService     { return c.policies }
func (c *Client) Activity() *ActivityService     { return c.activity }
func (c *Client) Compliance() *ComplianceService { return c.compliance }
func (c *Client) Health() *HealthService         { return c.health }

type requestOptions struct {
	skipAuth bool
	baseURL  string
	fullURL  string
}

func (c *Client) do(ctx context.Context, method, path string, body any, result any, opts ...requestOptions) error {
	var ro requestOptions
	if len(opts) > 0 {
		ro = opts[0]
	}

	baseURL := c.baseURL
	if ro.baseURL != "" {
		baseURL = ro.baseURL
	}

	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("vault: marshal request body: %w", err)
		}
	}

	reqURL := baseURL + path
	if ro.fullURL != "" {
		reqURL = ro.fullURL
	}

	var lastErr error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			delay := c.retryBase * time.Duration(1<<(attempt-1))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}

		var reqBody io.Reader
		if bodyBytes != nil {
			reqBody = bytes.NewReader(bodyBytes)
		}

		req, err := http.NewRequestWithContext(ctx, method, reqURL, reqBody)
		if err != nil {
			return fmt.Errorf("vault: create request: %w", err)
		}

		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		if !ro.skipAuth {
			token, err := c.auth.Token(ctx)
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("X-Tenant-Key", c.tenant)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("vault: request failed: %w", err)
			continue
		}

		respBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("vault: read response: %w", readErr)
			continue
		}

		if resp.StatusCode >= 500 {
			lastErr = parseAPIError(resp.StatusCode, respBody)
			continue
		}

		if resp.StatusCode >= 400 {
			return parseAPIError(resp.StatusCode, respBody)
		}

		if result == nil {
			return nil
		}

		if len(respBody) == 0 {
			return nil
		}

		if raw, ok := result.(*[]byte); ok {
			*raw = respBody
			return nil
		}

		respBody = unwrapEnvelope(respBody)

		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("vault: decode response: %w", err)
		}

		return nil
	}

	if lastErr != nil {
		return lastErr
	}
	return errors.New("vault: request failed after retries")
}

// unwrapEnvelope detects the Clavik API envelope {"success":bool,"status":int,"data":...,"error":...}
// and returns the inner "data" payload. If the body is not an envelope, it is returned unchanged.
func unwrapEnvelope(body []byte) []byte {
	var envelope struct {
		Success *bool           `json:"success"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil || envelope.Success == nil {
		return body
	}
	if len(envelope.Data) == 0 {
		return body
	}
	return []byte(envelope.Data)
}

func parseAPIError(statusCode int, body []byte) error {
	apiErr := &APIError{StatusCode: statusCode}

	var errBody struct {
		Message string          `json:"message"`
		Error   string          `json:"error"`
		Details json.RawMessage `json:"details"`
	}
	if err := json.Unmarshal(body, &errBody); err == nil {
		switch {
		case errBody.Message != "":
			apiErr.Message = errBody.Message
		case errBody.Error != "":
			apiErr.Message = errBody.Error
		default:
			apiErr.Message = string(body)
		}
		apiErr.Details = errBody.Details
	} else if len(body) > 0 {
		apiErr.Message = string(body)
	}

	return apiErr
}

// buildPath constructs a URL path from segments, escaping each for safe inclusion.
func buildPath(segments ...string) string {
	var b strings.Builder
	for _, seg := range segments {
		b.WriteByte('/')
		b.WriteString(url.PathEscape(seg))
	}
	return b.String()
}

// buildPathWithQuery constructs a URL path from segments and appends query parameters.
func buildPathWithQuery(params url.Values, segments ...string) string {
	path := buildPath(segments...)
	if len(params) == 0 {
		return path
	}
	return path + "?" + params.Encode()
}

func addQueryParam(params url.Values, key, value string) {
	if value != "" {
		params.Set(key, value)
	}
}

func addQueryParamInt32(params url.Values, key string, value int32) {
	if value > 0 {
		params.Set(key, fmt.Sprintf("%d", value))
	}
}

func addQueryParamEnum[T ~string](params url.Values, key string, value T) {
	if value != "" {
		params.Set(key, string(value))
	}
}
