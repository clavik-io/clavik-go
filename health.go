package vault

import (
	"context"
	"net/http"
	"strings"
)

// HealthService provides health check methods.
type HealthService struct {
	client *Client
}

// Check performs a liveness/readiness check. No authentication is required.
// The health endpoint may return plain text (e.g. "healthy") or JSON.
func (s *HealthService) Check(ctx context.Context) (HealthResponse, error) {
	var raw []byte
	if err := s.client.do(ctx, http.MethodGet, "", nil, &raw, requestOptions{
		skipAuth: true,
		fullURL:  s.client.healthURL,
	}); err != nil {
		return "", err
	}

	return HealthResponse(strings.TrimSpace(string(raw))), nil
}
