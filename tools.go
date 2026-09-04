package vault

import (
	"context"
	"net/http"
)

// ToolsService provides one-off cryptographic utilities.
type ToolsService struct {
	client *Client
}

// Random generates cryptographically secure random bytes.
func (s *ToolsService) Random(ctx context.Context, req RandomRequest) (*RandomResponse, error) {
	var resp RandomResponse
	if err := s.client.do(ctx, http.MethodPost, buildPath("tools", "random"), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Hash computes a cryptographic hash.
func (s *ToolsService) Hash(ctx context.Context, req HashRequest) (*HashResponse, error) {
	var resp HashResponse
	if err := s.client.do(ctx, http.MethodPost, buildPath("tools", "hash"), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Wrap envelope-encrypts plaintext with a managed key.
func (s *ToolsService) Wrap(ctx context.Context, req WrapRequest) (*WrapResponse, error) {
	var resp WrapResponse
	if err := s.client.do(ctx, http.MethodPost, buildPath("tools", "wrap"), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Unwrap decrypts data previously wrapped with a managed key.
func (s *ToolsService) Unwrap(ctx context.Context, req UnwrapRequest) (*UnwrapResponse, error) {
	var resp UnwrapResponse
	if err := s.client.do(ctx, http.MethodPost, buildPath("tools", "unwrap"), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
