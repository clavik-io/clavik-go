package vault

import (
	"context"
	"net/http"
)

// PoliciesService provides methods for account security policies.
type PoliciesService struct {
	client *Client
}

// Get retrieves the account security policy.
func (s *PoliciesService) Get(ctx context.Context) (*SecurityPolicy, error) {
	var policy SecurityPolicy
	if err := s.client.do(ctx, http.MethodGet, buildPath("policies"), nil, &policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

// setPolicyRequest wraps the policy for the SetPolicy proto envelope.
type setPolicyRequest struct {
	Policy SecurityPolicy `json:"policy"`
}

// Set updates the account security policy.
func (s *PoliciesService) Set(ctx context.Context, policy SecurityPolicy) (*SecurityPolicy, error) {
	var result SecurityPolicy
	if err := s.client.do(ctx, http.MethodPut, buildPath("policies"), setPolicyRequest{Policy: policy}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
