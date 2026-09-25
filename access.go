package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// AccessService provides methods for access policies, principals, API keys, and users.
type AccessService struct {
	client *Client
}

// ListPolicies returns access policies filtered by resource or principal.
func (s *AccessService) ListPolicies(ctx context.Context, opts ListPoliciesOptions) ([]AccessPolicy, error) {
	params := url.Values{}
	addQueryParamEnum(params, "resource_type", opts.ResourceType)
	addQueryParam(params, "resource_id", opts.ResourceID)
	addQueryParam(params, "principal_id", opts.PrincipalID)
	addQueryParam(params, "search", opts.Search)

	var resp dataListResponse[AccessPolicy]
	if err := s.client.do(ctx, http.MethodGet, buildPathWithQuery(params, "access", "policies"), nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// GrantAccess creates an access policy linking a principal to a resource.
func (s *AccessService) GrantAccess(ctx context.Context, req GrantAccessRequest) (*AccessPolicy, error) {
	var policy AccessPolicy
	if err := s.client.do(ctx, http.MethodPost, buildPath("access", "policies"), req, &policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

// GetPolicy retrieves an access policy by ID.
func (s *AccessService) GetPolicy(ctx context.Context, id string) (*AccessPolicy, error) {
	var policy AccessPolicy
	if err := s.client.do(ctx, http.MethodGet, buildPath("access", "policies", id), nil, &policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

// UpdatePolicy updates the permissions granted by an access policy.
func (s *AccessService) UpdatePolicy(ctx context.Context, id string, req UpdatePolicyRequest) (*AccessPolicy, error) {
	var policy AccessPolicy
	if err := s.client.do(ctx, http.MethodPut, buildPath("access", "policies", id), req, &policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

// RevokeAccess deletes an access policy.
func (s *AccessService) RevokeAccess(ctx context.Context, id string) error {
	return s.client.do(ctx, http.MethodDelete, buildPath("access", "policies", id), nil, nil)
}

// ListPrincipals returns principals (users, groups, service accounts).
func (s *AccessService) ListPrincipals(ctx context.Context, opts ListPrincipalsOptions) ([]Principal, error) {
	params := url.Values{}
	addQueryParamEnum(params, "principal_type", opts.PrincipalType)
	addQueryParam(params, "search", opts.Search)

	var resp dataListResponse[Principal]
	if err := s.client.do(ctx, http.MethodGet, buildPathWithQuery(params, "access", "principals"), nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// ListAPIKeys returns all API keys (hashed — plaintext is never returned).
func (s *AccessService) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	var resp dataListResponse[APIKey]
	if err := s.client.do(ctx, http.MethodGet, buildPath("access", "api-keys"), nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// CreateAPIKey creates an API key. The full key is returned once in the response.
//
// The API returns the key's plaintext BESIDE the envelope's "data", not inside
// it:
//
//	{"success":true, "status":201, "data":{"id":...,"key_prefix":...}, "api_key":"vault_..."}
//
// so the envelope is decoded here in full. Unwrapping it to "data", as every
// other call does, discards the one field this call exists for.
func (s *AccessService) CreateAPIKey(ctx context.Context, req CreateAPIKeyRequest) (*APIKeyWithSecret, error) {
	var raw []byte
	if err := s.client.do(ctx, http.MethodPost, buildPath("access", "api-keys"), req, &raw); err != nil {
		return nil, err
	}
	var envelope struct {
		Data   json.RawMessage `json:"data"`
		APIKey string          `json:"api_key"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("vault: decode response: %w", err)
	}
	var key APIKeyWithSecret
	if len(envelope.Data) > 0 {
		if err := json.Unmarshal(envelope.Data, &key.APIKey); err != nil {
			return nil, fmt.Errorf("vault: decode response: %w", err)
		}
	}
	key.Key = envelope.APIKey
	// The plaintext is shown once and cannot be fetched again. A key without
	// it is unusable, so say so rather than hand back an empty Key. The key
	// was created, so the error names its id for the caller to revoke it.
	if key.Key == "" {
		return nil, fmt.Errorf("vault: create api key: response carried no key (created key id %q)", key.ID)
	}
	return &key, nil
}

// RevokeAPIKey revokes an API key.
func (s *AccessService) RevokeAPIKey(ctx context.Context, id string) error {
	return s.client.do(ctx, http.MethodDelete, buildPath("access", "api-keys", id), nil, nil)
}

// ListUsers returns users synced from Cidaas.
func (s *AccessService) ListUsers(ctx context.Context, opts ListUsersOptions) ([]User, error) {
	params := url.Values{}
	addQueryParamEnum(params, "status", opts.Status)
	addQueryParam(params, "search", opts.Search)

	var resp dataListResponse[User]
	if err := s.client.do(ctx, http.MethodGet, buildPathWithQuery(params, "access", "users"), nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}
