package vault

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

// SecretsService provides methods for managing secrets.
type SecretsService struct {
	client *Client
}

// Create creates a new encrypted secret.
func (s *SecretsService) Create(ctx context.Context, req CreateSecretRequest) (*Secret, error) {
	var secret Secret
	if err := s.client.do(ctx, http.MethodPost, buildPath("secrets"), req, &secret); err != nil {
		return nil, err
	}
	return &secret, nil
}

// List returns a paginated list of secrets.
func (s *SecretsService) List(ctx context.Context, opts ListSecretsOptions) (*ListResponse[Secret], error) {
	params := url.Values{}
	addQueryParam(params, "folder_id", opts.FolderID)
	addQueryParamEnum(params, "secret_type", opts.SecretType)
	addQueryParam(params, "search", opts.Search)
	addQueryParamInt32(params, "skip", opts.Skip)
	addQueryParamInt32(params, "limit", opts.Limit)

	var resp ListResponse[Secret]
	if err := s.client.do(ctx, http.MethodGet, buildPathWithQuery(params, "secrets"), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Get retrieves a secret by ID.
func (s *SecretsService) Get(ctx context.Context, id string) (*Secret, error) {
	var secret Secret
	if err := s.client.do(ctx, http.MethodGet, buildPath("secrets", id), nil, &secret); err != nil {
		return nil, err
	}
	return &secret, nil
}

// Update updates a secret's value, name, or expiration.
func (s *SecretsService) Update(ctx context.Context, id string, req UpdateSecretRequest) (*Secret, error) {
	var secret Secret
	if err := s.client.do(ctx, http.MethodPut, buildPath("secrets", id), req, &secret); err != nil {
		return nil, err
	}
	return &secret, nil
}

// Delete permanently deletes a secret.
func (s *SecretsService) Delete(ctx context.Context, id string) error {
	return s.client.do(ctx, http.MethodDelete, buildPath("secrets", id), nil, nil)
}

// ListVersions returns the version history of a secret.
func (s *SecretsService) ListVersions(ctx context.Context, id string) ([]SecretVersion, error) {
	var resp dataListResponse[SecretVersion]
	if err := s.client.do(ctx, http.MethodGet, buildPath("secrets", id, "versions"), nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// RevertVersion reverts a secret to a previous version.
func (s *SecretsService) RevertVersion(ctx context.Context, id string, version int) error {
	return s.client.do(ctx, http.MethodPost, buildPath("secrets", id, "versions", strconv.Itoa(version), "revert"), nil, nil)
}
