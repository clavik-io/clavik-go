package vault

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

// KeysService provides methods for cryptographic key lifecycle and operations.
type KeysService struct {
	client *Client
}

// Create generates a new cryptographic key.
func (s *KeysService) Create(ctx context.Context, req CreateKeyRequest) (*Key, error) {
	var key Key
	if err := s.client.do(ctx, http.MethodPost, buildPath("keys"), req, &key); err != nil {
		return nil, err
	}
	return &key, nil
}

// List returns a paginated list of keys.
func (s *KeysService) List(ctx context.Context, opts ListKeysOptions) (*ListResponse[Key], error) {
	params := url.Values{}
	addQueryParam(params, "folder_id", opts.FolderID)
	addQueryParam(params, "search", opts.Search)
	addQueryParamInt32(params, "skip", opts.Skip)
	addQueryParamInt32(params, "limit", opts.Limit)

	var resp ListResponse[Key]
	if err := s.client.do(ctx, http.MethodGet, buildPathWithQuery(params, "keys"), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Get retrieves key metadata by ID.
func (s *KeysService) Get(ctx context.Context, id string) (*Key, error) {
	var key Key
	if err := s.client.do(ctx, http.MethodGet, buildPath("keys", id), nil, &key); err != nil {
		return nil, err
	}
	return &key, nil
}

// Delete deletes a key and all its versions.
func (s *KeysService) Delete(ctx context.Context, id string) error {
	return s.client.do(ctx, http.MethodDelete, buildPath("keys", id), nil, nil)
}

// ListVersions returns all versions of a key.
func (s *KeysService) ListVersions(ctx context.Context, id string) ([]KeyVersion, error) {
	var resp dataListResponse[KeyVersion]
	if err := s.client.do(ctx, http.MethodGet, buildPath("keys", id, "versions"), nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// GetVersion returns a specific version of a key.
func (s *KeysService) GetVersion(ctx context.Context, id, version string) (*KeyVersion, error) {
	var kv KeyVersion
	if err := s.client.do(ctx, http.MethodGet, buildPath("keys", id, "versions", version), nil, &kv); err != nil {
		return nil, err
	}
	return &kv, nil
}

// DeactivateVersion disables a specific key version.
func (s *KeysService) DeactivateVersion(ctx context.Context, id string, version int32) error {
	return s.client.do(ctx, http.MethodPost, buildPath("keys", id, "versions", strconv.Itoa(int(version)), "deactivate"), nil, nil)
}

// Rotate creates a new key version while keeping prior versions available.
func (s *KeysService) Rotate(ctx context.Context, id string) (*Key, error) {
	var key Key
	if err := s.client.do(ctx, http.MethodPost, buildPath("keys", id, "rotate"), nil, &key); err != nil {
		return nil, err
	}
	return &key, nil
}

// Encrypt encrypts plaintext using a managed key.
func (s *KeysService) Encrypt(ctx context.Context, req EncryptRequest) (*EncryptResponse, error) {
	var resp EncryptResponse
	if err := s.client.do(ctx, http.MethodPost, buildPath("keys", "encrypt"), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Decrypt decrypts ciphertext using a managed key.
func (s *KeysService) Decrypt(ctx context.Context, req DecryptRequest) (*DecryptResponse, error) {
	var resp DecryptResponse
	if err := s.client.do(ctx, http.MethodPost, buildPath("keys", "decrypt"), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Sign produces a cryptographic signature over data.
func (s *KeysService) Sign(ctx context.Context, req SignRequest) (*SignResponse, error) {
	var resp SignResponse
	if err := s.client.do(ctx, http.MethodPost, buildPath("keys", "sign"), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Verify verifies a signature against data.
//
// A nil error means the signature is valid, and the returned response has
// Valid set to true. A signature that does not match is reported as an error
// matching ErrValidation, not as a response with Valid false; any other error
// means the verification could not be performed.
func (s *KeysService) Verify(ctx context.Context, req VerifyRequest) (*VerifyResponse, error) {
	var resp VerifyResponse
	if err := s.client.do(ctx, http.MethodPost, buildPath("keys", "verify"), req, &resp); err != nil {
		return nil, err
	}
	// The API gives its verdict through the HTTP status — a mismatch is a
	// 400 and never reaches here — so a successful response IS a valid
	// signature. Set Valid from that, not from the body: the envelope's inner
	// "data" is an empty nested response whose own "success" is false, and
	// decoding Valid from it reported every valid signature as invalid (#1).
	resp.Valid = true
	return &resp, nil
}
