package vault

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// createAPIKeyBody is what the Clavik API returns for a created key, byte for
// byte: marshalled from vault-srv's CreateApiKeyResponse with the gateway's
// default marshaler. The plaintext is "api_key", a SIBLING of "data" — which is
// why unwrapping the envelope to "data" lost it.
const createAPIKeyBody = `{"success":true, "status":201, "data":{"id":"key-1", "tenant_id":"t1", "name":"ci", "key_hash":"", "key_prefix":"vault_ab", "created_at":"1790000000", "expires_at":"0", "last_used_at":"0", "created_by":"", "metadata":{}, "scopes":["vault:cred_read"]}, "api_key":"vault_PLAINTEXT", "error":null}`

func createAPIKeyAgainst(t *testing.T, status int, body string) (*APIKeyWithSecret, map[string]any, error) {
	t.Helper()
	var sent map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/access/api-keys" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &sent)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)

	client, err := NewClient(WithEndpoint(srv.URL), WithAPIKey("vault_caller"), WithTenant("t1"), WithMaxRetries(0))
	if err != nil {
		t.Fatal(err)
	}
	key, err := client.Access().CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		Name:   "ci",
		Scopes: []string{"vault:cred_read"},
	})
	return key, sent, err
}

func TestCreateAPIKeyReturnsThePlaintextKey(t *testing.T) {
	key, sent, err := createAPIKeyAgainst(t, http.StatusCreated, createAPIKeyBody)
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	// The plaintext is shown exactly once. Losing it here leaves the caller
	// with a key that exists and can never be used.
	if key.Key != "vault_PLAINTEXT" {
		t.Errorf("Key = %q, want %q", key.Key, "vault_PLAINTEXT")
	}
	if key.ID != "key-1" || key.Name != "ci" || key.KeyPrefix != "vault_ab" || key.TenantID != "t1" {
		t.Errorf("metadata = {ID:%q Name:%q KeyPrefix:%q TenantID:%q}, want {key-1 ci vault_ab t1}",
			key.ID, key.Name, key.KeyPrefix, key.TenantID)
	}
	if got, _ := json.Marshal(sent["scopes"]); string(got) != `["vault:cred_read"]` {
		t.Errorf("request scopes = %s, want [\"vault:cred_read\"]", got)
	}
}

// A success that carries no plaintext must not look like a usable key. The key
// was created, so the error names it for the caller to revoke.
func TestCreateAPIKeyWithoutPlaintextIsAnError(t *testing.T) {
	body := strings.Replace(createAPIKeyBody, `"api_key":"vault_PLAINTEXT"`, `"api_key":""`, 1)
	key, _, err := createAPIKeyAgainst(t, http.StatusCreated, body)
	if err == nil {
		t.Fatalf("CreateAPIKey = %+v, want an error for a response with no key", key)
	}
	if key != nil {
		t.Errorf("key = %+v, want nil alongside the error", key)
	}
	if !strings.Contains(err.Error(), "key-1") {
		t.Errorf("error = %q, want it to name the created key id so it can be revoked", err)
	}
}

// A refused request is still the API's error, unchanged by decoding the full
// envelope here.
func TestCreateAPIKeyRefusalIsAValidationError(t *testing.T) {
	_, _, err := createAPIKeyAgainst(t, http.StatusBadRequest,
		`{"success":false, "status":400, "data":null, "api_key":"", "error":{"message":"scopes are required"}}`)
	if !errors.Is(err, ErrValidation) {
		t.Errorf("err = %v, want ErrValidation", err)
	}
}
