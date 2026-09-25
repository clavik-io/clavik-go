package vault

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// verifySuccessBody is what the Clavik API returns for a signature that
// VERIFIES. The API serialises with unpopulated fields emitted, so the
// envelope's "data" is an empty nested response — `{"success":false,...}` —
// rather than being absent. VerifyResponse used to decode Valid from that
// inner "success", so a valid signature came back Valid == false (#1).
const verifySuccessBody = `{"success":true, "status":200, "data":{"success":false, "status":0, "data":null, "error":null}, "error":null}`

func verifyAgainst(t *testing.T, status int, body string) (*VerifyResponse, error) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/keys/verify" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)

	client, err := NewClient(WithEndpoint(srv.URL), WithAPIKey("vault_test"), WithTenant("t"), WithMaxRetries(0))
	if err != nil {
		t.Fatal(err)
	}
	return client.Keys().Verify(context.Background(), VerifyRequest{KeyID: "k", Data: "aGk=", Signature: "c2ln"})
}

func TestVerifyReportsAValidSignatureAsValid(t *testing.T) {
	resp, err := verifyAgainst(t, http.StatusOK, verifySuccessBody)
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil for a valid signature", err)
	}
	if !resp.Valid {
		t.Error("Verify() Valid = false for a valid signature; callers that check it reject every good signature")
	}
}

// The API reports a signature that does not match with a 400. That must stay
// an error — Valid is not how a mismatch is reported, and callers already
// branching on the error must see no change.
func TestVerifyReportsAMismatchAsAValidationError(t *testing.T) {
	resp, err := verifyAgainst(t, http.StatusBadRequest, `{"code":3,"message":"signature does not match","details":[]}`)
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("Verify() error = %v, want one matching ErrValidation", err)
	}
	if resp != nil {
		t.Errorf("Verify() response = %+v, want nil alongside the error", resp)
	}
}

// A server failure is neither a verdict of valid nor of mismatch.
func TestVerifyReportsAServerFailureAsAServerError(t *testing.T) {
	_, err := verifyAgainst(t, http.StatusInternalServerError, `{"code":13,"message":"failed to verify data","details":[]}`)
	if !errors.Is(err, ErrServerError) {
		t.Fatalf("Verify() error = %v, want one matching ErrServerError", err)
	}
}
