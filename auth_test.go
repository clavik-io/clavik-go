package vault

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// An API key must travel as "Authorization: Bearer <key>". The Clavik API's
// hand-written routes — the compliance report, access users, key and secret
// versions, folder permission changes — read that header and nothing else, so a
// key sent only as X-Access-Token is never looked up there and the call fails
// with 401. The other routes accept either header, which is why a client
// sending X-Access-Token looks fine until it reaches one of these.
func TestAPIKeyIsSentAsAuthorizationBearer(t *testing.T) {
	calls := []struct {
		name string
		call func(*Client) error
	}{
		{"hand-written route: compliance report", func(c *Client) error {
			_, err := c.Compliance().GetReport(context.Background())
			return err
		}},
		{"hand-written route: secret versions", func(c *Client) error {
			_, err := c.Secrets().ListVersions(context.Background(), "s1")
			return err
		}},
		{"gateway route: get key", func(c *Client) error {
			_, err := c.Keys().Get(context.Background(), "k1")
			return err
		}},
	}
	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			var got http.Header
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Header.Clone()
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"success":true, "status":200, "data":{}, "error":null}`)
			}))
			t.Cleanup(srv.Close)

			client, err := NewClient(WithEndpoint(srv.URL), WithAPIKey("vault_test"), WithTenant("t1"), WithMaxRetries(0))
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.call(client); err != nil {
				t.Fatalf("call failed: %v", err)
			}

			if a := got.Get("Authorization"); a != "Bearer vault_test" {
				t.Errorf("Authorization = %q, want %q", a, "Bearer vault_test")
			}
			// A second copy of the key in another header is not harmless: the
			// server refuses a request presenting two distinct credentials,
			// and a stale copy would be exactly that.
			if x := got.Get("X-Access-Token"); x != "" {
				t.Errorf("X-Access-Token = %q, want it unset", x)
			}
			if tk := got.Get("X-Tenant-Key"); tk != "t1" {
				t.Errorf("X-Tenant-Key = %q, want %q", tk, "t1")
			}
		})
	}
}
