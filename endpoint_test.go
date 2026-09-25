package vault

import "testing"

// Without WithEndpoint the client must talk to the hosted service. It used to
// be left with an empty base URL, so every request failed while the docs
// named a default (and that default, api.clavik.io, does not resolve).
func TestEndpointDefaults(t *testing.T) {
	cases := []struct {
		name       string
		opts       []Option
		wantBase   string
		wantHealth string
	}{
		{"no endpoint: the hosted service", nil,
			"https://portal.clavik.de/api/v1", "https://portal.clavik.de/health"},
		{"host only", []Option{WithEndpoint("https://clavik.example.com")},
			"https://clavik.example.com/api/v1", "https://clavik.example.com/health"},
		{"host with /api/v1", []Option{WithEndpoint("https://clavik.example.com/api/v1/")},
			"https://clavik.example.com/api/v1", "https://clavik.example.com/health"},
		{"health override alone is kept", []Option{WithHealthEndpoint("https://health.example.com/health")},
			"https://portal.clavik.de/api/v1", "https://health.example.com/health"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := append([]Option{WithAPIKey("vault_x"), WithTenant("t")}, tc.opts...)
			c, err := NewClient(opts...)
			if err != nil {
				t.Fatal(err)
			}
			if c.baseURL != tc.wantBase {
				t.Errorf("baseURL = %q, want %q", c.baseURL, tc.wantBase)
			}
			if c.healthURL != tc.wantHealth {
				t.Errorf("healthURL = %q, want %q", c.healthURL, tc.wantHealth)
			}
		})
	}
}
