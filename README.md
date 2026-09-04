<div align="center">

# Vault Go SDK

**Official Go client for the [Clavik Vault API](https://clavik.io)**

[![Go Reference](https://pkg.go.dev/badge/github.com/clavik-io/vault-go.svg)](https://pkg.go.dev/github.com/clavik-io/vault-go)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

</div>

---

## Requirements

- Go 1.22+
- No external dependencies (uses `net/http` and `encoding/json` only)

## Installation

```bash
go get github.com/clavik-io/vault-go
```

## Quick Start

### API Key Authentication

```go
package main

import (
	"context"
	"log"

	vault "github.com/clavik-io/vault-go"
)

func main() {
	ctx := context.Background()

	client, err := vault.NewClient(
		vault.WithEndpoint("https://api.clavik.io/api/v1"),
		vault.WithAPIKey("vk_live_..."),
		vault.WithTenant("my-account"),
	)
	if err != nil {
		log.Fatal(err)
	}

	secret, err := client.Secrets().Create(ctx, vault.CreateSecretRequest{
		Name:       "prod-db",
		SecretType: vault.SecretTypePassword,
		Password: &vault.SecretPassword{
			Username: "admin",
			Password: "s3cret",
			URL:      "https://db.example.com",
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("created secret: %s", secret.ID)
}
```

### Bearer Token Authentication

Use `WithBearerToken` when you already have a Cidaas OAuth2 token obtained through your own authentication flow:

```go
client, err := vault.NewClient(
	vault.WithEndpoint("https://api.clavik.io/api/v1"),
	vault.WithBearerToken("eyJhbGciOi..."),
	vault.WithTenant("my-account"),
)
```

### OAuth2 Client Credentials

Use `WithOAuth2` to let the SDK handle the full client-credentials flow, including automatic token refresh:

```go
client, err := vault.NewClient(
	vault.WithEndpoint("https://api.clavik.io/api/v1"),
	vault.WithOAuth2("client-id", "client-secret", "https://auth.cidaas.io/token"),
	vault.WithTenant("my-account"),
)
```

## Authentication

All three auth methods set the `Authorization: Bearer <token>` header. Choose one per client:

| Option | Use case |
| --- | --- |
| `WithAPIKey(key)` | Machine/CI access with a scoped API key |
| `WithBearerToken(token)` | Pre-existing bearer token (e.g., Cidaas token from your own flow) |
| `WithOAuth2(id, secret, url)` | Automatic client-credentials flow with token caching and refresh |

Every authenticated request also sends `X-Tenant-Key: <tenant-id>`.

## Services

The client exposes service-grouped methods:

| Service | Methods |
| --- | --- |
| `Secrets()` | Create, List, Get, Update, Delete, ListVersions, GetVersion, RevertVersion |
| `Keys()` | Create, List, Get, Delete, ListVersions, GetVersion, DeactivateVersion, Rotate, Encrypt, Decrypt, Sign, Verify |
| `Folders()` | Create, List, Get, Update, Delete, ListPermissions, GrantPermission, RemovePermission |
| `Access()` | ListPolicies, GrantAccess, GetPolicy, UpdatePolicy, RevokeAccess, ListPrincipals, ListAPIKeys, CreateAPIKey, RevokeAPIKey, ListUsers |
| `Tools()` | Random, Hash, Wrap, Unwrap |
| `Algorithms()` | ListSupported, GetRecommended |
| `Policies()` | Get, Set |
| `Activity()` | List, Get |
| `Compliance()` | GetReport |
| `Health()` | Check |

## Examples

### Secrets

```go
// Create a secret
secret, err := client.Secrets().Create(ctx, vault.CreateSecretRequest{
	Name:       "prod-db",
	SecretType: vault.SecretTypePassword,
	Password: &vault.SecretPassword{
		Username: "admin",
		Password: "s3cret",
		URL:      "https://db.example.com",
	},
})

// List secrets in a folder
secrets, err := client.Secrets().List(ctx, vault.ListSecretsOptions{
	FolderID: "folder-id",
	Limit:    20,
})

// Read a specific version
ver, err := client.Secrets().GetVersion(ctx, secret.ID, 1)
```

### Key Management & Crypto Operations

```go
// Create a signing key
key, err := client.Keys().Create(ctx, vault.CreateKeyRequest{
	Name:      "payments-signer",
	KeyType:   vault.KeyTypeSigning,
	Algorithm: "ES256",
})

// Rotate to a new version
rotated, err := client.Keys().Rotate(ctx, key.ID)

// Sign data
sig, err := client.Keys().Sign(ctx, vault.SignRequest{
	KeyID: key.ID,
	Data:  "base64-encoded-payload",
})

// Verify a signature
result, err := client.Keys().Verify(ctx, vault.VerifyRequest{
	KeyID:     key.ID,
	Data:      "base64-encoded-payload",
	Signature: sig.Data,
})
log.Printf("valid: %v", result.Valid)

// Encrypt / decrypt
ct, err := client.Keys().Encrypt(ctx, vault.EncryptRequest{
	KeyID: encKey.ID,
	Data:  "base64-encoded-plaintext",
})
pt, err := client.Keys().Decrypt(ctx, vault.DecryptRequest{
	KeyID: encKey.ID,
	Data:  ct.Data,
})
```

### Crypto Tools

```go
random, err := client.Tools().Random(ctx, vault.RandomRequest{Length: 32})

hash, err := client.Tools().Hash(ctx, vault.HashRequest{
	Algorithm: vault.HashAlgorithmSHA256,
	Data:      "payload",
})

wrapped, err := client.Tools().Wrap(ctx, vault.WrapRequest{
	KeyID:     encKey.ID,
	Plaintext: "secret-material",
})
```

### Folders & Permissions

```go
folder, err := client.Folders().Create(ctx, vault.CreateFolderRequest{
	Name:       "production",
	FolderType: vault.FolderTypeCredentials,
})

err = client.Folders().GrantPermission(ctx, folder.ID, vault.GrantPermissionRequest{
	UserID: "user-id",
	Roles:  []vault.FolderPermissionRole{vault.FolderPermissionRoleRead},
})
```

### Health Check

The health endpoint is served at the API root (not under `/api/v1`) and requires no authentication:

```go
health, err := client.Health().Check(ctx)
// health.Status == "SERVING"
```

## Configuration Options

| Option | Description | Default |
| --- | --- | --- |
| `WithEndpoint(url)` | API base URL | `https://api.clavik.io/api/v1` |
| `WithHealthEndpoint(url)` | Override health check URL | derived from endpoint |
| `WithAPIKey(key)` | Static API key authentication | — |
| `WithBearerToken(token)` | Pre-existing bearer token | — |
| `WithOAuth2(id, secret, url)` | OAuth2 client-credentials flow | — |
| `WithTenant(tenant)` | Required `X-Tenant-Key` header value | — |
| `WithHTTPClient(client)` | Custom `http.Client` | default with 30s timeout |
| `WithTimeout(duration)` | HTTP client timeout | 30s |
| `WithMaxRetries(n)` | Max retries for 5xx/network errors | 3 |
| `WithRetryBaseDelay(d)` | Base exponential backoff delay | 500ms |

## Error Handling

The SDK defines typed sentinel errors and a structured `APIError`:

```go
secret, err := client.Secrets().Get(ctx, "missing-id")
if errors.Is(err, vault.ErrNotFound) {
	// handle missing secret
}

var apiErr *vault.APIError
if errors.As(err, &apiErr) {
	log.Printf("status=%d message=%s", apiErr.StatusCode, apiErr.Message)
}
```

| Error | HTTP Status |
| --- | --- |
| `ErrValidation` | 400 |
| `ErrUnauthorized` | 401 |
| `ErrForbidden` | 403 |
| `ErrNotFound` | 404 |
| `ErrServerError` | 500+ |

Transient server and network errors are automatically retried with exponential backoff.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Follow [conventional commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, etc.)
4. Add tests for new functionality
5. Open a pull request

## License

[GPL-3.0](https://www.gnu.org/licenses/gpl-3.0) — see the organisation [LICENSE](https://github.com/clavik-io/.github/blob/main/LICENSE) for details.
