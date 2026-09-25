package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"os"
	"strings"

	vault "github.com/clavik-io/clavik-go"
)

func main() {
	ctx := context.Background()

	token := os.Getenv("VAULT_BEARER_TOKEN")
	tenant := os.Getenv("VAULT_TENANT_KEY")
	endpoint := os.Getenv("VAULT_ENDPOINT")
	isAPIKey := strings.HasPrefix(token, "vault_")

	client, err := vault.NewClient(
		vault.WithEndpoint(endpoint),
		// vault.WithBearerToken(token),
		vault.WithAPIKey(token),
		vault.WithTenant(tenant),
	)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	// ---------------------------------------------------------------
	// Health
	// ---------------------------------------------------------------
	health, err := client.Health().Check(ctx)
	if err != nil {
		log.Fatalf("Error: %v", err)
		return
	}
	log.Printf("[health] status=%s\n", health)

	// ---------------------------------------------------------------
	// Folders
	// ---------------------------------------------------------------
	credsFolder, err := client.Folders().Create(ctx, vault.CreateFolderRequest{
		Name:       "demo-credentials",
		FolderType: vault.FolderTypeCredentials,
	})
	must(err, "create credentials folder")
	log.Printf("[folders] created credentials folder id=%s\n", credsFolder.ID)

	keysFolder, err := client.Folders().Create(ctx, vault.CreateFolderRequest{
		Name:       "demo-keys",
		FolderType: vault.FolderTypeKeys,
	})
	must(err, "create keys folder")
	log.Printf("[folders] created keys folder id=%s\n", keysFolder.ID)

	folders, err := client.Folders().List(ctx, vault.ListFoldersOptions{})
	must(err, "list folders")
	log.Printf("[folders] total folders=%d\n", len(folders))

	_, err = client.Folders().Update(ctx, credsFolder.ID, vault.UpdateFolderRequest{
		Name: "demo-credentials-updated",
	})
	must(err, "update folder")
	log.Printf("[folders] updated folder\n")

	gotFolder, err := client.Folders().Get(ctx, credsFolder.ID)
	must(err, "get folder")
	log.Printf("[folders] get folder name=%s\n", gotFolder.Name)

	// Folder permissions — PUT/DELETE hit the hand-written FolderPermissionMiddleware,
	// which is blocked for API key authentication.
	if !isAPIKey {
		permsResult, err := client.Folders().GrantPermission(ctx, credsFolder.ID, vault.GrantPermissionRequest{
			UserID: "demo-user-id",
			Roles:  []vault.FolderPermissionRole{vault.FolderPermissionRoleRead, vault.FolderPermissionRoleWrite},
		})
		must(err, "grant folder permission")
		log.Printf("[folders] granted permissions, folder now has %d permission entries\n", len(permsResult))

		perms, err := client.Folders().ListPermissions(ctx, credsFolder.ID)
		must(err, "list folder permissions")
		log.Printf("[folders] permissions count=%d\n", len(perms))

		err = client.Folders().RemovePermission(ctx, credsFolder.ID, "demo-user-id")
		must(err, "remove folder permission")
		log.Printf("[folders] removed permission")
	} else {
		log.Printf("[folders] skipped folder permissions (not available to API keys)")
	}

	// ---------------------------------------------------------------
	// Secrets
	// ---------------------------------------------------------------
	secret, err := client.Secrets().Create(ctx, vault.CreateSecretRequest{
		Name:       "demo-db-creds",
		FolderID:   credsFolder.ID,
		SecretType: vault.SecretTypePassword,
		Password: &vault.SecretPassword{
			Username: "admin",
			Password: "s3cret",
			URL:      "https://db.example.com",
		},
		Metadata: map[string]string{"env": "demo"},
	})
	must(err, "create secret")
	log.Printf("[secrets] created id=%s name=%s\n", secret.ID, secret.Name)

	secrets, err := client.Secrets().List(ctx, vault.ListSecretsOptions{
		FolderID: credsFolder.ID,
		Limit:    10,
	})
	must(err, "list secrets")
	log.Printf("[secrets] listed total=%d\n", secrets.Total)

	gotSecret, err := client.Secrets().Get(ctx, secret.ID)
	must(err, "get secret")
	log.Printf("[secrets] get name=%s type=%s\n", gotSecret.Name, gotSecret.SecretType)

	_, err = client.Secrets().Update(ctx, secret.ID, vault.UpdateSecretRequest{
		Password: &vault.SecretPassword{
			Username: "admin",
			Password: "rotated",
			URL:      "https://db.example.com",
		},
	})
	must(err, "update secret")
	log.Printf("[secrets] updated\n")

	// Secret versions — hits the hand-written SecretVersionMiddleware.
	if !isAPIKey {
		versions, err := client.Secrets().ListVersions(ctx, secret.ID)
		must(err, "list secret versions")
		log.Printf("[secrets] versions count=%d\n", len(versions))

		if len(versions) > 0 {
			log.Printf("[secrets] latest version=%d created_at=%s\n", versions[0].Version, versions[0].CreatedAt)
		}
	} else {
		log.Printf("[secrets] skipped versions (not available to API keys)")
	}

	// ---------------------------------------------------------------
	// Keys
	// ---------------------------------------------------------------
	signingKey, err := client.Keys().Create(ctx, vault.CreateKeyRequest{
		Name:      "demo-signer",
		FolderID:  keysFolder.ID,
		KeyType:   vault.KeyTypeSigning,
		Algorithm: "RS256",
	})
	must(err, "create signing key")
	log.Printf("[keys] created signing key id=%s alg=%s\n", signingKey.ID, signingKey.Algorithm)

	encKey, err := client.Keys().Create(ctx, vault.CreateKeyRequest{
		Name:      "demo-enc-key",
		FolderID:  keysFolder.ID,
		KeyType:   vault.KeyTypeEncryption,
		Algorithm: "AES-GCM",
	})
	must(err, "create encryption key")
	log.Printf("[keys] created encryption key id=%s alg=%s\n", encKey.ID, encKey.Algorithm)

	keys, err := client.Keys().List(ctx, vault.ListKeysOptions{
		FolderID: keysFolder.ID,
		Limit:    10,
	})
	must(err, "list keys")
	log.Printf("[keys] listed total=%d\n", keys.Total)

	gotKey, err := client.Keys().Get(ctx, signingKey.ID)
	must(err, "get key")
	log.Printf("[keys] get name=%s version=%s\n", gotKey.Name, gotKey.Version)

	rotated, err := client.Keys().Rotate(ctx, signingKey.ID)
	must(err, "rotate key")
	log.Printf("[keys] rotated version=%s\n", rotated.Version)

	// Key versions — hits the hand-written KeyVersionMiddleware.
	if !isAPIKey {
		keyVersions, err := client.Keys().ListVersions(ctx, signingKey.ID)
		must(err, "list key versions")
		log.Printf("[keys] versions count=%d\n", len(keyVersions))

		if len(keyVersions) > 0 {
			log.Printf("[keys] latest version=%d disabled=%v\n", keyVersions[0].Version, keyVersions[0].Disabled)
		}
	} else {
		log.Printf("[keys] skipped versions (not available to API keys)")
	}

	// Sign & verify
	payload := base64.StdEncoding.EncodeToString([]byte(`{"action":"payment","amount":42}`))

	sigResp, err := client.Keys().Sign(ctx, vault.SignRequest{
		KeyID: signingKey.ID,
		Data:  payload,
	})
	must(err, "sign data")
	log.Printf("[keys] signature=%s...\n", truncate(sigResp.Data, 40))

	verifyResp, err := client.Keys().Verify(ctx, vault.VerifyRequest{
		KeyID:     signingKey.ID,
		Data:      payload,
		Signature: sigResp.Data,
	})
	must(err, "verify signature")
	log.Printf("[keys] valid=%v\n", verifyResp.Valid)

	// Encrypt & decrypt
	plaintext := base64.StdEncoding.EncodeToString([]byte("sensitive-data"))

	encResp, err := client.Keys().Encrypt(ctx, vault.EncryptRequest{
		KeyID: encKey.ID,
		Data:  plaintext,
	})
	must(err, "encrypt data")
	log.Printf("[keys] ciphertext=%s...\n", truncate(encResp.Data, 40))

	decResp, err := client.Keys().Decrypt(ctx, vault.DecryptRequest{
		KeyID: encKey.ID,
		Data:  encResp.Data,
	})
	must(err, "decrypt data")
	log.Printf("[keys] decrypted matches=%v\n", decResp.Data == plaintext)

	// ---------------------------------------------------------------
	// Tools
	// ---------------------------------------------------------------
	randomResp, err := client.Tools().Random(ctx, vault.RandomRequest{
		Length: 32,
		Format: vault.RandomFormatHex,
	})
	must(err, "generate random")
	log.Printf("[tools] random=%s (len=%d)\n", truncate(randomResp.Random, 32), randomResp.Length)

	hashResp, err := client.Tools().Hash(ctx, vault.HashRequest{
		Algorithm: vault.HashAlgorithmSHA256,
		Data:      "hello clavik",
		Format:    vault.HashFormatHex,
	})
	must(err, "hash data")
	log.Printf("[tools] hash=%s alg=%s\n", truncate(hashResp.Hash, 32), hashResp.Algorithm)

	wrapResp, err := client.Tools().Wrap(ctx, vault.WrapRequest{
		KeyID:     encKey.ID,
		Plaintext: "wrap-this-secret-material",
	})
	must(err, "wrap data")
	log.Printf("[tools] wrapped=%s...\n", truncate(wrapResp.WrappedData, 40))

	unwrapResp, err := client.Tools().Unwrap(ctx, vault.UnwrapRequest{
		KeyID:       encKey.ID,
		WrappedData: wrapResp.WrappedData,
	})
	must(err, "unwrap data")
	log.Printf("[tools] unwrapped=%s\n", unwrapResp.Plaintext)

	// ---------------------------------------------------------------
	// Algorithms
	// ---------------------------------------------------------------
	algos, err := client.Algorithms().ListSupported(ctx, vault.ListAlgorithmsOptions{})
	must(err, "list algorithms")
	log.Printf("[algorithms] supported count=%d\n", len(algos))
	for _, a := range algos {
		log.Printf("  - %s (type=%s recommended=%v)\n", a.Name, a.KeyType, a.Recommended)
	}

	recommended, err := client.Algorithms().GetRecommended(ctx, vault.RecommendedOptions{
		KeyType:       vault.KeyTypeSigning,
		SecurityLevel: vault.SecurityLevelHigh,
	})
	must(err, "get recommended algorithm")
	log.Printf("[algorithms] recommended=%s security=%s\n", recommended.Name, recommended.SecurityLevel)

	// ---------------------------------------------------------------
	// Policies
	// ---------------------------------------------------------------
	policy, err := client.Policies().Get(ctx)
	must(err, "get security policy")
	log.Printf("[policies] allowed=%v forbidden=%v\n", policy.AllowedAlgorithms, policy.ForbiddenAlgorithms)

	// SetPolicy is blocked for API key authentication.
	if !isAPIKey {
		updatedPolicy, err := client.Policies().Set(ctx, vault.SecurityPolicy{
			DefaultPolicy: &vault.SecurityRequirements{
				SecurityLevel: vault.SecurityLevelHigh,
			},
			AllowedAlgorithms:   []string{"AES-256-GCM", "ES256", "ES384"},
			ForbiddenAlgorithms: []string{"MD5", "SHA1"},
		})
		must(err, "set security policy")
		log.Printf("[policies] updated allowed=%v\n", updatedPolicy.AllowedAlgorithms)
	} else {
		log.Printf("[policies] skipped set policy (not available to API keys)")
	}

	// ---------------------------------------------------------------
	// Access — Policies, Principals, API Keys, Users
	// ---------------------------------------------------------------

	// GrantAccess, UpdateAccessPolicy, RevokeAccess, CreateApiKey, and
	// RevokeApiKey are blocked for API key authentication.
	if !isAPIKey {
		// Grant access
		accessPolicy, err := client.Access().GrantAccess(ctx, vault.GrantAccessRequest{
			ResourceType: vault.ResourceTypeKey,
			ResourceID:   signingKey.ID,
			PrincipalID:  "demo-service-account",
			Permissions:  []vault.Permission{vault.PermissionRead, vault.PermissionWrite},
		})
		must(err, "grant access")
		log.Printf("[access] granted policy id=%s\n", accessPolicy.ID)

		// Get policy
		gotPolicy, err := client.Access().GetPolicy(ctx, accessPolicy.ID)
		must(err, "get access policy")
		log.Printf("[access] policy permissions=%v\n", gotPolicy.Permissions)

		// Update policy
		updatedAccess, err := client.Access().UpdatePolicy(ctx, accessPolicy.ID, vault.UpdatePolicyRequest{
			Permissions: []vault.Permission{vault.PermissionRead},
		})
		must(err, "update access policy")
		log.Printf("[access] updated permissions=%v\n", updatedAccess.Permissions)

		// API keys
		apiKey, err := client.Access().CreateAPIKey(ctx, vault.CreateAPIKeyRequest{
			Name:   "demo-ci-key",
			Scopes: []string{"vault:cred_read", "vault:cred_write", "vault:cred_manage"},
		})
		must(err, "create API key")
		log.Printf("[access] created API key name=%s prefix=%s\n", apiKey.Name, apiKey.KeyPrefix)

		apiKeys, err := client.Access().ListAPIKeys(ctx)
		must(err, "list API keys")
		log.Printf("[access] API keys count=%d\n", len(apiKeys))

		err = client.Access().RevokeAPIKey(ctx, apiKey.ID)
		must(err, "revoke API key")
		log.Printf("[access] revoked API key")

		// Revoke access policy
		err = client.Access().RevokeAccess(ctx, accessPolicy.ID)
		must(err, "revoke access")
		log.Printf("[access] revoked access policy")
	} else {
		log.Printf("[access] skipped grant/update/revoke access, create/revoke API key (not available to API keys)")
	}

	// Read-only access operations — allowed for API keys.

	// List policies
	policies, err := client.Access().ListPolicies(ctx, vault.ListPoliciesOptions{
		ResourceType: vault.ResourceTypeKey,
		ResourceID:   signingKey.ID,
	})
	must(err, "list access policies")
	log.Printf("[access] policies count=%d\n", len(policies))

	// List principals
	principals, err := client.Access().ListPrincipals(ctx, vault.ListPrincipalsOptions{})
	must(err, "list principals")
	log.Printf("[access] principals count=%d\n", len(principals))

	apiKeys, err := client.Access().ListAPIKeys(ctx)
	must(err, "list API keys")
	log.Printf("[access] API keys count=%d\n", len(apiKeys))

	// Users — hits the hand-written GroupHTTPHandler, not the gRPC gateway.
	if !isAPIKey {
		users, err := client.Access().ListUsers(ctx, vault.ListUsersOptions{
			Status: vault.UserStatusActive,
		})
		must(err, "list users")
		log.Printf("[access] active users count=%d\n", len(users))
	} else {
		log.Printf("[access] skipped list users (not available to API keys)")
	}

	// ---------------------------------------------------------------
	// Activity
	// ---------------------------------------------------------------
	activityLogs, err := client.Activity().List(ctx, vault.ListActivityOptions{
		Limit: 5,
	})
	must(err, "list activity logs")
	log.Printf("[activity] logs count=%d total=%d\n", len(activityLogs.Data), activityLogs.Total)
	for _, entry := range activityLogs.Data {
		log.Printf("  - %s %s %s (%s)\n", entry.Timestamp, entry.Action, entry.ResourceName, entry.Status)
	}

	if len(activityLogs.Data) > 0 {
		logEntry, err := client.Activity().Get(ctx, activityLogs.Data[0].ID)
		must(err, "get activity log")
		log.Printf("[activity] entry action=%s user=%s\n", logEntry.Action, logEntry.UserEmail)

	}

	// ---------------------------------------------------------------
	// Compliance
	// ---------------------------------------------------------------
	if !isAPIKey {
		complianceReport, err := client.Compliance().GetReport(ctx)
		must(err, "compliance report")
		log.Printf("[compliance] report=%s\n", summarizeJSON(complianceReport))
	} else {
		log.Printf("[compliance] report (not available to API keys)")
	}

	// ---------------------------------------------------------------
	// Cleanup
	// ---------------------------------------------------------------
	err = client.Secrets().Delete(ctx, secret.ID)
	must(err, "delete secret")
	log.Printf("[cleanup] deleted secret")

	err = client.Keys().Delete(ctx, signingKey.ID)
	must(err, "delete signing key")
	log.Printf("[cleanup] deleted signing key")

	err = client.Keys().Delete(ctx, encKey.ID)
	must(err, "delete encryption key")
	log.Printf("[cleanup] deleted encryption key")

	err = client.Folders().Delete(ctx, credsFolder.ID)
	must(err, "delete credentials folder")
	log.Printf("[cleanup] deleted credentials folder")

	err = client.Folders().Delete(ctx, keysFolder.ID)
	must(err, "delete keys folder")
	log.Printf("[cleanup] deleted keys folder")

	log.Printf("\n✓ All SDK functions exercised successfully.")
}

func must(err error, op string) {
	if err == nil {
		return
	}

	var apiErr *vault.APIError
	if errors.As(err, &apiErr) {
		log.Fatalf("[%s] API error %d: %s\n  details: %s", op, apiErr.StatusCode, apiErr.Message, string(apiErr.Details))
		return
	}
	log.Fatalf("[%s] %v", op, err)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func summarizeJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "(empty)"
	}
	s := string(raw)
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}
