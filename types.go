package vault

import (
	"encoding/json"
	"strconv"
)

// Timestamp is a Unix timestamp that can unmarshal from both JSON numbers
// (custom HTTP handlers) and JSON strings (grpc-gateway int64 encoding).
type Timestamp int64

// UnmarshalJSON handles both "1234" and 1234.
func (t *Timestamp) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		if s == "" {
			*t = 0
			return nil
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return err
		}
		*t = Timestamp(n)
		return nil
	}
	var n int64
	if err := json.Unmarshal(data, &n); err != nil {
		return err
	}
	*t = Timestamp(n)
	return nil
}

func (t Timestamp) String() string {
	return strconv.FormatInt(int64(t), 10)
}

// ListResponse is a paginated list response from the API.
type ListResponse[T any] struct {
	Data  []T   `json:"items"`
	Total int64 `json:"count"`
}

// dataListResponse is used to unmarshal list endpoints that only return a data array.
type dataListResponse[T any] struct {
	Data  []T   `json:"items"`
	Count int64 `json:"count"`
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

type SecretType string

const (
	SecretTypePassword    SecretType = "SECRET_TYPE_PASSWORD"
	SecretTypeAPIKey      SecretType = "SECRET_TYPE_API_KEY"
	SecretTypeCertificate SecretType = "SECRET_TYPE_CERTIFICATE"
	SecretTypeSSHKey      SecretType = "SECRET_TYPE_SSH_KEY"
	SecretTypeTOTP        SecretType = "SECRET_TYPE_TOTP"
	SecretTypeGeneric     SecretType = "SECRET_TYPE_GENERIC"
)

type KeyType string

const (
	KeyTypeEncryption KeyType = "KEY_TYPE_ENCRYPTION"
	KeyTypeSigning    KeyType = "KEY_TYPE_SIGNING"
	KeyTypeJWK        KeyType = "KEY_TYPE_JWK"
)

type FolderPermissionRole string

const (
	FolderPermissionRoleAdmin FolderPermissionRole = "FOLDER_PERMISSION_ROLE_ADMIN"
	FolderPermissionRoleRead  FolderPermissionRole = "FOLDER_PERMISSION_ROLE_READ"
	FolderPermissionRoleWrite FolderPermissionRole = "FOLDER_PERMISSION_ROLE_WRITE"
)

type Permission string

const (
	PermissionRead   Permission = "PERMISSION_READ"
	PermissionWrite  Permission = "PERMISSION_WRITE"
	PermissionDelete Permission = "PERMISSION_DELETE"
	PermissionAdmin  Permission = "PERMISSION_ADMIN"
)

type ResourceType string

const (
	ResourceTypeKey    ResourceType = "RESOURCE_TYPE_KEY"
	ResourceTypeSecret ResourceType = "RESOURCE_TYPE_SECRET"
	ResourceTypeFolder ResourceType = "RESOURCE_TYPE_FOLDER"
	ResourceTypeTenant ResourceType = "RESOURCE_TYPE_TENANT"
)

type PrincipalType string

const (
	PrincipalTypeUser           PrincipalType = "PRINCIPAL_TYPE_USER"
	PrincipalTypeServiceAccount PrincipalType = "PRINCIPAL_TYPE_SERVICE_ACCOUNT"
	PrincipalTypeGroup          PrincipalType = "PRINCIPAL_TYPE_GROUP"
)

type ActivityLogStatus string

const (
	ActivityLogStatusSuccess ActivityLogStatus = "ACTIVITY_LOG_STATUS_SUCCESS"
	ActivityLogStatusFailure ActivityLogStatus = "ACTIVITY_LOG_STATUS_FAILURE"
	ActivityLogStatusError   ActivityLogStatus = "ACTIVITY_LOG_STATUS_ERROR"
)

type FolderType string

const (
	FolderTypeCredentials FolderType = "credentials"
	FolderTypeKeys        FolderType = "keys"
)

type UserStatus string

const (
	UserStatusActive    UserStatus = "active"
	UserStatusInactive  UserStatus = "inactive"
	UserStatusSuspended UserStatus = "suspended"
)

type SecurityLevel string

const (
	SecurityLevelHigh   SecurityLevel = "HIGH"
	SecurityLevelMedium SecurityLevel = "MEDIUM"
	SecurityLevelLow    SecurityLevel = "LOW"
)

type PerformanceHint string

const (
	PerformanceHintFast     PerformanceHint = "FAST"
	PerformanceHintBalanced PerformanceHint = "BALANCED"
	PerformanceHintSecure   PerformanceHint = "SECURE"
)

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

// SecretPassword holds credentials for a password-type secret.
type SecretPassword struct {
	Username string            `json:"username"`
	Password string            `json:"password"`
	URL      string            `json:"url,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SecretAPIKey holds an API key value.
type SecretAPIKey struct {
	APIKey   string            `json:"api_key"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SecretCertificate holds certificate and private key PEM data.
type SecretCertificate struct {
	Certificate string            `json:"certificate"`
	PrivateKey  string            `json:"private_key,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// SecretSSHKey holds SSH key material.
type SecretSSHKey struct {
	PublicKey  string            `json:"public_key,omitempty"`
	PrivateKey string            `json:"private_key"`
	Passphrase string            `json:"passphrase,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// SecretTOTP holds TOTP seed and configuration.
type SecretTOTP struct {
	Seed      string            `json:"seed"`
	Algorithm string            `json:"algorithm,omitempty"`
	Digits    int32             `json:"digits,omitempty"`
	Period    int32             `json:"period,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// CreateSecretRequest creates a new secret. Exactly one typed value field must
// be set, matching the SecretType (e.g. SecretTypePassword → Password).
type CreateSecretRequest struct {
	Name       string            `json:"name"`
	FolderID   string            `json:"folder_id,omitempty"`
	SecretType SecretType        `json:"secret_type"`
	ExpiresAt  int64             `json:"expires_at,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`

	// Exactly one of these typed value fields must be set.
	Password    *SecretPassword    `json:"password,omitempty"`
	APIKey      *SecretAPIKey      `json:"api_key,omitempty"`
	Certificate *SecretCertificate `json:"certificate,omitempty"`
	SSHKey      *SecretSSHKey      `json:"ssh_key,omitempty"`
	TOTP        *SecretTOTP        `json:"totp,omitempty"`
	Generic     map[string]any     `json:"generic,omitempty"`
}

// UpdateSecretRequest updates a secret. Set the typed value field matching
// the secret's type to change the stored value.
type UpdateSecretRequest struct {
	Name      string            `json:"name,omitempty"`
	ExpiresAt int64             `json:"expires_at,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`

	Password    *SecretPassword    `json:"password,omitempty"`
	APIKey      *SecretAPIKey      `json:"api_key,omitempty"`
	Certificate *SecretCertificate `json:"certificate,omitempty"`
	SSHKey      *SecretSSHKey      `json:"ssh_key,omitempty"`
	TOTP        *SecretTOTP        `json:"totp,omitempty"`
	Generic     map[string]any     `json:"generic,omitempty"`
}

type Secret struct {
	ID         string            `json:"id"`
	TenantID   string            `json:"tenant_id"`
	FolderID   string            `json:"folder_id"`
	Name       string            `json:"name"`
	SecretType SecretType        `json:"secret_type"`
	Value      string            `json:"value"`
	ExpiresAt  string            `json:"expires_at,omitempty"`
	CreatedAt  string            `json:"created_at"`
	CreatedBy  string            `json:"created_by"`
	UpdatedAt  string            `json:"updated_at"`
	UpdatedBy  string            `json:"updated_by"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type SecretVersion struct {
	ID        string            `json:"id"`
	SecretID  string            `json:"secret_id"`
	Version   int32             `json:"version"`
	Value     string            `json:"value"`
	CreatedAt Timestamp         `json:"created_at"`
	CreatedBy string            `json:"created_by"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type ListSecretsOptions struct {
	FolderID   string
	SecretType SecretType
	Search     string
	Skip       int32
	Limit      int32
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

type CreateKeyRequest struct {
	Name            string          `json:"name"`
	FolderID        string          `json:"folder_id,omitempty"`
	KeyType         KeyType         `json:"key_type"`
	Algorithm       string          `json:"algorithm,omitempty"`
	Purpose         string          `json:"purpose,omitempty"`
	SecurityLevel   string          `json:"security_level,omitempty"`
	ComplianceMode  []string        `json:"compliance_mode,omitempty"`
	PerformanceHint PerformanceHint `json:"performance_hint,omitempty"`
	ExpiresAt       string          `json:"expires_at,omitempty"`
}

type Key struct {
	ID             string   `json:"id"`
	TenantID       string   `json:"tenant_id"`
	Name           string   `json:"name"`
	FolderID       string   `json:"folder_id"`
	Version        string   `json:"version"`
	Algorithm      string   `json:"algorithm"`
	Purpose        string   `json:"purpose"`
	KeyType        KeyType  `json:"key_type"`
	SecurityLevel  string   `json:"security_level"`
	ComplianceMode []string `json:"compliance_mode,omitempty"`
	ExpiresAt      string   `json:"expires_at,omitempty"`
	CreatedAt      string   `json:"created_at"`
	CreatedBy      string   `json:"created_by"`
	UpdatedAt      string   `json:"updated_at"`
	UpdatedBy      string   `json:"updated_by"`
}

type KeyVersion struct {
	ID        string    `json:"id"`
	KeyID     string    `json:"key_id"`
	Version   int32     `json:"version"`
	Algorithm string    `json:"algorithm,omitempty"`
	KeyBytes  string    `json:"key_bytes,omitempty"`
	Active    bool      `json:"active,omitempty"`
	Disabled  bool      `json:"disabled"`
	CreatedAt Timestamp `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	UpdatedAt Timestamp `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

type ListKeysOptions struct {
	FolderID string
	Search   string
	Skip     int32
	Limit    int32
}

type EncryptRequest struct {
	KeyID   string `json:"key_id"`
	Version string `json:"key_version,omitempty"`
	Data    string `json:"data"`
}

type EncryptResponse struct {
	Data string `json:"data"`
}

type DecryptRequest struct {
	KeyID   string `json:"key_id"`
	Version string `json:"key_version,omitempty"`
	Data    string `json:"data"`
}

type DecryptResponse struct {
	Data string `json:"data"`
}

type SignRequest struct {
	KeyID   string `json:"key_id"`
	Version string `json:"key_version,omitempty"`
	Data    string `json:"data"`
}

type SignResponse struct {
	Data string `json:"data"`
}

type VerifyRequest struct {
	KeyID     string `json:"key_id"`
	Version   string `json:"key_version,omitempty"`
	Data      string `json:"data"`
	Signature string `json:"signature"`
}

type VerifyResponse struct {
	Valid bool `json:"success"`
}

// ---------------------------------------------------------------------------
// Folders
// ---------------------------------------------------------------------------

type CreateFolderRequest struct {
	Name       string     `json:"name"`
	ParentID   string     `json:"parent_id,omitempty"`
	FolderType FolderType `json:"folder_type"`
}

type UpdateFolderRequest struct {
	Name       string     `json:"name,omitempty"`
	ParentID   string     `json:"parent_id,omitempty"`
	FolderType FolderType `json:"folder_type,omitempty"`
}

type Folder struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	Name       string     `json:"name"`
	ParentID   string     `json:"parent_id"`
	FolderType FolderType `json:"folder_type"`
	CreatedAt  string     `json:"created_at"`
	CreatedBy  string     `json:"created_by"`
	UpdatedAt  string     `json:"updated_at"`
	UpdatedBy  string     `json:"updated_by"`
}

type FolderPermission struct {
	ID        string                 `json:"id"`
	TenantID  string                 `json:"tenant_id"`
	FolderID  string                 `json:"folder_id"`
	UserID    string                 `json:"user_id"`
	UserName  string                 `json:"user_name"`
	UserEmail string                 `json:"user_email"`
	Roles     []FolderPermissionRole `json:"roles"`
}

type GrantPermissionRequest struct {
	UserID string                 `json:"user_id"`
	Roles  []FolderPermissionRole `json:"roles"`
}

type ListFoldersOptions struct {
	ParentID   string
	FolderType FolderType
}

// ---------------------------------------------------------------------------
// Access
// ---------------------------------------------------------------------------

type AccessPolicy struct {
	ID           string       `json:"id"`
	TenantID     string       `json:"tenant_id"`
	ResourceType ResourceType `json:"resource_type"`
	ResourceID   string       `json:"resource_id"`
	PrincipalID  string       `json:"principal_id"`
	Principal    *Principal   `json:"principal,omitempty"`
	Permissions  []Permission `json:"permissions"`
	CreatedAt    string       `json:"created_at"`
	CreatedBy    string       `json:"created_by"`
	UpdatedAt    string       `json:"updated_at"`
	UpdatedBy    string       `json:"updated_by"`
}

type GrantAccessRequest struct {
	ResourceType ResourceType `json:"resource_type"`
	ResourceID   string       `json:"resource_id"`
	PrincipalID  string       `json:"principal_id"`
	Permissions  []Permission `json:"permissions"`
}

type UpdatePolicyRequest struct {
	Permissions []Permission `json:"permissions"`
}

type ListPoliciesOptions struct {
	ResourceType ResourceType
	ResourceID   string
	PrincipalID  string
	Search       string
}

type Principal struct {
	ID    string        `json:"id"`
	Type  PrincipalType `json:"type"`
	Name  string        `json:"name"`
	Email string        `json:"email"`
}

type ListPrincipalsOptions struct {
	PrincipalType PrincipalType
	Search        string
}

type APIKey struct {
	ID         string `json:"id"`
	TenantID   string `json:"tenant_id"`
	Name       string `json:"name"`
	KeyPrefix  string `json:"key_prefix"`
	CreatedAt  string `json:"created_at"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	CreatedBy  string `json:"created_by"`
}

type CreateAPIKeyRequest struct {
	Name      string            `json:"name"`
	ExpiresAt string            `json:"expires_at,omitempty"`
	Scopes    []string          `json:"scopes"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type APIKeyWithSecret struct {
	APIKey
	Key string `json:"key"`
}

type User struct {
	Sub         string     `json:"sub"`
	Email       string     `json:"email"`
	GivenName   string     `json:"given_name"`
	FamilyName  string     `json:"family_name"`
	Status      UserStatus `json:"status"`
	LastLoginAt int64      `json:"last_login_at,omitempty"`
}

type ListUsersOptions struct {
	Status UserStatus
	Search string
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

type RandomFormat string

const (
	RandomFormatHex       RandomFormat = "hex"
	RandomFormatBase64    RandomFormat = "base64"
	RandomFormatBase64URL RandomFormat = "base64url"
	RandomFormatBase32    RandomFormat = "base32"
)

type RandomRequest struct {
	Length int          `json:"length"`
	Format RandomFormat `json:"format,omitempty"`
}

type RandomResponse struct {
	Random string       `json:"random"`
	Length int          `json:"length"`
	Format RandomFormat `json:"format"`
}

type HashAlgorithm string

const (
	HashAlgorithmSHA256 HashAlgorithm = "sha256"
	HashAlgorithmSHA512 HashAlgorithm = "sha512"
	HashAlgorithmSHA384 HashAlgorithm = "sha384"
	HashAlgorithmSHA224 HashAlgorithm = "sha224"
	HashAlgorithmSHA1   HashAlgorithm = "sha1"
	HashAlgorithmMD5    HashAlgorithm = "md5"
)

type HashFormat string

const (
	HashFormatHex    HashFormat = "hex"
	HashFormatBase64 HashFormat = "base64"
)

type HashRequest struct {
	Algorithm HashAlgorithm `json:"algorithm,omitempty"`
	Data      string        `json:"data"`
	Format    HashFormat    `json:"format,omitempty"`
}

type HashResponse struct {
	Hash      string        `json:"hash"`
	Algorithm HashAlgorithm `json:"algorithm"`
	Format    HashFormat    `json:"format"`
}

type DataFormat string

const (
	DataFormatBase64 DataFormat = "base64"
	DataFormatHex    DataFormat = "hex"
)

type WrapRequest struct {
	KeyID     string     `json:"key_id"`
	Plaintext string     `json:"plaintext"`
	Format    DataFormat `json:"format,omitempty"`
}

type WrapResponse struct {
	WrappedData string `json:"wrappedData"`
}

type UnwrapRequest struct {
	WrappedData string     `json:"wrapped_data"`
	KeyID       string     `json:"key_id,omitempty"`
	Format      DataFormat `json:"format,omitempty"`
}

type UnwrapResponse struct {
	Plaintext string `json:"plaintext"`
}

// ---------------------------------------------------------------------------
// Algorithms
// ---------------------------------------------------------------------------

type AlgorithmInfo struct {
	Name          string   `json:"name"`
	DisplayName   string   `json:"displayName"`
	KeyType       KeyType  `json:"keyType"`
	KeySizes      []int    `json:"keySizes,omitempty"`
	Description   string   `json:"description"`
	Recommended   bool     `json:"recommended"`
	SecurityLevel string   `json:"securityLevel"`
	Performance   string   `json:"performance"`
	Compliance    []string `json:"compliance,omitempty"`
	MinKeySize    int      `json:"minKeySize,omitempty"`
	MaxKeySize    int      `json:"maxKeySize,omitempty"`
}

type ListAlgorithmsOptions struct {
	KeyType KeyType
}

type RecommendedOptions struct {
	KeyType        KeyType
	SecurityLevel  SecurityLevel
	ComplianceMode string
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

type SecurityRequirements struct {
	SecurityLevel     SecurityLevel   `json:"securityLevel,omitempty"`
	ComplianceMode    []string        `json:"complianceMode,omitempty"`
	PerformanceHint   PerformanceHint `json:"performanceHint,omitempty"`
	KeySizePreference int             `json:"keySizePreference,omitempty"`
}

type SecurityPolicy struct {
	DefaultPolicy       *SecurityRequirements `json:"defaultPolicy,omitempty"`
	EncryptionPolicy    *SecurityRequirements `json:"encryptionPolicy,omitempty"`
	SigningPolicy       *SecurityRequirements `json:"signingPolicy,omitempty"`
	AllowedAlgorithms   []string              `json:"allowedAlgorithms,omitempty"`
	ForbiddenAlgorithms []string              `json:"forbiddenAlgorithms,omitempty"`
}

// ---------------------------------------------------------------------------
// Activity
// ---------------------------------------------------------------------------

type ActivityLog struct {
	ID           string            `json:"id"`
	TenantID     string            `json:"tenant_id"`
	Timestamp    string            `json:"timestamp"`
	UserID       string            `json:"user_id"`
	UserName     string            `json:"user_name"`
	UserEmail    string            `json:"user_email"`
	Action       string            `json:"action"`
	ResourceType string            `json:"resource_type"`
	ResourceID   string            `json:"resource_id"`
	ResourceName string            `json:"resource_name"`
	Status       ActivityLogStatus `json:"status"`
	IPAddress    string            `json:"ip_address"`
	UserAgent    string            `json:"user_agent"`
	Details      string            `json:"details"`
	ErrorMessage string            `json:"error_message"`
}

type ListActivityOptions struct {
	UserID       string
	Action       string
	ResourceType string
	ResourceID   string
	Status       ActivityLogStatus
	StartTime    string
	EndTime      string
	Skip         int32
	Limit        int32
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

type HealthResponse string
