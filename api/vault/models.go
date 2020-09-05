package vault

import (
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideservices/provide-go/api"
)

// Vault provides secure key management
type Vault struct {
	api.Model
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

// Key represents a symmetric or asymmetric signing key
type Key struct {
	api.Model
	VaultID     *uuid.UUID `json:"vault_id"`
	Type        *string    `json:"type"` // symmetric or asymmetric
	Usage       *string    `json:"usage"`
	Spec        *string    `json:"spec"`
	Name        *string    `json:"name"`
	Description *string    `json:"description"`

	Address          *string `json:"address,omitempty"`
	HDDerivationPath *string `json:"hd_derivation_path,omitempty"`
	PublicKey        *string `json:"public_key,omitempty"`
}

// Secret represents a string, encrypted by the vault master key
type Secret struct {
	api.Model
	VaultID     *uuid.UUID `json:"vault_id"`
	Type        *string    `json:"type"` // arbitrary secret type
	Name        *string    `json:"name"`
	Description *string    `json:"description"`
	Value       *string    `json:"value,omitempty"`
}

// EncryptRequest contains the data to be encrypted and an optional nonce
type EncryptRequest struct {
	Data  string  `json:"data"`
	Nonce *string `json:"nonce,omitempty`
}

// EncryptResponse contains the response from the encrypt API request
type EncryptResponse struct {
}

// DecryptResponse contains the response from the decrypt API request
type DecryptResponse struct {
}

// SignRequest contains a message to be signed
type SignRequest struct {
	Message string `json:"message"`
}

// SignResponse contains the signature for the message
type SignResponse struct {
	Signature string `json:"signature"`
}

// VerifyRequest contains the message and signature for verification
type VerifyRequest struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

// VerifyResponse contains a flag indicating if the signature was verified
type VerifyResponse struct {
	Verified bool `json:"verified"`
}
