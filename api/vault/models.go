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

	// these fields are only populated for ephemeral keys
	Ephemeral  *bool   `json:"ephemeral,omitempty"`
	PrivateKey *string `json:"private_key,omitempty"`
	Seed       *string `json:"seed,omitempty"`

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

// EncryptDecryptRequestResponse contains the data (i.e., encrypted or decrypted) and an optional nonce
type EncryptDecryptRequestResponse struct {
	Data  string  `json:"data"`
	Nonce *string `json:"nonce,omitempty"`
}

// SignRequest contains a message to be signed
type SignRequest struct {
	Message string `json:"message"`
}

// SignResponse contains the signature for the message
type SignResponse struct {
	Signature      *string `json:"signature,omitempty"`
	Address        *string `json:"address,omitempty"`
	DerivationPath *string `json:"hd_derivation_path,omitempty"`
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

// SealUnsealRequestResponse provides the unseal information
type SealUnsealRequestResponse struct {
	UnsealerKey    *string `json:"key,omitempty"`
	ValidationHash *string `json:"validation_hash,omitempty"`
}
