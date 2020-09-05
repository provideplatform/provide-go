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
