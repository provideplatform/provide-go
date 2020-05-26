package provide

import (
	"fmt"
	"os"
)

const defaultVaultHost = "vault.provide.services"
const defaultVaultPath = "api/v1"
const defaultVaultScheme = "https"

// Vault client
type Vault struct {
	APIClient
}

// InitVault convenience method
func InitVault(token *string) *Vault {
	host := defaultVaultHost
	if os.Getenv("VAULT_API_HOST") != "" {
		host = os.Getenv("VAULT_API_HOST")
	}

	path := defaultVaultPath
	if os.Getenv("VAULT_API_PATH") != "" {
		host = os.Getenv("VAULT_API_PATH")
	}

	scheme := defaultVaultScheme
	if os.Getenv("VAULT_API_SCHEME") != "" {
		scheme = os.Getenv("VAULT_API_SCHEME")
	}

	return &Vault{
		APIClient{
			Host:   host,
			Path:   path,
			Scheme: scheme,
			Token:  token,
		},
	}
}

// CreateVault on behalf of the given API token
func CreateVault(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitVault(stringOrNil(token)).Post("vaults", params)
}

// ListVaults retrieves a paginated list of vaults scoped to the given API token
func ListVaults(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitVault(stringOrNil(token)).Get("vaults", params)
}

// ListVaultKeys retrieves a paginated list of vault API keys
func ListVaultKeys(token, vaultID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("vaults/%s/keys", vaultID)
	return InitVault(stringOrNil(token)).Get(uri, params)
}

// CreateVaultKey creates a new API token for the given vault ID.
func CreateVaultKey(token, vaultID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("vaults/%s/keys", vaultID)
	return InitVault(stringOrNil(token)).Post(uri, params)
}

// DeleteVaultKey creates a new API token for the given vault ID.
func DeleteVaultKey(token, vaultID, keyID string) (int, interface{}, error) {
	uri := fmt.Sprintf("vaults/%s/keys/%s", vaultID, keyID)
	return InitVault(stringOrNil(token)).Delete(uri)
}

// SignMessage signs a message with the given key
func SignMessage(token, vaultID, keyID, msg string) (int, interface{}, error) {
	uri := fmt.Sprintf("vaults/%s/keys/%s/sign", vaultID, keyID)
	return InitVault(stringOrNil(token)).Post(uri, map[string]interface{}{
		"message": msg,
	})
}

// VerifySignature verifies a signature
func VerifySignature(token, vaultID, keyID, msg, sig string) (int, interface{}, error) {
	uri := fmt.Sprintf("vaults/%s/keys/%s/verify", vaultID, keyID)
	return InitVault(stringOrNil(token)).Post(uri, map[string]interface{}{
		"message":   msg,
		"signature": sig,
	})
}

// ListVaultSecrets retrieves a paginated list of vault API secrets
func ListVaultSecrets(token, vaultID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("vaults/%s/secrets", vaultID)
	return InitVault(stringOrNil(token)).Get(uri, params)
}

// CreateVaultSecret creates a new API token for the given vault ID.
func CreateVaultSecret(token, vaultID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("vaults/%s/secrets", vaultID)
	return InitVault(stringOrNil(token)).Post(uri, params)
}

// DeleteVaultSecret creates a new API token for the given vault ID.
func DeleteVaultSecret(token, vaultID, secretID string) (int, interface{}, error) {
	uri := fmt.Sprintf("vaults/%s/secrets/%s", vaultID, secretID)
	return InitVault(stringOrNil(token)).Delete(uri)
}
