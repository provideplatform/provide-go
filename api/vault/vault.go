package vault

import (
	"fmt"
	"os"

	"github.com/provideservices/provide-go/api"
	"github.com/provideservices/provide-go/common"
)

const defaultVaultHost = "vault.provide.services"
const defaultVaultPath = "api/v1"
const defaultVaultScheme = "https"

// Vault client
type Vault struct {
	api.Client
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
		api.Client{
			Host:   host,
			Path:   path,
			Scheme: scheme,
			Token:  token,
		},
	}
}

// CreateVault on behalf of the given API token
func CreateVault(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitVault(common.StringOrNil(token)).Post("vaults", params)
}

// ListVaults retrieves a paginated list of vaults scoped to the given API token
func ListVaults(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitVault(common.StringOrNil(token)).Get("vaults", params)
}

// ListVaultKeys retrieves a paginated list of vault keys
func ListVaultKeys(token, vaultID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("vaults/%s/keys", vaultID)
	return InitVault(common.StringOrNil(token)).Get(uri, params)
}

// CreateVaultKey creates a new vault key
func CreateVaultKey(token, vaultID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("vaults/%s/keys", vaultID)
	return InitVault(common.StringOrNil(token)).Post(uri, params)
}

// DeleteVaultKey deletes a key
func DeleteVaultKey(token, vaultID, keyID string) (int, interface{}, error) {
	uri := fmt.Sprintf("vaults/%s/keys/%s", vaultID, keyID)
	return InitVault(common.StringOrNil(token)).Delete(uri)
}

// SignMessage signs a message with the given key
func SignMessage(token, vaultID, keyID, msg string, opts map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("vaults/%s/keys/%s/sign", vaultID, keyID)
	return InitVault(common.StringOrNil(token)).Post(uri, map[string]interface{}{
		"message": msg,
		"options": opts,
	})
}

// VerifySignature verifies a signature
func VerifySignature(token, vaultID, keyID, msg, sig string, opts map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("vaults/%s/keys/%s/verify", vaultID, keyID)
	return InitVault(common.StringOrNil(token)).Post(uri, map[string]interface{}{
		"message":   msg,
		"signature": sig,
		"options":   opts,
	})
}

// ListVaultSecrets retrieves a paginated list of secrets in the vault
func ListVaultSecrets(token, vaultID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("vaults/%s/secrets", vaultID)
	return InitVault(common.StringOrNil(token)).Get(uri, params)
}

// CreateVaultSecret stores a new secret in the vault
func CreateVaultSecret(token, vaultID, value, name, description, secretType string) (int, interface{}, error) {
	uri := fmt.Sprintf("vaults/%s/secrets", vaultID)
	return InitVault(common.StringOrNil(token)).Post(uri, map[string]interface{}{
		"name":        name,
		"description": description,
		"type":        secretType,
		"value":       value,
	})
}

// RetrieveVaultSecret stores a new secret in the vault
func RetrieveVaultSecret(token, vaultID, secretID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("vaults/%s/secrets/%s", vaultID, secretID)
	return InitVault(common.StringOrNil(token)).Get(uri, params)
}

// DeleteVaultSecret deletes a secret from the vault
func DeleteVaultSecret(token, vaultID, secretID string) (int, interface{}, error) {
	uri := fmt.Sprintf("vaults/%s/secrets/%s", vaultID, secretID)
	return InitVault(common.StringOrNil(token)).Delete(uri)
}

// EncryptWithNonce encrypts provided data with a key from the vault and provided nonce
func EncryptWithNonce(token, vaultID, keyID, data, nonce string) (int, interface{}, error) {
	uri := fmt.Sprintf("vaults/%s/keys/%s/encrypt", vaultID, keyID)
	return InitVault(common.StringOrNil(token)).Post(uri, map[string]interface{}{
		"data":  data,
		"nonce": nonce,
	})
}

// Encrypt encrypts provided data with a key from the vault and a randomly generated nonce
func Encrypt(token, vaultID, keyID, data string) (int, interface{}, error) {
	uri := fmt.Sprintf("vaults/%s/keys/%s/encrypt", vaultID, keyID)
	return InitVault(common.StringOrNil(token)).Post(uri, map[string]interface{}{
		"data": data,
	})
}

// Decrypt decrypts provided encrypted data with a key from the vault
func Decrypt(token, vaultID, keyID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("vaults/%s/keys/%s/decrypt", vaultID, keyID)
	return InitVault(common.StringOrNil(token)).Post(uri, params)
}
