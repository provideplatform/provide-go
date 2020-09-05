package vault

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/provideservices/provide-go/api"
	"github.com/provideservices/provide-go/common"
)

const defaultVaultHost = "vault.provide.services"
const defaultVaultPath = "api/v1"
const defaultVaultScheme = "https"

// Service for the vault api
type Service struct {
	api.Client
}

// InitVault convenience method to initialize an `vault.Service` instance
func InitVault(token *string) *Service {
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

	return &Service{
		api.Client{
			Host:   host,
			Path:   path,
			Scheme: scheme,
			Token:  token,
		},
	}
}

// CreateVault on behalf of the given API token
func CreateVault(token string, params map[string]interface{}) (*Vault, error) {
	status, resp, err := InitVault(common.StringOrNil(token)).Post("vaults", params)
	if err != nil {
		return nil, err
	}

	if vlt, vltOk := resp.(*Vault); vltOk {
		return vlt, nil
	}

	return nil, fmt.Errorf("failed to create vault; status: %v", status)
}

// ListVaults retrieves a paginated list of vaults scoped to the given API token
func ListVaults(token string, params map[string]interface{}) ([]*Vault, error) {
	status, resp, err := InitVault(common.StringOrNil(token)).Get("vaults", params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch vaults; status: %v", status)
	}

	vaults := make([]*Vault, 0)
	for _, item := range resp.([]interface{}) {
		vlt := &Vault{}
		vltraw, _ := json.Marshal(item)
		json.Unmarshal(vltraw, &vlt)
		vaults = append(vaults, vlt)
	}

	return vaults, nil
}

// ListVaultKeys retrieves a paginated list of vault keys
func ListVaultKeys(token, vaultID string, params map[string]interface{}) ([]*Key, error) {
	uri := fmt.Sprintf("vaults/%s/keys", vaultID)
	status, resp, err := InitVault(common.StringOrNil(token)).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch keys; status: %v", status)
	}

	keys := make([]*Key, 0)
	for _, item := range resp.([]interface{}) {
		key := &Key{}
		keyraw, _ := json.Marshal(item)
		json.Unmarshal(keyraw, &key)
		keys = append(keys, key)
	}

	return keys, nil
}

// CreateVaultKey creates a new vault key
func CreateVaultKey(token, vaultID string, params map[string]interface{}) (*Key, error) {
	uri := fmt.Sprintf("vaults/%s/keys", vaultID)
	status, resp, err := InitVault(common.StringOrNil(token)).Post(uri, params)
	if err != nil {
		return nil, err
	}

	if key, keyOk := resp.(*Key); keyOk {
		return key, nil
	}

	return nil, fmt.Errorf("failed to create key; status: %v", status)
}

// DeleteVaultKey deletes a key
func DeleteVaultKey(token, vaultID, keyID string) error {
	uri := fmt.Sprintf("vaults/%s/keys/%s", vaultID, keyID)
	status, _, err := InitVault(common.StringOrNil(token)).Delete(uri)
	if err != nil {
		return err
	}

	if status != 204 {
		return fmt.Errorf("failed to delete key; status: %v", status)
	}

	return nil
}

// SignMessage signs a message with the given key
func SignMessage(token, vaultID, keyID, msg string, opts map[string]interface{}) (*SignResponse, error) {
	uri := fmt.Sprintf("vaults/%s/keys/%s/sign", vaultID, keyID)
	status, resp, err := InitVault(common.StringOrNil(token)).Post(uri, map[string]interface{}{
		"message": msg,
		"options": opts,
	})
	if err != nil {
		return nil, err
	}

	if r, rOk := resp.(*SignResponse); rOk {
		return r, nil
	}

	return nil, fmt.Errorf("failed to sign message; status: %v", status)
}

// VerifySignature verifies a signature
func VerifySignature(token, vaultID, keyID, msg, sig string, opts map[string]interface{}) (*VerifyResponse, error) {
	uri := fmt.Sprintf("vaults/%s/keys/%s/verify", vaultID, keyID)
	status, resp, err := InitVault(common.StringOrNil(token)).Post(uri, map[string]interface{}{
		"message":   msg,
		"signature": sig,
		"options":   opts,
	})
	if err != nil {
		return nil, err
	}

	if r, rOk := resp.(*VerifyResponse); rOk {
		return r, nil
	}

	return nil, fmt.Errorf("failed to verify message signature; status: %v", status)
}

// ListVaultSecrets retrieves a paginated list of secrets in the vault
func ListVaultSecrets(token, vaultID string, params map[string]interface{}) ([]*Secret, error) {
	uri := fmt.Sprintf("vaults/%s/secrets", vaultID)
	status, resp, err := InitVault(common.StringOrNil(token)).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch secrets; status: %v", status)
	}

	secrets := make([]*Secret, 0)
	for _, item := range resp.([]interface{}) {
		secret := &Secret{}
		secretraw, _ := json.Marshal(item)
		json.Unmarshal(secretraw, &secret)
		secrets = append(secrets, secret)
	}

	return secrets, nil
}

// CreateVaultSecret stores a new secret in the vault
func CreateVaultSecret(token, vaultID, value, name, description, secretType string) (*Secret, error) {
	uri := fmt.Sprintf("vaults/%s/secrets", vaultID)
	status, resp, err := InitVault(common.StringOrNil(token)).Post(uri, map[string]interface{}{
		"name":        name,
		"description": description,
		"type":        secretType,
		"value":       value,
	})
	if err != nil {
		return nil, err
	}

	if secret, secretOk := resp.(*Secret); secretOk {
		return secret, nil
	}

	return nil, fmt.Errorf("failed to create secret; status: %v", status)
}

// RetrieveVaultSecret stores a new secret in the vault
func RetrieveVaultSecret(token, vaultID, secretID string, params map[string]interface{}) (*Secret, error) {
	uri := fmt.Sprintf("vaults/%s/secrets/%s", vaultID, secretID)
	status, resp, err := InitVault(common.StringOrNil(token)).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if secret, secretOk := resp.(*Secret); secretOk {
		return secret, nil
	}

	return nil, fmt.Errorf("failed to fetch secret; status: %v", status)
}

// DeleteVaultSecret deletes a secret from the vault
func DeleteVaultSecret(token, vaultID, secretID string) error {
	uri := fmt.Sprintf("vaults/%s/secrets/%s", vaultID, secretID)
	status, _, err := InitVault(common.StringOrNil(token)).Delete(uri)
	if err != nil {
		return err
	}

	if status != 204 {
		return fmt.Errorf("failed to delete secret; status: %v", status)
	}

	return nil
}

// Encrypt encrypts provided data with a key from the vault and a randomly generated nonce
func Encrypt(token, vaultID, keyID, data string) (*EncryptResponse, error) {
	uri := fmt.Sprintf("vaults/%s/keys/%s/encrypt", vaultID, keyID)
	status, resp, err := InitVault(common.StringOrNil(token)).Post(uri, map[string]interface{}{
		"data": data,
	})
	if err != nil {
		return nil, err
	}

	if r, rOk := resp.(*EncryptResponse); rOk {
		return r, nil
	}

	return nil, fmt.Errorf("failed to encrypt payload; status: %v", status)
}

// EncryptWithNonce encrypts provided data with a key from the vault and provided nonce
func EncryptWithNonce(token, vaultID, keyID, data, nonce string) (*EncryptResponse, error) {
	uri := fmt.Sprintf("vaults/%s/keys/%s/encrypt", vaultID, keyID)
	status, resp, err := InitVault(common.StringOrNil(token)).Post(uri, map[string]interface{}{
		"data":  data,
		"nonce": nonce,
	})
	if err != nil {
		return nil, err
	}

	if r, rOk := resp.(*EncryptResponse); rOk {
		return r, nil
	}

	return nil, fmt.Errorf("failed to encrypt payload; status: %v", status)
}

// Decrypt decrypts provided encrypted data with a key from the vault
func Decrypt(token, vaultID, keyID string, params map[string]interface{}) (*DecryptResponse, error) {
	uri := fmt.Sprintf("vaults/%s/keys/%s/decrypt", vaultID, keyID)
	status, resp, err := InitVault(common.StringOrNil(token)).Post(uri, params)
	if err != nil {
		return nil, err
	}

	if r, rOk := resp.(*DecryptResponse); rOk {
		return r, nil
	}

	return nil, fmt.Errorf("failed to decrypt payload; status: %v", status)
}
