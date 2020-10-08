package util

import (
	"fmt"
	"os"

	ident "github.com/provideservices/provide-go/api/ident"
	vault "github.com/provideservices/provide-go/api/vault"
	common "github.com/provideservices/provide-go/common"
)

var (
	// DefaultVaultAccessJWT for the default vault context
	DefaultVaultAccessJWT string

	// defaultVaultRefreshJWT for the default vault context
	defaultVaultRefreshJWT string

	// defaultVaultSealUnsealKey for the default vault context
	defaultVaultSealUnsealKey string
)

// RequireVault panics if the VAULT_REFRESH_TOKEN is not given or an access
// token is otherwise unable to be obtained; attepts to unseal the vault if possible
func RequireVault() {
	defaultVaultRefreshJWT = os.Getenv("VAULT_REFRESH_TOKEN")
	if defaultVaultRefreshJWT != "" {
		accessToken, err := refreshVaultAccessToken()
		if err != nil {
			common.Log.Panicf("failed to refresh vault access token; %s", err.Error())
		}

		DefaultVaultAccessJWT = *accessToken
		if DefaultVaultAccessJWT == "" {
			common.Log.Panicf("failed to authorize vault access token for environment")
		}
	}

	defaultVaultSealUnsealKey = os.Getenv("VAULT_SEAL_UNSEAL_KEY")
	if defaultVaultSealUnsealKey == "" {
		common.Log.Panicf("failed to parse VAULT_SEAL_UNSEAL_KEY from environent")
	}

	err := UnsealVault()
	if err != nil {
		common.Log.Panicf("failed to unseal vault; %s", err.Error())
	}
}

// SealVault seals the configured vault context
func SealVault() error {
	_, err := vault.Seal(DefaultVaultAccessJWT, map[string]interface{}{
		"key": defaultVaultSealUnsealKey,
	})

	if err != nil {
		common.Log.Warningf("failed to seal vault; %s", err.Error())
		return err
	}

	return nil
}

// UnsealVault unseals the configured vault context
func UnsealVault() error {
	_, err := vault.Unseal(common.StringOrNil(DefaultVaultAccessJWT), map[string]interface{}{
		"key": defaultVaultSealUnsealKey,
	})

	if err != nil {
		common.Log.Warningf("failed to unseal vault; %s", err.Error())
		return err
	}

	return nil
}

func refreshVaultAccessToken() (*string, error) {
	token, err := ident.CreateToken(defaultVaultRefreshJWT, map[string]interface{}{
		"grant_type": "refresh_token",
	})

	if err != nil {
		common.Log.Warningf("failed to authorize access token for given vault refresh token; %s", err.Error())
		return nil, err
	}

	if token.AccessToken == nil {
		err := fmt.Errorf("failed to authorize access token for given vault refresh token: %s", token.ID.String())
		common.Log.Warning(err.Error())
		return nil, err
	}

	return token.AccessToken, nil
}
