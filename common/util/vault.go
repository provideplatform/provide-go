package util

import (
	"fmt"
	"os"
	"time"

	ident "github.com/provideplatform/provide-go/api/ident"
	vault "github.com/provideplatform/provide-go/api/vault"
	common "github.com/provideplatform/provide-go/common"
)

const refreshTokenTickInterval = 60000 * 45 * time.Millisecond
const refreshTokenSleepInterval = 60000 * 10 * time.Millisecond

const requireVaultTickerInterval = time.Second * 5
const requireVaultSleepInterval = time.Second * 1
const requireVaultTimeout = time.Minute * 1

var (
	// DefaultVaultAccessJWT for the default vault context
	DefaultVaultAccessJWT string

	// defaultVaultRefreshJWT for the default vault context
	defaultVaultRefreshJWT string

	// defaultVaultSealUnsealKey for the default vault context
	defaultVaultSealUnsealKey string
)

// RequireVault panics if the VAULT_REFRESH_TOKEN is not given or an access
// token is otherwise unable to be obtained; attempts to unseal the vault if possible
func RequireVault() {
	startTime := time.Now()

	common.Log.Warningf("Starting RequireVault timer")
	timer := time.NewTicker(requireVaultTickerInterval)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			common.Log.Warningf("TIMER")
			stat := ident.Status()
			common.Log.Warningf("Ident Status: %s", stat)
			if stat == nil {
				defaultVaultRefreshJWT = os.Getenv("VAULT_REFRESH_TOKEN")
				common.Log.Warningf("defaultVaultRefreshJWT: %s", defaultVaultRefreshJWT)

				if defaultVaultRefreshJWT != "" {
					accessToken, err := refreshVaultAccessToken()
					if err != nil {
						common.Log.Warningf("failed to refresh vault access token; %s", err.Error())
						continue
					}

					DefaultVaultAccessJWT = *accessToken
					if DefaultVaultAccessJWT == "" {
						common.Log.Warning("failed to authorize vault access token for environment")
						continue
					}

					go func() {
						timer := time.NewTicker(refreshTokenTickInterval)
						for {
							select {
							case <-timer.C:
								token, err := refreshVaultAccessToken()
								if err != nil {
									common.Log.Warningf("failed to refresh vault access token; %s", err.Error())
								} else {
									DefaultVaultAccessJWT = *token
								}
							default:
								time.Sleep(refreshTokenSleepInterval)
							}
						}
					}()
				}

				defaultVaultSealUnsealKey = os.Getenv("VAULT_SEAL_UNSEAL_KEY")
				common.Log.Warningf("defaultVaultSealUnsealKey: %s", defaultVaultSealUnsealKey)
				if defaultVaultSealUnsealKey != "" {
					common.Log.Debug("parsed VAULT_SEAL_UNSEAL_KEY from environment")

					err := UnsealVault()
					if err != nil {
						common.Log.Warningf("failed to unseal vault; %s", err.Error())
						continue
					}
				}

				vaults, err := vault.ListVaults(DefaultVaultAccessJWT, map[string]interface{}{})
				common.Log.Warningf("Num Vaults: %d", len(vaults))
				if err != nil {
					common.Log.Warningf("failed to fetch vaults for given token; %s", err.Error())
					continue
				}

				if len(vaults) > 0 {
					// HACK
					common.Log.Warningf("HACK")
					Vault = vaults[0]
					common.Log.Debugf("resolved default vault instance: %s", Vault.ID.String())
				} else {
					common.Log.Warningf("Getting Vault")
					Vault, err = vault.CreateVault(DefaultVaultAccessJWT, map[string]interface{}{
						"name":        fmt.Sprintf("default vault %d", time.Now().Unix()),
						"description": "default vault instance",
					})
					if err != nil {
						common.Log.Warningf("failed to create default vault instance; %s", err.Error())
						continue
					}
					common.Log.Debugf("created default vault instance: %s", Vault.ID.String())
				}

				return
			}
		default:
			common.Log.Warningf("DEFAULT")
			common.Log.Warningf("Timed out? %d", startTime.Add(requireVaultTimeout).Before(time.Now()))
			if startTime.Add(requireVaultTimeout).Before(time.Now()) {
				common.Log.Panicf("failed to require vaults is not working")
			} else {
				time.Sleep(requireVaultSleepInterval)
			}
		}
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
