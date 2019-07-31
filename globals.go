package provide

import (
	"crypto/rsa"
	"os"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/kthomas/go-logger"
)

// Log global
var (
	jwtPublicKey    *rsa.PublicKey
	jwtPublicKeyPEM string

	log = logger.NewLogger("provide-go", getLogLevel(), true)
)

func init() {
	jwtPublicKeyPEM = os.Getenv("JWT_SIGNER_PUBLIC_KEY")
	if jwtPublicKeyPEM != "" {
		publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(jwtPublicKeyPEM))
		if err != nil {
			log.Panicf("Failed to parse JWT public key; %s", err.Error())
		}
		jwtPublicKey = publicKey
	}
}

func getLogLevel() string {
	lvl := os.Getenv("LOG_LEVEL")
	if lvl == "" {
		lvl = "debug"
	}
	return lvl
}

func stringOrNil(str string) *string {
	if str == "" {
		return nil
	}
	return &str
}
