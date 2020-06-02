package provide

import (
	"crypto/rsa"
	"os"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/kthomas/go-logger"
)

// Log global
var (
	jwtPublicKey    *rsa.PublicKey
	jwtPublicKeyPEM string

	log *logger.Logger
)

func init() {
	jwtPublicKeyPEM = strings.Replace(os.Getenv("JWT_SIGNER_PUBLIC_KEY"), `\n`, "\n", -1)
	if jwtPublicKeyPEM != "" {
		publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(jwtPublicKeyPEM))
		if err != nil {
			log.Panicf("Failed to parse JWT public key; %s", err.Error())
		}
		jwtPublicKey = publicKey
	}

	log = logger.NewLogger("provide-go", getLogLevel(), getSyslogEndpoint())
}

func getLogLevel() string {
	lvl := os.Getenv("LOG_LEVEL")
	if lvl == "" {
		lvl = "debug"
	}
	return lvl
}

func getSyslogEndpoint() *string {
	var endpoint *string
	if os.Getenv("SYSLOG_ENDPOINT") != "" {
		endpoint = stringOrNil(os.Getenv("SYSLOG_ENDPOINT"))
	}
	return endpoint
}

func stringOrNil(str string) *string {
	if str == "" {
		return nil
	}
	return &str
}
