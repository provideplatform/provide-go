package common

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

	Log *logger.Logger
)

func init() {
	jwtPublicKeyPEM = strings.Replace(os.Getenv("JWT_SIGNER_PUBLIC_KEY"), `\n`, "\n", -1)
	if jwtPublicKeyPEM != "" {
		publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(jwtPublicKeyPEM))
		if err != nil {
			Log.Panicf("Failed to parse JWT public key; %s", err.Error())
		}
		jwtPublicKey = publicKey
	}

	Log = logger.NewLogger("provide-go", getLogLevel(), getSyslogEndpoint())
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
		endpoint = StringOrNil(os.Getenv("SYSLOG_ENDPOINT"))
	}
	return endpoint
}

// StringOrNil returns a pointer to the string, or nil if the given string is empty
func StringOrNil(str string) *string {
	if str == "" {
		return nil
	}
	return &str
}
