package common

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/kthomas/go-logger"
	"github.com/kthomas/go-pgputil"

	selfsignedcert "github.com/kthomas/go-self-signed-cert"
)

const defaultJWTApplicationClaimsKey = "prvd"
const defaultJWTNatsClaimsKey = "nats"
const defaultJWTAuthorizationAudience = "https://provide.services/api/v1"
const defaultJWTAuthorizationIssuer = "https://ident.provide.services"
const defaultJWTAuthorizationTTL = time.Hour * 24
const defaultNatsJWTAuthorizationAudience = "https://websocket.provide.services"

// gin configuration vars
var (
	// ListenAddr is the http server listen address
	ListenAddr string

	// ListenPort is the http server listen port
	ListenPort string

	// CertificatePath is the SSL certificate path used by HTTPS listener
	CertificatePath string

	// PrivateKeyPath is the private key used by HTTPS listener
	PrivateKeyPath string

	// ServeTLS is true when CertificatePath and PrivateKeyPath are valid
	ServeTLS bool
)

// jwt configuration vars
var (

	// JWTApplicationClaimsKey is the key within the JWT payload where application-specific claims are encoded
	JWTApplicationClaimsKey string

	// JWTAuthorizationAudience is the audience who will consume the JWT; this will be set as the JWT "aud" claim
	JWTAuthorizationAudience string

	// JWTAlternativeAuthorizationAudiences are additional valid audiences who will consume signed JWTs, keyed on a scope; these will be allowed to be set as the JWT "aud" claim
	JWTAlternativeAuthorizationAudiences map[string]interface{}

	// JWTAuthorizationIssuer is the common name of the operator of the token vending machine; this will be set as the JWT "iss" claim
	JWTAuthorizationIssuer string

	// JWTAuthorizationTTL is the ttl in milliseconds for new token authorizations, calculated from the issued at timestamp ("iat" claim)
	JWTAuthorizationTTL time.Duration

	// JWTNatsClaimsKey is the key within the JWT claims payload where NATS-specific claims are encoded
	JWTNatsClaimsKey string

	// JWTNatsAuthorizationAudience is the audience who will consume the NATS bearer authorization JWT; this will be set as the JWT "aud" claim
	JWTNatsAuthorizationAudience string

	// JWTKeypairs is a map of JWTKeypair instances which contains the configured RSA public/private keypairs for JWT signing and/or verification, keyed by fingerprint
	jwtKeypairs     map[string]*jwtKeypair
	jwtPublicKey    *rsa.PublicKey
	jwtPublicKeyPEM string

	// Log global
	Log *logger.Logger
)

type jwtKeypair struct {
	fingerprint string
	publicKey   rsa.PublicKey
	privateKey  *rsa.PrivateKey
}

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

// RequireGin initializes the gin configuration
func RequireGin() {
	ListenAddr = os.Getenv("LISTEN_ADDR")
	if ListenAddr == "" {
		ListenPort = os.Getenv("PORT")
		if ListenPort == "" {
			ListenPort = "8080"
		}
		ListenAddr = fmt.Sprintf("0.0.0.0:%s", ListenPort)
	}

	requireTLSConfiguration()
}

func requireTLSConfiguration() {
	certificatePath := os.Getenv("TLS_CERTIFICATE_PATH")
	privateKeyPath := os.Getenv("TLS_PRIVATE_KEY_PATH")
	if certificatePath != "" && privateKeyPath != "" {
		CertificatePath = certificatePath
		PrivateKeyPath = privateKeyPath
		ServeTLS = true
	} else if os.Getenv("REQUIRE_TLS") == "true" {
		privKeyPath, certPath, err := selfsignedcert.GenerateToDisk([]string{})
		if err != nil {
			Log.Panicf("failed to generate self-signed certificate; %s", err.Error())
		}
		PrivateKeyPath = *privKeyPath
		CertificatePath = *certPath
		ServeTLS = true
	}
}

// RequireJWT allows a package to conditionally require a valid JWT configuration
// in the ident environment; at least one RS256 keypair must be configured using
// the JWT_SIGNER_PRIVATE_KEY and JWT_SIGNER_PUBLIC_KEY environment variables
func RequireJWT() {
	Log.Debug("attempting to read required JWT configuration environment for signing JWT tokens")

	if os.Getenv("JWT_APPLICATION_CLAIMS_KEY") != "" {
		JWTApplicationClaimsKey = os.Getenv("JWT_APPLICATION_CLAIMS_KEY")
	} else {
		JWTApplicationClaimsKey = defaultJWTApplicationClaimsKey
	}

	if os.Getenv("JWT_NATS_CLAIMS_KEY") != "" {
		JWTNatsClaimsKey = os.Getenv("JWT_NATS_CLAIMS_KEY")
	} else {
		JWTNatsClaimsKey = defaultJWTNatsClaimsKey
	}

	JWTNatsAuthorizationAudience = os.Getenv("JWT_NATS_AUTHORIZATION_AUDIENCE")
	if JWTNatsAuthorizationAudience == "" {
		JWTNatsAuthorizationAudience = defaultNatsJWTAuthorizationAudience
	}

	JWTAuthorizationAudience = os.Getenv("JWT_AUTHORIZATION_AUDIENCE")
	if JWTAuthorizationAudience == "" {
		JWTAuthorizationAudience = defaultJWTAuthorizationAudience
	} else if JWTAuthorizationAudience == "_self" {
		ip, err := ResolvePublicIP()
		if err != nil {
			Log.Panicf("failed to resolve public ip; %s", err.Error())
		}
		JWTAuthorizationAudience = fmt.Sprintf("http://%s:%s/api/v1", *ip, ListenPort)
	}

	JWTAlternativeAuthorizationAudiences = map[string]interface{}{}
	if os.Getenv("JWT_ALT_AUTHORIZATION_AUDIENCES") != "" {
		err := json.Unmarshal([]byte(os.Getenv("JWT_ALT_AUTHORIZATION_AUDIENCES")), &JWTAlternativeAuthorizationAudiences)
		if err != nil {
			Log.Panicf("failed to parse JWT_ALT_AUTHORIZATION_AUDIENCES from environment; %s", err.Error())
		}
	}

	JWTAuthorizationIssuer = os.Getenv("JWT_AUTHORIZATION_ISSUER")
	if JWTAuthorizationIssuer == "" {
		JWTAuthorizationIssuer = defaultJWTAuthorizationIssuer
	}

	if os.Getenv("JWT_AUTHORIZATION_TTL") != "" {
		ttlMillis, err := strconv.Atoi(os.Getenv("JWT_AUTHORIZATION_TTL"))
		if err != nil {
			Log.Panicf("failed to parse JWT_AUTHORIZATION_TTL from environment; %s", err.Error())
		}
		JWTAuthorizationTTL = time.Millisecond * time.Duration(ttlMillis)
	} else {
		JWTAuthorizationTTL = defaultJWTAuthorizationTTL
	}

	requireJWTKeypairs()
}

// RequireJWTVerifiers allows a package to conditionally require RS256 signature
// verification in the configured environment via JWT_SIGNER_PUBLIC_KEY; the
// use-case for this support is when another microservice is depending on the
// token authorization middleware provided in this package
func RequireJWTVerifiers() {
	Log.Debug("attempting to read required public key from environment for verifying signed JWT")
	if jwtKeypairs == nil {
		jwtKeypairs = map[string]*jwtKeypair{}
	}

	jwtPublicKeyPEM := strings.Replace(os.Getenv("JWT_SIGNER_PUBLIC_KEY"), `\n`, "\n", -1)
	publicKey, err := pgputil.DecodeRSAPublicKeyFromPEM([]byte(jwtPublicKeyPEM))
	if err != nil {
		Log.Panicf("failed to parse JWT public key; %s", err.Error())
	}

	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		Log.Panicf("failed to resolve JWT public key fingerprint; %s", err.Error())
	}
	fingerprint := ssh.FingerprintLegacyMD5(sshPublicKey)

	jwtKeypairs[fingerprint] = &jwtKeypair{
		fingerprint: fingerprint,
		publicKey:   *publicKey,
	}

	Log.Debugf("jwt keypair configured: %s", fingerprint)
}

func requireJWTKeypairs() {
	Log.Debug("attempting to read required RS256 keypair(s) from environment for signing JWT tokens")
	jwtKeypairs = map[string]*jwtKeypair{}

	jwtPrivateKeyPEM := strings.Replace(os.Getenv("JWT_SIGNER_PRIVATE_KEY"), `\n`, "\n", -1)
	privateKey, err := pgputil.DecodeRSAPrivateKeyFromPEM([]byte(jwtPrivateKeyPEM))
	if err != nil {
		Log.Panicf("failed to parse JWT private key; %s", err.Error())
	}

	jwtPublicKeyPEM := strings.Replace(os.Getenv("JWT_SIGNER_PUBLIC_KEY"), `\n`, "\n", -1)
	publicKey, err := pgputil.DecodeRSAPublicKeyFromPEM([]byte(jwtPublicKeyPEM))
	if err != nil {
		Log.Panicf("failed to parse JWT public key; %s", err.Error())
	}

	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		Log.Panicf("failed to resolve JWT public key fingerprint; %s", err.Error())
	}
	fingerprint := ssh.FingerprintLegacyMD5(sshPublicKey)

	jwtKeypairs[fingerprint] = &jwtKeypair{
		fingerprint: fingerprint,
		publicKey:   *publicKey,
		privateKey:  privateKey,
	}
}

func resolveJWTFingerprints() []string {
	fingerprints := make([]string, 0, len(jwtKeypairs))
	for k := range jwtKeypairs {
		fingerprints = append(fingerprints, k)
	}
	return fingerprints
}

// ResolveJWTKeypair returns the configured public/private signing keypair and its
// fingerprint, if one has been configured; this impl will be upgraded soon to allow
// many key to be configured
func ResolveJWTKeypair(fingerprint *string) (*rsa.PublicKey, *rsa.PrivateKey, *string) {
	if jwtKeypairs == nil || len(jwtKeypairs) == 0 {
		return nil, nil, nil
	}

	var keypair *jwtKeypair

	if fingerprint == nil {
		keypair = jwtKeypairs[resolveJWTFingerprints()[0]]
	} else {
		if jwtKeypair, jwtKeypairOk := jwtKeypairs[*fingerprint]; jwtKeypairOk {
			keypair = jwtKeypair
		}
	}

	if keypair == nil {
		return nil, nil, nil
	}

	return &keypair.publicKey, keypair.privateKey, &keypair.fingerprint
}

// ResolvePublicIP resolves the public IP of the caller
func ResolvePublicIP() (*string, error) {
	url := "https://api.ipify.org?format=text" // FIXME
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	ip, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	ipstr := string(ip)
	return &ipstr, nil
}

// StringOrNil returns a pointer to the string, or nil if the given string is empty
func StringOrNil(str string) *string {
	if str == "" {
		return nil
	}
	return &str
}
