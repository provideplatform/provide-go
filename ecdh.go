package provide

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/aead/ecdh"
)

type point struct {
	X, Y *big.Int
}

// C25519ComputeSecret - computes the shared secret given a private key and peer's public key
func C25519ComputeSecret(privateKey, peerPublicKey []byte) []byte {
	var privkey crypto.PrivateKey
	privkey = privateKey

	var pubkey crypto.PublicKey
	pubkey = peerPublicKey

	c25519 := ecdh.X25519()
	return c25519.ComputeSecret(privkey, pubkey)
}

// C25519GenerateKeyPair - generates a c25519 keypair suitable for Diffie-Hellman key exchange
func C25519GenerateKeyPair() (publicKey, privateKey []byte, err error) {
	c25519 := ecdh.X25519()

	privkey, pubkey, err := c25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Warningf("failed to generate c25519 key pair; %s", err.Error())
		return nil, nil, err
	}

	privateKey = privkey.([]byte)
	publicKey = pubkey.([]byte)

	if privateKey == nil || publicKey == nil {
		return nil, nil, fmt.Errorf("failed to generate c25519 key pair")
	}

	log.Debugf("generated c25519 keypair with public key: %s", string(publicKey))
	return publicKey, privateKey, nil
}

func checkPrivateKey(typ interface{}) (key []byte, ok bool) {
	switch t := typ.(type) {
	case []byte:
		key = t
		ok = true
	case *[]byte:
		key = *t
		ok = true
	}

	return key, ok
}

func checkPublicKey(typ interface{}) (key point, ok bool) {
	switch t := typ.(type) {
	case point:
		key = t
		ok = true
	case *point:
		key = *t
		ok = true
	}

	return key, ok
}
