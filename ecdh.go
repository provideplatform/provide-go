package provide

import (
	"crypto/rand"
	"fmt"

	"github.com/aead/ecdh"
)

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
