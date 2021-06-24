package crypto

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/aead/ecdh"
	"github.com/provideplatform/provide-go/common"
)

type point struct {
	X, Y *big.Int
}

// C25519ComputeSecret - computes the shared secret given a private key and peer's public key
func C25519ComputeSecret(privateKey, peerPublicKey []byte) []byte {
	privkeyBytes := [32]byte{}
	pubkeyBytes := [32]byte{}

	copy(privkeyBytes[:], privateKey)
	copy(pubkeyBytes[:], peerPublicKey)

	var privkey crypto.PrivateKey
	privkey = privkeyBytes

	var pubkey crypto.PublicKey
	pubkey = pubkeyBytes

	c25519 := ecdh.X25519()
	return c25519.ComputeSecret(privkey, pubkey)
}

// C25519GenerateKeyPair - generates a c25519 keypair suitable for Diffie-Hellman key exchange
func C25519GenerateKeyPair() (publicKey, privateKey []byte, err error) {
	c25519 := ecdh.X25519()

	privkey, pubkey, err := c25519.GenerateKey(rand.Reader)
	if err != nil {
		common.Log.Warningf("failed to generate c25519 key pair; %s", err.Error())
		return nil, nil, err
	}

	privkeyBytes := privkey.([32]byte)
	pubkeyBytes := pubkey.([32]byte)

	privateKey = privkeyBytes[:]
	publicKey = pubkeyBytes[:]

	if privateKey == nil || publicKey == nil {
		return nil, nil, fmt.Errorf("failed to generate c25519 key pair")
	}

	common.Log.Debugf("generated c25519 keypair with public key: %s", string(publicKey))
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
