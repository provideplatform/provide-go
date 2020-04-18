package provide

import (
	"bytes"
	"encoding/hex"
	"fmt"

	abstractcrypto "gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/kyber.v0/random"
)

// TECGenerateKeyPair - creates and returns an Twisted Edwards Curve (TEC) keypair;
func TECGenerateKeyPair() (publicKey, privateKey []byte, err error) {
	curve := babyJubJubCurveSuite()

	privkey := curve.NewKey(nil)
	pubkey := curve.Point().Mul(nil, privkey)

	if privkey != nil && pubkey != nil {
		privkeyBin, privKeyErr := privkey.MarshalBinary()
		if privKeyErr != nil {
			return nil, nil, fmt.Errorf("failed to marshal private key to binary encoding; %s", privKeyErr.Error())
		}

		pubkeyBin, pubKeyErr := pubkey.MarshalBinary()
		if pubKeyErr != nil {
			return nil, nil, fmt.Errorf("failed to marshal public key to binary encoding; %s", pubKeyErr.Error())
		}

		privateKey = []byte(hex.EncodeToString(privkeyBin))
		publicKey = []byte(hex.EncodeToString(pubkeyBin))
	}

	if privateKey == nil || publicKey == nil {
		return nil, nil, fmt.Errorf("failed to generate key pair on twisted edwards curve")
	}

	log.Debugf("generated twisted edwards keypair with public key: %s", string(publicKey))
	return publicKey, privateKey, nil
}

// TECSign signs the given message using the given private key, which is assumed to be hex-encoded
// TODO: see crypto/anon/sig.go to add anonymous sigs
func TECSign(privateKey, message []byte) ([]byte, error) {
	suite := babyJubJubCurveSuite()

	privkeyBin, err := hex.DecodeString(string(privateKey))
	if err != nil {
		log.Warningf("failed to decode private key from hex; %s", err.Error())
		return nil, err
	}

	privkey := suite.Scalar()
	err = privkey.UnmarshalBinary(privkeyBin)
	if err != nil {
		log.Warningf("failed to unmarshal binary private key; %s", err.Error())
		return nil, err
	}

	rand := random.Stream

	v := suite.Scalar().Pick(rand)
	T := suite.Point().Mul(nil, v)

	// Create challenge c based on message and T
	c := tecHash(message, T)

	// Compute response r = v - x*c
	r := suite.Scalar()
	r.Mul(privkey, c).Sub(v, r)

	// Return verifiable signature {c, r}
	// Verifier will be able to compute v = r + x*c
	// And check that hashElgamal for T and the message == c
	buf := bytes.Buffer{}
	sig := basicSig{c, r}
	err = suite.Write(&buf, &sig)
	if err != nil {
		log.Warningf("failed to sign %d-byte message; %s", len(message), err.Error())
		return nil, err
	}

	signature := buf.Bytes()

	log.Debugf("signed %d-byte message; signature:\n%s", len(message), hex.Dump(signature))
	return signature, nil
}

// TECVerify verifies a signature for the given message and public key; the public key is assumed to be hex-encoded
func TECVerify(publicKey, message []byte, signature []byte) error {
	suite := babyJubJubCurveSuite()

	pubkeyBin, err := hex.DecodeString(string(publicKey))
	if err != nil {
		log.Warningf("failed to decode public key from hex; %s", err.Error())
		return err
	}

	pubkey := suite.Point()
	err = pubkey.UnmarshalBinary(pubkeyBin)
	if err != nil {
		log.Warningf("failed to unmarshal public key; %s", err.Error())
		return err
	}

	log.Debugf("attempting to verify %d-byte message using public key: %s", len(message), string(publicKey))

	buf := bytes.NewBuffer(signature)
	sig := basicSig{}
	if err := suite.Read(buf, &sig); err != nil {
		return err
	}
	r := sig.R
	c := sig.C

	// Compute base**(r + x*c) == T
	var P, T abstractcrypto.Point
	P = suite.Point()
	T = suite.Point()
	T.Add(T.Mul(nil, r), P.Mul(pubkey, c))

	// verify that the hash based on the message and T matches the challange c from the signature
	c = tecHash(message, T)
	if !c.Equal(sig.C) {
		return fmt.Errorf("failed to verifiy %d-byte message using public key: %s", len(message), string(publicKey))
	}

	return nil
}

// tecHash returns a secret that depends on on a message and a point
func tecHash(message []byte, p abstractcrypto.Point) abstractcrypto.Scalar {
	suite := babyJubJubCurveSuite()
	pb, _ := p.MarshalBinary()
	c := suite.Cipher(pb)
	c.Message(nil, nil, message)
	return suite.Scalar().Pick(c)
}
