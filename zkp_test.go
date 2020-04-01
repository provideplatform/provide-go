package provide

import (
	"testing"
)

func TestTECGenerateKeyPair(t *testing.T) {
	publicKey, privateKey, _ := TECGenerateKeyPair()
	if publicKey == nil || privateKey == nil {
		t.Fail()
	}

	log.Debugf("private key: %s", privateKey)
	log.Debugf("public key: %s", publicKey)
}
