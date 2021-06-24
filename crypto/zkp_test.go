package crypto

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/provideplatform/provide-go/common"
)

func TestTECGenerateKeyPair(t *testing.T) {
	publicKey, privateKey, _ := TECGenerateKeyPair()
	if publicKey == nil || privateKey == nil {
		t.Fail()
	}

	common.Log.Debugf("private key: %s", privateKey)
	common.Log.Debugf("public key: %s", publicKey)
}

func TestTECSign(t *testing.T) {
	publicKey, privateKey, _ := TECGenerateKeyPair()
	if publicKey == nil || privateKey == nil {
		t.Fail()
	}

	msg := []byte("hello world")
	sig, err := TECSign(privateKey, msg)
	if err != nil {
		fmt.Printf("failed to sign message; %s", err.Error())
		t.Fail()
		return
	}

	fmt.Printf("signature:\n%s", hex.Dump(sig))
}

func TestTECVerify(t *testing.T) {
	publicKey, privateKey, _ := TECGenerateKeyPair()
	if publicKey == nil || privateKey == nil {
		t.Fail()
	}

	common.Log.Debugf("public key: %s", publicKey)

	msg := []byte("hello world")
	sig, err := TECSign(privateKey, msg)
	if err != nil {
		t.Fail()
	}

	err = TECVerify(publicKey, msg, sig)
	if err != nil {
		fmt.Printf("FAIL; %s", err.Error())
		t.Fail()
		return
	}

	common.Log.Debugf("verified signed message:\n%s", hex.Dump(sig))
}
