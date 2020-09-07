package crypto

import (
	"testing"
)

func TestBcoinGenerateKeyPair(t *testing.T) {
	addr, privateKey, _ := BcoinGenerateKeyPair(0x00)
	if addr == nil || privateKey == nil {
		t.Fail()
	}
}
