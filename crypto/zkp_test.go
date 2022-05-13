/*
 * Copyright 2017-2022 Provide Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
