package provide

import (
	"fmt"

	"gopkg.in/dedis/kyber.v0/edwards"
	"gopkg.in/dedis/kyber.v0/random"
	// "gopkg.in/dedis/kyber.v0/nist"
)

// TECGenerateKeyPair - creates and returns an Twisted Edwards Curve (TEC) keypair;
func TECGenerateKeyPair() (publicKey, privateKey []byte, err error) {
	curve := new(edwards.ExtendedCurve)
	curve.Init(ZKPBabyJubJub(), false)

	privkey := curve.Scalar().Pick(random.Stream)
	pubkey := curve.Point().Mul(nil, privkey)

	if privkey != nil && pubkey != nil {
		privateKey = []byte(privkey.String())
		publicKey = []byte(pubkey.String())
	}

	if privateKey == nil || publicKey == nil {
		return nil, nil, fmt.Errorf("failed to generate key pair on twisted edwards curve")
	}

	return publicKey, privateKey, nil
}

// ZKPBabyJubJub describes the twisted Edwards curve, babyJubJub, required for zero-knowledge proofs
func ZKPBabyJubJub() *edwards.Param {
	var p edwards.Param

	p.Name = "babyJubJub"
	p.P.SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	p.Q.SetString("2736030358979909402780800718157159386076813972158567259200215660948447373041", 10)
	p.R = 8

	p.A.SetInt64(168700)
	p.D.SetInt64(168696)

	p.FBX.SetString("17777552123799933955779906779655732241715742912184938656739573121738514868268", 10)
	p.FBY.SetString("2626589144620713026669568689430873010625803728049924121243784502389097019475", 10)

	p.PBX.SetString("16540640123574156134436876038791482806971768689494387082833631921987005038935", 10)
	p.PBY.SetString("20819045374670962167435360035096875258406992893633759881276124905556507972311", 10)

	return &p
}
