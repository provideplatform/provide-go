package crypto

import (
	"crypto/cipher"
	"crypto/sha256"
	"hash"
	"io"
	"reflect"

	abstractcrypto "gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/kyber.v0/cipher/sha3"
	"gopkg.in/dedis/kyber.v0/edwards"
	"gopkg.in/dedis/kyber.v0/random"
)

type basicSig struct {
	C abstractcrypto.Scalar // challenge
	R abstractcrypto.Scalar // response
}

type suiteBabyJubJub struct {
	edwards.ExtendedCurve
}

// babyJubJubCurve returns the babyJubJub curve
func babyJubJubCurve() *edwards.ExtendedCurve {
	curve := new(edwards.ExtendedCurve)
	return curve.Init(BabyJubJub(), false)
}

func babyJubJubCurveSuite() abstractcrypto.Suite {
	suite := new(suiteBabyJubJub)
	suite.Init(BabyJubJub(), false)
	return suite
}

// BabyJubJub describes the twisted Edwards curve, babyJubJub, required for zero-knowledge proofs
func BabyJubJub() *edwards.Param {
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

// Hash sha256
func (s *suiteBabyJubJub) Hash() hash.Hash {
	return sha256.New()
}

// SHA3/SHAKE128 Sponge Cipher
func (s *suiteBabyJubJub) Cipher(key []byte, options ...interface{}) abstractcrypto.Cipher {
	return sha3.NewShakeCipher128(key, options...)
}

func (s *suiteBabyJubJub) Read(r io.Reader, objs ...interface{}) error {
	return abstractcrypto.SuiteRead(s, r, objs)
}

func (s *suiteBabyJubJub) Write(w io.Writer, objs ...interface{}) error {
	return abstractcrypto.SuiteWrite(s, w, objs)
}

func (s *suiteBabyJubJub) New(t reflect.Type) interface{} {
	return abstractcrypto.SuiteNew(s, t)
}

func (s *suiteBabyJubJub) NewKey(rand cipher.Stream) abstractcrypto.Scalar {
	if rand == nil {
		rand = random.Stream
	}
	return s.Scalar().Pick(rand)
}
