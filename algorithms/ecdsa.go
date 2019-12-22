package algorithms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
)

const (
	ECDSA_SHA256 = "ES256"
	ECDSA_SHA384 = "ES384"
	ECDSA_SHA512 = "ES512"
	EC256_KEYSZ  = 32 // 256 bits = 32 bytes
	EC348_KEYSZ  = 48 // 384 bits = 48 bytes
	EC512_KEYSZ  = 66 // 521 bits ~ 66 bytes
)

type ecdsaAlg struct {
	algorithm
	keysz int
	curve elliptic.Curve
}

// List of ECDSA algorithms.
var (
	AlgorithmES256 = &ecdsaAlg{
		algorithm: algorithm{name: ECDSA_SHA256, hash: crypto.SHA256},
		keysz:     EC256_KEYSZ,
		curve:     elliptic.P256(),
	}
	AlgorithmES384 = &ecdsaAlg{
		algorithm: algorithm{name: ECDSA_SHA384, hash: crypto.SHA384},
		keysz:     EC348_KEYSZ,
		curve:     elliptic.P384(),
	}
	AlgorithmES512 = &ecdsaAlg{
		algorithm: algorithm{name: ECDSA_SHA512, hash: crypto.SHA512},
		keysz:     EC512_KEYSZ,
		curve:     elliptic.P521(),
	}
)

// Sign returns the ECDSA signature for the given data and private key. The key
// is assumed to be PEM encoded.
func (e ecdsaAlg) Sign(data string, key []byte) ([]byte, error) {
	privateKey, err := e.PrivateKey(key)
	if err != nil {
		return nil, err
	}
	h := e.hash.New()
	h.Write([]byte(data))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, h.Sum(nil))
	if err != nil {
		return nil, err
	}
	bitSize := e.curve.Params().BitSize
	sz := bitSize / 8
	if bitSize%8 > 0 {
		sz++
	}
	rBytes := bigIntToBytes(r, sz)
	sBytes := bigIntToBytes(s, sz)
	return append(rBytes, sBytes...), nil
}

// Valid returns nil if the signature is valid for the given data and ECDSA
// public key. Otherwise an error is returned. The key is assumed to be PEM
// encoded.
func (e ecdsaAlg) Valid(data string, signature, key []byte) error {
	publicKey, err := e.PublicKey(key)
	if err != nil {
		return err
	}
	r := big.NewInt(0).SetBytes(signature[:e.keysz])
	s := big.NewInt(0).SetBytes(signature[e.keysz:])
	h := e.hash.New()
	h.Write([]byte(data))
	if !ecdsa.Verify(publicKey, h.Sum(nil), r, s) {
		return ErrInvalidSignature
	}
	return nil
}

// Name returns the name of the ECDSA algorithm.
func (e ecdsaAlg) Name() string {
	return e.name
}

// ValidFromPrivateKey returns nil if the signature is valid for the given data
// and ECDSA private key. Otherwise an error is returned. The key is assumed to
// be PEM encoded.
func (e ecdsaAlg) ValidFromPrivateKey(data string, signature, key []byte) error {
	if len(signature) != 2*e.keysz {
		return ErrSignatureLength
	}
	privateKey, err := e.PrivateKey(key)
	if err != nil {
		return err
	}
	publicKey := privateKey.Public().(*ecdsa.PublicKey)
	r := big.NewInt(0).SetBytes(signature[:e.keysz])
	s := big.NewInt(0).SetBytes(signature[e.keysz:])
	h := e.hash.New()
	h.Write([]byte(data))
	if !ecdsa.Verify(publicKey, h.Sum(nil), r, s) {
		return ErrInvalidSignature
	}
	return nil
}

// PrivateKey returns an ECDSA Private Key object for the given PEM encoded
// private key.
func (e ecdsaAlg) PrivateKey(key []byte) (*ecdsa.PrivateKey, error) {
	der := pemBlock(key)
	return x509.ParseECPrivateKey(der)
}

// PublicKey returns an ECDSA Public Key object for the given PEM encoded public
// key.
func (e ecdsaAlg) PublicKey(key []byte) (*ecdsa.PublicKey, error) {
	der := pemBlock(key)
	p, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	switch p := p.(type) {
	case *ecdsa.PublicKey:
		return p, nil
	}
	return nil, ErrInvalidKeyType
}
