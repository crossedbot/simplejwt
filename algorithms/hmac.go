package algorithms

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256"
	_ "crypto/sha512" // has both sha384 and sha512
)

const (
	HMAC_SHA256 = "HS256"
	HMAC_SHA384 = "HS384"
	HMAC_SHA512 = "HS512"
)

type hmacAlg algorithm

// List of HMAC algorithms.
var (
	AlgorithmHS256 = &hmacAlg{name: HMAC_SHA256, hash: crypto.SHA256}
	AlgorithmHS384 = &hmacAlg{name: HMAC_SHA384, hash: crypto.SHA384}
	AlgorithmHS512 = &hmacAlg{name: HMAC_SHA512, hash: crypto.SHA512}
)

// Sign returns the signature for the given data using the given key via the
// HMAC algorithm.
func (ha *hmacAlg) Sign(data string, key []byte) ([]byte, error) {
	h := hmac.New(ha.hash.New, key)
	h.Write([]byte(data))
	return h.Sum(nil), nil
}

// Valid returns nil if the signature matches the given data and key. Otherwise,
// an error is returned.
func (ha *hmacAlg) Valid(data string, signature, key []byte) error {
	signature2, err := ha.Sign(data, key)
	if err != nil {
		return err
	}
	if !hmac.Equal(signature, signature2) {
		return ErrInvalidSignature
	}
	return nil
}

// Name returns the name of the HMAC algorithm.
func (ha *hmacAlg) Name() string {
	return ha.name
}
