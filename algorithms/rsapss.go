package algorithms

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

const (
	RSAPSS_SHA256 = "PS256"
	RSAPSS_SHA384 = "PS384"
	RSAPSS_SHA512 = "PS512"
)

type rsapssAlg struct {
	rsaAlg
	Options *rsa.PSSOptions
}

// List of RSA PSS algorithms.
var (
	AlgorithmPS256 = rsapssAlg{
		rsaAlg: *AlgorithmRS256,
		Options: &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       crypto.SHA256,
		},
	}
	AlgorithmPS384 = rsapssAlg{
		rsaAlg: *AlgorithmRS384,
		Options: &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       crypto.SHA384,
		},
	}
	AlgorithmPS512 = rsapssAlg{
		rsaAlg: *AlgorithmRS512,
		Options: &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       crypto.SHA512,
		},
	}
)

// Sign returns the RSA PSS signature for the given data and private key. The
// key is assumed to be PEM encode.
func (r rsapssAlg) Sign(data string, key []byte) ([]byte, error) {
	privateKey, err := r.PrivateKey(key)
	if err != nil {
		return nil, err
	}
	h := r.hash.New()
	h.Write([]byte(data))
	return rsa.SignPSS(rand.Reader, privateKey, r.hash, h.Sum(nil), r.Options)
}

// Valid returns nil if the signature matches the given data and key. Otherwise,
// an error is returned.
func (r rsapssAlg) Valid(data string, signature, key []byte) error {
	publicKey, err := r.PublicKey(key)
	if err != nil {
		return err
	}
	h := r.hash.New()
	h.Write([]byte(data))
	return rsa.VerifyPSS(publicKey, r.hash, h.Sum(nil), signature, r.Options)
}

// Name returns the name of the algorithm.
func (r rsapssAlg) Name() string {
	return r.name
}

// PrivateKey returns an RSA Private Key object for the given PEM encoded
// private key.
func (r rsapssAlg) PrivateKey(key []byte) (*rsa.PrivateKey, error) {
	return r.rsaAlg.PrivateKey(key)
}

// PublicKey returns an RSA Public Key object for the given PEM encoded public
// key.
func (r rsapssAlg) PublicKey(key []byte) (*rsa.PublicKey, error) {
	return r.rsaAlg.PublicKey(key)
}
