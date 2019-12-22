package algorithms

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
)

const (
	RSA_SHA256 = "RS256"
	RSA_SHA384 = "RS384"
	RSA_SHA512 = "RS512"
)

type rsaAlg algorithm

// List of RSA algorithms.
var (
	AlgorithmRS256 = &rsaAlg{name: RSA_SHA256, hash: crypto.SHA256}
	AlgorithmRS384 = &rsaAlg{name: RSA_SHA384, hash: crypto.SHA384}
	AlgorithmRS512 = &rsaAlg{name: RSA_SHA512, hash: crypto.SHA512}
)

// Sign returns the RSA signature for the given data and private key. The key is
// assumed to be PEM encode.
func (r rsaAlg) Sign(data string, key []byte) ([]byte, error) {
	privateKey, err := r.PrivateKey(key)
	if err != nil {
		return nil, err
	}
	h := r.hash.New()
	h.Write([]byte(data))
	return rsa.SignPKCS1v15(rand.Reader, privateKey, r.hash, h.Sum(nil))
}

// Valid returns nil if the signature matches the given data and key. Otherwise,
// an error is returned.
func (r rsaAlg) Valid(data string, signature, key []byte) error {
	publicKey, err := r.PublicKey(key)
	if err != nil {
		return err
	}
	h := r.hash.New()
	h.Write([]byte(data))
	return rsa.VerifyPKCS1v15(publicKey, r.hash, h.Sum(nil), signature)
}

// Name returns the name of the algorithm.
func (r rsaAlg) Name() string {
	return r.name
}

// PrivateKey returns an RSA Private Key object for the given PEM encoded
// private key.
func (r rsaAlg) PrivateKey(key []byte) (*rsa.PrivateKey, error) {
	var p interface{}
	var err error
	der := pemBlock(key)
	if p, err = x509.ParsePKCS1PrivateKey(der); err != nil {
		if p, err = x509.ParsePKCS8PrivateKey(der); err != nil {
			return nil, err
		}
	}
	if privateKey, ok := p.(*rsa.PrivateKey); ok {
		return privateKey, nil
	}
	return nil, ErrInvalidKeyType
}

// PublicKey returns an RSA Public Key object for the given PEM encoded public
// key.
func (r rsaAlg) PublicKey(key []byte) (*rsa.PublicKey, error) {
	der := pemBlock(key)
	p, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		if c, err := x509.ParseCertificate(der); err != nil {
			return nil, err
		} else {
			p = c.PublicKey
		}
	}
	if publicKey, ok := p.(*rsa.PublicKey); ok {
		return publicKey, nil
	}
	return nil, ErrInvalidKeyType
}
