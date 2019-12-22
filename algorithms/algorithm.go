package algorithms

import (
	"crypto"
	"encoding/pem"
	"errors"
	"math/big"
)

// List of possible errors.
var (
	ErrInvalidKeyType   = errors.New("invalid key type")
	ErrInvalidSignature = errors.New("invalid signature for given key")
	ErrSignatureLength  = errors.New("invalid signature length")
	ErrNoneKey          = errors.New("\"none\" algorithm cannot use key")
)

// SigningAlgorithm represents the interface to an algorithm for signing JWTs.
type SigningAlgorithm interface {
	Sign(data string, key []byte) ([]byte, error)
	Valid(data string, signature, key []byte) error
	Name() string
}

type algorithm struct {
	name string
	hash crypto.Hash
}

func pemBlock(key []byte) []byte {
	block := new(pem.Block)
	if block, _ = pem.Decode([]byte(key)); block == nil {
		return nil
	}
	return block.Bytes
}

func bigIntToBytes(i *big.Int, sz int) []byte {
	bPadded := make([]byte, sz)
	b := i.Bytes()
	copy(bPadded[sz-len(b):], b)
	return bPadded
}
