package algorithms

import ()

type noneAlg algorithm

// List of "none" algorithms.
var (
	AlgorithmNone = &noneAlg{name: "none"}
)

// Sign returns an empty byte array if no key was given. Otherwise an error is
// returned.
func (n noneAlg) Sign(data string, key []byte) ([]byte, error) {
	if key != nil && len(key) != 0 {
		return nil, ErrNoneKey
	}
	return []byte(""), nil
}

// Valid returns nil if no key was given and the signature is nil or empty.
// Otherwise an error is returned.
func (n noneAlg) Valid(data string, signature, key []byte) error {
	if key != nil && len(key) != 0 {
		return ErrNoneKey
	}
	if signature != nil && len(signature) != 0 {
		return ErrSignatureLength
	}
	return nil
}

// Name returns the name of the algorithm.
func (n noneAlg) Name() string {
	return n.name
}
