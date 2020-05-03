package algorithms

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNoneSign(t *testing.T) {
	data := "data"
	b, err := AlgorithmNone.Sign(data, []byte{})
	require.Nil(t, err)
	require.Equal(t, []byte{}, b)
	b, err = AlgorithmNone.Sign(data, []byte{0x01, 0x02, 0x03, 0x04})
	require.Nil(t, b)
	require.Equal(t, ErrNoneKey, err)
}

func TestNoneValid(t *testing.T) {
	data := "data"
	err := AlgorithmNone.Valid(data, []byte{}, []byte{})
	require.Nil(t, err)
	err = AlgorithmNone.Valid(data, []byte("signature"), []byte{})
	require.Equal(t, ErrNoneKey, err)
	err = AlgorithmNone.Valid(data, []byte{}, []byte{})
	require.Equal(t, ErrSignatureLength, err)
}

func TestNoneName(t *testing.T) {
	expected := AlgorithmNone.name
	actual := AlgorithmNone.Name()
	require.Equal(t, expected, actual)
}
